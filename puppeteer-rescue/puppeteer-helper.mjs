import { promises as fs } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

// The parent maps `code` straight onto a typed FailureCode. It travels as a value
// so that rewording a message can never silently change how a failure is classified.
const fail = (code, message) => Object.assign(new Error(message), { code });

const DISABLE_FEATURES = "--disable-features=";

// Chrome keeps only the last occurrence of a switch, so passing our hardening list
// alongside Puppeteer's own would silently drop one of the two. The union is folded
// into a single flag that is appended after the defaults, which keeps both sets.
function mergeDisableFeatures(defaultArgs, requestedArgs) {
  const features = new Set();
  const collect = (args) => {
    for (const arg of args) {
      if (arg.startsWith(DISABLE_FEATURES)) {
        for (const feature of arg.slice(DISABLE_FEATURES.length).split(",")) {
          if (feature.length > 0) {
            features.add(feature);
          }
        }
      }
    }
  };
  collect(defaultArgs);
  collect(requestedArgs);
  const merged = requestedArgs.filter((arg) => !arg.startsWith(DISABLE_FEATURES));
  if (features.size > 0) {
    merged.push(`${DISABLE_FEATURES}${[...features].join(",")}`);
  }
  return merged;
}

const inputBytes = [];
let inputLength = 0;
for await (const chunk of process.stdin) {
  inputLength += chunk.length;
  if (inputLength > 64 * 1024) {
    throw fail("invalid_request", "helper input exceeds 64 KiB");
  }
  inputBytes.push(chunk);
}

const input = JSON.parse(Buffer.concat(inputBytes).toString("utf8"));
const requiredStrings = [
  "browserExecutable",
  "moduleRoot",
  "outputDirectory",
  "targetUrl",
];
for (const field of requiredStrings) {
  if (typeof input[field] !== "string" || input[field].length === 0) {
    throw fail("invalid_request", `invalid ${field}`);
  }
}
for (const field of [
  "timeoutMs",
  "quietWindowMs",
  "pollIntervalMs",
  "maxResponseBytes",
  "maxScreenshotBytes",
  "maxScreenshotPixels",
]) {
  if (!Number.isSafeInteger(input[field]) || input[field] <= 0) {
    throw fail("invalid_request", `invalid ${field}`);
  }
}
if (!Array.isArray(input.browserArgs) || !input.browserArgs.every((arg) => typeof arg === "string")) {
  throw fail("invalid_request", "invalid browserArgs");
}

const packageFile = path.join(path.resolve(input.moduleRoot), "package.json");
const requireFromRuntime = createRequire(packageFile);
const puppeteer = requireFromRuntime("puppeteer-core");
const puppeteerVersion = requireFromRuntime("puppeteer-core/package.json").version;
const outputDirectory = path.resolve(input.outputDirectory);
const htmlPath = path.join(outputDirectory, "page.html");
const finalUrlPath = path.join(outputDirectory, "final-url.txt");
const screenshotPath = path.join(outputDirectory, "screenshot.png");

let browser;
let primaryError;
let httpStatus = null;
try {
  const defaultArgs = await puppeteer.defaultArgs({
    headless: true,
    userDataDir: path.join(outputDirectory, "browser-profile"),
  });
  const launchArgs = mergeDisableFeatures(defaultArgs, input.browserArgs);
  const effectiveArgs = [...defaultArgs, ...launchArgs];
  if (effectiveArgs.some((arg) => arg === "--no-sandbox" || arg === "--disable-setuid-sandbox")) {
    throw fail("provider_failed", "Puppeteer attempted to disable the browser sandbox");
  }
  browser = await puppeteer.launch({
    executablePath: input.browserExecutable,
    headless: true,
    userDataDir: path.join(outputDirectory, "browser-profile"),
    args: launchArgs,
    timeout: input.timeoutMs,
    protocolTimeout: input.timeoutMs,
    handleSIGINT: false,
    handleSIGTERM: false,
    handleSIGHUP: false,
  });
  const pages = await browser.pages();
  const page = pages[0] ?? (await browser.newPage());
  page.setDefaultNavigationTimeout(input.timeoutMs);
  page.setDefaultTimeout(input.timeoutMs);
  const navigationResponse = await page.goto(input.targetUrl, {
    waitUntil: "domcontentloaded",
    timeout: input.timeoutMs,
  });
  httpStatus = navigationResponse?.status() ?? null;

  const settleDeadline = Date.now() + input.timeoutMs;
  let settled = false;
  while (Date.now() < settleDeadline) {
    const status = await page.evaluate(() => {
      const now = performance.now();
      if (!globalThis.__axiomCollectObserver) {
        globalThis.__axiomCollectLastMutation = now;
        const observer = new MutationObserver(() => {
          globalThis.__axiomCollectLastMutation = performance.now();
        });
        observer.observe(document, {
          subtree: true,
          childList: true,
          attributes: true,
          characterData: true,
        });
        globalThis.__axiomCollectObserver = observer;
      }
      return {
        ready: document.readyState,
        quietMs: now - globalThis.__axiomCollectLastMutation,
      };
    });
    if (status.ready === "complete" && status.quietMs >= input.quietWindowMs) {
      settled = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, input.pollIntervalMs));
  }
  if (!settled) {
    throw fail("budget_exhausted", "page did not reach a stable loaded state");
  }

  const finalUrl = page.url();
  if (!finalUrl) {
    throw fail("provider_failed", "browser did not report a final URL");
  }
  if (Buffer.byteLength(finalUrl) > 16 * 1024) {
    throw fail("budget_exhausted", "browser final URL exceeds 16 KiB");
  }
  const html = await page.content();
  const htmlBytes = Buffer.byteLength(html);
  if (htmlBytes === 0) {
    throw fail("content_empty", "browser returned an empty document");
  }
  if (htmlBytes > input.maxResponseBytes) {
    throw fail("budget_exhausted", "per-response byte budget exhausted");
  }
  await fs.writeFile(htmlPath, html, { flag: "wx" });
  await fs.writeFile(finalUrlPath, finalUrl, { flag: "wx" });

  if (input.screenshot === true) {
    const session = await page.createCDPSession();
    const metrics = await session.send("Page.getLayoutMetrics");
    const rect = metrics.cssContentSize ?? metrics.contentSize;
    const values = [rect?.x, rect?.y, rect?.width, rect?.height];
    const pixels = rect?.width * rect?.height;
    if (
      !values.every(Number.isFinite) ||
      rect.width <= 0 ||
      rect.height <= 0 ||
      !Number.isFinite(pixels) ||
      pixels > input.maxScreenshotPixels
    ) {
      throw fail(
        "budget_exhausted",
        "full-page screenshot dimensions are invalid or exceed the pixel limit",
      );
    }
    const screenshot = await page.screenshot({
      type: "png",
      fullPage: true,
      captureBeyondViewport: true,
    });
    if (screenshot.length === 0) {
      throw fail("provider_failed", "browser produced an empty screenshot");
    }
    if (screenshot.length > input.maxScreenshotBytes) {
      throw fail("budget_exhausted", "screenshot exceeds the remaining byte budget");
    }
    await fs.writeFile(screenshotPath, screenshot, { flag: "wx" });
  }
} catch (error) {
  primaryError = error;
} finally {
  if (browser) {
    try {
      await browser.close();
    } catch (error) {
      const cleanupMessage = error instanceof Error ? error.message : String(error);
      const browserProcess = browser.process();
      let forcedTerminationMessage = "";
      if (browserProcess && browserProcess.exitCode === null && browserProcess.signalCode === null) {
        try {
          browserProcess.kill("SIGKILL");
        } catch (killError) {
          const killMessage = killError instanceof Error ? killError.message : String(killError);
          forcedTerminationMessage = `; forced termination failed: ${killMessage}`;
        }
      }
      primaryError = fail(
        primaryError?.code ?? "provider_failed",
        `${primaryError ? `${primaryError.message}; ` : ""}browser cleanup failed: ${cleanupMessage}${forcedTerminationMessage}`,
      );
    }
  }
}

if (primaryError) {
  const message = primaryError instanceof Error ? primaryError.message : String(primaryError);
  const code = primaryError?.code ?? "provider_failed";
  // Both streams are written: stdout carries the typed contract the parent parses,
  // stderr stays human-readable for anyone running the helper directly.
  process.stdout.write(`${JSON.stringify({ ok: false, puppeteerVersion, code, message })}\n`);
  process.stderr.write(`Puppeteer capture failed: ${message}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`${JSON.stringify({ ok: true, puppeteerVersion, httpStatus })}\n`);
}
