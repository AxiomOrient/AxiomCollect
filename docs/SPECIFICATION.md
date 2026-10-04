# Specification

## Input contract

Schema version은 `7`이다.

`FetchRequest`는 사용자 의도만 가진다.

- `url`
- `mode`: `auto | static | rendered`
- `browser_capability`: `content | screenshot`
- `evidence.selectors`
- `evidence.required_text`
- `evidence.minimum_text_bytes`

`ExecutionPolicy`는 operator authority다.

- finite `BudgetConfig`
- `network`: 기본 `public_only`
- optional screenshot artifact root
- `adaptive`: device hint, bounded attempt count, Phase 0/recipe/browser/extraction toggles, Jina Reader opt-out, and explicit persistence paths

URL host는 소문자와 root label 제거로 정규화해 DNS 검증·주소 pin·egress proxy가 모두 같은 문자열을 본다. URL은 최대 8 KiB, selector는 최대 32개/각 512 bytes, required text는 최대 64개/각 4 KiB/총 64 KiB다. 제품 hard cap을 넘는 budget은 거부한다. Screenshot은 operator-configured artifact root와 `auto|rendered`가 필요하다.

CLI만 budget/private/artifact option을 받는다. MCP input에는 이 권한이 없다.

## Mode semantics

- explicit mode: hidden HTTP prefetch나 다른 capability 전환 없음
- `auto/content`: `Phase 0 public routes/media/recipes → origin HTTP → WAF-profile adaptive grid → rendered chain`
- `auto/screenshot`: rendered chain direct
- rendered chain: `installed browser/eoka → configured Puppeteer Core rescue`
- terminal: invalid/policy/DNS/budget/internal failure
- escalatable: unusable/empty/unsupported content, dynamic shell, unmet evidence, backend availability/failure

`auto/content`의 후보는 원본 URL에서 결정적으로 만들며, built-in HTTP transport와 같은 DNS/IP·redirect·retry·byte·operation·wall budget을 사용한다. 직접 HTTP/media route는 요청 시도 단위로, browser/egress route는 공개 upstream 연결 단위로 network operation을 계수한다. Phase 0에는 외부 기준의 공식·공개 API/RSS/metadata/oEmbed/mobile 변형, 내장 Rust `media_oembed`의 명시적 YouTube·Vimeo·SoundCloud 카탈로그, checked-in recipe, Threads inline metadata rescue가 포함된다. Jina Reader fallback은 기본 활성화이며 `--no-jina-reader`로 제외할 수 있다. origin HTTP가 transient/불충분하면 embedded WAF profile detector가 URL transform·일반 UA·referer grid의 우선순위를 정하지만 TLS fingerprint impersonation은 하지 않는다. `max_attempts`는 probe를 포함해 network hard limit 안에서만 허용된다. credential·token·secret 계열 query key가 있는 원본 URL은 정책 단계에서 거부해 어떤 route에도 전달하지 않는다. CAPTCHA, 로그인·인증, paywall이 관찰되면 이를 해제하거나 우회하지 않고 `access_restricted` typed failure로 즉시 중단한다.

`static`은 built-in HTTP다. `rendered`는 installed Chromium-family browser를 eoka CDP로 먼저 사용하고, eoka 실패·불충분과 명시적 rescue 설정이 모두 있을 때만 Puppeteer Core로 복구한다. Provider CLI, browser daemon, browser bundle은 없다.

## Browser contract

- Chrome, Chromium, Chrome Canary, Brave, Edge의 기존 설치를 순서대로 탐색
- 명시 경로는 `--browser-path`/`AXIOM_COLLECT_BROWSER` 사용
- Chromium-family version probe와 실제 CDP/JavaScript handshake 요구
- browser 설치·다운로드 없음
- eoka `=0.5.4`, binary patch 비활성
- optional Puppeteer Core `=25.4.0`, Node.js 20+, `--puppeteer-root`/`AXIOM_COLLECT_PUPPETEER_ROOT`
- runtime npm/npx 호출 없음; setup은 lifecycle script와 browser download를 비활성화
- sandbox 유지
- unique temporary HOME/profile과 mock keychain
- loopback CDP, parent-owned egress proxy
- 모든 subresource 연결의 connection-time public DNS/IP 검사와 공개 upstream connection-operation 상한
- final URL 재검증
- 각 backend는 DOM stable state, final URL, screenshot을 같은 page에서 관찰
- `--auto-forge`는 같은 브라우저·같은 egress 세션에서 이미 관찰한 same-origin JSON/API response를 최대 32개까지 bounded body capture로 선택하며, CDP body read는 network operation으로 계수하지 않고 새 endpoint 재요청·cookie injection을 하지 않음
- rendered main-document response status는 navigate가 돌려준 main frame의 `Document` response에서만 취하며 nested iframe status를 채택하지 않음
- rendered main-document response status를 관찰하며 2xx가 아니면 error HTML을 content success로 취급하지 않음
- browser의 비정상 종료 코드나 잘린 진단 출력은 이미 검증된 capture를 실패로 바꾸지 않고 attempt 진단으로 남김
- timeout/cancel/close failure 시 Chrome/Node process group 또는 job과 artifact 정리

Windows의 Job Object 경로는 구현되어 있지만 Windows native build/runtime는 Windows 호스트에서 별도로 검증해야 한다. Linux의 source·process fixture 검증은 macOS/Windows와 실제 브라우저 runtime 검증을 대신하지 않는다.

## HTTP semantics

Public route 후보와 `media_oembed`는 built-in HTTP transport를 재사용한다. `media_oembed`는 명시적 YouTube·Vimeo·SoundCloud 호스트만 공식 oEmbed endpoint로 파생하고, transport의 public DNS/IP 검증·manual redirect·retry·byte·operation·wall budget을 그대로 적용한다. 응답에서는 allowlisted scalar metadata만 보존하며 media/caption/thumbnail/signed URL/embed HTML은 내려받거나 반환하지 않는다. derived oEmbed endpoint의 실패는 origin의 접근 결정으로 취급하지 않는다. route provider, 후보 URL, 전이 원인은 attempt trace에 남기며, 성공한 후보의 `final_url`과 `provider_used`를 보존한다. Wayback 후보는 CDX JSON의 `timestamp`와 `statuscode=200`을 검증한 뒤에만 snapshot replay를 실행하며, CDX와 replay attempt를 모두 trace에 남긴다. 민감한 query key가 있는 원본 URL은 route 생성 전에 policy reject된다.

- 2xx만 content candidate
- 204/205 거부
- 301/302/303/307/308만 수동 redirect
- 429/502/503/504와 connect/timeout만 bounded retry
- redirect마다 URL/DNS/IP 재검증
- error body를 content success로 추출하지 않음
- origin backend의 401/402와 인증·paywall로 판정된 403은 route를 종결한다. Auto mode의 403은 body를 한 번 adaptive probe로 분류하며 challenge marker가 없으면 즉시 terminal이고, challenge marker가 있을 때만 bounded public grid를 허용한다.
- 파생 route 후보의 401/403은 해당 route의 불가용이므로 전이 가능
- response body streaming 중 per-response/total/wall budget 확인
- adaptive profile route도 같은 body·wall·operation budget을 사용하며 origin 401/402/403은 기존 terminal safety boundary로 유지한다. Network operation은 HTTP/media의 outbound request attempt 또는 browser/egress의 public upstream connection이며, CDP 내부 body read는 별도 32개 cap과 byte budget으로 제한한다.
- recipe header는 `Accept`, `Referer`, `X-Requested-With`, `Content-Type`, `User-Agent`만 허용하고 `Cookie`, `Authorization`, secret-like query는 전달하지 않는다.
- `--enable-learning`일 때만 host/device route win을 30일 TTL·500건 한도의 JSON store와 optional JSONL observation에 기록한다. MCP 기본 실행은 persistence를 쓰지 않는다.

## Extraction과 evidence

- HTML/XHTML: title, description, main/article/body visible text, links, JSON-LD, selector hits. A thin JavaScript shell may use an article `articleBody`/description from JSON-LD when it is longer than the visible shell.
- HTML 옵션: `--maincontent`는 semantic article/main/content root를 boilerplate보다 우선하고, 기본 CLI는 외부 기준에 맞춰 markdown 변환을 활성화한다. `--no-markdown`과 `--no-extract`로 각각 plain DOM/raw response 계약을 선택할 수 있다.
- JSON/+json: strict parse와 structured text
- XML/RSS/Atom: visible text
- text/*: charset decode와 whitespace normalization
- charset은 선언된 Content-Type, BOM, 문서 안 `<meta charset>` 또는 `http-equiv=content-type`의 속성 순으로 결정하고 없으면 UTF-8
- PDF: text layer, malformed/textless 입력 실패
- 기타 binary: unsupported

선언된 media type이 내용 추론보다 우선한다. `text/*`는 첫 문자가 `{` 또는 `[`여도 text로 처리한다. Content-Type이 없거나 `application/octet-stream`인 경우에만 PDF/HTML/XML/JSON을 sniff하고, JSON 추론 parse 실패는 plain text로 복구한다.

HTML은 하나의 DOM에서 script/style/noscript/template을 제외해 순회한다. Required text는 case-normalized multi-pattern matcher 한 번으로 평가한다. 요청한 evidence는 모두 만족해야 한다.

## Output contract

`ok=true` 조건:

1. `transport_status=accepted`
2. `content_status=parsed`
3. usable content
4. evidence 요청 시 `evidence_status=satisfied`
5. content/final URL/backend/extraction provenance와 nonempty trace
6. `failure=null`
7. result invariant 통과

실패는 typed `FailureCode`를 갖는다. 후보 content를 보존한 실패는 그 후보의 `provider_used`와 extraction metadata를 유지하고, 최종 backend 실패는 `failure_provider`에 기록한다.

각 attempt는 backend, phase, redacted URL, duration, bytes, 실제 egress operation count, redirect chain, outcome, transition reason/error를 기록한다. 성공한 attempt의 `error`에는 결과를 실패로 만들지 않는 browser 종료 진단이 들어갈 수 있다.

## MCP contract

- newline-delimited stdio JSON-RPC
- current-only protocol `2026-07-28`
- default input frame limit 1 MiB
- `server/discover`, `tools/list`, `tools/call`
- `retrieve_public_url`, `doctor`
- typed input/output JSON Schema
- 짧은 text summary + 단일 `structuredContent`
- `initialize` handshake는 지원하지 않음

## Operator commands

아래 명령은 저장소 루트에서 실행한다.

## Public route catalog

- Reddit RSS, Hacker News Firebase API, GitHub REST API, arXiv Atom API, Stack Exchange API, Bluesky/Mastodon/dev.to/Lobsters/V2EX 공개 API, Crossref/Wikipedia/OpenLibrary/npm/PyPI metadata API, Naver blog/news mobile URL, X syndication·oEmbed를 URL에서 결정적으로 파생한다. YouTube oEmbed는 `media_oembed`만 소유한다.

Jina Reader는 URL 앞에 `https://r.jina.ai/`를 붙여 공개 페이지를 읽는 외부 서비스다. 기본적으로 활성화되지만 `--no-jina-reader`로 명시적으로 제외할 수 있다. 사용 시 최종 URL과 provider를 결과에서 확인해야 한다.

## Browser 설치 정책

이미 설치된 브라우저만 사용한다.

- 자동 탐색 우선순위는 Google Chrome, Chromium, Chrome Canary, Brave, Edge다.
- `--browser-path`로 지정한 실행 파일은 Chromium 계열 version probe와 실제 CDP handshake를 모두 통과해야 한다.
- Chrome for Testing, chrome-headless-shell, Playwright/Puppeteer browser bundle을 다운로드하거나 설치하지 않는다.
- 프로그램과 dependency의 browser 자동 다운로드를 금지한다.
- `eoka 0.5.4`를 정확히 고정하며 custom CDP filtering과 JS evasion을 사용한다.
- optional rescue는 `puppeteer-core 25.4.0`만 정확히 고정한다. 런타임은 npm이나 installer를 호출하지 않는다.
- eoka의 Chrome binary patch는 사용하지 않는다.
- 사용자 browser profile이나 로그인 keychain을 사용하지 않는다.
- macOS에서는 isolated profile과 `--use-mock-keychain`을 사용해 키체인 접근·팝업·credential 저장을 막는다.

설치된 호환 브라우저를 찾지 못하면 `rendered`는 `tool_unavailable`로 실패한다. 설치 부작용은 절대 일으키지 않는다.

### Optional Puppeteer Core 복구 준비

eoka가 설치 Chrome의 특정 CDP 동작과 충돌할 때만 쓰는 2차 경로다. 이 기능을 사용하지 않으면 Node.js와 npm은 전혀 필요하지 않다. 준비 작업은 명시적으로 한 번 실행하며 빈 source tree 밖 디렉터리를 지정한다.

```bash
RUNTIME_DIR=/absolute/path/to/empty/puppeteer-runtime
mkdir "$RUNTIME_DIR"
cp puppeteer-rescue/package.json puppeteer-rescue/package-lock.json "$RUNTIME_DIR"/
(
  cd "$RUNTIME_DIR"
  PUPPETEER_SKIP_DOWNLOAD=true npm ci --ignore-scripts --no-audit --no-fund
)

axiom-collect \
  --puppeteer-root /absolute/path/to/empty/puppeteer-runtime \
  doctor --require-rendered --pretty
```

`npm ci`는 exact `puppeteer-core` library만 설치한다. Chrome/Chromium 다운로드, `npx`, browser installer는 실행하지 않는다. `AXIOM_COLLECT_PUPPETEER_ROOT`와 optional `AXIOM_COLLECT_NODE`로도 경로를 설정할 수 있다.

## 설치, build와 전체 검증

Rust `1.97.1`이 필요하다.

```bash
cargo install --path . --locked
cargo build --release --locked
./scripts/verify.sh
./scripts/clean.sh
```

`verify.sh`는 저장소 정책, format, 모든 target의 check, warning을 오류로 처리하는 Clippy, 그리고 호스트 환경에 의존하지 않는 unit/integration test를 실행한다. 브라우저나 public network가 필요한 rendered test는 `#[ignore]`로 분리되어 있으며, 필요한 환경에서 해당 `cargo test` 명령을 직접 실행한다.

브라우저가 준비된 경우에는 `cargo test --test provider_integration --locked -- --ignored --skip puppeteer_rescue`를 직접 실행한다. 준비된 rescue runtime은 `AXIOM_COLLECT_TEST_BROWSER`와 `AXIOM_COLLECT_TEST_PUPPETEER_ROOT`를 설정한 뒤 해당 ignored 테스트를 직접 실행한다. `clean.sh`는 Cargo target, runtime artifact, 저장소 안의 Puppeteer 의존성, `.DS_Store`만 제거하며, 삭제 전 목록은 `./scripts/clean.sh --dry-run`으로 확인한다.

## Codex skill

`skills/axiom-collect/`가 canonical Axiom Collect skill package다. 스킬은 retrieval engine을 복제하지 않고 `axiom-collect` 바이너리를 호출한다. 플랫폼별 완성 바이너리는 `references`에 넣지 않는다. 로컬 사용은 `AXIOM_COLLECT_BIN` 또는 `AXIOM_COLLECT_ROOT`로 명시하고, 배포 시에는 대상 플랫폼의 release binary를 스킬의 `bin/axiom-collect`에 별도로 공급한다. 소스 저장소에는 플랫폼별 binary를 커밋하지 않는다.

## 사용

```bash
axiom-collect retrieve https://example.com --mode static --pretty

axiom-collect retrieve https://example.com \
  --mode auto \
  --selector h1 \
  --require-text "Example Domain" \
  --minimum-text-bytes 20 \
  --omit-content \
  --pretty

axiom-collect retrieve https://example.com \
  --mode auto \
  --device mobile \
  --max-attempts 8 \
  --maincontent \
  --no-markdown \
  --pretty
```

성공은 다음 세 층을 모두 만족해야 한다.

```text
transport_status = accepted
content_status   = parsed
evidence_status  = satisfied | not_requested
ok               = true
```

HTTP 2xx만으로 성공하지 않는다. 반대로 rendered error page도 성공하지 않는다. HTTP와 두 browser backend 모두 main-document non-2xx를 거부한다. 빈 문서, 추출 실패, 동적 shell, 요청한 evidence 불충족은 실패 또는 `auto`의 공개 route·adaptive grid·browser 전이 원인이 된다. CAPTCHA·인증·paywall gate는 `access_restricted`로 반환하며 이를 해제하는 fallback은 시도하지 않는다.

### Rendered DOM과 screenshot

```bash
axiom-collect \
  --browser-path "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  retrieve https://example.com \
  --mode rendered \
  --browser-capability screenshot \
  --artifact-dir ./artifacts \
  --pretty
```

`AXIOM_COLLECT_BROWSER` 환경 변수로 브라우저 경로를 설정할 수도 있다. 렌더링 하위 리소스는 별도 도메인 나열 없이 허용되지만, 모든 연결은 로컬 egress proxy가 연결 시점 DNS/IP를 검사해 public 주소로만 제한한다.

전체 페이지 screenshot은 남은 total-byte budget에 맞춰 pixel 상한을 먼저 적용하고, CDP base64 결과도 디코딩 전 상한을 확인한다.

각 rendered 요청은 다음을 소유하고 반드시 정리한다.

- 권한 `0700` 임시 profile
- sandbox가 켜진 headless browser process group/job object
- loopback CDP endpoint 또는 격리된 Node/Puppeteer Core process group
- domain·DNS/IP·operation·byte budget을 집행하는 egress proxy
- 성공한 screenshot artifact 또는 실패 시 제거되는 부분 artifact

## 실행 권한 경계

`FetchRequest`에는 URL, mode, capability, evidence처럼 사용자 의도만 들어간다. 예산, private-network 권한, artifact directory는 `ExecutionPolicy`로 분리되어 CLI operator나 embedding host만 결정한다.

`--allow-private`는 explicit `static` mode에만 허용된다. MCP input에는 private-network 권한, 예산, artifact path가 없다. MCP screenshot은 server 시작 시 `axiom-collect mcp --artifact-dir <DIR>`로 artifact root를 설정해야 한다.

## Doctor와 MCP

```bash
axiom-collect doctor --pretty
axiom-collect --puppeteer-root /absolute/path/to/puppeteer-runtime doctor --require-rendered --pretty
axiom-collect capabilities --pretty
axiom-collect mcp
```

MCP는 newline-delimited stdio transport와 1 MiB 기본 input-frame limit를 사용한다. 지원 protocol은 `2026-07-28` 하나이며 도구는 `retrieve_public_url`, `doctor`다.

## Exit code

| 코드 | 의미 |
|---:|---|
| 0 | 성공 |
| 1 | 일반 실행 실패 |
| 2 | 잘못된 요청 |
| 3 | URL/DNS 정책 거부 |
| 4 | budget 소진 |
| 5 | 설치된 호환 브라우저 없음 |
| 6 | mode/capability 미지원 |

설계와 계약은 `docs/ARCHITECTURE.md`, `docs/SPECIFICATION.md`에 있다. 검증은 로컬 `scripts/verify.sh`만 사용한다. GitHub Actions, CI/CD, release automation, `.github/workflows/`는 지원하지 않으며 생성·수정하지 않는다. 저장소 정책과 clean-break 규칙은 `AGENTS.md`에 있다.

## Process deadline and cleanup limits

External commands share one monotonic work deadline across stdin, process completion and output drains. Timeout, error and cancellation request group/job cleanup. Drop-path reaping is best effort, and numeric process-group IDs are not generation-pinned capabilities. Descendants that leave the original group/session and PID/PGID reuse races remain outside the guarantee. Synchronous spawning and OS cleanup can exceed the cooperative work budget; successful commands are not required to terminate every detached descendant.

Actual browser, macOS and Windows execution require separate host qualification. Source publication does not establish release readiness. License and dependency attribution remain in [LICENSE](../LICENSE) and [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
