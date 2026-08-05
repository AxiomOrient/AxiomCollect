# Axiom Collect

**Axiom Collect**는 특정 공개 HTTP(S) URL을 회수하고, 추출된 콘텐츠와 요청한 증거 조건을 검증하는 독립 Rust CLI/MCP 프로그램이다. 상위 research orchestrator가 의도를 해석하고 수집 계획을 세우면 이 프로그램이 실제 URL 회수·렌더링·검증을 담당한다. 스킬은 이 실행 파일을 호출하는 얇은 사용 지침이며 수집 엔진을 재구현하지 않는다.

## 제품 구조

```text
CLI JSON (canonical) ─┐
                      ├─ intent → Engine ← operator policy
MCP 2026-07-28 ───────┘       │
                    Phase 0 public API/feed/recipe routes
                              │ insufficient
                         origin HTTP probe
                              │ blocked or thin
                    WAF-profile adaptive HTTP grid
                              │ insufficient
                   installed browser/eoka CDP
                              │ failure or insufficient
              explicit Puppeteer Core rescue + same installed browser
                              │
                    extraction → evidence → invariant → result
```

- `static`은 내장 HTTP만 사용한다.
- `auto/content`는 외부 `insane-search`의 Phase 0 순서를 기준으로 플랫폼 공개 API/RSS·제한된 media oEmbed metadata·checked-in recipe를 먼저 시도하고, origin HTTP probe와 WAF-profile 기반 URL transform·UA·referer grid를 거친 뒤 설치된 브라우저로 전이한다.
- `rendered`는 설치된 Chromium 계열 브라우저를 eoka의 Rust CDP transport로 먼저 제어하고, 명시적으로 준비된 경우에만 Puppeteer Core 복구 경로를 사용한다.
- `auto/content`는 Phase 0/recipe 결과가 없거나 origin HTTP가 차단·동적 shell·evidence 불충족일 때 adaptive grid와 mobile/apex 변형을 시도하고, 그래도 부족할 때만 브라우저로 전이한다.
- `auto/screenshot`은 불필요한 HTTP 선행 요청 없이 브라우저로 바로 간다.
- explicit mode는 HTTP/rendered 의도를 바꾸지 않는다. eoka→Puppeteer 전이는 같은 rendered capability 내부의 실패 복구다.

기본 실행에는 Node.js가 필요하지 않다. `axiom-collect` Rust 바이너리가 static HTTP와 eoka CDP 렌더링을 직접 수행한다. Node.js 20+는 사용자가 Puppeteer Core rescue를 별도로 설정한 경우에만 필요하다.

## 공개 route fallback 정책

공개 route는 `auto/content`에서만 실행되며, `static`과 explicit `rendered`의 의미를 바꾸지 않는다.

- Reddit RSS, Hacker News Firebase API, GitHub REST API, arXiv Atom API, Stack Exchange API, Bluesky/Mastodon/dev.to/Lobsters/V2EX 공개 API, Crossref/Wikipedia/OpenLibrary/npm/PyPI metadata API, Naver blog/news mobile URL, X syndication·oEmbed를 URL에서 결정적으로 파생한다. YouTube oEmbed는 `media_oembed`만 소유한다.
- Wayback CDX에서 공개 200 snapshot을 확인한 뒤 snapshot replay를 시도하며, `www`의 mobile 변형과 Jina Reader(`r.jina.ai`)는 bounded fallback으로만 사용한다. Jina Reader만 제외하려면 `--no-jina-reader`를 사용한다.
- `auto`의 YouTube·Vimeo·SoundCloud 공개 미디어 URL은 내장 Rust oEmbed provider(`media_oembed`)로 안전한 public metadata JSON을 조회한다. 동일한 public DNS/IP·redirect·retry·operation·byte·wall budget을 사용하며 media·caption·embed HTML·thumbnail·signed URL·credential·외부 실행 파일은 조회하거나 결과에 포함하지 않는다.
- 원본 URL의 query key가 API key·token·secret·session·password 계열이면 요청 자체를 거부해 어느 route에도 전달하지 않는다.
- 모든 route는 같은 public DNS/IP·operation·byte·wall budget과 evidence 검증을 공유한다. 직접 HTTP/media route는 요청 시도 단위로, browser/egress route는 공개 upstream 연결 단위로 network operation을 계수한다.
- route URL, provider, transition reason은 trace에 남긴다.
- CAPTCHA, 로그인, credential 사용, paywall 우회는 시도하지 않고 typed failure로 중단한다.
- 외부 프로젝트의 WAF profile YAML은 제품 fingerprint를 detector로만 사용한다. 실제 요청은 기존 public DNS/IP 검증·budget·egress를 통과하는 일반 UA/referer 조합이며, curl_cffi TLS impersonation이나 credential/cookie 주입은 도입하지 않는다.
- `--auto-forge`는 브라우저가 이미 관찰한 same-origin JSON/API response만 최대 32개까지 bounded CDP body capture로 선택한다. CDP body read는 외부 network operation으로 계수하지 않으며, 새 endpoint 호출·쿠키 재사용·signed media URL 반환은 하지 않는다.
- `--enable-learning`을 명시한 CLI 실행만 host/device별 성공 route를 30일·500건 한도로 기록한다. 기본 MCP/CLI 실행은 persistence를 쓰지 않는다.

Jina Reader는 URL 앞에 `https://r.jina.ai/`를 붙여 공개 페이지를 읽는 외부 서비스다. 기본적으로 활성화되지만 `--no-jina-reader`로 명시적으로 제외할 수 있다. 사용 시 최종 URL과 provider를 결과에서 확인해야 한다.

미디어 provider는 기본 설치에 포함되며 Python 또는 별도 실행 파일 설치가 필요 없다. 카탈로그에 없는 플랫폼과 직접 media URL은 이 provider가 추측하지 않고 나머지 public route와 browser chain에 맡긴다.

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

### 플랫폼 검증 상태

Windows용 프로세스 트리 정리 구현(`cfg(windows)`의 Job Object)은 현재 코드에 유지되어 있다. 다만 이 macOS 컴퓨터에서는 Windows 바이너리, Windows 브라우저, 네이티브 Job Object 정리를 실행할 수 없으므로 Windows build/runtime 검증은 `[UNVERIFIED]`이며 이후 Windows 호스트에서 수행한다. 현재 로컬 검증 결과는 macOS에 대해서만 의미가 있다.

후속 Windows 검증에는 Windows build, 설치 브라우저 렌더링, Puppeteer rescue, timeout/cancellation/SIGINT, 그리고 브라우저·Node 자식 프로세스 전체가 Job Object와 함께 종료되는지를 포함해야 한다.

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

## 소스 공개 경계

GitHub source publication에는 Rust source, 문서, tests, skill package와 재현 가능한
local verification entrypoint만 포함한다. `target/`, runtime artifact, Puppeteer
runtime dependency, 플랫폼별 binary는 공개 source에 포함하지 않는다. Windows
Job Object와 실제 설치 브라우저를 포함한 rendered 경로는 별도 환경 증거이며, source
publication만으로 검증 완료나 제품 release를 주장하지 않는다.

직접 dependency와 선택적 Puppeteer Core의 attribution은
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)에 기록한다.
