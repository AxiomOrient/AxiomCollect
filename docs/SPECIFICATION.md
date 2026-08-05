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

Windows의 Job Object 경로는 구현되어 있지만, 현재 macOS 검증 호스트에서는 Windows native build/runtime를 실행할 수 없다. 따라서 Windows 검증 상태는 `[UNVERIFIED]`이며 Windows 호스트에서 별도로 검증한다.

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
