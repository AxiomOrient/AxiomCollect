# Security

## 범위와 신뢰

제품은 공개 HTTP(S) URL 회수와 content extraction만 담당한다. 로그인, credential 주입, 결제, CAPTCHA/paywall 우회, destructive browser interaction은 범위 밖이다. 회수된 content는 항상 `untrusted_external`이다.

## Network 경계

- `http`/`https` 외 scheme과 URL userinfo를 거부한다.
- public-only가 기본이며 private, loopback, link-local, documentation, multicast, reserved/special IP가 DNS 결과에 하나라도 있으면 fail-closed한다.
- HTTP redirect는 자동 추적하지 않고 URL·DNS·IP를 매번 재검증한다.
- HTTP client는 environment proxy와 automatic redirect를 사용하지 않고 검증한 IP에 연결한다.
- 렌더링 브라우저의 모든 HTTP(S) egress는 loopback proxy를 통과한다.
- proxy가 연결 시점 DNS/IP, 실제 연결 IP, operation/byte budget을 소유한다.
- rendered final URL도 별도로 재검증한다.
- `allow_private`는 CLI/embedding operator의 explicit `static` 요청에만 허용한다.

## Browser 경계

- 이미 설치된 Chromium 계열 브라우저만 허용한다.
- Google Chrome, Chromium, Chrome Canary, Brave, Edge를 탐색할 수 있지만 설치하지 않는다.
- browser bundle, installer, auto-download fallback은 금지한다.
- `eoka`의 binary patch는 비활성화한다.
- optional rescue는 exact `puppeteer-core` library와 Node.js만 사용한다. runtime은 npm/npx를 호출하지 않고 explicit existing browser path만 launch한다.
- rescue setup은 lifecycle script와 browser download를 비활성화하며 source tree 밖의 명시적 빈 디렉터리만 대상으로 한다.
- 요청마다 임시 HOME과 권한 `0700` profile을 만든다.
- 사용자 browser profile, cookie, credential, login keychain을 읽거나 보존하지 않는다.
- macOS에서 `--use-mock-keychain`을 사용해 키체인 접근과 popup을 방지한다.
- browser sandbox를 끄지 않는다.
- CDP는 loopback-only endpoint로 연결한다.
- Chrome과 optional Node helper는 Unix process group 또는 Windows job object 단위로 종료한다.

## Resource와 실패 경계

- wall, connect/read, response/extracted/total bytes, network operation, redirect, retry, retry delay, browser launch에 hard limit가 있다.
- URL, evidence, CSS selector, MCP frame에도 hard limit가 있다.
- PDF object/page stream은 전체 extraction budget에서 파생한 decompression limit로 처리한다.
- subprocess diagnostic은 bounded drain한다.
- timeout/cancel/CLI interrupt 시 browser tree와 proxy를 종료한다.
- CDP close, process wait/kill, egress shutdown 실패를 숨기지 않는다.
- partial screenshot은 실패 시 제거하며 성공 artifact만 size와 SHA-256을 기록한다.
- result invariant가 provenance나 상태 모순을 발견하면 `internal_error`로 fail-closed한다.

## Data 노출

- URL query value와 fragment는 result/trace에서 redaction한다.
- browser 오류도 요청 URL을 redaction한 뒤 노출한다.
- MCP input은 사용자 intent만 받으며 budget, network authority, filesystem path를 받지 않는다.
- 저장소는 browser profile, cookie, credential, cache를 보존하지 않는다.
