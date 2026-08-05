# Architecture

## 정체성과 공개 경계

**Axiom Collect**의 본질은 검색 엔진이 아니라 검증 가능한 URL retrieval이다. 공개 API는 `FetchRequest`, `ExecutionPolicy`, `Engine`, `FetchResult`, `RuntimeConfig`로 제한한다.

독립 Rust 프로그램이 canonical 제품이며 CLI/MCP가 실행 계약이다. Codex skill은 이 계약을 설명하고 호출할 뿐 engine이나 fallback을 복제하지 않는다. 상위 research orchestrator는 의도 해석과 수집 계획을 소유하고 실제 URL effect는 `axiom-collect`에 위임한다.

```text
User intent                         Operator authority
FetchRequest                        ExecutionPolicy
  URL / mode / evidence               budget / network / artifact root
          │                                      │
          └────────── compile_request ────────────┘
                         │
                   PreparedRequest
                         │
                       Engine
```

MCP caller는 private network, 과도한 budget, 임의 filesystem path를 요청할 수 없다.

## Backend 전이

상태 전이는 실제로 fallback이 존재하는 engine route에만 둔다.

```text
auto/content:    Phase 0 public/API/media/recipe → origin HTTP probe
                                  ├─ sufficient → result
                                  └─ blocked/thin → WAF profile transform×UA×referer grid
                                                       ├─ sufficient → result
                                                       └─ insufficient → public fallback/rendered chain

rendered chain:  installed browser/eoka
                  ├─ sufficient → result (optional same-origin auto-forge selection)
                  └─ failed/insufficient → configured Puppeteer Core rescue

auto/screenshot: rendered chain
static:          HTTP
rendered:        rendered chain
```

Route 실행은 effect와 판정을 나눈다. `RouteExecutor`는 DNS·socket·subprocess·browser를 수행하고, `run_route`는 그 결과만으로 전이·후보 보존·종결 분류·provenance를 결정한다. 분기가 있는 쪽은 후자인데 `auto`는 public DNS를 요구하고 private-network 권한은 explicit `static`에만 있으므로 loopback 서버로는 사다리를 구동할 수 없다. 따라서 사다리 검증은 network policy를 완화하는 대신 scripted provider outcome으로 `run_route`를 직접 구동한다.

Origin이 스스로 익명 접근을 거부한 경우(HTTP·rendered backend의 401/402와 인증·paywall로 분류된 403)는 관찰된 gate와 같은 종결 경계다. Auto의 403은 body challenge marker를 확인하는 한 번의 adaptive probe만 허용하고, 인증·paywall이면 즉시 종결한다. 파생 route 후보가 돌려준 401/403은 그 route의 불가용이지 대상의 접근 결정이 아니므로 전이 가능하게 남는다.

성공 콘텐츠의 `provider_used`와 마지막 실패의 `failure_provider`는 별도 provenance다. Explicit mode에는 hidden HTTP prefetch나 capability 변경이 없다. `browser → browser_puppeteer`는 rendered capability 내부의 명시적 복구이며 trace에 두 attempt가 모두 남는다.

## Browser session 소유권

동시성과 실패 경계가 실제로 존재하는 지점에만 상태를 둔다. 렌더 세션의 수명은 분기 없는 단일 순서이므로 별도의 상태 열거가 아니라 소유 타입 하나로 표현한다. `BrowserSession`은 다음을 함께 획득하고 함께 해제한다.

- 임시 HOME과 권한 `0700` browser profile
- sandbox가 활성화된 installed browser process group/job object
- loopback-only eoka CDP connection
- public DNS/IP·operation/byte budget을 집행하는 egress proxy

기동 도중 실패하면 그 시점까지 존재하는 자원만 역순으로 해제하고, 정리 실패는 원래 실패에 결합해 숨기지 않는다. capability probe와 실제 retrieval은 같은 타입을 쓰므로 순서가 두 곳에 복제되지 않는다.

정리 결과는 close와 egress로 나눠 보고한다. 이미 검증된 capture를 정리 실패가 가리지 않아야 하고, capture 실패도 정리 실패 정보를 잃지 않아야 하기 때문이다. browser의 비정상 종료 코드나 잘린 진단 출력은 실패가 아니라 attempt 진단으로 남는다.

Puppeteer 복구도 동일한 격리 원칙을 사용한다. Rust가 Node process group, 임시 HOME/profile, egress proxy, wall/byte/operation/browser-launch budget을 소유한다. checked-in helper는 exact `puppeteer-core`와 이미 설치된 browser executable만 받아 launch/capture/close하고, 결과는 bounded 임시 파일과 stdout의 typed status/failure로 반환한다.

CLI `Ctrl-C`, request timeout, future cancellation은 retrieval future를 drop해 process group과 proxy를 정리한다. 정상 경로는 CDP close 후 bounded wait, 실패 경로는 tree kill과 wait를 수행한다.

## 순수 판정과 부수 효과

| 경계 | 책임 |
|---|---|
| `domain` | request/result schema, layered status, invariant, URL redaction, 기본 budget 상수 |
| `request` | intent+authority 검증, evidence 사전 컴파일 |
| `budget` | wall/byte/operation/redirect/retry 예약과 잔여량 |
| `engine` | backend event 전이와 최종 상태 조립 |
| `evidence` | bounded selector와 multi-pattern text 판정 |
| `content_safety` | 단일 multi-pattern scan 기반 prompt-injection 신호 보고 |
| `access_gate` | CAPTCHA·인증·paywall 신호의 보수적 감지와 fail-closed 판정 |
| `extract` | 단일 DOM 기반 콘텐츠/metadata 추출 |
| `public_routes` | URL에서 파생한 공개 API/RSS/metadata/Reader 후보와 route provenance; Jina Reader operator opt-out |
| `adaptive` | insane-search 기준 WAF profile detector, URL transform, safe identity/referer grid, Threads metadata rescue |
| `recipe` | host-scoped YAML rewrite와 allowlisted request headers |
| `learning`, `observations` | explicit CLI opt-in route win store와 JSONL diagnostics |
| `auto_forge` | browser가 이미 관찰한 same-origin API response의 bounded ranking |
| `policy` | URL/domain/IP 규칙과 연결 대상 확정 |
| `transport` | built-in HTTP, redirect/retry/body effect |
| `archive` | Wayback CDX lookup, public 200 capture validation, snapshot replay |
| `media` | Built-in Rust oEmbed metadata adapter for the explicit YouTube, Vimeo, and SoundCloud catalog, reusing `transport` |
| `egress` | browser와 외부 provider의 connection-time public-network enforcement와 upstream connection-operation 계수 |
| `process` | isolated subprocess, bounded diagnostic, group/job cleanup |
| `rendered` | eoka/Puppeteer shared runtime config, browser lifecycle policy, attempt result/failure, artifact cleanup |
| `browser` | installed browser/eoka CDP session, settling, capture, artifact lifecycle |
| `puppeteer` | opt-in rendered recovery adapter; isolated Node/Chrome process and bounded file handoff |
| `cli`, `mcp` | 입력/출력 adapter |

Evidence, content safety, status mapping, invariant는 입력에만 의존한다. DNS, socket, HTTP, browser, filesystem만 effect boundary다.

## 렌더 안정화

브라우저는 navigation 전에 main-document network event를 구독한다. CDP event stream은 유한한 broadcast buffer이므로 안정화 polling 주기마다 계속 배수해 subresource event가 main-document response를 밀어내지 못하게 한다. `Network.responseReceived`는 nested iframe의 주 리소스에도 `Document` 타입을 붙이므로, navigate가 돌려준 main frame id와 일치하는 event만 채택한다. 최종 URL의 response status가 2xx인지 확인한 뒤 `document.readyState=complete`와 MutationObserver의 500 ms quiet window를 기다린다. 최대 대기는 남은 read/wall budget으로 제한된다.

전체 HTML을 polling하지 않는다. mutation timestamp만 검사하고 안정화 후 `outerHTML`을 한 번 직렬화한다. DOM, observed final URL, screenshot은 같은 page에서 순서대로 수집한다.

`--auto-forge`가 켜지면 안정화 직후 JSON/API resource의 response body를 최대 32개까지 CDP에서 읽고, same-origin·status·MIME·URL pattern·page-token overlap으로 하나를 선택한다. 이 CDP body read는 외부 network operation으로 계수하지 않고, response/total-byte budget으로 제한한다. 선택은 이미 관찰한 응답에만 적용되며 쿠키나 signed URL을 새 요청에 재사용하지 않는다.

## 복잡도

실제 입력 크기를 `N`, evidence text pattern 총길이를 `P`, link 수를 `L`, selector 수를 `S`라 할 때:

- visible HTML text: `O(N)` 단일 DOM traversal이며 whitespace 정규화를 같은 pass에서 수행해 중간 문자열을 만들지 않는다
- 고정 CSS selector는 프로세스당 1회만 컴파일한다
- rendered settle: `O(M)` mutation event, polling은 상수 크기 상태만 확인, 최종 DOM capture `O(N)`
- Puppeteer rescue: 같은 settle/capture 복잡도이며 eoka 성공 시 실행 비용은 `O(1)` configuration check뿐
- required-text evidence: `O(N + P + matches)` Aho–Corasick 단일 scan
- content-safety 신호: 같은 방식의 단일 case-insensitive scan `O(N)`
- proxy header framing: `O(N)` incremental delimiter scan
- link dedup/sort: `O(L log L)`
- CSS evidence: `O(S·N)`, 단 `S ≤ 32`

CSS selector는 완전한 selector semantics를 유지해야 하며 selector 수가 hard-bounded이므로 `O(S·N)`을 유지한다. DOM index를 별도로 만드는 것은 복잡도와 메모리를 늘리면서 현재 상한에서 실익이 없다.

제거된 비효율:

- script/style block마다 전체 문자열을 재작성하던 `O(N²)`
- required text마다 content 전체를 재검색하던 반복 scan
- 렌더 안정화를 위해 전체 HTML을 반복 직렬화·비교하는 방식
- content-safety 신호마다 content 전체를 다시 훑던 반복 scan
- 문서마다 같은 리터럴 selector를 다시 파싱하던 비용
- 순회 결과를 정규화하고 다시 trim하며 만들던 전체 문자열 3중 복사
- 정상 경로에서 같은 rendered 결과를 얻기 위한 무조건적 복수 backend 실행
