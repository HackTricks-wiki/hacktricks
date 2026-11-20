# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## A2A란

A2A (Agent2Agent)는 한 AI agent가 다른 agent를 찾아 HTTP를 통해 작업을 보낼 수 있게 해주는 개방형 protocol입니다. MCP는 agent를 **tools and data**에 연결하고, A2A는 보통 다른 팀이나 회사가 소유한 원격 서비스인 **other agents**에 연결합니다. A2A server는 LLM agent가 뒤에 있는 웹 API이므로, protocol 자체의 객체(agent cards, tasks, push-notification webhooks, extended cards)에는 일반적인 API 테스트에 더해 구체적인 인증, IDOR 및 SSRF 검사가 필요합니다.<sup>[[1]](#references)[[2]](#references)</sup>

주요 구성 요소는 다음과 같습니다.

- **Agent Card:** agent를 설명하는 JSON 문서입니다. 이름, 설명, skills, service URL(s), 지원되는 transports, capabilities (streaming, push notifications, extended card)와 client가 사용해야 하는 `securitySchemes`가 포함됩니다. `https://<host>/.well-known/agent-card.json`에 게시됩니다. spec 0.2.x를 따르는 이전 배포 환경에서는 `/.well-known/agent.json`을 사용합니다.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** 작업 단위입니다. 메시지가 task를 생성하고(서버에서 생성한 `id`와 `contextId` 포함), client는 나중에 이를 읽거나 취소하거나 구독합니다.<sup>[[1]](#references)</sup>
- **Transports:** HTTP를 통한 JSON-RPC 2.0 (streaming에는 SSE 사용), gRPC, HTTP+JSON REST binding입니다.<sup>[[1]](#references)</sup>
- **Authentication:** credentials는 HTTP headers에 포함하며(예: `Authorization: Bearer ...`), JSON-RPC payload 내부에 넣지 않습니다. agent card에 필요한 scheme이 표시됩니다.<sup>[[1]](#references)</sup>

버전에 따라 method 이름이 달라졌으므로 두 세트 모두 시도해 보세요.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| 작업 | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| 메시지 전송 | `message/send` | `SendMessage` | `POST /message:send` |
| 스트리밍 전송 | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| task 가져오기 | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| task 목록 조회 | - | `ListTasks` | `GET /tasks` |
| task 취소 | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification 설정 | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

1.0 spec은 `A2A-Version` header(또는 request parameter)를 사용해 버전을 선택하며, 해당 값이 없는 요청은 0.3으로 처리됩니다.<sup>[[1]](#references)</sup>

## Discovery

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

카드에서 다음을 기록합니다.

- 모든 서비스 `url`: 1.0에서는 `supportedInterfaces` 아래에 있으며, 이전 버전의 카드에는 최상위 `url`이 있을 수 있습니다. 내부 호스트 이름, 스테이징 URL, 대체 포트를 포함해 각 엔드포인트와 전송 방식을 기록합니다.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: 에이전트가 할 수 있는 일과 그 뒤에 어떤 도구 또는 데이터가 있는지 보여줍니다.
- `securitySchemes` / `security`: 비어 있거나 누락되어 있다면, 해당 에이전트는 인증 정보 없이 호출되도록 의도되었을 가능성이 높습니다.
- `capabilities.pushNotifications` 및 `capabilities.extendedAgentCard` (0.3에서는 `supportsAuthenticatedExtendedCard`).

명세에 따르면 공개 카드는 인증 정보나 내부 구현 세부 정보를 포함하면 안 됩니다. 따라서 공개 카드에 내부 URL, 키 또는 상세한 도구 목록이 있으면 그 자체로 발견 사항입니다.<sup>[[1]](#references)</sup>

### 멀티 에이전트 호스트에서의 Agent Card 이름 충돌

카드의 `name`은 사람이 읽을 수 있는 레이블이지, 안정적인 라우팅 식별자가 아닙니다.<sup>[[1]](#references)[[5]](#references)</sup> 호스트가 서로 다른 원격 피어 두 개를 같은 로컬 이름으로 등록하면 에이전트 트리, 생성된 도구 이름, 클라이언트 맵 또는 브로커 경로가 신뢰하는 피어를 대상으로 한 작업을 다른 피어로 보낼 수 있습니다.<sup>[[5]](#references)</sup> 이 공격을 위해서는 공격자가 제어하는 피어가 **동일한 라우팅 네임스페이스**에 등록되어야 합니다. 인터넷에 중복 카드를 게시하는 것만으로는 충분하지 않습니다.<sup>[[5]](#references)</sup>

제어 가능한 피어 두 개와 서로 다른 URL, 무해한 마커를 사용해 호스트의 **등록부터 디스패치까지**의 경로를 테스트합니다.<sup>[[5]](#references)</sup>

1. 신뢰하는 피어의 카드, 출처, 로컬 선택자를 기록합니다. 카드의 `name`은 같지만 URL은 직접 제어하는 엔드포인트를 가리키는 두 번째 피어를 등록합니다.
2. 이름으로 신뢰하는 피어를 선택하는 작업을 트리거합니다. 등록 순서를 바꿔 모두 시도하고, 이름이 도구 식별자가 되는 경우에는 호스트의 일반적인 이름 정규화 방식도 확인합니다. 마커를 수신한 엔드포인트와 응답을 반환한 에이전트를 기록합니다.
3. 두 번째 카드의 이름만 바꾸고 다시 시도합니다. 이름 충돌이 있는 경우에만 요청이 두 번째 엔드포인트에 도달한다면 잘못된 피어로 디스패치된다는 뜻입니다. 민감한 컨텍스트나 인증 정보가 실제로 첨부되었는지는 별도로 확인합니다. 이름 충돌만으로는 인증 정보나 도구 권한이 이전되었다고 입증되지 않습니다.

호출자가 카드 이름을 확인하는 대신 출처에 바인딩된 고정 엔드포인트를 호출한다면 이 테스트는 적용되지 않습니다.<sup>[[5]](#references)</sup> 이후의 악성 피어 응답 및 prompt-injection의 영향을 확인하려면 [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary)를 따르세요.

## A2A 엔드포인트 테스트

### 인증되지 않은 작업 제출

카드에 나열된 모든 `url`에 인증 정보 없이 최소한의 메시지를 보냅니다:

```bash
# 0.2 / 0.3 style
curl -s https://target/a2a -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"message/send",
  "params":{"message":{"role":"user","messageId":"6f1c2b9e-0000-4000-8000-000000000001",
            "parts":[{"kind":"text","text":"Reply only with the word PONG."}]}}}'

# 1.0 style
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER","messageId":"6f1c2b9e-0000-4000-8000-000000000002",
            "parts":[{"text":"Reply only with the word PONG."}]}}}'
```

`PONG`을 반환하는 `Task` 또는 `Message` 결과는 card에 security scheme이 선언되어 있는데도 RPC endpoint에서 인증을 강제하지 않는다는 뜻입니다(인증은 UI나 card에서만 강제될 수 있습니다). card에 scheme이 선언되어 있지 않다면 agent의 skills로 어떤 리소스에 접근할 수 있는지 확인하세요. 내부 데이터를 읽거나 도구를 호출할 수 있는 unauthenticated agent는 해당 도구에 대한 unauthenticated API와 다를 바 없습니다.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

사양에 따르면 서버는 모든 요청에서 호출자가 해당 task에 접근할 수 있는지 확인해야 하며, 필터가 지정되지 않은 경우에도 `ListTasks` 결과를 호출자 범위로 제한해야 합니다.<sup>[[1]](#references)</sup> 두 개의 identity(A와 B)로 테스트하세요.

1. A로 task를 생성하고 `id`와 `contextId`를 저장합니다.
2. B로(또는 자격 증명 없이) A의 `id`를 사용해 `tasks/get` / `GetTask`를 호출한 다음, 매개변수 없이 `ListTasks`를 호출합니다.
3. A의 task에 대해 cancel과 subscribe도 시도하고, A의 `taskId` 또는 `contextId`가 포함된 새 메시지를 B로 전송합니다(B의 텍스트가 A의 대화에 추가될 수 있습니다).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

취약: B가 A의 기록, 산출물 또는 상태를 받거나 A의 작업을 변경할 수 있습니다. 안전: `TaskNotFoundError`가 반환되며, "존재하지만 권한이 없음"과 "존재하지 않음"을 구분할 수 없습니다.<sup>[[1]](#references)</sup> Task ID는 UUID인 경우가 많으므로 leak이 발생할 수 있는 위치(공유 링크, 로그, 푸시 알림 payload, 오류 메시지)에서 찾아보세요.

### 푸시 알림 webhook SSRF

`capabilities.pushNotifications`가 true이면 클라이언트는 agent에 webhook URL을 제공하고, agent는 나중에 해당 URL로 작업 업데이트가 포함된 `POST` 요청을 보냅니다. 명세에 따르면 agent는 사설 대역, localhost, link-local 주소를 거부하고 allowlist를 사용해야 합니다.<sup>[[1]](#references)</sup> 작업을 생성하고, `url`이 사용자의 OAST 호스트를 가리키는 푸시 알림 설정을 등록하여 아웃바운드 요청을 확인한 다음, (범위에서 허용하는 경우에만) `http://127.0.0.1:<port>/` 또는 `http://169.254.169.254/` 같은 내부 대상으로 요청을 보내세요. 오류와 응답 시간을 비교해 내부 서비스를 파악하세요. agent는 요청에 설정된 인증 헤더도 추가하므로, 다른 사용자의 설정 URL을 변경할 수 있다면 공격자가 선택한 호스트로 해당 헤더가 전송되지 않는지 확인하세요. [SSRF](../pentesting-web/ssrf-server-side-request-forgery/)를 참고하세요.

### 두 번째 SSRF 진입점인 File-URL Parts

A2A 1.0에서는 메시지나 artifact에 `url`이 포함된 `Part`로 파일 참조를 전달할 수 있습니다(0.3에서는 `kind: "file"` 및 `file.uri`를 사용합니다).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> 프로토콜은 참조를 전달하며, 이를 가져오는 것은 애플리케이션의 동작이지 A2A SDK의 필수 동작은 아닙니다.<sup>[[6]](#references)</sup> 이는 위에서 설명한 푸시 알림 callback URL과는 별개입니다. 두 방향 모두 테스트하세요. 클라이언트가 제공한 파일이 A2A 서버로 전송되는 경우와, 신뢰도가 낮은 peer가 반환한 파일 URL을 orchestrator가 처리하는 경우입니다.<sup>[[1]](#references)[[6]](#references)</sup>

허가된 1.0 JSON-RPC endpoint에서는 일반 텍스트 part를 고유한 OAST 경로의 URL로 바꾸고 **어떤 구성 요소**가 요청을 보내는지 확인하세요:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

수신자가 이를 역참조하는 경우에만 [SSRF workflow](../pentesting-web/ssrf-server-side-request-forgery/)를 사용해 범위 내 내부 대상, 리디렉션, DNS 확인 변경을 테스트하세요. 유효한 `Part`나 성공적인 task 응답만으로는 SSRF가 입증되지 않습니다. 대상에서 실제로 요청을 가져왔는지, 가져온 콘텐츠가 agent에 전달되는지 확인하세요.<sup>[[6]](#references)</sup>

### 확장 agent card 접근

`GetExtendedAgentCard`는 인증을 요구해야 하며 공개 card보다 더 많은 skill 및 configuration을 반환할 수 있습니다.<sup>[[1]](#references)</sup> 자격 증명 없이, 그리고 권한이 낮은 ID로 호출한 뒤 결과를 공개 card와 비교하세요.

### Push notification config 및 task 내 자격 증명 leak

Push notification config에는 webhook URL과 agent가 해당 URL로 전송하는 자격 증명이 저장됩니다. 사양에 따르면 모든 push notification config 작업(create, get, list, delete)은 호출자가 해당 task에 접근할 수 있는지 확인해야 합니다.<sup>[[1]](#references)</sup> [task IDOR 섹션](#task-idor-tasksget-gettask-cancel-subscribe)의 두 ID 테스트를 이 경로에서도 반복하세요. 다른 사용자의 config를 읽을 수 있으면 webhook token이 leak되고, 쓸 수 있으면 해당 사용자의 task 업데이트가 공격자의 host로 리디렉션됩니다.

task 중 agent에 추가 인증이 필요한 경우 task를 `TASK_STATE_AUTH_REQUIRED`로 전환합니다. 클라이언트는 대역 외 방식으로 인증을 준비할 수 있습니다. 사양에서는 대역 내 메커니즘을 협의한 경우가 아니면 agent가 대역 외 방식으로 자격 증명을 받아야 한다고 명시합니다. 대역 내 교환을 통해 자격 증명이 A2A agent 체인을 따라 전달되어 체인 내 모든 agent에 노출될 수 있습니다.<sup>[[1]](#references)</sup> orchestrator 테스트에서는 사용자가 한 downstream agent에 제공한 자격 증명이 다른 agent(또는 task IDOR를 통해 다른 사용자)가 읽을 수 있는 메시지, artifact, task history에 나타나는지 확인하세요.

Agent card 필드와 task 결과도 호출하는 agent가 신뢰할 수 없는 입력입니다. [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)의 간접 prompt injection 기법과 [AI Agent Security Methodology](AI-Agent-Security-Methodology.md)의 agent 간 신뢰 검사를 사용해 테스트하세요.



## References

- [1] [A2A 프로토콜 사양](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Agent2Agent Protocol (A2A) 발표](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A 사양 v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A 사양 v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Multi-Agent System의 Agent 이름 충돌 공격](https://arxiv.org/abs/2609.27624)
- [6] [A2A .NET SDK 보안 가이드](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [A2A Python v1.0 마이그레이션 가이드](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
