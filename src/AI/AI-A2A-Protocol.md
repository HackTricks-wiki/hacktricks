# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## What is A2A

A2A (Agent2Agent)는 하나의 AI agent가 다른 agent를 발견하고 HTTP를 통해 작업을 보낼 수 있게 해주는 개방형 protocol입니다. MCP는 agent를 **tools and data**에 연결하고, A2A는 agent를 **other agents**에 연결합니다. 이 other agents는 보통 다른 팀이나 회사가 소유한 원격 서비스입니다. A2A server는 LLM agent가 뒤에서 동작하는 web API이므로, protocol 자체의 객체(agent cards, tasks, push-notification webhooks, extended cards)는 일반적인 API 테스트에 특정 인증, IDOR 및 SSRF 검사를 추가합니다.<sup>[[1]](#references)[[2]](#references)</sup>

주요 구성 요소는 다음과 같습니다.

- **Agent Card:** agent를 설명하는 JSON 문서입니다. 이름, 설명, skills, service URL(s), 지원되는 transports, capabilities (streaming, push notifications, extended card) 및 client가 사용해야 하는 `securitySchemes`를 포함합니다. `https://<host>/.well-known/agent-card.json`에 게시됩니다. 이전 spec 0.2.x를 따르는 배포 환경에서는 `/.well-known/agent.json`을 사용합니다.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** 작업 단위입니다. message가 task를 생성하고(서버에서 생성한 `id` 및 `contextId` 포함), 이후 client가 이를 읽거나 취소하거나 구독합니다.<sup>[[1]](#references)</sup>
- **Transports:** HTTP를 통한 JSON-RPC 2.0 (streaming에는 SSE 사용), gRPC, HTTP+JSON REST binding입니다.<sup>[[1]](#references)</sup>
- **Authentication:** credentials는 HTTP headers에 입력합니다(예: `Authorization: Bearer ...`). JSON-RPC payload 안에는 절대 넣지 않습니다. 사용할 scheme은 agent card에 명시됩니다.<sup>[[1]](#references)</sup>

버전별로 method 이름이 변경되었으므로 두 형식을 모두 시도하세요.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operation | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| 메시지 전송 | `message/send` | `SendMessage` | `POST /message:send` |
| Streaming 전송 | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Task 가져오기 | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Task 목록 조회 | - | `ListTasks` | `GET /tasks` |
| Task 취소 | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification config | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

1.0 spec에서는 `A2A-Version` header(또는 request parameter)를 사용해 버전을 선택하며, 이 값이 없는 request는 0.3으로 처리됩니다.<sup>[[1]](#references)</sup>

## Discovery

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

카드에서 다음 항목을 기록합니다.

- 모든 서비스 `url`(대개 내부 호스트 이름, staging URL 또는 공개 사이트와 다른 포트).
- `skills`: agent가 할 수 있는 일과 그 뒤에 있는 도구 또는 데이터를 보여 줍니다.
- `securitySchemes` / `security`: 비어 있거나 누락된 경우, agent는 자격 증명 없이 호출하도록 설계되었을 가능성이 큽니다.
- `capabilities.pushNotifications` 및 `capabilities.extendedAgentCard`(0.3에서는 `supportsAuthenticatedExtendedCard`).

사양에 따르면 공개 카드에는 자격 증명이나 내부 구현 세부 정보가 포함되어서는 안 됩니다. 따라서 공개 카드에 내부 URL, 키 또는 자세한 도구 목록이 있다면 이미 보안 문제입니다.<sup>[[1]](#references)</sup>

## A2A endpoint 테스트

### 인증되지 않은 task 제출

카드에 나열된 모든 `url`에 자격 증명 없이 최소한의 메시지를 보냅니다:

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

`Task` 또는 `Message` 결과가 `PONG`이고 card에 보안 scheme이 선언되어 있다면, RPC endpoint에서 인증이 적용되지 않는다는 뜻입니다(UI나 card에서만 적용될 수 있습니다). card에 scheme이 선언되어 있지 않다면, agent의 skills로 접근할 수 있는 항목을 확인하세요. 내부 데이터를 읽거나 도구를 호출할 수 있는 unauthenticated agent는 해당 도구를 위한 unauthenticated API와 같습니다.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

사양에 따르면 서버는 모든 요청에서 호출자가 해당 task에 접근할 수 있는지 확인해야 하며, 필터가 없더라도 `ListTasks` 결과를 호출자로 제한해야 합니다.<sup>[[1]](#references)</sup> 두 개의 identity(A와 B)로 테스트하세요.

1. A로 task를 생성하고 `id`와 `contextId`를 저장합니다.
2. B로(또는 credentials 없이) A의 `id`를 사용해 `tasks/get` / `GetTask`를 호출한 다음, 매개변수 없이 `ListTasks`를 호출합니다.
3. A의 task에 대해 cancel과 subscribe도 시도하고, A의 `taskId` 또는 `contextId`가 포함된 새 message를 B로 전송합니다(이렇게 하면 B의 텍스트가 A의 대화에 추가됩니다).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

취약: B가 A의 기록, artifacts 또는 상태를 받거나 A의 task를 변경할 수 있습니다. 안전: `TaskNotFoundError`를 반환하며, "존재하지만 내 것이 아님"과 "존재하지 않음"을 구분하지 않습니다.<sup>[[1]](#references)</sup> Task ID는 UUID인 경우가 많으므로, leak될 수 있는 위치(공유 링크, 로그, push notification payload, 오류 메시지)에서 찾아보세요.

### Push notification webhook SSRF

`capabilities.pushNotifications`가 true이면 클라이언트는 agent에 webhook URL을 제공하고, agent는 이후 해당 URL로 task 업데이트를 담은 `POST` 요청을 보냅니다. 사양은 agent가 private range, localhost 및 link-local 주소를 거부하고 allowlist를 사용해야 한다고 명시합니다.<sup>[[1]](#references)</sup> task를 생성하고, `url`이 사용자의 OAST host를 가리키는 push notification config를 등록해 아웃바운드 요청을 확인한 다음, (범위가 허용하는 경우에만) `http://127.0.0.1:<port>/` 또는 `http://169.254.169.254/` 같은 내부 대상으로 요청을 보내세요. 오류와 응답 시간을 비교해 내부 서비스를 파악합니다. agent는 설정된 authentication header도 이 요청에 추가하므로, 다른 사용자의 config URL을 변경할 수 있다면 공격자가 선택한 host로 해당 header가 전송되지 않는지 확인하세요. [SSRF](../pentesting-web/ssrf-server-side-request-forgery/)를 참조하세요.

### Extended agent card 접근

`GetExtendedAgentCard`는 authentication을 요구해야 하며, public card보다 더 많은 skill과 configuration을 반환할 수 있습니다.<sup>[[1]](#references)</sup> credentials 없이, 그리고 낮은 권한의 identity로 호출한 뒤 결과를 public card와 비교하세요.

### Push notification config 및 task 내 credential leak

Push notification config에는 webhook URL과 agent가 해당 URL로 보내는 credentials가 저장됩니다. 사양은 모든 push notification config 작업(create, get, list, delete)에서 호출자가 해당 task에 접근할 수 있는지 확인하도록 요구합니다.<sup>[[1]](#references)</sup> [task IDOR 섹션](#task-idor-tasksget-gettask-cancel-subscribe)의 두 identity 테스트를 이 경로들에서 반복하세요. 다른 사용자의 config를 읽을 수 있으면 webhook token이 leak되고, 쓸 수 있으면 해당 사용자의 task 업데이트가 사용자의 host로 리디렉션됩니다.

task 도중 agent가 추가 authorization을 필요로 하면 task를 `TASK_STATE_AUTH_REQUIRED`로 전환합니다. 클라이언트는 대역 외 방식으로 authorization을 제공할 수 있습니다. 사양은 대역 내 방식에 합의한 경우가 아니라면 agent가 대역 외 방식으로 credentials를 받아야 한다고 명시합니다. 대역 내 교환은 여러 A2A agent로 이어지는 체인에 credential을 전달하여 체인의 모든 agent에 노출할 수 있습니다.<sup>[[1]](#references)</sup> orchestrator 테스트에서 사용자가 한 downstream agent를 위해 제공한 credential이 다른 agent가 읽을 수 있는 메시지, artifacts 또는 task 기록에 나타나는지 확인하세요. 다른 사용자가 task IDOR를 통해 읽을 수 있는 경우도 확인합니다.

Agent card 필드와 task 결과도 호출하는 agent에게는 신뢰할 수 없는 입력입니다. [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)의 간접 prompt injection 기법과 [AI Agent Security Methodology](AI-Agent-Security-Methodology.md)의 agent 간 신뢰 검사를 사용해 테스트하세요.

## References

- [1] [A2A Protocol 사양](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Agent2Agent Protocol (A2A) 발표](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A 사양 v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A 사양 v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
