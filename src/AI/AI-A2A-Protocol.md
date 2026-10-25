# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## A2Aとは

A2A (Agent2Agent) は、あるAI agentが別のagentを見つけ、HTTP経由で作業を依頼できるオープンプロトコルです。MCPはagentを**tools and data**に接続し、A2Aはagentを**他のagent**に接続します。後者は通常、別のチームや企業が所有するリモートサービスです。A2A serverは背後にLLM agentを持つWeb APIであるため、プロトコル固有のオブジェクト（agent cards、tasks、push-notification webhooks、extended cards）に対して、通常のAPIテストに加えて、特定の認証、IDOR、SSRFのチェックが必要になります。<sup>[[1]](#references)[[2]](#references)</sup>

主な構成要素は次のとおりです。

- **Agent Card:** agentを説明するJSONドキュメントです。名前、説明、skills、service URL(s)、サポートするtransports、capabilities（streaming、push notifications、extended card）、およびclientが使用する必要のある`securitySchemes`が記載されています。`https://<host>/.well-known/agent-card.json`で公開されます。spec 0.2.xに準拠する古いデプロイでは、`/.well-known/agent.json`が使われます。<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** 作業単位です。messageによってtaskが作成され（serverが`id`と`contextId`を生成）、clientは後からそのtaskを読み取る、キャンセルする、またはサブスクライブします。<sup>[[1]](#references)</sup>
- **Transports:** HTTP上のJSON-RPC 2.0（streamingにはSSEを使用）、gRPC、およびHTTP+JSON REST bindingです。<sup>[[1]](#references)</sup>
- **Authentication:** credentialはHTTP headers（例: `Authorization: Bearer ...`）に含め、JSON-RPC payloadには決して含めません。必要なschemeはagent cardに記載されています。<sup>[[1]](#references)</sup>

バージョン間でmethod名が変わっているため、両方の形式を試してください。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| 操作 | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| messageの送信 | `message/send` | `SendMessage` | `POST /message:send` |
| streamingで送信 | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| taskの取得 | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| taskの一覧表示 | - | `ListTasks` | `GET /tasks` |
| taskのキャンセル | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification config | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

1.0 specでは、バージョンの選択に`A2A-Version` header（またはrequest parameter）を使います。これがないrequestは0.3として扱われます。<sup>[[1]](#references)</sup>

## Discovery

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

カードから、次の情報を書き留めます。

- すべてのサービスの`url`（内部ホスト名、ステージングURL、または公開サイトとは異なるポートであることがよくあります）。
- `skills`：agentが実行できることと、その背後にあるツールやデータがわかります。
- `securitySchemes` / `security`：空または存在しない場合、agentは認証情報なしで呼び出されることを想定している可能性があります。
- `capabilities.pushNotifications` と `capabilities.extendedAgentCard`（0.3では`supportsAuthenticatedExtendedCard`）。

仕様では、公開カードに認証情報や内部実装の詳細を含めてはならないとされています。そのため、公開カードに内部URL、キー、または詳細なツール一覧が含まれていれば、それだけですでに発見事項となります。<sup>[[1]](#references)</sup>

## A2Aエンドポイントのテスト

### 認証なしでのタスク送信

カードに記載されたすべての`url`に、認証情報なしで最小限のメッセージを送信します：

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

`Task` または `Message` の結果が `PONG` で、カードが security scheme を宣言している場合、RPC endpoint で認証が強制されていないことを意味します（UI またはカード上でのみ強制されている可能性があります）。カードが scheme を宣言していない場合は、agent の skills で何にアクセスできるか確認してください。内部データを読み取ったりツールを呼び出したりできる unauthenticated agent は、それらのツールに対する unauthenticated API と同じです。

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

仕様では、サーバーは各リクエストで呼び出し元が task にアクセスできることを確認し、フィルターが指定されていない場合も `ListTasks` の対象を呼び出し元に限定する必要があります。<sup>[[1]](#references)</sup> 2つの identity（A と B）でテストします。

1. A として task を作成し、その `id` と `contextId` を保存します。
2. B（または認証情報なし）として、A の `id` を指定して `tasks/get` / `GetTask` を呼び出し、次にパラメーターなしで `ListTasks` を呼び出します。
3. A の task に対する cancel と subscribe も試し、A の `taskId` または `contextId` を含む新しい message を B として送信します（これにより、B のテキストが A の会話に追加されます）。

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

脆弱な状態: BがAの履歴、成果物、ステータスを受け取れる、またはAのタスクを変更できる。安全な状態: `TaskNotFoundError`が返され、「存在するが自分のものではない」場合と「存在しない」場合に違いがない。<sup>[[1]](#references)</sup> Task IDはUUIDであることが多いため、漏えいする場所（共有リンク、ログ、push notification payload、エラーメッセージ）を探してください。

### Push notification webhook SSRF

`capabilities.pushNotifications`がtrueの場合、クライアントはエージェントにwebhook URLを渡し、エージェントは後からそのURLにタスクの更新を含む`POST`リクエストを送信します。仕様では、エージェントはプライベートレンジ、localhost、link-localアドレスを拒否し、allowlistを使用する必要があるとされています。<sup>[[1]](#references)</sup> タスクを作成し、`url`が自分のOASTホストを指すpush notification configを登録して、送信リクエストがあることを確認します。その後（スコープで許可されている場合のみ）、`http://127.0.0.1:<port>/`や`http://169.254.169.254/`などの内部ターゲットを指定します。エラーや応答時間を比較して、内部サービスを特定します。エージェントは設定された認証ヘッダーもこれらのリクエストに追加するため、別のユーザーのconfigのURLを変更できる場合、攻撃者が選んだホストにそのヘッダーが送信されないことを確認してください。[SSRF](../pentesting-web/ssrf-server-side-request-forgery/)を参照してください。

### Extended agent cardへのアクセス

`GetExtendedAgentCard`には認証が必要であり、公開カードより多くのスキルや設定が返される場合があります。<sup>[[1]](#references)</sup> 認証情報なし、および低権限のIDで呼び出し、公開カードと結果を比較してください。

### Push notification configとタスク内の認証情報漏えい

Push notification configには、webhook URLと、エージェントがそこに送信する認証情報が保存されます。仕様では、すべてのpush notification config操作（作成、取得、一覧表示、削除）で、呼び出し元がそのタスクにアクセスできることを確認する必要があります。<sup>[[1]](#references)</sup> [task IDOR section](#task-idor-tasksget-gettask-cancel-subscribe)での2つのIDを使ったテストを、これらのルートでも繰り返してください。他のユーザーのconfigを読み取れるとwebhook tokenが漏えいし、書き換え可能な場合は、そのユーザーのタスク更新を自分のホストにリダイレクトできます。

タスク中に追加の認証が必要になると、エージェントはタスクを`TASK_STATE_AUTH_REQUIRED`に移行します。クライアントはout-of-bandで認証を手配できます。仕様では、in-bandの仕組みが合意されていない限り、エージェントはout-of-bandで認証情報を受け取らなければならないとされています。in-bandの交換では、認証情報がA2Aエージェントの連鎖を介して渡され、その連鎖内のすべてのエージェントに露出する可能性があります。<sup>[[1]](#references)</sup> オーケストレーターをテストする際は、ある下流エージェント用にユーザーが渡した認証情報が、他のエージェント（またはtask IDORを介した他のユーザー）が読み取れるメッセージ、成果物、タスク履歴に現れないか確認してください。

Agent cardのフィールドとタスク結果も、呼び出し元エージェントにとって信頼できない入力です。[AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)の間接的なprompt injection手法と、[AI Agent Security Methodology](AI-Agent-Security-Methodology.md)のエージェント間の信頼性チェックを使ってテストしてください。

## References

- [1] [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Agent2Agent Protocol（A2A）の発表](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A仕様 v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A仕様 v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
