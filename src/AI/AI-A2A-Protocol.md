# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## What is A2A

A2A (Agent2Agent) は、あるAI agentが別のagentを検出し、HTTP経由で作業を依頼できるオープンプロトコルです。MCPはagentを**tools and data**に接続し、A2Aはagentを**他のagent**に接続します。接続先は通常、別のチームや会社が所有するリモートサービスです。A2AサーバーはLLM agentを背後に持つWeb APIであるため、プロトコル独自のオブジェクト（agent cards、tasks、push-notification webhooks、extended cards）により、通常のAPIテストに特有の認証、IDOR、SSRFのチェックが加わります。<sup>[[1]](#references)[[2]](#references)</sup>

主な構成要素は次のとおりです。

- **Agent Card:** agentを説明するJSONドキュメントです。名前、説明、skills、service URL(s)、対応するtransports、capabilities（streaming、push notifications、extended card）、およびclientが使用する必要のある`securitySchemes`が記載されています。`https://<host>/.well-known/agent-card.json`で公開されます。spec 0.2.xに準拠する古いデプロイでは、`/.well-known/agent.json`が使われます。<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** 作業単位です。messageによってtask（サーバーが生成する`id`と`contextId`を含む）が作成され、clientは後からそのtaskを読み取る、キャンセルする、またはsubscribeします。<sup>[[1]](#references)</sup>
- **Transports:** HTTP上のJSON-RPC 2.0（streamingにはSSEを使用）、gRPC、およびHTTP+JSON REST bindingです。<sup>[[1]](#references)</sup>
- **Authentication:** credentialsはHTTP headers（例: `Authorization: Bearer ...`）に含め、JSON-RPC payloadには決して含めません。使用するschemeはagent cardに記載されています。<sup>[[1]](#references)</sup>

method名はversion間で変更されているため、両方の形式を試してください。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operation | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| メッセージの送信 | `message/send` | `SendMessage` | `POST /message:send` |
| ストリーミング送信 | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| taskの取得 | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| taskの一覧表示 | - | `ListTasks` | `GET /tasks` |
| taskのキャンセル | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification config | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

1.0 specでは、versionの選択に`A2A-Version` header（またはrequest parameter）を使用します。これがないrequestは0.3として扱われます。<sup>[[1]](#references)</sup>

## Discovery

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

カードから、次の情報を書き留めます。

- 各サービスの `url`：1.0では `supportedInterfaces` の下にあり、古いカードではトップレベルの `url` として公開されている場合があります。内部ホスト名、ステージングURL、代替ポートを含め、各エンドポイントとトランスポートを記録します。<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`：エージェントが実行できることと、その背後にあるツールやデータを示します。
- `securitySchemes` / `security`：空または存在しない場合、そのエージェントはおそらく認証情報なしで呼び出される想定です。
- `capabilities.pushNotifications` と `capabilities.extendedAgentCard`（0.3では `supportsAuthenticatedExtendedCard`）。

仕様では、公開カードに認証情報や内部実装の詳細を含めるべきではないとされています。そのため、公開カード内の内部URL、キー、詳細なツール一覧は、すでに指摘事項に該当します。<sup>[[1]](#references)</sup>

### マルチエージェントホストにおけるAgent Cardの名前衝突

カードの `name` は人間が読めるラベルであり、安定したルーティングIDではありません。<sup>[[1]](#references)[[5]](#references)</sup> ホストが異なる2つのリモートピアを同じローカル名で登録すると、エージェントツリー、生成されたツール名、クライアントマップ、ブローカールートによって、信頼されたピア宛てのタスクがもう一方のピアに送られる可能性があります。<sup>[[5]](#references)</sup> これには、攻撃者が制御するピアが**同じルーティング名前空間**に登録されている必要があります。インターネット上に重複したカードを公開するだけでは不十分です。<sup>[[5]](#references)</sup>

制御下にある2つのピアと無害なマーカーを使って、ホストの**登録からディスパッチまで**の経路をテストします。<sup>[[5]](#references)</sup>

1. 信頼されたピアのカード、オリジン、ローカルセレクターを記録します。`name` は同じで、URLが自分の制御するエンドポイントを指す2つ目のピアを登録します。
2. 名前で信頼されたピアを選択する操作を実行します。登録順序を両方試し、名前がツール識別子になる場合は、ホスト標準の名前正規化も試します。どのエンドポイントがマーカーを受信したか、どのエージェントが応答を返したかを記録します。
3. 2つ目のカードの名前だけを変更して繰り返します。名前が衝突した場合に限りリクエストが2つ目のエンドポイントに届くなら、誤ったピアへのディスパッチが証明されます。機密コンテキストや認証情報が実際に付与されたかは、別途確認します。名前の衝突だけでは、認証情報やツール権限の移転が証明されたことには**なりません**。

呼び出し元がカード名を解決せず、オリジンに紐づいた固定エンドポイントを指定する場合、このテストは該当しません。<sup>[[5]](#references)</sup> その後の悪意あるピアの応答とプロンプトインジェクションの影響については、[AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary)を参照してください。

## A2Aエンドポイントのテスト

### 認証なしのタスク送信

カードに記載されたすべての `url` に、認証情報なしで最小限のメッセージを送信します：

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

A `Task` または `Message` の結果が `PONG` で、card が security scheme を宣言している場合、RPC endpoint では認証が強制されていないことを意味します（UI または card でのみ強制されている可能性があります）。card が scheme を宣言していない場合は、agent の skills で何にアクセスできるかを確認してください。内部データを読み取ったり、tools を呼び出したりできる unauthenticated agent は、それらの tools に対する unauthenticated API と同じです。

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

仕様では、サーバーはすべてのリクエストで呼び出し元にその task へのアクセス権があることを確認し、filter が指定されていない場合も `ListTasks` の対象を呼び出し元に限定する必要があります。<sup>[[1]](#references)</sup> 2つの identity（A と B）を使ってテストします。

1. A として task を作成し、その `id` と `contextId` を保存します。
2. B として（または credentials なしで）、A の `id` を指定して `tasks/get` / `GetTask` を呼び出し、続けてパラメーターなしで `ListTasks` を呼び出します。
3. A の task に対する cancel と subscribe も試し、A の `taskId` または `contextId` を含む新しい message を B として送信します（これにより、B のテキストが A の会話に追加されます）。

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

脆弱: BがAの履歴、artifact、またはステータスを受け取る、あるいはAのtaskを変更できる。安全: `TaskNotFoundError`を返し、「存在するが自分のものではない」と「存在しない」を区別しない。<sup>[[1]](#references)</sup> Task IDはUUIDであることが多いため、leakする場所（共有リンク、ログ、push notificationのpayload、エラーメッセージ）を探す。

### Push notification webhook SSRF

`capabilities.pushNotifications`がtrueの場合、clientはagentにwebhook URLを渡し、agentは後でtaskの更新をそのURLに`POST`する。仕様では、agentはprivate range、localhost、link-local addressを拒否し、allowlistを使用すべきとされている。<sup>[[1]](#references)</sup> taskを作成し、`url`が自身のOAST hostを指すpush notification configを登録して、outbound requestを確認する。続いて（scopeで許可される場合に限り）、`http://127.0.0.1:<port>/`や`http://169.254.169.254/`などのinternal targetを試す。エラーと応答時間を比較してinternal serviceを特定する。agentは設定済みのauthentication headerもこれらのrequestに追加するため、別ユーザーのconfigのURLを変更できる場合、攻撃者が選んだhostにそのheaderが送信されないことを確認する。[SSRF](../pentesting-web/ssrf-server-side-request-forgery/)を参照。

### 2つ目のSSRFの入口となるFile-URL Part

A2A 1.0では、messageまたはartifactに、`url`を持つ`Part`としてfile referenceを含められる（0.3では`kind: "file"`と`file.uri`を使用）。<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> protocolが運ぶのはreferenceであり、それを取得するかどうかはapplicationの動作であって、A2A SDKの要件ではない。<sup>[[6]](#references)</sup> これは上記のpush notification callback URLとは別のもの。両方向をテストする: clientからA2A serverに送られるfileと、信頼度の低いpeerからorchestratorに返されるfile URL。<sup>[[1]](#references)[[6]](#references)</sup>

認可された1.0 JSON-RPC endpointでは、通常のtext partを一意なOAST pathへのURLに置き換え、**どのcomponent**がrequestを行うか確認する:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

受信側がその参照を解決する場合に限り、[SSRF workflow](../pentesting-web/ssrf-server-side-request-forgery/)を使って、スコープ内の内部宛先、リダイレクト、DNS解決の変更をテストしてください。有効な`Part`やタスクへの応答が成功しただけではSSRFの証拠にはなりません。宛先でfetchが行われたことと、取得したコンテンツがagentに届くかを確認してください。<sup>[[6]](#references)</sup>

### Extended agent cardへのアクセス

`GetExtendedAgentCard`には認証が必要であり、公開カードより多くのskillsや設定が返される場合があります。<sup>[[1]](#references)</sup> 認証情報なしの場合と、低権限のidentityの場合に呼び出し、結果を公開カードと比較してください。

### Push notification configとタスク内の認証情報のleak

Push notification configにはwebhook URLと、agentがそこに送信する認証情報が保存されます。仕様では、すべてのpush notification config操作（create、get、list、delete）で、呼び出し元がそのタスクにアクセスできることを確認する必要があります。<sup>[[1]](#references)</sup> これらのrouteに対して、[task IDOR section](#task-idor-tasksget-gettask-cancel-subscribe)と同じ2つのidentityによるテストを繰り返してください。他のユーザーのconfigを読み取れるとwebhook tokenがleakし、書き換えられると、そのユーザーのタスク更新をあなたのhostにリダイレクトできます。

タスク中にagentが追加の認証を必要とすると、タスクは`TASK_STATE_AUTH_REQUIRED`に移行します。clientは帯域外で認証を手配できます。仕様では、帯域内の仕組みが合意されていない限り、agentは帯域外で認証情報を受け取る必要があります。帯域内のやり取りでは、認証情報がA2A agentの連鎖を通じて渡され、その連鎖内のすべてのagentに露出する可能性があります。<sup>[[1]](#references)</sup> orchestratorのテストでは、ある下流agent用にユーザーが提供した認証情報が、他のagentが読み取れるメッセージ、artifact、タスク履歴に現れるか、またはtask IDORを通じて他のユーザーから読み取れるか確認してください。

Agent cardのフィールドやタスクの結果も、呼び出し側agentにとって信頼できない入力です。[AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)に記載された間接prompt injectionの手法と、[AI Agent Security Methodology](AI-Agent-Security-Methodology.md)に記載されたagent間の信頼性チェックを使ってテストしてください。



## References

- [1] [A2A Protocol仕様](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Agent2Agent Protocol（A2A）の発表](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A仕様 v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A仕様 v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [マルチエージェントシステムにおけるagent名の衝突攻撃](https://arxiv.org/abs/2609.27624)
- [6] [A2A .NET SDK Security Guide](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [A2A Python v1.0移行ガイド](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
