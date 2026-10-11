# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

エージェントの評価では、**攻撃者が制御する入力から、外部で観測可能な影響まで**を追跡します。Jailbreaking、キャラクターの変更、system promptの開示によって、推論チャネルが影響を受けることは証明できます。しかし、重大なfindingとなるのは、データアクセス、不正なtool action、下流のinjection sink、永続化、または別のエージェントにつながる一連の攻撃です。<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)は、網羅範囲（goal hijacking、tool misuse、privilege abuse、supply chain、code execution、memory poisoning、inter-agent trust、cascading failures、human trust、rogue agents）の分類に役立ちます。モデルの予想外のテキストをテストの終点とせず、エンドツーエンドの攻撃経路を構築してから、これらのラベルを使用してください。<sup>[[1]](#references)[[2]](#references)</sup>

## ターゲットマップの作成

payloadを作成する前に、各エージェントのワークフローについて、以下の5つの側面を記録します。<sup>[[2]](#references)</sup>

| Dimension | What to enumerate | Security question |
|---|---|---|
| **信頼できない入力** | Chat/API parameters、URLs、documents、email、tickets、calendar entries、retrieved chunks、memory、tool results、peer-agent messages | 攻撃者が配置したコンテンツが、後でmodel contextに入る可能性があるのはどこか？ |
| **Tools** | Tool names and schemas、side effects、auto-execution、confirmation behavior、dynamically loaded tools | どの呼び出しがsecretの読み取り、stateの書き込み、メッセージの送信、データの削除、コードの実行、または価値の移転を行うか？ |
| **権限** | User delegation、service accounts、API tokens、credential lifetime、tenant/resource scope、network reach | 各呼び出しはどのidentityで実行されるか。また、tool boundaryで認可が再確認されるか？ |
| **処理** | Query builders、shells、URL fetchers、template engines、interpreters、parsers、file operations、deserializers | modelが生成したデータが、別のinterpreterのsyntaxになるのはどこか？ |
| **出力** | Responses、rendered Markdown/HTML、links、image fetches、webhooks、email、files、logs、reports、metrics、peer-agent traffic | secretを運んだり、二次リクエストを発生させたりする可能性のある、外部から観測可能なチャネルはどれか？ |

これを、提供されているintegrationの一覧に矮小化しないでください。有用な成果物では、各sourceから、到達するcontext内の正確な位置、その時点で利用可能なtools、各toolが使用するcredential、下流のinterpreter、すべてのegress経路までを対応付けます。同じtoolでも、ユーザーごとのread tokenであれば影響は小さい一方、共有のadministrator credentialであれば重大な影響をもたらす可能性があります。<sup>[[2]](#references)</sup>

## Reconnaissance

### すべての配信・取り込み経路をマッピングする

配信面（web、mobile、API、email、chat platform、browser extension）から調査を始め、clientからbackendへの通信をproxy経由で取得します。UIでは非表示のfield、search/autocomplete/filter parameters、conversation-state objects、uploadおよびindexing jobs、tool responses、sub-agent trafficを調べます。mobile専用のclientでは、実際のrequest schemaを確認する前に、certificate pinningを回避するためemulatorとinstrumentationが必要になる場合があります。<sup>[[2]](#references)</sup>

次に、modelの下にあるstackをマッピングします。orchestration framework、prompt assembly、retrievalとmemory stores、runtime（例：Python、container、WASM）、mounted volumes、host services、internal APIs、cloud metadataへの到達性、隣接するnetworkを調べます。frameworkのdefault設定は重要です。一部の「tool calls」は、コードを生成または評価して実装されているためです。その結果が封じ込められるかどうかは、runtime/sandbox boundaryによって決まります。<sup>[[2]](#references)</sup>

### 非破壊的なprobeでroutingを特定する

scope内のrequestを、いくつかの無関係なrequestと比較します。その際、response全体、status code、latency、streamingの挙動を保持します。タスク固有の推論が始まる前に常に同じように拒否される場合は、独立したgateway/classifierがある可能性があります。文脈に応じた拒否は、requestがmodelに到達したことを示唆します。空の回答や、単に情報を抽出しただけの回答は、keyword searchまたは限定的なretrievalを示している可能性があります。これらは仮説として扱い、同じprobeを別のAPI fieldや取り込み経路から再送して確認します。<sup>[[2]](#references)</sup>

Reconは、エージェントの挙動を変化させる最も早い攻撃者制御下のsourceと、そこから到達可能なtools、identities、interpreters、outputsを評価で特定できた時点で完了です。<sup>[[2]](#references)</sup>

## Exploitation：trust boundaryを越える

promptの文言だけでなく、チャネルをテストします。まずdirect injectionを行い、ユーザーから見える入口で何がブロックされるかを確認します。その後、以下の目立ちにくい経路を通じて、同等の意図を再度試します。<sup>[[2]](#references)</sup>

- **間接的なコンテンツ：** pages、files、email、tickets、metadata、alt text、HTML comments、off-screen text、zero-width characters。[AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)でpayloadの配信手法を参照してください。
- **Retrievalとmemory：** 後でretrievedされるコンテンツ、または後続のsessionで再読み込みされるstateをpoisonします。元のsourceを削除すると挙動がなくなるかを記録します。
- **Tool outputとpeer agents：** tool responseまたはagent間messageにmarkerを配置し、user inputとfinal outputにのみ適用されるfilterを、内部通信が回避できるかテストします。
- **Supply chain：** tool descriptors、plugins、接続されたservers、skills、models、dependenciesを、信頼できるinstruction sourceとして確認します。MCP固有のテストについては、[MCP Servers](AI-MCP-Servers.md#mcp-vulns)を参照してください。
- **Human approval：** 実際のstructured tool callと、modelが生成したapproval textを比較します。攻撃者からの影響により、送信先、scope、対象object、または取り消せない副作用が省略されないかテストします。

最初は無害で一意なmarkerを使用します。source artifact、（観測可能であれば）組み立てられたcontext、選択されたtool call、approval data、backendのrequest/response、最終stateを保存します。これにより、実際にactionが起きたというhallucinated claimと、実際の影響を区別できます。<sup>[[2]](#references)</sup>

## Execution：実際の影響を証明する

影響に至る経路は、次の2種類に分かれます。<sup>[[2]](#references)</sup>

1. **Capability abuse：** 許可されたtool自体が、すでに目的の処理を実行できるケースです。例として、あるtenantのrecordを読み取り、攻撃者から見えるreportに書き込む、emailを送信する、recordを変更する、fileを削除する、paymentを開始する、といったものがあります。二次的なsoftware bugは必要ありません。
2. **下流のsinkの悪用：** 攻撃者に誘導されたmodel outputが、別のcomponentにおけるsyntaxとなるケースです。database queryでは[SQL injection](../pentesting-web/sql-injection/README.md)または[NoSQL injection](../pentesting-web/nosql-injection.md)、shell wrapperでは[command injection](../pentesting-web/command-injection.md)、指定したURLでは[SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)、file操作ではpath traversal、template/code evaluatorではRCE、object parserでは[unsafe deserialization](../pentesting-web/deserialization/README.md)がないか確認します。

候補となる各ケースで、以下の一連の流れを証明します。<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

読み取り専用の連携でも、後続のコンポーネントが読み取った内容を公開できる場合は悪用可能です。通常の応答に加え、攻撃者が制御するリンク、自動画像取得、webhook、ログ、レポート、カウンター、通知、他のエージェントへのメッセージなど、見落とされがちなegressもテストしてください。<sup>[[2]](#references)</sup>

## 目的に対するアクション

1つのアクションを確認したら、最初に目に見えた影響で止めず、影響範囲全体を評価してください。<sup>[[2]](#references)</sup>

- **情報窃取:** 秘密情報、ユーザーレコード、内部ファイル、会話データ、またはprompt/contextの内容が、観測可能なチャネルを通じて外部に出る。
- **不正なアクション:** エージェントが正規の書き込み機能を攻撃者の目的に利用する。
- **サービス拒否:** 破壊的なツールや、繰り返される高コストな操作が、完全性または可用性に影響する。
- **永続化:** 汚染されたメモリ、インデックス化されたコンテンツ、信頼済み状態、または実行時の変更が、元のセッションや情報源を取り除いた後も残る。
- **拡散:** 信頼されたpeerが侵害されたエージェントのメッセージまたは共有状態を利用し、自身のツールと認証情報でアクションを繰り返す。

深刻度は、モデルのテキストがどれほど意外に見えるかではなく、到達可能なデータ、実効的な権限、sinkの悪用可能性、egress、永続化、拡散に基づいて判断してください。<sup>[[2]](#references)</sup>

## 評価時に検証するコントロール

Promptフィルターや、より優れたシステムpromptは攻撃者のコストを高めることがありますが、認可境界として扱ってはなりません。以下のコントロールは、直接入力、間接コンテンツ、メモリ、ツール、peerエージェントを通じて同じ攻撃チェーンを再実行し、検証してください。<sup>[[2]](#references)</sup>

- 決定論的なポリシーレイヤーが、**すべてのツール呼び出し**で認証済みユーザー、テナント、オブジェクト、アクション、宛先を確認する。モデルが呼び出し元のIDを指定したり、上書きしたりできない。
- 読み取り権限と書き込み権限には、個別の最小権限・短命な認証情報を使用する。影響の大きいツールは必要なときだけ公開し、取り込んだコンテンツから自動実行されないようにする。
- ネットワークのegressと内部宛先を、モデルが選択したURLとは独立して許可リストで管理する。必要がない限り、実行環境からメタデータエンドポイント、マウントされた秘密情報、隣接サービスへのアクセスを遮断する。
- 承認UIは正規の構造化リクエストから生成し、自由形式のモデル要約ではなく、正確な引数、ID、宛先、影響を受けるオブジェクト、副作用を表示する。
- 成功は宛先システムまたは記録システムで検証する。エージェントの説明、ツール呼び出しリクエスト、HTTPリダイレクトは、主張された状態変更の証拠にはならない。
- メモリと検索エントリーは出所と信頼ラベルを保持し、無効化できるようにする。また、後のアクションで使用する際に再認可する。
- エージェント間メッセージは、未信頼のリクエストとして認証・認可する。peerの評判やagent cardによって、受信側のツールが暗黙に委譲されることはない。

## References

- [1] [2026年版 OWASP Agentic Applications Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AIエージェントを攻撃するためのハッカーガイド](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
