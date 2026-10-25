# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

エージェントの評価では、**攻撃者が制御する入力から、外部から観測可能な影響まで**を追跡します。Jailbreaking、文字の変更、system promptの開示は、推論チャネルが操作可能であることを示します。しかし、重大な発見となるのは、データアクセス、不正なtoolの実行、下流のinjection sink、永続化、別のエージェントなどにつながる一連の流れです。<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)は、テスト範囲（goal hijacking、tool misuse、privilege abuse、supply chain、code execution、memory poisoning、inter-agent trust、cascading failures、human trust、rogue agents）の分類に役立ちます。モデルが予想外のテキストを出した時点でテストを終わらせず、エンドツーエンドの攻撃経路を構築してから、これらの分類を使用してください。<sup>[[1]](#references)[[2]](#references)</sup>

## Build the target map

payloadを作成する前に、各エージェントワークフローについて、次の5つの観点を記録してください。<sup>[[2]](#references)</sup>

| 観点 | 洗い出す項目 | セキュリティ上の問い |
|---|---|---|
| **信頼できない入力** | Chat/APIパラメーター、URL、ドキュメント、メール、チケット、カレンダー項目、取得したチャンク、メモリ、toolの結果、他のエージェントからのメッセージ | 攻撃者が、後にモデルのコンテキストに入る内容を配置できる場所はどこか？ |
| **Tools** | toolの名前とスキーマ、副作用、自動実行、確認動作、動的に読み込まれるtool | どの呼び出しが秘密情報を読み取り、状態を書き換え、メッセージを送信し、データを削除し、コードを実行し、価値を移転するか？ |
| **権限** | ユーザー委任、サービスアカウント、API token、認証情報の有効期間、テナント/リソースの範囲、ネットワーク到達性 | 各呼び出しはどのIDで実行され、toolの境界で認可が再確認されるか？ |
| **処理** | クエリビルダー、shell、URL fetcher、template engine、interpreter、parser、ファイル操作、deserializer | モデルが生成したデータが、別のinterpreterの構文になるのはどこか？ |
| **出力** | 応答、レンダリングされたMarkdown/HTML、リンク、画像fetch、webhook、メール、ファイル、ログ、レポート、メトリクス、他のエージェントとの通信 | どの観測可能なチャネルが秘密情報を運んだり、二次リクエストを発生させたりするか？ |

これを、宣伝されている連携機能の一覧にまとめてはいけません。有用な成果物では、各入力元が到達する正確なコンテキスト位置、その時点で利用可能なtool、各toolが使う認証情報、下流のinterpreter、すべての外向き通信経路を対応づけます。同じtoolでも、ユーザーごとの読み取りtokenであれば影響は小さく、共有のadministrator認証情報を使う場合は重大になり得ます。<sup>[[2]](#references)</sup>

## Reconnaissance

### あらゆる入力・取り込み経路を洗い出す

入力面（web、mobile、API、email、chat platform、browser extension）から始め、クライアントとバックエンド間の通信をproxy経由で確認します。UIで隠されているフィールド、検索/autocomplete/filterのパラメーター、会話状態オブジェクト、uploadとindexingのjob、toolの応答、sub-agentの通信を調べます。Mobile専用クライアントの場合、実際のrequestスキーマを確認する前に、証明書pinningを回避するためemulatorとinstrumentationが必要になることがあります。<sup>[[2]](#references)</sup>

次に、モデルの下にあるstackを洗い出します。orchestration framework、prompt assembly、retrievalとmemoryのstore、runtime（例：Python、container、WASM）、mountされたvolume、host service、内部API、cloud metadataへの到達性、隣接するnetworkを確認します。frameworkのデフォルト設定も重要です。コードを生成または評価することで実装される「tool call」があり、生成結果が封じ込められるかどうかはruntime/sandboxの境界によって決まるためです。<sup>[[2]](#references)</sup>

### 破壊的でないprobeでルーティングを特定する

対象範囲内のrequestを、無関係な複数のrequestと比較します。その際、応答全体、status code、latency、streaming動作を保持してください。タスク固有の推論が始まる前に常に同じ拒否が返る場合は、別のgateway/classifierの存在が考えられます。文脈に応じた拒否は、requestがモデルに到達したことを示唆します。空の回答や、抽出のみの回答は、キーワード検索または限定的なretrievalを示している可能性があります。これらは仮説として扱い、同じprobeを別のAPI fieldや取り込み経路から再送して確認してください。<sup>[[2]](#references)</sup>

評価で特定すべきなのは、エージェントの動作を変える、攻撃者が制御可能な最も早い入力元と、そこから到達可能なtool、ID、interpreter、出力です。これができた時点でReconは完了です。<sup>[[2]](#references)</sup>

## Exploitation: trust boundaryを越える

promptの文言だけでなく、チャネルをテストしてください。まずdirect injectionで、ユーザーに見える入口が何をブロックするかを確認し、次に、以下の見えにくい経路を通して同等の意図を再度試します。<sup>[[2]](#references)</sup>

- **間接コンテンツ:** ページ、ファイル、メール、チケット、metadata、alt text、HTMLコメント、画面外のテキスト、zero-width character。payloadの配信手法については[AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)を参照してください。
- **Retrievalとmemory:** 後でretrievalされるコンテンツ、または後続セッションで再読み込みされる状態を汚染します。元のソースを削除すると動作もなくなるかどうかを記録してください。
- **Toolの出力と他のエージェント:** toolの応答またはエージェント間のメッセージにmarkerを埋め込み、ユーザー入力と最終出力にのみ適用されるfilterを、内部通信が回避するかどうかをテストします。
- **Supply chain:** tool descriptor、plugin、接続先server、skill、model、dependencyを、信頼された指示のソースとして確認します。MCP固有のテストについては[MCP Servers](AI-MCP-Servers.md#mcp-vulns)を参照してください。
- **人間による承認:** 実際の構造化tool callと、モデルが生成した承認文を比較します。攻撃者の影響によって、宛先、範囲、影響を受けるオブジェクト、取り消せない副作用が省略されるかどうかをテストしてください。

まず、無害で一意なmarkerを使います。ソースのartifact、観測可能であれば組み立てられたコンテキスト、選択されたtool call、承認データ、バックエンドのrequest/response、最終状態を保存してください。これにより、影響を受けた状態と、実際には発生していない処理を発生したかのように述べるhallucinationを区別できます。<sup>[[2]](#references)</sup>

### Toolリスク判定器に対するpolicy風テキスト

モデルベースのtool gateは、有用な分類コンテキストに含まれた攻撃者制御テキストを受け取る場合があります。たとえばLangChainのexperimental `AutoModeMiddleware`は、提案されたtool call、その引数、任意のtool description、直近最大30件のメッセージをTypeSafeの`is_risky` judgeに送信します。返されたNoulの確率が`0.5`以上の場合、設定済みのtoolをブロックします。このmiddlewareは、リストにないtoolを分類しません。<sup>[[5]](#references)</sup> TypeSafeも、stateがデータとして扱われる想定であっても、state内の敵対的なテキストが分類結果に影響する可能性があると警告しています。<sup>[[6]](#references)</sup>

**偽装policy**は、単にsystem messageを装うのとは異なります。信頼度の低いstateに別のラベルやリスク定義を置き、developerが定義した基準ではなく、そちらをjudgeに使わせようとします。Datadogのテストでは、ユーザーが編集可能な`profile_description`が、`can_edit:false`とともにtoolの引数へコピーされていました。そのpolicy風テキストは、変更前に別の権限チェックで拒否されるはずなので、書き込みの試行は低リスクだと主張していました。40回の試行で、`is_risky`の平均スコアは`0.893`から`0.290`に下がりました。一方、直接的なrole spoofingとの比較では平均`0.905`でした。平均が`0.5`を下回ったからといって、個々の呼び出しがすべてgateを通過したことにはなりません。また、この実験では不正な書き込みが完了したことも実証されていません。<sup>[[7]](#references)</sup>

この境界をテストする際は、classifierの判定とtoolの実際の認可結果を区別してください。編集可能なfieldのうち、どれがjudgeに渡されるかを確認し、同じ操作をpolicy風テキストあり/なしで比較して、最終状態を個別に検証します。別個の権限チェックでは、connectorのサービスアカウント権限ではなく、認証済みrequesterの権限を必ず使う必要があります。<sup>[[7]](#references)</sup> その他のclassifierの失敗パターンについては[prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass)を参照してください。[LLM gateway trust boundaries](AI-LLM-Gateway-Security.md)は、これとは異なるルーティングと認証情報の境界を扱っています。

### Subagentのコンテキスト分離

forkされないClaude Agent SDKのsubagentは、独自の`AgentDefinition.prompt`、委任prompt、利用可能なtoolを受け取りますが、親のsystem promptや会話は受け取りません。定義で`tools`が省略されている場合、subagentが利用可能なtoolを継承します。また、プロジェクトの`CLAUDE.md`が読み込まれる場合があります。そのため、子が親と同じfilesystemまたは実行toolを使える場合、親だけに適用されるprompt制限は、信頼できる境界とは言えません。<sup>[[4]](#references)</sup>

親が拒否するrequestと、同じタスクを名前付きsubagentに委任した場合とを比較して、この境界をテストしてください。NCC Groupの報告では、OSのファイル一覧の取得は拒否されたものの、子に対する無害な「layout map」という依頼に言い換えると成功しました。<sup>[[3]](#references)</sup>

親の最終回答だけでなく、子が実際に行ったtool callと有効なtool allowlistを調べてください。子が親ならアクセスしないはずのファイルにアクセスしたかどうかを確認します。<sup>[[4]](#references)</sup> これはguardrailの継承失敗であり、[Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/)やcontainerからの脱出を証明するものではありません。<sup>[[3]](#references)[[4]](#references)</sup>

## Execution: 実際の影響を証明する

影響に至る経路は、操作から大きく2つに分かれます。<sup>[[2]](#references)</sup>

1. **権限の悪用:** 許可されたtoolが、すでに目的の処理を実行できる場合です。たとえば、あるtenantのレコードを読み取って攻撃者が確認できるレポートに書き込む、メールを送信する、レコードを変更する、ファイルを削除する、支払いを開始するといった操作が該当します。二次的なソフトウェアの脆弱性は必要ありません。
2. **下流sinkの悪用:** 攻撃者に誘導されたモデルの出力が、別のコンポーネントにとっての構文になる場合です。[SQL injection](../pentesting-web/sql-injection/README.md)や[NoSQL injection](../pentesting-web/nosql-injection.md)につながるdatabase query、[command injection](../pentesting-web/command-injection.md)につながるshell wrapper、[SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)につながる指定可能なURL、path traversalにつながるファイル操作、RCEにつながるtemplate/code evaluator、[unsafe deserialization](../pentesting-web/deserialization/README.md)につながるobject parserを確認してください。

候補ごとに、次の一連の流れを証明してください。<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

読み取り専用の integration でも、後続のコンポーネントが読み取った内容を公開できるなら、悪用される可能性があります。通常の応答に加え、攻撃者が制御するリンク、自動画像取得、webhook、ログ、レポート、カウンター、通知、他の agent へのメッセージなど、見落とされがちなデータ流出経路もテストしてください。<sup>[[2]](#references)</sup>

## 目的に対するアクション

1つのアクションを確認したら、最初に見えた影響で調査を終えず、影響範囲全体を評価してください。<sup>[[2]](#references)</sup>

- **情報漏えい:** 秘密情報、ユーザーレコード、内部ファイル、会話データ、または prompt/context の内容が、観測可能な経路を通じて外部に送信される。
- **不正なアクション:** agent が正規の書き込み機能を攻撃者の目的に利用する。
- **サービス拒否:** 破壊的なツールや、繰り返される高コストな操作が、完全性または可用性に影響を与える。
- **永続化:** 汚染されたメモリ、インデックス化されたコンテンツ、信頼された状態、またはランタイムの変更が、元のセッションやコンテンツの削除後も残る。
- **伝播:** 信頼された peer が侵害された agent のメッセージや共有状態を受け取り、自身のツールと認証情報を使って同じアクションを繰り返す。

深刻度は、model のテキストがどれほど意外に見えるかではなく、アクセス可能なデータ、実効権限、sink の悪用可能性、データ流出経路、永続化、伝播に基づいて判断してください。<sup>[[2]](#references)</sup>

## 評価中に検証する対策

prompt フィルターや、より優れた system prompt は攻撃者のコストを上げることはできますが、認可の境界として扱うべきではありません。直接入力、間接コンテンツ、メモリ、ツール、peer agent を介して同じ攻撃チェーンを再実行し、以下の対策を検証してください。<sup>[[2]](#references)</sup>

- 決定論的なポリシーレイヤーが、**すべてのツール呼び出し**で、認証済みユーザー、tenant、オブジェクト、アクション、宛先を確認する。model が呼び出し元の identity を指定したり上書きしたりできない。
- 読み取りと書き込みの権限に、分離された最小権限の短命な認証情報を使用する。影響の大きいツールは必要な時だけ公開し、取り込んだコンテンツから自動実行しない。
- ネットワークの egress と内部宛先を、model が選択した URL とは独立して allowlist に登録する。必要な場合を除き、metadata endpoint、マウントされた secret、隣接サービスへのランタイムアクセスをブロックする。
- 承認 UI は、正規の構造化リクエストから生成し、自由形式の model 要約ではなく、正確な引数、identity、宛先、影響対象オブジェクト、副作用を表示する。
- 成功は宛先システムまたは system of record で検証する。agent の説明、ツール呼び出しリクエスト、HTTP redirect は、主張された状態変更の証明にはならない。
- メモリと検索エントリは出所と信頼ラベルを保持し、無効化できるようにする。また、後続のアクションで使用する際に再認可する。
- agent 間メッセージは、信頼できないリクエストとして認証・認可する。peer の評判や agent card によって、受信側のツール使用権限が暗黙に委譲されることはない。

A2A agent card、task flow、およびその攻撃対象領域については、[A2A Protocol Security](AI-A2A-Protocol.md)を確認してください。

## References

- [1] [2026年版 OWASP Agentic Applications トップ10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agent を攻撃するための Hacker ガイド](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [AI Agent を sandbox から脱出させるのは、実際どれほど難しいのか？](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK の Subagent](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode middleware のソースコード](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev model jaggedness: 敵対的コンテンツ](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [judge としての Jev: 偽造されたポリシーが Jev を操る仕組み](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
