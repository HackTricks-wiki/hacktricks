# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

Agent assessmentでは、**攻撃者が制御する入力から、外部から観測可能な影響まで**を追跡します。Jailbreaking、文字の変更、system promptの開示は、推論チャネルが影響を受けることを示します。しかし、重大なfindingとなるのは、データアクセス、不正なtool action、後続のinjection sink、永続化、または別のagentへつながる一連の攻撃です。<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)は、網羅範囲（goal hijacking、tool misuse、privilege abuse、supply chain、code execution、memory poisoning、inter-agent trust、cascading failures、human trust、rogue agents）を分類する際に役立ちます。モデルの予想外のテキストをテストの終点とせず、end-to-endの攻撃経路を構築した後に、これらの分類を使用してください。<sup>[[1]](#references)[[2]](#references)</sup>

## 対象のマップを作成する

payloadを書く前に、各agent workflowについて、次の5つの側面を記録します。<sup>[[2]](#references)</sup>

| 側面 | 列挙する内容 | セキュリティ上の問い |
|---|---|---|
| **信頼できない入力** | Chat/API parameters、URL、文書、メール、ticket、calendar entry、取得されたchunk、memory、tool result、peer-agent message | 後からmodel contextに入るコンテンツを、攻撃者が配置できる場所はどこか？ |
| **Tools** | Tool名とschema、side effect、自動実行、確認動作、動的にロードされるtool | どのcallがsecretを読み取り、stateを書き換え、messageを送信し、データを削除し、codeを実行し、またはvalueを移転するか？ |
| **権限** | User delegation、service account、API token、credentialの有効期間、tenant/resource scope、ネットワーク到達範囲 | 各callはどのidentityで実行され、toolの境界でauthorizationが再確認されるか？ |
| **処理** | Query builder、shell、URL fetcher、template engine、interpreter、parser、file operation、deserializer | modelが生成したデータが、別のinterpreterのsyntaxになる場所はどこか？ |
| **出力** | Response、renderされたMarkdown/HTML、link、image fetch、webhook、email、file、log、report、metric、peer-agent traffic | secretを運んだり、二次requestを引き起こしたりする可能性のある、観測可能なchannelはどれか？ |

これを、宣伝されているintegrationの一覧にまとめないでください。有用な成果物は、各sourceから、到達する正確なcontext上の位置、その時点で利用可能なtool、各toolが使用するcredential、後続のinterpreter、すべてのegress経路までを対応付けたものです。同じtoolでも、ユーザーごとのread tokenであれば影響は小さく、共有のadministrator credentialを使う場合は重大になり得ます。<sup>[[2]](#references)</sup>

## Reconnaissance

### あらゆる配信・取り込み経路をマッピングする

配信面（web、mobile、API、email、chat platform、browser extension）から調査を始め、clientからbackendへのtrafficをproxy経由で確認します。UIでは隠されているfield、search/autocomplete/filter parameter、conversation-state object、uploadおよびindexing job、tool response、sub-agent trafficを調べます。実際のrequest schemaを確認する前にcertificate pinningを回避する必要がある場合は、mobile専用clientにemulatorとinstrumentationが必要になることがあります。<sup>[[2]](#references)</sup>

次に、modelの下位にあるstackをマッピングします。orchestration framework、prompt assembly、retrievalおよびmemory store、runtime（例：Python、container、WASM）、mountされたvolume、host service、internal API、cloud metadataへの到達可能性、隣接networkなどです。frameworkのdefault設定も重要です。一部の「tool call」は、codeを生成または評価することで実装されているため、runtime/sandboxの境界によって、その結果が封じ込められるかどうかが決まります。<sup>[[2]](#references)</sup>

### 非破壊的なprobeでroutingを特定する

対象内のrequestと、関連性のない複数のrequestを比較します。その際、完全なresponse、status code、latency、streamingの動作を保持します。タスク固有の推論より前に一貫して拒否される場合は、独立したgateway/classifierがある可能性があります。文脈に応じた拒否はrequestがmodelに到達したことを示唆します。空の回答や、純粋に抜粋した回答は、keyword searchや限定的なretrievalを示す場合があります。これらは仮説として扱い、同じprobeを別のAPI fieldや取り込み経路から再実行して確認してください。<sup>[[2]](#references)</sup>

攻撃者が制御するsourceのうち、agentの動作を変える最も早いもの**と**、そのsourceから到達できるtool、identity、interpreter、outputを特定できた時点で、Reconは完了です。<sup>[[2]](#references)</sup>

## Exploitation: 信頼境界を越える

promptの文言だけでなく、channelもテストしてください。まず直接のinjectionを試し、ユーザーに見える入口が何を遮断するかを確認します。次に、以下の目立ちにくい経路を通じて、同等の意図を再度試します。<sup>[[2]](#references)</sup>

- **間接コンテンツ:** page、file、email、ticket、metadata、alt text、HTML comment、画面外のテキスト、またはzero-width character。payloadの配信手法については、[AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)を参照してください。
- **Retrievalとmemory:** 後でretrievalされるコンテンツ、または後続sessionで再読み込みされるstateを汚染します。元のsourceを削除すると動作が止まるか記録します。
- **Tool outputとpeer agent:** tool responseまたはagent間messageにmarkerを埋め込み、ユーザー入力と最終出力にのみ適用されるfilterを、内部trafficが迂回するかテストします。
- **Supply chain:** tool descriptor、plugin、接続されたserver、skill、model、dependencyを、信頼されたinstruction sourceとして確認します。MCP固有のテストについては、[MCP Servers](AI-MCP-Servers.md#mcp-vulns)を参照してください。
- **Human approval:** 実際のstructured tool callと、modelが生成した承認文を比較します。攻撃者による影響で、宛先、scope、影響を受けるobject、または取り消せないside effectを省略できないかテストします。

まず、無害で一意なmarkerを使います。source artifact、観測可能であれば組み立て済みcontext、選択されたtool call、approval data、backend request/response、最終stateを保存します。これにより、影響を与えたことと、actionを実行したというhallucinatedな主張とを区別できます。<sup>[[2]](#references)</sup>

### Tool-risk judge内のpolicy風テキスト

modelベースのtool gateは、有用な分類context内にある攻撃者制御のテキストを受け取ることがあります。たとえば、LangChainのexperimental `AutoModeMiddleware`は、提案されたtool call、そのargument、任意のtool description、および直近最大30件のmessageを、TypeSafeの`is_risky` judgeに送信します。返されたNoul probabilityが`0.5`以上の場合、設定済みのtoolをブロックします。このmiddlewareでは、リストにないtoolは分類されません。<sup>[[5]](#references)</sup> TypeSafeも、stateがデータとして扱われる想定であっても、state内のadversarial textが分類に影響する可能性があると警告しています。<sup>[[6]](#references)</sup>

**偽装policy**は、単にsystem messageを名乗ることとは異なります。信頼度の低いstate内に別のlabelやrisk定義を置き、developerが定義した基準ではなく、それらをjudgeに使わせようとします。Datadogのテストでは、ユーザーが編集できる`profile_description`が、`can_edit:false`とともにtool argumentへコピーされていました。そのpolicy風テキストは、mutationが起きる前に別のpermission checkで拒否されるはずなので、writeの試行は低リスクだと主張していました。40回の実行で、`is_risky`の平均scoreは`0.893`から`0.290`に低下しました。一方、直接的なrole-spoofingとの比較では平均`0.905`でした。平均値が`0.5`を下回ったことは、個々のcallがすべてgateを通過したことを証明するものではありません。また、この実験では、不正なwriteが完了したことも**実証されていません**。<sup>[[7]](#references)</sup>

この境界をテストする際は、classifierの判定とtoolの実際のauthorization結果を区別してください。編集可能なfieldのうちどれがjudgeに渡るかを確認し、policy風テキストの有無で同じactionを比較し、最終stateを独立して検証します。別個のpermission checkでは、connectorのservice-account権限ではなく、認証済みrequesterの権限を使用する必要があります。<sup>[[7]](#references)</sup> その他のclassifierのfailure modeについては、[prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass)を参照してください。[LLM gateway trust boundaries](AI-LLM-Gateway-Security.md)は、異なるroutingおよびcredentialの境界を扱います。

### Subagentのcontext isolation

forkしないClaude Agent SDK subagentは、独自の`AgentDefinition.prompt`、delegation prompt、利用可能なtoolを受け取りますが、parentのsystem promptやconversationは受け取りません。definitionで`tools`を省略すると、subagentに利用可能なtoolを継承します。また、projectの`CLAUDE.md`が読み込まれる場合もあります。そのため、childがparentと同じfilesystemやexecution toolを使える場合、parentだけに適用されるprompt制限は信頼できる境界になりません。<sup>[[4]](#references)</sup>

parentが拒否する直接requestと、同じタスクを名前付きsubagentに委譲した場合を比較して、この境界をテストします。NCC Groupの報告では、childに対して無害な「layout map」と言い換えることで、拒否されたOSのfile enumerationが成功しました。<sup>[[3]](#references)</sup>

parentの最終回答だけでなく、childの実際のtool callと有効なtool allowlistを調べます。childがparentならアクセスしないfileにアクセスしたか確認してください。<sup>[[4]](#references)</sup> これはguardrailの継承失敗であり、[Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/)やcontainerからのescapeを証明するものではありません。<sup>[[3]](#references)[[4]](#references)</sup>

### Mobile GUI agent: 画面上のinstructionとaction rebinding

phoneのGUI agentは、次のcross-app actionを選ぶ前に、各screenshotをcloud modelに送信することがあります。**間接的なvisual injection**をテストするには、agentが許可されたタスクの途中で確認するSMS、email、またはpageに、攻撃者が制御するテキストを配置します。直接のタスクpromptと、screenshot内だけに同じinstructionが表示される場合を比較し、次のactionと高リスク操作に関する判断を調べます。評価対象のassistantでは、client側の`checkPrompt`は直接のタスクテキストを検査していましたが、screenshotの内容には同等のfilterを適用していませんでした。これは[agentic-browser screenshot injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md)のmobileおよびcross-app版であり、Android component authenticationを迂回する方法ではありません。<sup>[[9]](#references)</sup>

side effectのテスト例として、攻撃者が制御するformに機密fieldを入力するようagentに求め、その後、人間に「upload」のclickを要求する方法があります。一方、pageはfieldの入力が変わるとすぐに送信します。human handoffでは、pageのcodeがすでに送信したデータを保護できません。agentの説明を証拠とみなさず、実際の送信を検証してください。sourceはこれを可能性のあるpatternとして示しており、すべてのassistantで実証されたcompromiseとして示しているわけではありません。<sup>[[9]](#references)</sup>

**GUI TOCTOU / action rebinding**は別のfailure modeです。agentは`t0`に観察した画面から入力を計画しますが、入力が注入される`t1`より前にforeground UIが変わります。<sup>[[8]](#references)</sup> 後の`t2`にscreenshotを撮っても、すでに実行されたactionを取り消すことはできません。<sup>[[9]](#references)</sup> 許可されたAndroid testでは、次のworkflowを再利用できます。<sup>[[8]](#references)</sup>

1. 対象controlの画面上の座標を特定し、制御されたapp内の同じ場所に無害なcontrolを表示します。
2. agentがその画面を観察するまでcarrierを表示しておき、観察からactionまでの間に通常のforeground transitionを発生させます。
3. 計画されたtapが新しいappのcontrolに当たるかを確認し、agentの説明に頼らず、対象appで結果のstateを検証します。

元のaction-rebinding研究では、危険なpermissionを持たないappを使ってこれを実証しています。また、複数ステップのflowでagentのtask-recovery loopを通じてtransitionを繰り返す方法も説明しています。<sup>[[8]](#references)</sup>

このprimitiveが、すべてのassistantで変更なしに機能すると**想定しないでください**。Doubaoの評価では、最上位Activityが変わると`OpClickUI`はclickをスキップし、直前の3ステップ以内に`OpOpenApp`が現れた場合はscreenshotを比較していました。そのため、single tap、long press、double tapでは、攻撃者が信頼性をもってタイミングを制御することは困難でした。`OpTypeText`、`OpSwipeUI`、`OpScrollWheelAction`には同等のguardがありませんでしたが、報告では実用上の影響はより限定的と評価されました。<sup>[[9]](#references)</sup>

## Execution: 実際の影響を証明する

影響に至る経路は、大きく2つに分かれます。<sup>[[2]](#references)</sup>

1. **Capability abuse:** 認可されたtool自体が、すでに目的のactionを実行できます。例として、あるtenantのrecordを読み取って攻撃者から見えるreportに書き込む、emailを送信する、recordを変更する、fileを削除する、paymentを開始するといったものがあります。二次的なsoftware bugは必要ありません。
2. **Downstream sink exploitation:** 攻撃者に操作されたmodel outputが、別のcomponentのsyntaxになります。[SQL injection](../pentesting-web/sql-injection/README.md)や[NoSQL injection](../pentesting-web/nosql-injection.md)が可能なdatabase query、[command injection](../pentesting-web/command-injection.md)が可能なshell wrapper、選択されたURLを使った[SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)、traversalが可能なfile operation、RCEが可能なtemplate/code evaluator、[unsafe deserialization](../pentesting-web/deserialization/README.md)が可能なobject parserを確認します。

候補ごとに、次の一連の流れを証明してください。<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

読み取り専用の連携機能でも、後続のコンポーネントが読み取った内容を公開できる場合は悪用可能です。通常の応答に加え、攻撃者が制御するリンク、自動画像取得、webhook、ログ、レポート、カウンター、通知、他のエージェントへのメッセージなど、見落とされやすい外部送信経路もテストしてください。<sup>[[2]](#references)</sup>

## 目的に対するアクション

1つのアクションを確認した後、最初に目に見えた影響だけで評価を終わらせず、影響範囲全体を評価してください。<sup>[[2]](#references)</sup>

- **情報窃取:** 秘密情報、ユーザーレコード、内部ファイル、会話データ、またはプロンプト／コンテキストの内容が、観測可能なチャネルを通じて外部に送信される。
- **不正なアクション:** エージェントが正規の書き込み機能を使い、攻撃者の目的を実行する。
- **サービス拒否:** 破壊的なツールや、繰り返される高コストな操作が、完全性または可用性に影響を与える。
- **永続化:** 汚染されたメモリ、インデックス化されたコンテンツ、信頼された状態、またはランタイムの変更が、発生元のセッションやソースの削除後も残る。
- **伝播:** 信頼されたピアが、侵害されたエージェントのメッセージまたは共有状態を取り込み、自身のツールと認証情報を使ってそのアクションを繰り返す。

深刻度は、モデルの出力がどれほど意外に見えるかではなく、アクセス可能なデータ、実効的な権限、sinkの悪用可能性、外部送信、永続化、伝播に基づいて判断してください。<sup>[[2]](#references)</sup>

## 評価時に検証するコントロール

プロンプトフィルターや、より優れたシステムプロンプトは攻撃者のコストを高めることがありますが、認可境界として扱ってはいけません。以下のコントロールを検証するには、直接入力、間接的なコンテンツ、メモリ、ツール、ピアエージェントを経由して同じ攻撃チェーンを再実行してください。<sup>[[2]](#references)</sup>

- 決定論的なポリシーレイヤーが、**ツール呼び出しのたびに**認証済みユーザー、テナント、オブジェクト、アクション、宛先を確認する。モデルは呼び出し元のIDを指定したり、上書きしたりできない。
- 読み取りと書き込みの権限には、分離された最小権限の短命な認証情報を使う。影響の大きいツールは必要なときだけ公開し、取り込んだコンテンツから自動実行しない。
- ネットワークの外部送信先と内部宛先は、モデルが選択したURLとは独立して許可リストで制限する。必要な場合を除き、ランタイムからメタデータエンドポイント、マウントされた秘密情報、隣接サービスへのアクセスをブロックする。
- 承認UIは、正規の構造化リクエストから生成し、自由形式のモデル要約ではなく、正確な引数、ID、宛先、影響を受けるオブジェクト、副作用を表示する。
- 成功は宛先システムまたは信頼できる記録システムで検証する。エージェントによる説明、ツール呼び出しリクエスト、HTTPリダイレクトは、主張された状態変更の証明にはならない。
- メモリと検索エントリーには、出所と信頼ラベルを保持し、無効化できるようにする。また、後続のアクションで使用する際に再認可する。
- エージェント間メッセージは、信頼できないリクエストとして認証・認可する。ピアの評判やagent cardによって、受信側のツール使用権限が暗黙に委譲されることはない。

A2A agent card、タスクフロー、およびその攻撃対象領域については、[A2A Protocol Security](AI-A2A-Protocol.md)を確認してください。

## References

- [1] [2026年版 OWASP Agentic Applications Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AIエージェントを攻撃するためのハッカーガイド](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [AIエージェントをサンドボックスから脱出させるのは、実際どれほど難しいのか？](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDKのサブエージェント](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Modeミドルウェアのソース](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jevモデルの不均一性：敵対的コンテンツ](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [審査員としてのJev：偽造ポリシーがJevを誘導する仕組み](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [権限不要の操作：大規模マルチモーダルモデルを活用するGUIエージェントを信頼できるか？](https://arxiv.org/html/2601.12349v1)
- [9] [AIアシスタントがハッカーの攻撃チェーンの一部となるとき | Doubao Phoneのセキュリティ分析](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
