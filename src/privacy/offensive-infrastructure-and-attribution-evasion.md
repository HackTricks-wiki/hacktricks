# 攻撃インフラとアトリビューション回避

{{#include ../banners/hacktricks-training.md}}

オペレーターが単一のプロキシだけで意味のある匿名性を得られることはほとんどありません。実際のキャンペーンでは**分離グラフ**を構築します。オペレーターはアクセスノードに接続し、中継ノードが出口からそのノードを隠し、リダイレクターが本物のC2を保護し、使い捨てのドメイン名が公開エッジを指します。

あらゆる経路について、標準化された長所・短所・導入・検知の観点を確認するには、[匿名インターネットアクセス手法カタログ](anonymous-internet-access-techniques.md)を参照してください。このページでは、敵対的なインフラの構成についてさらに詳しく説明します。

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

ターゲットが最後に確認したアドレスは、したがって経路の証拠であり、キーボードを操作していた人物の証明ではありません。MITREは主要な構成要素を、Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568)、Web Service (T1102)に分類しています。<sup>[[1]](#references)</sup>

## Infrastructure classes

| Class | アクターが利用する理由 | 長期的に残る露出情報 | 防御側が最も有効にたどる手掛かり |
|---|---|---|---|
| レンタルVPS/cloud | 高速で予測可能、ルーティング可能で、容易に再構築できる | テナント、課金、コンソール、接続元ログイン、イメージ履歴 | アカウント／control-planeイベントと、繰り返し現れるサーバーフィンガープリント |
| 商用VPN/Tor | 大規模な共有egress群。サーバー管理が不要 | プロバイダー／通信事業者の可視性とエンドツーエンドのタイミング | 宛先の振る舞い、エンドポイントの証拠、フロー相関 |
| Residential/mobile proxy | コンシューマーASNと地理的な自然さ | ブローカー／顧客記録、proxywareまたは感染ホストの挙動 | 不可能な移動、プロキシプロトコル、セッションごとのアドレス変化 |
| 侵害されたサーバー／ルーター／IoT | 被害者の評判と管轄区域を借用できる | インプラント、管理フロー、繰り返し接続する上流コントローラー | 単一の出口IPではなく、デバイステレメトリーとORBのトポロジー |
| CDN/redirector | 公開エッジとバックエンドC2を分離する | TLS/HTTPの文法、証明書、ルーティング、cloudアカウントの痕跡 | エッジとオリジンの相関、リクエスト形状のクラスタリング |
| 正規のWebサービス | 許可されたGitHub/cloud/socialトラフィックに紛れ込める | APIトークン、テナント／オブジェクト識別子、異常なプロセス系譜 | エンドポイントのプロセスとサービス／APIのセマンティクス |
| 物理／携帯／衛星経路 | 見かけ上の物理的な発信元を変える | RF、通信事業者、加入者、デバイス、位置情報の記録 | 無線／物理的証拠とネットワーク証拠の組み合わせ |

## Operational relay box networks

**ORB network**は、中継サービスとして使用される管理型プロキシ群です。Mandiantはこれを、リースサーバーで構成されるプロビジョニング済みネットワーク、侵害されたルーター／IoTで構成される非プロビジョニング型ネットワーク、そしてハイブリッド型に分類しています。成熟したトポロジーには、4つの論理的な役割があります。<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** インベントリ、認証情報、ヘルス状態、ルーティングポリシーを管理します。
2. **Access/relay node:** 顧客またはオペレーターを認証します。変化するメッシュへの安定した入口です。
3. **Traversal nodes:** 1つ以上のリース済みまたは侵害済みシステムが、不透明な接続を中継します。
4. **Exit/staging node:** 偵察、エクスプロイト、C2の対象に対して、最終的な送信元アドレスを提示します。

メッシュは国、ASN、レイテンシ、可用性に基づいて出口を選択し、状態の悪いノードをローテーションできます。複数の脅威グループが同じネットワークを借りることもあります。Mandiantは、一部のORBでIPv4アドレスが関連付けられた期間が最短で31日だったことを確認しており、古くなったIPリストをブロックするのではなく、**ネットワークを進化するアクターのような存在として扱う**ことを推奨しています。<sup>[[2]](#references)</sup>

### これによって得られるもの—そして漏れるもの

- ターゲットには、地理的に近く、住宅用に見える出口が表示されることがあります。
- 出口が見られるのは、ターゲットと直前のホップであり、必ずしもオペレーターではありません。
- アクセスサービスには、顧客とルート要求が見えます。独立して管理されるメッシュでは、顧客と出口を分離できる場合がありますが、強力な取引相手の記録が残ります。
- ポート、ハンドシェイクの順序、サーバーバナー、証明書、稼働時間帯、コントローラーとの関係が繰り返し現れることで、IPがローテーションしていてもネットワーク群が露見する可能性があります。
- 侵害されたルーターにはエンドポイントテレメトリーがないことがよくありますが、ISPには加入者情報とフローデータが残っています。押収されれば、インプラントや設定の痕跡が明らかになります。

{% hint style="info" %}
認可された演習では、組織所有のVMまたはルーターでトポロジーを再現し、コントローラーのアトリビューションマップを保持してください。オープンプロキシや第三者のデバイスを利用してはいけません。[lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)では、中継者に被害を与えることなく、同じく防御側から見えるホップ構造を作成できます。
{% endhint %}

## Residential and mobile proxy networks

Residential proxyサービスは、セッションにコンシューマーブロードバンドのアドレスを割り当てます。mobile proxyは、通信事業者のNATプールを経由してegressします。供給元には、明示的に登録された機器、コンシューマーアプリにバンドルされたSDK/proxyware、再販業者、マルウェアなどがあります。これらの由来は同じではありません。十分な説明に基づく同意がなければ、プライバシーサービスは侵害インフラになります。

ローテーション方式は検知に影響します。

- **リクエストごとのローテーション**では、上位レイヤーのIDが安定したまま、IPやASN／地域が急速に不連続に変化します。
- **sticky sessions**では、出口が数分から数時間維持され、通常の加入者のように見えます。
- **backconnect gateways**では、顧客にはブローカーのエンドポイントが1つだけ見え、出口は内部で選択されます。
- **mobile pools**では、多数の実際の加入者が少数の通信事業者NATアドレスの背後に配置されるため、IPブロックのコストが高くなります。

防御側は、IPを認証済みセッション、TLS／クライアントフィンガープリント、HTTPの順序、デバイスcookie、振る舞いと相関させるべきです。すべての上位レイヤーの特徴が同一のまま、ローカルの住宅回線からのログインとされた接続が別の国から続いている場合、レピュテーションだけよりも強い証拠になります。一方、アドレス共有やmobile handoffによって正当なアドレス変動も発生するため、住宅用／プロキシという分類だけで断定してはいけません。

### Proxyware control planes and reseller overlap

Residential poolを、出口の単純な一覧としてモデル化しないでください。IPIDEAエコシステムの分析から、再利用可能な**二層のcontrol plane**が明らかになりました。組み込みSDKはまず、デバイス／登録メタデータをTier Oneドメインに報告し、スケジューリング情報とTier Twoの`connect`／`proxy` IP:portペアを受け取ります。ノードは定期的にTier Twoのconnect portをポーリングしてエンコードされたタスクを取得し、ペアとなるproxy portへの2つ目の接続を開いて、指定された宛先に受け取ったバイト列を中継します。名目上は異なるSDKやproxyブランドが、それぞれ別の探索ドメインを持っていたものの、共通の所有関係や再販業者との関係を通じて、共有のTier Twoインフラと重複する出口プールに収束していました。<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

これは、住宅用IPブロックよりも持続性の高いハンティングの手掛かりになります:<sup>[[13]](#references)</sup>

- 想定外のユーティリティ、VPN、ゲーム、または組み込みデバイスのプロセスが、安定したデバイスID／顧客キーを送信し、変化するサーバーリストを受け取る。
- エンドポイントが通常とは異なるポート上の直接IPをポーリングし、その後、新しい宛先ソケットを開く直前に、同じアドレス上の別のポートに接続する。
- 複数の見かけ上のブランドで、Tier Twoのアドレス、プロトコル文法、SDKコード、またはexit nodeの重複が見られる。
- 異なるTier Oneドメインに接続する個別のアプリケーションが、同じTier Twoプールからアドレスを受け取る。

この重複は、 attribution も難しくします。あるベンダーが広告しているプールにIPが含まれていることを確認しても、該当時点でどのリセラー、顧客、または脅威アクターが使用したかは特定できません。フローのタイムスタンプ、プロセスの系譜、Tier Oneの応答本文、Tier Twoのタスク識別子を保存してください。<sup>[[13]](#references)</sup> 許可された演習では、この階層構造は組織所有のエンドポイントのみでエミュレートしてください。消費者向けデバイスやサードパーティのproxywareは決して登録しないでください。

## Multi-hop proxy chains

MITREは、external proxiesと**multi-hop proxies (T1090.003)**を区別しています。重要な特性はホップ数ではなく、知識と管理の分離です。<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

一方の事業者が A と B の両方を運用している場合、ログの共有や通信フローのタイミングから回路を再構成できる可能性があります。同じエンドポイントやアカウントから商用 VPN を順次追加しても、共通の身元情報、支払い情報、タイミングの証拠が残る一方で、遅延が増えるだけの場合があります。Tor は独立して選択されるリレーと共通のクライアント設計によってこの問題を軽減しますが、低遅延の対話型ネットワークでは、通信の両端を観測する相手に対する耐性を保証できません。

よくある失敗には、DNS または IPv6 のバイパス、アプリケーションによる独自のソケット接続、リレーへの管理トラフィックの直接到達、活動の同期、SSH キーの再利用、身元を特定できるアカウントへのログインがあります。正しい検証方法は障害テストです。各リレーを順番に停止し、ワークロードが平文の経路にフォールバックできないことを確認してください。

### トンネルの崩壊と上流側の leak

リレーアーキテクチャは、障害発生時に最も帰属特定されやすくなることがよくあります。Unit 42 は、被害者側 VPS、リレー VPS、レジデンシャルプロキシ、Tor、その他のプロキシサービスを使用した多段のスパイ活動経路を記録しました。トンネルが省略されたり崩壊したりすると、隠された上流インフラがリレーや被害者側システムに直接接続していました。同じ調査では、上流インフラ上で一時的に露出した X.509 証明書も、階層をまたぐピボットに利用されました。<sup>[[14]](#references)</sup>

**データプレーン**（`victim <-> exit`）と**コントロールプレーン**（`operator/upstream -> relay administration`）は分離してください。所有する各階層で、イングレスログと認証ログ、証明書の履歴、短時間で失敗した接続を保持してください。成功した C2 セッションだけを記録してはいけません。リレー障害時にのみ現れる、または複数の被害者側ノードを直接管理する送信元は、通常の出口ノードよりも上流の候補として有力ですが、その ASN や地理的位置情報は、オペレーターの身元を証明するものではなく、あくまで仮説です。

認可されたラボでは、ワークロードを fail closed にしてください。Linux のネットワーク名前空間内に隔離されたワークロードでは、最初の経路がトンネルを使用する必要があります。トンネルを削除した後は、物理アップリンクを選択するのではなく、リクエストと経路検索の両方が失敗する必要があります。

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNSとIPv6について、また各リレー境界でテストを繰り返します。プローブが1つでも成功した場合は、ポリシールーティングやファイアウォールを修正する前に、実際のインターフェース／送信元アドレスを記録してください。その観測結果が、調査担当者に見える attribution leak です。

## Redirector tiers and traffic shaping

公開 **redirector** は、作戦固有の文法に一致するトラフィックを受け入れ、保護された team server に転送します。それ以外のすべてのトラフィックは拒否するか、無害なコンテンツを返します。

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

複数の階層を設けることで露出を抑えられます。パブリックドメインを使い捨てても、team serverを露出させる必要はありません。CDNはanycastのキャパシティと信頼性の高い外部ドメインを提供しますが、CDNアカウントとエッジログが帰属特定の手掛かりになります。TLS fingerprint、証明書の履歴、特徴的なパスやヘッダー順序、レスポンスサイズ、リダイレクトの挙動、origin allowlistによって、一見無関係なfrontを関連付けられることがあります。

検知では、正規化前のreverse-proxyフィールドを記録し、SNI/Host/authorityを比較し、珍しいヘッダーの組み合わせを調べ、レスポンス本文とTLS fingerprintをクラスタリングし、cloud/CDNの監査ログから設定の重複を探します。許可を得たred teamでは、実在ブランドの模倣や、無関係な第三者の背後に置いたcredential collectionを避けてください。

## Domain frontingとdomainless fronting

従来型の**domain fronting (T1090.004)**では、TLS接続のSNIで許可されたfront domainを提示する一方、暗号化されたHTTP `Host`またはHTTP/2の`:authority`で別のback-end domainを要求します。協力するCDNは内部の値に基づいてルーティングします。TLSを復号できないネットワーク観測者に見えるのはfrontですが、CDNには両方の値とoriginが見えます。domainlessの亜種では、SNIが空のまま、別のルーティングフィールドが宛先を選択することがあります。<sup>[[4]](#references)</sup>

これは魔法のようななりすましではありません。中継者が意図的または偶発的に不一致を許可し、内部の名前をルーティングできる場合に限り機能します。主要プロバイダーは、アカウントをまたいだfrontingを制限しています。Encrypted ClientHello (ECH)によって経路上の観測者に見える情報は変わりますが、CDN、endpoint、applicationの記録が消えるわけではありません。

検知ポイントには、次のものがあります。

- endpoint上のプロセスの親子関係と、そのapplicationに想定されない宛先
- TLS inspectionが合法かつ利用可能な場合の、SNIとHTTP authorityの不一致
- 1つのtenant/frontが別のauthority/originにルーティングされていることを示すCDNログ
- 通常は対話型のサービスに対する、不自然に長時間または定期的なセッション
- front domainが変わっても安定している暗号化フローのサイズと間隔

安全なlabでは、自組織が所有するreverse proxy上でルーティングの不一致をシミュレートし、公開CDNを悪用しません。

## 動的名前解決：DDNS、DGA、fast flux

動的名前解決では、論理サービスと固定インフラを切り離します。

- **DDNS:** 認証済みクライアントが、アドレスの変更後に安定した名前を更新します。
- **DGA:** endpointとcontrollerが時間/key seedから候補domainを導出し、operatorはその一部を登録します。
- **Fast flux:** 名前が、侵害された多数のアドレスまたはproxyアドレスを短いTTLで頻繁に返します。
- **Double flux:** サービスアドレスと権威name serverアドレスの両方をローテーションし、control layerも隠します。

Fast fluxは敵対的に使われる負荷分散パターンであり、単に「DNS応答が多い」ことを指すわけではありません。より強い証拠は、短いTTL、多数の一意なアドレス、広範なASN/地域への分散、ノードの短い存続期間、繰り返されるapplicationの挙動、不審な登録履歴を組み合わせて得られます。CDNも、これらの特性のいくつかを正当に備えています。MITREは、DNSの挙動をプロセスおよびその後の接続と相関させることを推奨しています。<sup>[[5]](#references)</sup>

DGAは、語彙のエントロピー、子音/数字のパターン、NXDOMAINの急増、同期した初回観測domain、プロセスのコンテキストから検知できます。単語リスト型DGAや生成モデルは単純なエントロピー判定を回避するため、フリート全体にわたる時間的クラスタリングとendpointの系譜がより重要になります。

## 侵害されたdomainとdomain shadowing

攻撃者は、registrar/DNSアカウントを乗っ取ったり、放置されたsubdomainを取得したり、評判の良いdomainの配下にレコードを追加したりする場合があります。**Domain shadowing**では、正規のapexを維持したまま、多数の攻撃者管理下のsubdomainを、変化する配信ホストまたはC2ホストに向けます。これにより、ドメインの経過年数と評判を利用し、domain全体を対象にしたブロックを回避できる可能性があります。<sup>[[6]](#references)</sup>

防御側には、registrarと権威DNSの監査ログ、MFA、registry/registrar lock、新たなdelegation/API token/name serverに対するアラート、certificate transparencyの監視、DNSで参照されるcloudリソースの一覧が必要です。subdomainの名前解決と証明書の履歴は、apexの評判とは別に調査してください。

## Webサービスとdead-drop resolver

**Dead-drop resolver (T1102.001)**は、正規の投稿、プロフィール、文書、repository、cloud object、またはblockchainのフィールドに、現在のC2へのエンコードされたポインターを保存します。マルウェアはその公開objectを取得し、domain/IPを復号して次のstageに接続します。双方向型では、サービスAPIを介してコマンドやファイルをやり取りします。<sup>[[7]](#references)</sup>

GitHub固有のresolverの亜種では、認証済みのrepository channelが失敗した場合に限り、Issues Search APIを使用します。クライアントは現在の日付、repository、issue typeに一致するissueを検索し、各issueのcomments URLをたどり、`<!--`と`-->`のマーカー間からciphertextを抽出します。ホストごとに日付から導出した方法で復号した後、`Owner`、`LicRepo`、`LicToken`などのフィールドで、主要なrepositoryのowner、path、tokenを置き換えます。これにより、クライアントを置き換えずにoperatorがcredentialとendpointをローテーションできます。issue commentはresolverであり、repositoryのファイルは引き続きtasking channelです。<sup>[[15]](#references)</sup>

これは耐障害性を高め、静的なバイナリ分析からback-end C2を隠します。一方で、安定したobject、tenant、repository、API、アクセスパターンの識別子も生み出します。防御側は次の情報を関連付けるべきです。

1. サービスに接続したプロセス
2. 正確なAPI path/objectとレスポンスhash
3. 復号または文字列処理の挙動
4. その直後の新たなoutbound connection
5. フリート内の他の場所で見られる同一の挙動

GitHub、cloud storage、ソーシャルメディアをすべてブロックするのは、現実的でないことがほとんどです。サービスを考慮したegress policyとプロセスレベルの相関は、domainだけに基づくブロックより効果的です。

## ペルソナ、アカウント、調達の分離区画

ペルソナ、recovery email、電話番号、決済手段、ブラウザー、admin IPが区画間をつなぐと、インフラの匿名性は崩れます。国家と結びついた作戦では、使用するずっと前からソーシャルプロフィール、メールID、cloudアカウントを育ててきました。ATT&CKでは、これをEstablish Accounts (T1585)として記録し、social、email、cloudのsub-techniqueを含めています。<sup>[[8]](#references)</sup>

防御側や調査担当者は、次の情報からグラフを構築します。

- 作成時刻と初回ログイン時刻、locale、time zone、作業時間帯
- recovery情報、MFAデバイス、身分証明書、決済手段
- browser/TLS fingerprintと接続元ネットワークの履歴
- avatarの再利用、画像の出所、文体、ソーシャルグラフの拡大
- 共通するdomain registrant、name server、証明書、analytics ID、repository commit
- 公開relayの構成を迂回するmanagement-plane操作

許可を得たred teamでは、合成ペルソナを演習統括者に記録し、組織所有のrecovery/決済手段を使い、関係のない実在人物へのなりすましを避け、事前に利用終了計画を定める必要があります。SOCが気付かない状態は維持しても、作戦が説明責任を果たせない状態にしてはなりません。

## 脅威モデル化する新たな複合パターン

以下は**防御側主導の組み合わせ**であり、特定の攻撃者がそれぞれの設計をそのまま導入したという主張ではありません。すでに観測されているプリミティブを組み合わせたもので、purple teamの仮説として役立ちます。

### 非対称な一方向tasking

コマンドは公開、broadcast、または追記専用の情報源から届き、結果は時間をおいて無関係なchannelから送信されます。このプリミティブの例には、web-service one-way communicationとdead dropがあります。分離により、単一のフローが双方向に見えることを防ぎ、単純なrequest/responseの相関を困難にします。<sup>[[9]](#references)</sup>

**検知:** object単位の読み取りを保存し、その後のより広い時間枠でプロセスの状態変化とoutbound transferを相関させます。直後に応答がなくても、同じ公開objectを読み取る珍しいプロセスを探します。

### 多段階channelへの移行

目立たない第1段階でインベントリを収集し、選別したシステムだけを無関係な第2段階のchannelに移行させます。第2のendpoint、protocol、processは、第1段階のインフラと共通点がない場合があります。これにより、高度なインフラの露出を抑えます。この手法はATT&CK T1104で明示的にモデル化されています。<sup>[[10]](#references)</sup>

**検知:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`を関連付けます。最初のdomainをブロックしただけでインシデントを終わらせないでください。

### protocolをまたぐrelay変換

異なるhop間で、パケットを透過的に転送するのではなく、HTTPS、QUIC、WebSocket、DNS、SSH、またはmessage-queue APIを変換します。変換によって単一のエンドツーエンドのprotocol fingerprintは消えますが、特徴的なタイミング、buffering、意味的な変換を伴うgatewayが生まれます。Protocol tunneling (T1572)は、proxyやサービスのなりすましと組み合わせられることがあります。<sup>[[11]](#references)</sup>

**検知:** あるprotocolを受信し、時間とbyte数が密接に対応する別のprotocolを開始するgateway hostを探します。endpointの目的と、実際に運ばれているprotocolを比較します。

### エッジデバイス上での受動的な起動

beaconを送信する代わりに、implantがrouter/VPNにすでに到達している通信を監視し、magic value、source-portのパターン、認証済みtokenがある場合に限って起動します。通常の通信は実際のサービスに転送され続けます。ATT&CKではこれをTraffic Signaling (T1205)と呼び、network deviceやAPTの事例を記録しています。<sup>[[12]](#references)</sup>

**検知:** firmware/fileの完全性、許可を得た調査時のraw packet capture、予期しないsocket filter、サービスの挙動の差異を調べます。定期的なbeaconがないからといって、エッジデバイスがクリーンだとは限りません。

### serverlessと短命なoriginのローテーション

frontは安定した論理IDを維持しつつ、短命なfunction/containerで個々のstageを複数のregion/accountにわたって処理します。これにより、disk上の存続期間と固定origin IPを減らせますが、control-planeでの作成、image/layer、role、secret、request ID、billing telemetryが永続的な関連情報になります。

**検知:** workloadの外部にcloud監査ログとinvocation logを保持し、deployment template、role、environment key、frontとoriginの関係をクラスタリングします。

### プライバシー層の多様化

作戦では、均一な経路を意図的に避けることがあります。たとえば、あるchannelにはリースしたrelayを使い、taskingには公開objectを使い、exitには自組織のlab用cellular linkを使い、管理には別の組織ネットワークを使います。これにより、1つのプロバイダーを侵害した場合の価値は下がりますが、層をまたぐタイミングと運用ミスのリスクは高まります。

**検知:** identity、DNS、SaaS、network、cloudのセンサーを横断するcampaignの時系列を構築します。同一のindicatorではなく、同期した状態遷移を探します。

### 分散型または透明性ログ型のdead drop

攻撃者は、永続的で公開された追記専用システム、content-addressed store、または透明性ログに似たfeedに、小さな暗号化ポインターを置くことがあります。公開objectは耐障害性が高い一方で、正確なindex/content hashとクライアントのpolling挙動が安定した識別子になります。

**検知:** 完全なAPI/object識別子とレスポンスhashを記録し、不変のobjectをpollingした後に復号や新たな接続を行う、通常とは異なるプロセスにアラートを出します。

### 遅延型のstore-and-forward作戦

対話型C2は強いタイミング相関を生みます。store-and-forward方式では、暗号化されたjobをまとめて送り、数分から数時間後に、別のqueueまたは物理的な転送経路から結果を返します。応答性を犠牲にすることで、エンドツーエンドのタイミング相関を弱めます。

**検知:** 相関の時間枠を広げ、定期的なqueueアクセスをモデル化し、endpoint上のstagingを調べます。batch処理によって信号はpacket timingから、スケジュールされたプロセスやファイルの挙動へ移りますが、消えるわけではありません。

## 設計レビュー：観測者ごとに考える

すべての経路について、導入前と収集後にこの表を埋めてください。

| Layer | 送信元が見えるか？ | 宛先が見えるか？ | 内容が見えるか？ | 安定した識別子 | 保持期間/法的管理者 |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

一般的なプロバイダー1社がすべての列を埋められるなら、その構成はtargetから隠せても、強固な分離は実現できていません。社内のどの統括者も活動を演習に結び付けられないなら、プロフェッショナルなred teamingには適していません。

## References

- [1] [MITRE ATT&CK — インフラの取得 (T1583)、インフラの侵害 (T1584)、Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexusの諜報活動グループがORB networkを使用](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — インフラの侵害：Domain (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service：Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — アカウントの作成 (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service：一方向通信 (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — 世界最大のResidential Proxy Networkを妨害](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns：世界規模の諜報活動を解明](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaignがイラクのインフラを標的に](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
