# Offensive Infrastructure and Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

オペレーターが単一のプロキシだけで意味のある匿名性を得られることはほとんどありません。実際のキャンペーンでは**分離グラフ**を構築します。オペレーターはアクセスノードに接続し、中継ノードが出口ノードからアクセスノードを隠し、リダイレクターが実際の C2 を保護し、使い捨ての名前が公開エッジを指します。

すべての経路について、標準化された長所・短所・導入・検知の観点を確認するには、[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)を使用してください。このページでは、敵対的インフラストラクチャの構成をさらに詳しく解説します。

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

ターゲットが最後に観測したアドレスは経路を示す証拠であり、誰がキーボードを操作していたかの証明ではありません。MITREは主要な構成要素を、Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568)、Web Service (T1102)に分類しています。<sup>[[1]](#references)</sup>

## インフラストラクチャの分類

| 分類 | 使われる理由 | 持続的に残る露出 | 防御側に最適な調査の手がかり |
|---|---|---|---|
| レンタルVPS/cloud | 高速で予測可能、ルーティング可能で、簡単に再構築できる | テナント、請求、コンソール、ログイン元、イメージの履歴 | アカウント／コントロールプレーンのイベントと、繰り返し現れるサーバーのフィンガープリント |
| 商用VPN/Tor | 大規模な共有egress群で、サーバー管理が不要 | プロバイダーによる可視性とエンドツーエンドのタイミング | 宛先での挙動、エンドポイントの証拠、フローの相関 |
| Residential/mobile proxy | コンシューマー向けASNと地理的な妥当性 | ブローカー／顧客の記録、proxywareまたは感染ホストの挙動 | 不可能な移動、proxyプロトコル、セッションごとのアドレス変化 |
| 侵害されたサーバー／ルーター／IoT | 被害者の評判と管轄区域を借用できる | インプラント、管理フロー、繰り返し接続する上流コントローラー | 1つの出口IPではなく、デバイスのテレメトリとORBのトポロジー |
| CDN/redirector | 外部に見えるエッジとバックエンドC2を分離する | TLS/HTTPの文法、証明書、ルーティング、クラウドアカウントの痕跡 | エッジからオリジンへの相関と、リクエスト形状のクラスタリング |
| 正規のWebサービス | 許可されたGitHub/cloud/socialのトラフィックに紛れ込む | APIトークン、テナント／オブジェクト識別子、異常なプロセス系譜 | エンドポイントのプロセスとサービス／APIのセマンティクス |
| 物理／セルラー／衛星経路 | 見かけ上の物理的な発信元を変える | RF、通信事業者、加入者、デバイス、位置情報の記録 | 無線／物理の証拠とネットワークの証拠を組み合わせる |

## 運用型リレーボックスネットワーク

**ORBネットワーク**は、中継サービスとして使われる管理型proxyフリートです。Mandiantはこれを、リースサーバーで構成されたプロビジョニング済みネットワーク、侵害されたルーター／IoTで構成された非プロビジョニングネットワーク、そしてハイブリッドに分類しています。成熟したトポロジーには、次の4つの論理的な役割があります。<sup>[[2]](#references)</sup>

1. **管理サーバー (ACOS):** インベントリ、認証情報、稼働状況、ルーティングポリシーを管理する。
2. **アクセス／リレーノード:** 顧客またはオペレーターを認証する。変化するメッシュへの安定した入口となる。
3. **中継ノード:** 1つ以上のリースまたは侵害されたシステムが、内容を判別できない接続を中継する。
4. **出口／ステージングノード:** 偵察、侵害、またはC2のターゲットに対して、最終的な送信元アドレスを示す。

メッシュは国、ASN、レイテンシ、または可用性に基づいて出口を選び、状態の悪いノードをローテーションできます。複数の脅威グループが同じネットワークを借りる場合もあります。Mandiantは、一部のORBでIPv4アドレスが関連付けられる期間がわずか31日という事例を確認しました。そのため、古くなったIPリストをブロックするのではなく、**ネットワークを進化するアクターのような存在として扱う**ことを推奨しています。<sup>[[2]](#references)</sup>

### これで得られるもの—そして何が leak するのか

- ターゲットからは、地理的に近く、住宅用に見える出口が見える場合がある。
- 出口から見えるのはターゲットと直前のホップであり、必ずしもオペレーターではない。
- アクセスサービスからは顧客と経路リクエストが見える。独立して管理されたメッシュなら、顧客と出口を切り離せるが、強力な取引相手の記録が残る。
- IPがローテーションしていても、繰り返されるポート、ハンドシェイクの順序、サーバーバナー、証明書、稼働時間帯、コントローラー間の関係からフリートが露呈することがある。
- 侵害されたルーターにはエンドポイントのテレメトリがないことが多いが、ISPには加入者とフローのデータが残る。押収されれば、インプラントや設定の痕跡が明らかになる。

{% hint style="info" %}
許可された演習では、組織が所有するVMまたはルーターでトポロジーを再現し、コントローラーの帰属マップを保持してください。公開proxyや第三者のデバイスを取り込んではいけません。[ラボガイド](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)では、中継者に被害を与えずに、同じ防御側から見えるホップ構造を作成します。
{% endhint %}

## Residentialおよびmobile proxyネットワーク

Residential proxyサービスは、セッションにコンシューマー向けブロードバンドのアドレスを割り当てます。mobile proxyは、通信事業者のNATプールを経由してegressします。供給元には、明示的に登録された機器、コンシューマーアプリにバンドルされたSDK／proxyware、再販業者、またはマルウェアがあります。これらの由来は同じではありません。十分な説明に基づく同意がなければ、プライバシーサービスは侵害されたインフラストラクチャになります。

ローテーション方式は検知に影響します。

- **リクエストごとのローテーション**では、上位レイヤーの識別情報が安定したまま、IPやASN／地理情報が急速に不連続に変化する。
- **スティッキーセッション**では、出口が数分から数時間維持され、通常の加入者に似た状態になる。
- **バックコネクトゲートウェイ**では、顧客にはブローカーのエンドポイントが1つ見え、出口は内部で選択される。
- **mobileプール**では、多数の実際の加入者が少数の通信事業者NATアドレスを共有するため、IPブロックによる影響が大きくなる。

防御側は、IPを認証済みセッション、TLS／クライアントのフィンガープリント、HTTPの順序、デバイスcookie、挙動と相関させるべきです。上位レイヤーの特徴がすべて同じまま、ローカルの住宅用回線からのログインと思われる接続が別の国から続く場合、単なるレピュテーションより強い証拠になります。一方で、アドレス共有やmobileのハンドオフは正当な変動を生むため、住宅用／proxyという分類だけで判断してはいけません。

### Proxywareのコントロールプレーンと再販業者の重複

Residentialプールを、出口の単純なリストとしてモデル化してはいけません。IPIDEAエコシステムの分析では、再利用可能な**2階層のコントロールプレーン**が明らかになりました。組み込まれたSDKはまず、デバイス／登録のメタデータをTier Oneドメインに報告し、スケジューリング情報とTier Twoの`connect`／`proxy` IP:portペアを受け取ります。ノードは定期的にTier Twoのconnectポートをポーリングしてエンコードされたタスクを取得し、ペアになったproxyポートへの2つ目の接続を開いて、指定されたバイト列を要求先に中継します。名目上は異なるSDKやproxyブランドでも、それぞれ別の検出ドメインを使いながら、共通の所有関係や再販業者との関係を通じて、共有されたTier Twoインフラストラクチャと重複する出口プールに収束していました。<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

これは、住宅用 IP ブロックよりも持続性の高いハンティングの手掛かりになります。<sup>[[13]](#references)</sup>

- 予期しないユーティリティ、VPN、ゲーム、または組み込みデバイスのプロセスが、安定したデバイス ID／顧客キーを送信し、変化するサーバーリストを受け取る。
- エンドポイントが通常とは異なるポート上の直接 IP をポーリングし、その直後に同じアドレスの別ポートへ接続してから、新しい宛先ソケットを開く。
- 複数の見かけ上異なるブランドが、Tier Two アドレス、プロトコル文法、SDK コード、または出口ノードの重複を共有している。
- 異なる Tier One ドメインに接続する別々のアプリケーションが、同じ Tier Two プールのアドレスを受け取る。

この重複は帰属の特定も難しくします。あるベンダーが公表するプール内で IP を確認しても、該当時点でどのリセラー、顧客、または脅威アクターが使用したかは特定できません。フローのタイムスタンプ、プロセスの系譜、Tier One の応答本文、Tier Two のタスク識別子を保持してください。<sup>[[13]](#references)</sup> 許可された演習では、この階層を組織所有のエンドポイントだけで模倣してください。消費者向けデバイスやサードパーティの proxyware を登録してはいけません。

## マルチホッププロキシチェーン

MITRE は外部プロキシと**マルチホッププロキシ (T1090.003)** を区別しています。重要なのはホップ数ではなく、知識と管理の分離です。<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

一方の当事者が A と B の両方を運用している場合、ログや通信フローのタイミングが共有されることで、回線を再構成できる。同じエンドポイント／アカウントから商用 VPN を順番に利用しても、遅延が増える一方で、共通の身元情報、支払い情報、タイミングの証拠は残る場合がある。Tor は独立して選択されたリレーと共通のクライアント設計によってこの問題を軽減するが、低遅延の対話型ネットワークでは、通信の両端を計測する観測者に対する耐性を保証できない。

よくある失敗には、DNS や IPv6 のバイパス、アプリケーションによる独自ソケットの作成、リレーへの管理トラフィックの直接到達、同期した活動、SSH キーの再利用、身元を特定できるアカウントへのログインがある。適切な検証はフェイルテストである。各リレーを順番に停止し、ワークロードが平文経路へフォールバックできないことを確認する。

### トンネルの崩壊と上流への漏えい

リレーアーキテクチャは、障害時に最も追跡可能になることが多い。Unit 42 は、被害者側の VPS、リレー VPS、レジデンシャルプロキシ、Tor、その他のプロキシサービスを使った多層のスパイ活動経路を記録した。トンネルが省略または崩壊した際には、隠された上流インフラがリレーおよび被害者側システムに直接接続した。同じ調査では、上流インフラ上で一時的に露出した X.509 証明書も、階層をまたぐピボットに利用された。<sup>[[14]](#references)</sup>

**データプレーン**（`victim <-> exit`）と**コントロールプレーン**（`operator/upstream -> relay administration`）を分離する。所有する各階層で、イングレスログと認証ログ、証明書の履歴、短時間の失敗した接続を保持し、成功した C2 セッションだけに限定しない。リレー障害時にのみ現れる、または複数の被害者側ノードを直接管理する送信元は、通常の出口ノードより上流の候補として有力だが、その ASN や地理的位置情報はあくまで仮説であり、オペレーターの身元を証明するものではない。

認可されたラボでは、ワークロードがフェイルクローズするようにする。Linux のネットワーク名前空間に隔離したワークロードでは、最初の経路をトンネル経由にする。トンネルを削除した後は、物理アップリンクが選択されるのではなく、リクエストと経路検索の両方が失敗しなければならない。

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNS と IPv6 について、また各 relay 境界でテストを繰り返します。プローブが1つでも成功した場合は、policy routing や firewall を修正する前に、実際の interface/source address を記録してください。その観測結果が、調査担当者に見える attribution leak です。

## Redirector tiers and traffic shaping

public **redirector** は、operation 固有の grammar に一致する traffic を受け入れ、保護された team server に転送します。それ以外は拒否するか、無害なコンテンツを返します。

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

複数の階層を設ければ、露出を抑えられます。公開ドメインがburnされても、team serverまで露出する必要はありません。CDNはanycastの容量と信頼性の高い外向きドメインを提供しますが、CDNアカウントとエッジログが帰属特定の手掛かりになります。TLS fingerprints、証明書の履歴、特徴的なパスやヘッダー順序、レスポンスサイズ、リダイレクトの挙動、オリジンのallowlistから、一見無関係なフロントを関連付けられることがあります。

検知では、正規化前のreverse-proxyフィールドを記録し、SNI/Host/authorityを比較し、まれなヘッダーの組み合わせを調べ、レスポンス本文とTLS fingerprintsをクラスタリングし、cloud/CDNの監査ログで設定の重複を検索します。承認済みのred teamでは、実在ブランドの模倣や、無関係な第三者の背後での認証情報収集を避けてください。

## Domain frontingとdomainless fronting

従来型の**domain fronting (T1090.004)**では、TLS接続で許可されたフロントドメインをSNIに指定し、暗号化されたHTTP `Host`またはHTTP/2 `:authority`で別のバックエンドドメインを要求します。協力するCDNは内側の値に基づいてルーティングします。TLS復号を行わないネットワーク監視者に見えるのはフロントですが、CDNには両方の値とオリジンが見えます。domainlessの亜種では、SNIが空で、別のルーティングフィールドが宛先を選択する場合があります。<sup>[[4]](#references)</sup>

これは魔法のようななりすましではありません。仲介者が意図的または偶然に不一致を許可し、内側の名前のルーティング方法を知っている場合にのみ機能します。大手プロバイダーは、アカウントをまたぐfrontingを制限しています。Encrypted ClientHello (ECH)により、経路上の監視者から見える情報は変わりますが、CDN、エンドポイント、アプリケーションの記録は消えません。

検知のポイントには次のものがあります。

- エンドポイントのプロセス系譜と、そのアプリケーションでは想定されない宛先。
- TLS inspectionが合法かつ利用可能な場合の、SNIとHTTP authorityの不一致。
- あるtenant/frontが別のauthority/originにルーティングしていることを示すCDNログ。
- 通常は対話型のサービスに対する、異常に長時間または定期的なセッション。
- frontドメインが変わっても安定している暗号化フローのサイズと頻度。

安全なラボでは、所有するreverse proxy上でルーティングの不一致をシミュレートします。公開CDNを悪用しません。

## Dynamic resolution: DDNS、DGA、fast flux

Dynamic resolutionを使うと、論理サービスを固定インフラから切り離せます。

- **DDNS:** 認証済みクライアントが、アドレスの変更後に安定した名前を更新します。
- **DGA:** エンドポイントとコントローラーが、時間/鍵のseedから候補ドメイン名を導出し、運用者はその一部だけを登録します。
- **Fast flux:** 名前が、侵害されたアドレスやproxyアドレスの集合を短いTTLで頻繁に返します。
- **Double flux:** サービスアドレスと権威name serverアドレスの両方をローテーションし、制御レイヤーも隠します。

Fast fluxは攻撃者が利用する負荷分散パターンであり、単に「DNSの回答が多い」ことではありません。低いTTL、多数の一意なアドレス、広範囲に分散したASN/地域、ノードの短い稼働期間、繰り返されるアプリケーションの挙動、疑わしい登録履歴を組み合わせると、より強い証拠になります。CDNも、これらの性質のいくつかを正当に持ちます。MITREは、DNSの挙動とプロセスおよびその後の接続を関連付けることを推奨しています。<sup>[[5]](#references)</sup>

DGAは、語彙的なエントロピー、子音/数字のパターン、NXDOMAINの急増、同時期に初めて確認されたドメイン、プロセスのコンテキストから検知できます。Wordlist DGAや生成モデルは単純なエントロピー規則を回避するため、フリート全体での時間的なクラスタリングとエンドポイントの系譜がより重要になります。

## 侵害されたドメインとdomain shadowing

攻撃者は、registrar/DNSアカウントを乗っ取ったり、放置されたサブドメインを乗っ取ったり、信頼性の高いドメインの配下にレコードを追加したりすることがあります。**Domain shadowing**では、正規のapexを維持したまま、攻撃者が制御する多数のサブドメインを、変化する配信ホストやC2ホストに向けます。これにより、ドメインの経年と評判を利用し、ドメイン全体を対象とするブロックを回避できる場合があります。<sup>[[6]](#references)</sup>

防御側には、registrarと権威DNSの監査ログ、MFA、registry/registrarロック、新しいdelegation/API token/name serverのアラート、certificate-transparencyの監視、DNSから参照されるcloudリソースの一覧が必要です。サブドメインの名前解決と証明書の履歴は、apexの評判とは切り離して調査してください。

## Webサービスとdead-drop resolver

**Dead-drop resolver (T1102.001)**は、正規の投稿、プロフィール、ドキュメント、リポジトリ、cloud object、またはblockchainのフィールドに、現在のC2を指すエンコード済みポインターを保存します。マルウェアは公開オブジェクトを取得し、ドメイン/IPをデコードして次のステージに接続します。双方向型の亜種は、サービスAPIを通じてコマンドやファイルをやり取りします。<sup>[[7]](#references)</sup>

GitHubに特化したresolverの亜種では、認証済みのrepository channelが失敗した場合に限り、Issues Search APIを使用します。クライアントは、現在の日付、リポジトリ、issue typeに一致するissueを検索し、各issueのcomments URLをたどり、`<!--`と`-->`のマーカーの間からciphertextを抽出します。ホストごとに日付から導出した方法で復号した後、`Owner`、`LicRepo`、`LicToken`などのフィールドで、メインのrepository owner、パス、tokenを置き換えます。これにより、クライアントを置き換えずに運用者が認証情報とエンドポイントをローテーションできます。issue commentはresolverであり、repositoryファイルは引き続きtasking channelとして使われます。<sup>[[15]](#references)</sup>

Androidの亜種では、起動時に2つの公開Telegramページのどちらかを選び、APKに埋め込まれたマーカーの2つの出現箇所の間からciphertextを抽出します。値をBase64URLでデコードし、AES-128-CBCで復号します。`SHA-256(marker)`の先頭16バイトが鍵で、残りの16バイトがIVです。平文は実際のC2 base URLであり、TelegramページのURLではありません。名前解決を再現する場合は、ページの内容と正確なマーカーを維持してください。公開ページを変更すれば、APKを再ビルドせずにエンドポイントをローテーションできます。<sup>[[16]](#references)</sup>

これは耐障害性を高め、静的バイナリ解析からバックエンドC2を隠します。一方で、安定したオブジェクト、tenant、repository、API、アクセスパターンの識別子が生まれます。防御側は次の情報を関連付ける必要があります。

1. サービスに接続したプロセス。
2. 正確なAPI path/objectとレスポンスhash。
3. デコードまたは文字列処理の動作。
4. その直後の新しいアウトバウンド接続。
5. フリート内の別の場所で見られる同一の挙動。

GitHub、cloud storage、またはソーシャルメディアをすべてブロックするのは、現実的でないことがほとんどです。サービスを考慮したegress policyとプロセスレベルの相関は、ドメインだけに基づくブロックより効果的です。

## ペルソナ、アカウント、調達の区分

ペルソナ、復旧用メール、電話番号、支払い、ブラウザー、または管理者IPが区分をまたいでつながると、インフラの匿名性は損なわれます。国家に関連する作戦では、使用するずっと前からソーシャルプロフィール、メールID、cloudアカウントを準備してきました。ATT&CKではこれをEstablish Accounts (T1585)として記録しており、ソーシャル、メール、cloudのサブテクニックが含まれます。<sup>[[8]](#references)</sup>

防御側や調査担当者は、次の情報からグラフを構築します。

- 作成と初回ログインの時刻、locale、タイムゾーン、活動スケジュール。
- 復旧用フィールド、MFAデバイス、本人確認書類、支払い手段。
- ブラウザー/TLS fingerprintsと送信元ネットワークの履歴。
- アバターの再利用、画像の出所、文体、ソーシャルグラフの成長。
- 共有されたドメイン登録者、name server、証明書、analytics ID、repository commit。
- 公開relayアーキテクチャを経由しない管理プレーン上の操作。

承認済みのred teamでは、synthetic personaを演習責任者に記録し、組織所有の復旧/支払いチャネルを使用し、関係のない実在人物へのなりすましを避け、計画的に廃止してください。SOCが気付かない状態でも、作戦を説明不能な状態にしてはなりません。

## 脅威モデルに含めるべき新たな複合パターン

以下は**防御側の視点で組み合わせたものであり、特定の攻撃者が個々の設計をそのまま展開したと主張するものではありません**。すでに確認されているプリミティブを組み合わせたもので、purple-teamの仮説として有用です。

### 非対称な一方向tasking

コマンドは公開、broadcast、またはappend-onlyの送信元から届き、結果は遅れて無関係なチャネル経由で送信されます。このプリミティブの例として、web-service one-way communicationとdead dropがあります。分離により、単一のフローが双方向に見えるのを防ぎ、単純なrequest/response相関を困難にします。<sup>[[9]](#references)</sup>

**検知:** オブジェクト単位の読み取りを保持し、プロセスの状態変化と後続のアウトバウンド転送を、より長い時間幅で関連付けます。直後に返信がなくても、同じ公開オブジェクトを読むまれなプロセスを探してください。

### 多段階channel promotion

静かな初期ステージがインベントリを収集し、選択したシステムだけを無関係な第2ステージのチャネルに移行させます。第2のエンドポイント、プロトコル、プロセスは、第1ステージとインフラを共有しない場合があります。これにより、高機能なインフラの露出が抑えられ、ATT&CK T1104でも明示的にモデル化されています。<sup>[[10]](#references)</sup>

**検知:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`を関連付けます。最初のドメインをブロックしただけでインシデントを終了しないでください。

### プロトコルをまたぐrelay変換

各ホップがパケットをそのまま転送するのではなく、HTTPS、QUIC、WebSocket、DNS、SSH、またはmessage-queue APIを相互変換します。変換により、単一のエンドツーエンドのプロトコルfingerprintは消えますが、特徴的なタイミング、buffering、意味上の変換を持つgatewayが生じます。Protocol tunneling (T1572)は、proxyやサービスのなりすましと組み合わせられます。<sup>[[11]](#references)</sup>

**検知:** あるプロトコルを受信し、別のプロトコルを開始するgateway hostについて、バイト数とタイミングの強い関連を探します。エンドポイントの意図と実際に運ばれるプロトコルを比較してください。

### エッジデバイス上での受動的な起動

beaconを送る代わりに、implantはルーター/VPNにすでに到達しているトラフィックを監視し、magic value、送信元ポートのパターン、または認証済みtokenを検出した場合にのみ動作します。通常のトラフィックは実サービスへ引き続き送られます。ATT&CKではこれをTraffic Signaling (T1205)と呼び、ネットワークデバイスやAPTの事例が記録されています。<sup>[[12]](#references)</sup>

**検知:** firmware/file integrity、承認済み調査時のraw packet capture、想定外のsocket filter、サービスの挙動の差異を確認します。定期的なbeaconがないからといって、エッジデバイスがクリーンだとは限りません。

### Serverlessと短命なoriginのローテーション

frontは安定した論理IDを維持しながら、短命なfunction/containerが複数のリージョン/アカウントで個別のステージを処理します。これにより、ディスク上の痕跡と固定origin IPの寿命が短くなりますが、control-planeの作成記録、image/layer、role、secret、request ID、課金テレメトリが永続的な関連付けのグラフになります。

**検知:** cloudの監査ログとinvocation logをworkloadの外部に保持し、deployment template、role、environment key、frontとoriginの関係をクラスタリングします。

### Privacy layerの多様化

作戦では、意図的に単一の均質な経路を避ける場合があります。たとえば、あるチャネルにはリースしたrelay、taskingには公開オブジェクト、出口には所有するラボのcellular link、管理には別の組織ネットワークを使います。これにより、単一プロバイダーの侵害による影響を抑えられますが、レイヤーをまたぐタイミングと運用ミスのリスクが増します。

**検知:** identity、DNS、SaaS、network、cloudのセンサーを横断してキャンペーンのタイムラインを構築します。同一のindicatorではなく、同期した状態遷移を探してください。

### 分散型または透明性ログ型のdead drop

攻撃者は、耐久性のある公開append-onlyシステム、content-addressed store、または透明性ログに似たfeedに、小さな暗号化ポインターを置くことがあります。公開オブジェクトは高い耐障害性を持ちますが、その正確なindex/content hashとクライアントのpolling挙動が安定した識別子になります。

**検知:** API/objectの完全な識別子とレスポンスhashを記録し、immutable objectをpollingした後にデコードや新規接続を行う非標準プロセスにアラートを設定します。

### 遅延型store-and-forward作戦

対話型C2は強いタイミング相関を生みます。store-and-forward設計では、暗号化されたjobをまとめ、数分から数時間後に、別のqueueや物理的な移送経路を通じて結果を返します。応答性を犠牲にする代わりに、エンドツーエンドのタイミング相関を弱めます。

**検知:** 相関分析の時間幅を長くし、定期的なqueueアクセスをモデル化し、エンドポイントでのstage準備を調べます。batch処理では、シグナルがパケットのタイミングから、スケジュールされたプロセス/ファイルの挙動へ移ります。消えるわけではありません。

## 設計レビュー: 監視者の視点で考える

すべての経路について、展開前と収集後にこの表を埋めてください。

| レイヤー | 送信元が見えるか？ | 宛先が見えるか？ | 内容が見えるか？ | 安定した識別子 | 保持期間/法的な管理者 |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

一般的なプロバイダー1社がすべての列を埋められるなら、そのアーキテクチャはtargetからの隠蔽には役立っても、堅牢な分離は実現していません。内部の責任者が活動を演習に紐付けられないなら、プロフェッショナルなred teamingには不適切です。

## References

- [1] [MITRE ATT&CK — インフラの取得 (T1583)、インフラの侵害 (T1584)、Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexusの諜報活動を行う攻撃者がORBネットワークを使用](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — インフラの侵害: ドメイン (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — アカウントの作成 (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: 一方向通信 (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — 世界最大のResidential Proxy Networkを妨害](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Shadow Campaigns: 世界規模の諜報活動の解明](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaign、イラクのインフラを標的に](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AIがオーバーレイを構築。被害者はPINを奪われる](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
