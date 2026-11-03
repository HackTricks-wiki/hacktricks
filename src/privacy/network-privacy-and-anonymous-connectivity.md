# ネットワークプライバシーと匿名接続

{{#include ../banners/hacktricks-training.md}}

ネットワークプライバシーは経路の選択であり、完全な身元保護ではありません。誰に **送信元**、**宛先**、**コンテンツ**、**タイミング**を関連付けられたくないのかを考えて、経路を選択してください。

正規化された一覧として、すべてのアクセス経路ファミリーについて `Pros`、`Cons`、ステップごとの `Procedure`、`Detection` をまとめた[匿名インターネットアクセス技術カタログ](anonymous-internet-access-techniques.md)から始めてください。このページでは、一般的に導入可能な選択肢を詳しく説明します。

## 各監視者が通常確認できる情報

| 経路 | ローカルネットワーク / ISP | 中継者 | 宛先 | 主な制限 | 相対速度 |
|---|---|---|---|---|---|
| 直接 HTTPS | 送信元、宛先メタデータ、タイミング / 通信量 | ホスティング / CDN は接続を確認 | 送信元 IP、ブラウザー / アプリのデータ | 送信元 IP のプライバシーは保護されない | 最速 |
| 商用 VPN | VPN への接続。通常の宛先メタデータは見えない | VPN は送信元と宛先のメタデータを確認 | VPN の出口 IP | 1 つのプロバイダーが相関分析の拠点になる | 通常は高速 |
| 自己ホスト型 VPN/VPS | VPS への接続 | ホスト / アカウント / 決済 / コントロールプレーンのログ | VPS の出口 IP | レンタルサーバー / アカウントと容易に結び付けられる | 通常は高速 |
| Tor Browser | Tor / bridge への接続。タイミング / 通信量 | 各リレーが限定的な情報を確認 | Tor の出口、ブラウザーデータ | 速度が遅い。アカウント / エンドポイント / 相関のリスク | 中速 / 低速 |
| Tails/Whonix | 同様の Tor 経路だが、より強固なルーティング境界がある | Tor と同じ制限 | Tor の出口 / アプリケーションデータ | 運用上のミスやホスト / ハードウェアの情報は残る | 中速 / 低速 |
| 公共ゲスト Wi-Fi + HTTPS | 施設はローカルデバイス / タイミングと宛先を確認 | 施設の ISP はメタデータを確認 | ゲストのパブリック IP | 物理的な場所 / キャプティブポータル / デバイスとの相関 | 高速 / 変動 |
| セルラーホットスポット | 通信事業者は契約者 / デバイス / 位置情報と宛先を確認 | 使用している場合は VPN / Tor | 通信事業者、VPN、または Tor の出口 IP | モバイル契約と位置情報は持続的な識別子になる | 高速 / 変動 |
| Mixnet | アクセス回線は mixnet の利用、タイミング / 通信量を確認 | 複数のミキシングノード | ゲートウェイ / 出口 | エコシステムは発展途上。遅延と帯域幅のコスト | 最低速 |

HTTPS は通信中のコンテンツを保護しますが、すべてのメタデータを保護するわけではありません。EFF によると、ページのパス、認証情報、メッセージが暗号化されていても、ドメイン、時刻、通信量は中継者から見える場合があります。<sup>[[1]](#references)</sup>

暗号化オーバーレイは、自動的に匿名ネットワークになるわけではありません。Yggdrasil の直接ピアは、互いの IP アドレスを確認できます。<sup>[[20]](#references)</sup> その[ユーザー空間転送と SOCKS トランスポート](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack)はトンネリングの選択肢であり、送信元の匿名化レイヤーではありません。<sup>[[20]](#references)[[21]](#references)</sup>

## VPN：信頼が集中する、高速なプライバシー保護

VPN は、アクセス ISP から宛先メタデータを隠す、信頼できないネットワーク上の最初のホップを保護する、エンゲージメントで安定した出口アドレスを使う、またはプライベートネットワークにアクセスするといった用途に役立ちます。ただし、ユーザーを **匿名化するものではありません**。VPN は送信元からの接続を確認でき、宛先メタデータを観察できます。また、アカウント、Cookie、GPS、フィンガープリント、決済情報は残ります。<sup>[[1]](#references)</sup>

### プロバイダーの評価チェックリスト

1. **所有者と管轄区域：** 法人、親会社、事業を行う国、インフラの下請け業者、適用される法的手続きを確認します。
2. **収集データ：** アカウント / 請求情報、送信元 IP、接続時刻、帯域幅、クラッシュテレメトリー、DNS クエリ、宛先ログを区別します。「閲覧ログなし」は「データを一切保有しない」という意味ではありません。
3. **保持と削除：** 正確な保持期間と、バックアップ、不正対策システム、処理業者にも同じスケジュールが適用されるかを確認します。
4. **根拠：** 対象範囲、日付、調査結果、修正内容が公開された監査、再現可能な / オープンなクライアント、透明性レポート、インシデントの文書化を優先します。
5. **プロトコルとクライアント：** 保守されている WireGuard、OpenVPN、または他のレビュー済みプロトコル、自動更新、DNS と IPv6 の処理、kill switch、プラットフォームごとの leak テストを確認します。
6. **ビジネスモデル：** 無料または割引されたサービスの資金源を把握します。アプリストアに掲載されているだけでは、信頼できる運用の証拠になりません。
7. **決済方法との適合性：** 別の決済方法を使えば、VPN への請求情報の開示を減らせる場合がありますが、接続のたびに観察される送信元 IP は消せません。

### VPN の設定と検証

1. プロバイダー / 組織の署名付きクライアントを、公式の配布元からインストールします。
2. 文書化された経路が VPN を迂回する必要がない限り、**full tunnel** を選択します。Split tunneling は相関や leak の経路を生み出します。
3. 接続失敗時に閉じる / 常時接続の動作を有効にし、再接続中の通信をブロックします。
4. DNS をトンネル経由にし、IPv4 と IPv6 の両方をテストします。安全にトンネル経由にできないプロトコルを無効にする場合は、機能が失われることを受け入れたうえで行います。
5. スリープ / 復帰、ネットワーク切り替え、キャプティブポータルへのログイン、トンネルのクラッシュ、ホットスポットのテザリングをテストします。NCSC は、一部のプラットフォームでは、テザリングされたクライアントの通信がスマートフォンの VPN を迂回する可能性があると警告しています。<sup>[[2]](#references)</sup>
6. 組織が管理するテストエンドポイントを使い、確認された IPv4、IPv6、DNS リゾルバー、接続タイミングを記録します。機密性の高いエンゲージメントで、無作為な「leak テスト」サイトを使わないでください。
7. クライアント、OS、ネットワーク、ポリシーを変更した後に再テストします。

### 敵対的な LAN におけるルーティングの迂回

VPN は「接続中」と表示されたまま、一部のパケットが迂回することがあります。これは、OS が VPN によるパケット暗号化より**前に**経路を選択するためです。TunnelCrack は、一般的なルーティング例外を悪用する 2 つの方法を実証しました。**LocalNet** はインターネット上の宛先を直接接続されたサブネット上にあるように見せかけ、**ServerIP** は VPN ゲートウェイの名前解決を偽装し、VPN トランスポートに必要な平文ネットワークの例外を対象アドレスに適用させます。これらはクライアント / ルーティングの不具合であり、WireGuard、OpenVPN、IPsec、TLS の破綻ではありません。HTTPS のペイロードはエンドツーエンドで暗号化されたままですが、ローカルの監視者は宛先 / タイミングのメタデータや、平文プロトコルのデータを取得できる可能性があります。<sup>[[18]](#references)</sup>

TunnelVision は、DHCP option 121 を通じて同じ暗号化前のプリミティブを適用します。悪意のある、または侵害された DHCP サーバーは、VPN の包括経路より具体的なクラスレス経路を設定し、任意のホストまたは範囲への通信に物理インターフェースを選択させることができます。VPN の制御チャネルは維持される場合があるため、トンネル切断時にのみ作動する kill switch は有効にならない可能性があります。また、単一のパブリックな「IP leak」チェックでは、選択的な迂回を見逃すことがあります。<sup>[[19]](#references)</sup>

物理インターフェースで DHCP と認証済み VPN トランスポートのみを許可するパケットフィルター型 kill switch を使えば、fail-closed の動作にできます。ただし、標的を絞った経路注入によって、選択的なサービス拒否のサイドチャネルが生じる可能性は残ります。重大な影響を伴う Linux ワークロードには、より強固な[ワークロードごとの経路強制を行うネットワーク名前空間パターン](advanced-network-privacy-architectures.md#enforce-the-route-per-workload)を優先してください。このパターンでは、アプリケーションの名前空間に物理インターフェースも平文ネットワークのデフォルト経路もありません。<sup>[[19]](#references)</sup>

#### 所有するラボでの検証

所有する AP、DHCP サーバー、VPN エンドポイント、宛先を用いて、実際に使用するクライアント / OS / バージョンをテストしてください。ルーティングやパケットフィルターの実装はプラットフォームごとに異なるため、製品全体に関する主張はすぐに古くなります。出口 IP を表示するウェブサイトだけでは、すべての宛先への通信がトンネルを通ることの証明にならないため、テストサーバーだけでなくエンドポイント自体でもキャプチャしてください。<sup>[[18]](#references)[[19]](#references)</sup>

1. VPN に接続し、VPN サーバーのアドレスを記録して、IPv4 / IPv6 のルーティングテーブルとポリシールーティングルールをすべて保存します。Windows では `route print`、macOS では `netstat -rn`、Linux では以下のコマンドを使用します。
2. 所有する複数の宛先 IP について、選択された経路を確認します。文書化された VPN トランスポートのエンドポイントを除き、次のホップ / インターフェースはトンネルでなければなりません。
3. TunnelVision をテストするには、管理下の DHCP ネットワークでリースを更新し、option 121 の経路を**所有するテスト宛先だけ**に設定します。テストに合格するのは、通信がトンネルを通るかブロックされる場合です。物理インターフェースから宛先への通信が送信されてはいけません。
4. LocalNet をテストするには、クライアントにラボ内のみで使うパブリックなドキュメント用サブネット（`203.0.113.0/24` など）を割り当て、所有するテスト宛先をその範囲に置きます。LAN アクセスを有効にしても、インターネット上の宛先がトンネルを迂回しないことを確認します。
5. ServerIP をテストするには、VPN 接続前に、管理下の DNS で所有する VPN ホスト名を所有するテスト宛先に名前解決させ、ラボのゲートウェイから実際の所有 VPN エンドポイントへ VPN トランスポートを転送します。クライアントが、偽装したアドレス宛ての無関係なアプリケーション通信を例外扱いしてはいけません。
6. 「local network access」の有効 / 無効を切り替えて再テストし、再接続後、スリープ / 復帰後、ネットワーク切り替え後、VPN プロセスのクラッシュ後にも確認します。IPv4、IPv6、DNS を個別にテストします。
7. 物理インターフェースのキャプチャを確認します。DHCP と VPN サーバー宛ての暗号化パケットは含まれていても、所有するテスト宛先に直接アドレス指定されたパケットが含まれていてはいけません。また、バイパスが拒否された後、ユーザーへの確認や接続の修復を経て、気付かないうちにフォールバックしないことも確認します。

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser：より強力なWeb上のunlinkability

Torは複数のrelayを経由する回線を構築するため、通常、単一のrelayが送信元と宛先の両方を知ることはありません。宛先からはユーザーのIPではなくTor exitが見え、通常、ローカルネットワークからはTorへの接続が見えます。<sup>[[3]](#references)</sup> Torは低遅延のTCPアプリケーション向けに設計されているため速度が遅く、両端を相関分析できる攻撃者に対する保護は保証できません。<sup>[[4]](#references)</sup>

### Tor Browserの安全な使用手順

1. Tor BrowserはTor Projectまたは公式ミラーからのみダウンロードし、可能な場合は署名を検証します。
2. Tor SOCKS portを指定した通常のブラウザではなく、**Tor Browser**を使います。通常のブラウザでは、DNS/WebRTCや識別につながる状態がleakする可能性があります。<sup>[[5]](#references)</sup>
3. デフォルトのサイズ、フォント、拡張機能、プライバシー設定を維持します。追加のアドオンによって、ブラウザが他と区別されやすくなることがあります。<sup>[[6]](#references)</sup>
4. 互換性の問題を許容できる場合は、セキュリティレベルを**Safer**または**Safest**に設定します。
5. Torへの直接接続がブロックされる場合や、通常のrelay IPがローカル環境に過度に見える場合はbridgeを使います。bridgeは簡単な識別を難しくしますが、トラフィック分析をなくすものではありません。<sup>[[7]](#references)</sup>
6. 身元が特定されるアカウントにログインしたり、個人を特定できる情報を提供したり、ダウンロードしたアクティブなドキュメントを外部ネットワークに接続されたアプリケーションで開いたりしないでください。
7. IDごとに別のセッション／コンテキストを使います。「New circuit」はブラウザ／アプリケーションのIDを消去することと同じではありません。状況に応じて**New Identity**を使うか、隔離環境を再起動してください。
8. 認証済みHTTPSまたは認証済みonion serviceを優先します。Tor exitは暗号化されていないHTTPトラフィックを監視できます。

### TorとVPNの併用

併用すれば自動的に安全性が高まるわけではありません。Torの前にVPNを使うと、ISPからTor relayへの直接接続を隠せますが、VPNには送信元が見えます。Torの後にVPNを使うと、VPNにはTor通過後のアクティビティが継続的に見え、anonymity setが小さくなる可能性があります。設定ミスによってleakが発生することもあります。Tor Projectは、明確な脅威モデルを持つ上級者以外には、こうした組み合わせを推奨していません。<sup>[[8]](#references)</sup>

## 公共Wi-FiとゲストWi-Fi

最新のHTTPSを使えば、通常、傍受している周囲の人が適切に暗号化されたWebコンテンツを読むことはできません。しかし、ゲストWi-Fiは匿名性を保証しません。施設側は接続時刻、デバイス識別子、captive portalのデータ、宛先、DHCPの詳細を記録できます。カメラ、購入履歴、移動手段、物理的な監視によってユーザーが特定されることもあります。また、名前のよく似た偽のhotspotによって、portalの認証情報を盗まれたり、暗号化されていないトラフィックを操作されたりする可能性もあります。<sup>[[9]](#references)</sup>

### ゲストネットワークの適法な使用手順

1. ゲスト向けに提供されているネットワーク、または所有者から明示的な許可を得たネットワークだけを使います。正確なSSIDとportalの接続手順をスタッフに確認します。
2. 到着前にendpointとtravel routerを更新します。ファイル／プリンター共有、受信側の検出、自動接続、保存済みネットワークの探索を無効にします。
3. OSのプライベート／ランダム化Wi-Fiアドレスを有効にします。最新のAppleシステムでは、オープンまたは脆弱なネットワークでローテーションするアドレスを使用できます。最新のAndroidでは、SSIDごとに永続的なランダム化が一般的です。これによりローカルで使われる識別子を1つ減らせます。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. 特権ワークステーションとゲストネットワークの間に、組織が管理するtravel routerまたは信頼度の低いbridge deviceを置く方法を優先します。これによりファイアウォール／VPNポリシーを一元化できますが、施設側からrouterが見えなくなるわけではありません。<sup>[[12]](#references)</sup>
5. 指定された信頼度の低いデバイス／ブラウザだけを使ってcaptive portalを完了します。匿名のコンテキストで個人情報や使い回しの認証情報を入力しないでください。接続できたらportalのブラウザを閉じます。
6. 機密性の高い操作を始める前に、full-tunnel VPNまたはTorを起動し、fail-closedの動作を確認します。
7. 使用後はネットワークを削除し、portalアカウントとデータ保持に関するポリシーを確認します。

{% hint style="danger" %}
近隣のWi-Fiのcracking、portalの回避、leakしたゲスト用認証情報の使用、別のゲストのアクセス権の複製、カフェにRaspberry Piを隠す行為は、許可されていない活動であり、プライバシー保護の手段ではありません。安全な代替策は、適法なゲストネットワーク、クライアントが承認した現場、または施設所有者の書面による同意を得て設置・回収する、記録済みのdrop nodeです。
{% endhint %}

## Travel router

travel routerは、ワークステーションを敵対的なローカルブロードキャストから隔離し、ファイアウォールを適用し、一貫した内部SSIDを提供し、VPNを自動再接続できます。**匿名性を確保するものではありません**。上流ネットワークにはその無線識別情報とトラフィックのタイミングが見え、VPN providerにはトンネルの送信元が見えます。

- サポートされているOpenWrt／vendor firmwareを使い、未使用のサービスを削除します。
- Ethernetまたは固有のパスワードを設定した専用の管理用SSIDから管理します。
- WAN側からの管理、UPnP、WPS、ファイル共有、予期しない受信トラフィックを無効にします。
- サポートされ、許可されている場合に限り、WAN MACをランダム化／プライベート化します。
- DNSとIPv6を含むVPNポリシーをrouterで適用し、トンネルが切断した場合は外部への通信をブロックします。
- スマートフォンのhotspot経由で接続したデバイスの通信が、スマートフォン上のVPNを必ず通るとは限りません。実際にテストしてください。

## Cellular、SIM、eSIM

Cellularは便利ですが、匿名ではありません。通信事業者は加入者／デバイス識別子と、ネットワーク接続から推定した位置情報を保持します。eSIMもモバイル契約の一種です。プリペイドでも未登録とは限りません。要件は国によって異なり、変更されます。<sup>[[13]](#references)</sup>

運用上の注意：

- 個人データの露出を減らす目的で、別のサポート対象デバイスを使います。架空の加入者を作るために使ってはいけません。
- 同じ場所にいることが脅威モデルに含まれる場合、「別の」デバイスを個人用スマートフォンと常に一緒に持ち歩かないでください。
- 使用しないCellular、Wi-Fi、Bluetooth、位置情報へのアクセスを無効にします。電源を切るほうが、UIの切り替えより強い無線の遮断になります。
- 機密性の高いトラフィックは承認済みのVPN/Tor経路に通します。ただし、通信事業者には契約／デバイスの位置とトンネルの接続先が知られることを理解してください。
- 登録要件とデータ保持ルールは、所管の規制当局または現地の弁護士に確認してください。「匿名SIMの国」などのオンラインリストを当てにしないでください。

## DNSとTLSメタデータ

- **DoH/DoT/DoQ**はクライアントとresolver間のDNSを暗号化し、ローカル環境での単純な読み取りや改ざんを防ぎます。ただし、resolverにはクエリと通信識別情報が見えます。信頼先を移すだけであり、匿名性を提供するものではありません。<sup>[[14]](#references)</sup>
- **ODoH**はproxyを追加することで、proxyとtargetが共謀しない限り、resolverにクライアントのIPが知られないようにします。トラフィック分析は明示的に対象外です。<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**は、クライアント、DNS、サーバーが対応している場合、TLS handshake内の内部サーバー名を保護できます。宛先IP、タイミング、通信量、endpointは引き続き見えます。<sup>[[16]](#references)</sup>
- VPNまたはTor環境が正しく設定されている場合、DNSはその環境でサポートされている経路を通るべきです。別のresolverを追加すると、新たな監視者が生まれたり、fingerprintが変化したりする可能性があります。

### 暗号化DNS／ECHの検証手順

1. DNSをVPN/Tor環境、OS、アプリケーションのどれが管理するか決めます。無関係なresolverを重ねるのではなく、意図した**1つ**の層で設定します。
2. 公開されているプライバシー／データ保持ポリシーを確認してresolverを選び、プラットフォームが対応している場合はstrictな暗号化モードを有効にします。opportunistic fallbackでは、気づかないうちに平文に戻ることがあります。
3. 自分が管理する権威DNSテストゾーンの一意なsubdomainを照会し、権威DNSのログで意図したrecursive resolverが確認できることを確かめます。
4. 許可を得たうえで、テスト対象デバイスのトラフィックだけをcaptureします。アクセスネットワークが平文DNSを読めないことを確認します。ただし、暗号化されたresolver／tunnelの接続先は見える点に注意してください。
5. 暗号化resolverがブロックされた場合や到達できない場合をテストします。合格条件は、選択したfail-closedの動作または文書化されたfallback動作であり、意図しない平文クエリではありません。
6. ECHについては、管理下にあるECH対応ホストを使い、クライアント／サーバーの診断情報を調べて、**inner** ClientHelloが受け入れられたことを確認します。HTTPSレコードが提示されただけでは、ECHが成功した証拠になりません。
7. ネットワーク変更後、captive portal利用後、ブラウザ更新後、VPN再接続後に再テストします。後任の管理者が迂回経路を作らないよう、DNS/ECHを管理するコンポーネントを記録します。

## Mixnet

NymやKatzenpostなどのmixnetは、固定サイズのpacket、遅延、順序変更、cover trafficを追加し、タイミング相関への耐性を高めます。こうした特性には遅延と帯域幅のコストがあり、独立した大規模導入の証拠も限られています。現在の一般消費者向けmixnetは、Tor/VPNの高速な代替手段や確実な代替手段ではなく、**発展途上で遅延の大きい選択肢**として扱ってください。<sup>[[17]](#references)</sup>

### 評価手順

1. 保守されているclientと、正確にサポートされているアプリケーションを確認します。文書化されていないproxyに、任意のブラウザ／システムトラフィックを無理に通さないでください。
2. entry、mix node、gateway、宛先、共謀に関する前提を含む、最新の脅威モデルを読みます。
3. 別のテスト用隔離環境に公式の署名済みソースからインストールし、自分が管理する無害なendpointだけを使います。
4. 配送遅延、メッセージサイズの上限、信頼性、再送、gatewayが利用できない場合の挙動を測定します。
5. ローカルのトラフィックと管理下のendpointを調べ、意図した経路と送信元を確認します。返信にも同じプライバシー設計が適用されるか確認します。
6. シャットダウン／障害時の動作をテストします。アプリケーションが警告なく直接インターネットアクセスにfallbackしてはいけません。
7. 速度だけを理由にcover trafficを無効にしたり、遅延を減らしたり、通常と異なる固定経路を選んだりしないでください。こうした変更は、提示されている匿名性モデルを無効にする可能性があります。
8. 特定の導入形態、独立した分析、運用上の信頼性が、想定される影響の重大さに見合うまでは、実験段階に留めます。

## ネットワーク接続前のチェックリスト

- [ ] 許可の範囲に、アクセスネットワーク、target、日程、送信元インフラが含まれている。
- [ ] endpointに無関係なIDや有効な同期セッションが含まれていない。
- [ ] IPv4、IPv6、DNS、再接続時の動作が計画と一致している。
- [ ] DHCP／ローカルサブネットへのroute注入を制御し、テストトラフィックが物理interfaceに移動しないようにできる。
- [ ] 宛先から見えるのが、想定したegressだけである。
- [ ] captive portalとhotspotの動作を、機密性の高いトラフィックを使わずにテスト済みである。
- [ ] ローカルの共有／検出とネットワークへの自動接続が無効になっている。
- [ ] 監視者の一覧と、残存するトラフィック相関リスクを受け入れている。
- [ ] providerのポリシー、データ保持、緊急連絡先が最新である。

知識を分割するrelay、経路を強制するワークロード、pluggable transport、onion service、I2P、使い捨てのリモートブラウザについては、[高度なネットワークプライバシーアーキテクチャ](advanced-network-privacy-architectures.md)を参照してください。



## References

- [1] [EFF — 適切なVPNの選び方](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — デバイスセキュリティガイダンス：Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Torが提供するプライバシーと匿名性の保護](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Torの簡単な紹介](https://spec.torproject.org/intro/)
- [5] [Tor Project — 他のブラウザでTorを使う](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browserのプラグインとアドオン](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Torのブロックを解除する](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — VPNとTor Browserを併用する](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — 公共Wi-Fiネットワークは安全か？](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — AppleデバイスでのWi-Fiプライバシー](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomizationの実装](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — セキュアな特権アクセスワークステーションの原則](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — SIM登録義務：政策と規制の観点](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNSプライバシーサービス運用者への推奨事項](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — 脅威モデル](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — トンネルの回避：ルーティングテーブルの悪用によるVPNクライアントトラフィックのleak](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision：攻撃者がルーティングベースのVPNの匿名性を暴き、VPN全体でleakを起こす方法](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Yggdrasil FAQ：Yggdrasilは匿名か？](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
