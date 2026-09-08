# 再現可能な Privacy Testing

Privacy setup は接続できた時点では完成していません。通常利用、障害、復旧、teardown の下で、主張した境界がテストされて初めて完成します。自分が所有している、または検査を許可されているインフラを対象にテストしてください。公開の「leak test」サイトは別の観測者になります。

## 小規模な許可済みテスト環境を構築する

理想的には別々の provider/network 上で、次の3つの役割を用意します：
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
各テストの前に、以下を記録する。

- test ID、UTCでの開始時刻と終了時刻、operatorおよびauthorization；
- endpoint/OS/clientのバージョンと設定ハッシュ；
- 予想されるIPv4、IPv6、DNS、TLS、account、paymentおよび物理的な観測結果；
- 検査するログ、その時計およびタイムゾーン；
- pass/failルールとteardown時刻。

機密性の高いidentityを最初にテストしてはならない。synthetic accountと、testerが所有する無害で一意なcanary値を使用する。

## ネットワーク経路テスト

### 1. ベースラインを取得する

privacy pathを有効にする前に、ローカルのrouteとresolverを記録する：
```bash
ip route
ip -6 route
resolvectl status
```
macOS では `route -n get default`、`netstat -rn -f inet6`、および `scutil --dns` を使用します。出力は管理された証拠ストアにのみ保存してください。ローカル識別子が含まれる可能性があります。

### 2. 接続して routing を確認する

VPN/Tor/workload namespace を有効にしてから、管理対象のパブリックアドレスに対して選択された route を確認します：
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
ドキュメントのアドレスをテストサーバーのアドレスに置き換えます。選択したインターフェース/テーブルが設計と一致していることを確認します。

### 3. 両端から観察する

所有するエンドポイントの URL を設定し、一意で無害なパスをリクエストします：
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
実際に tester が管理する domain、authenticated TLS、および機密性のない path token を使用します。サーバーログを確認し、以下を調べます。

- source address/ASN と想定される egress
- IPv4 と IPv6 のどちらか
- endpoint で確認できる Host/SNI の挙動
- user agent と application headers
- 正確な時刻と request の再利用

分離されているはずの request に、`X-Forwarded-For`、一意な debug headers、または identity-bearing cookies を追加しないでください。

### 4. owned canary で DNS をテストする

query logs を管理できる authoritative test zone を設定します。compartment 経由で一意のランダムな label を query します。
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
権威ログを確認します。通常、権威ログから見えるのはクライアントとは限らず、recursive resolver です。その resolver を、想定している VPN/Tor/application DNS の設計と比較します。ランダムな public DNS leak サイトは必要ありません。

### 5. fail-closed 動作をテストする

管理下のエンドポイントを対象にした無害なリクエストループを実行し続け、その後 privacy path を停止します。workload は物理インターフェースへ切り替えるのではなく、失敗しなければなりません。両方の address family と DNS を確認します。
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
以下の状況で繰り返す：

- tunnel process の crash；
- Wi-Fi から Ethernet への切り替え、または hotspot への切り替え；
- sleep/wake；
- DHCP renewal；
- captive-portal state；
- provider reconnect/key expiry。

Linux namespace/container では、その tunnel を停止し、他の default route や resolver が存在しないことを確認する：
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
名前やコマンドは deployment ごとに異なります。コンソールから復旧できないリモートの production host には貼り付けないでください。

### 6. ローカルソケットとパケットを調査する

許可を得たうえで、実際に通信しているプロセスやインターフェースを確認します：
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
`TEST_SERVER_IP` を明示的な所有アドレスに置き換え、無関係なユーザーを広範に捕捉しないようにします。物理インターフェースにはトンネル/bridge peer が見える一方、平文の宛先トラフィックは意図したレイヤーにのみ存在する必要があります。

## Tor と onion-service のテスト

1. Tor Browser で Tor Project の接続チェックにアクセスし、Tor の使用を確認します。これを身元の証明として扱わないでください。<sup>[[1]](#references)</sup>
2. 固有の canary を付けて所有する HTTPS endpoint にアクセスし、Tor exit が認識され、識別用 cookie がなく、標準的な browser context であることを確認します。
3. **New Identity** を選択し、別の canary で再アクセスして、想定どおりにローカル状態が消去されたことを確認します。Exit IP の変更は保証されておらず、New Identity の目的でもありません。
4. onion service には Tor Browser 経由のみでアクセスします。認証済みの外部 scan で service host に public listener がないことを確認し、application response に public hostname/IP が含まれていないことを確認します。
5. origin の outbound DNS/HTTP、template、error page、email/webhook、third-party asset を調査します。直接 fetch を行うと、origin や operator account が漏洩する可能性があります。
6. client authorization が有効な場合、credential のないクリーンな Tor Browser では接続できず、credential のあるものでは接続できることを確認します。
7. テスト用 authorization key を rotate し、revoked client が onion identity を変更せずにアクセスできなくなることを確認します。

## Browser-compartment のテスト

テストに必要なフィールドのみを記録し、保持期間を短くした管理対象のページを作成します。personal compartment と privacy compartment について、以下を比較します。

- cookie/local storage/service worker と cache
- browser sync/login state
- language、time zone、screen/window dimensions、font
- WebRTC/network candidate
- permission と extension から確認できる変更
- server 上の TLS/HTTP user-agent data

Tor Browser を「よりランダム」にしようとしないでください。合格条件は、personal browser との差を最大化することではなく、標準的な anonymity set との類似性と personal state が存在しないことです。

copy/paste、drag/drop、download した file の opening、password-manager suggestion、identity-provider button をテストします。これらは compartment 間の橋渡しになることがよくあります。

## Operating-system isolation のテスト

### Tails

1. Persistent Storage のない session で、無害な file/canary から開始します。
2. 完全に shutdown し、reboot して、それが消えていることを確認します。
3. 必須の persistence category を1つだけ有効にして繰り返し、無関係な browser/application state が保持されていないことを確認します。
4. portal login 後に Unsafe Browser を sensitive activity に使用できないこと、および Tor application が正常に reconnect することを確認します。

### Whonix/Qubes

1. Gateway/net qube を停止し、Workstation/app qube が IPv4、IPv6、DNS に到達できないことを証明します。
2. 明示的に設定された inter-qube clipboard/file path のみを試行し、その他の shared-folder/device path が存在しないことを確認します。
3. disposable qube で無害なテスト document を開き、閉じて、その state が消えることを確認します。
4. vault qube に NetVM がなく、template/default の変更によって取得できないことを確認します。
5. テスト VM を snapshot/restore し、identity-bearing state が予期せず復元されないか調査します。

## Communications metadata のテスト

選択した各 messenger について、以下を行います。

1. 管理対象の device 上に、テスト専用の participant を作成します。
2. registration に必要なもの（phone、app-store account、IP、push service、username、invitation）を記録します。
3. notification preview、linked desktop、wearable、backup を調査しながら、無害な message を1件送信します。
4. 独立した経路で safety/security code を確認します。
5. receipt/push を無効化するか、Tor/local transport を一度に1つ有効化し、reliability/metadata の変化を観察します。
6. テスト backup を export または restore し、含まれる profile、contact、history を正確に記録します。
7. テスト device を紛失/revoke し、残りの participant に想定された key/device change が表示されることを確認します。

関係のない人に連絡したり、abusive traffic を生成したりしてテストしないでください。

## File-sanitization のテスト

1. 元の file を hash し、暗号化された evidence storage に保存します：
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) に記載されている形式固有のプロセスを使用して、クリーニング済みのコピーを作成します。
3. メタデータのインベントリを比較します：
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. 使い捨てのコンテキストでコピーをレンダリング/開きます。隠しコンテンツ、添付ファイル、リンク、フォーム、レイヤー、サムネイル、視覚的な識別子を確認します。
5. ステージング済みのコピーだけを検索し、既知の canary の作成者名/メールアドレス/パス文字列を探します。
6. 最終出力をハッシュ化し、公開される正確なファイルを別の担当者に検証してもらいます。

ExifTool の出力に存在しないことは、匿名性の証明ではありません。フォーマット内部、ピクセル、文章、配布記録は残ります。

## Payment privacy test

許可された最小金額、または公式の test network/sandbox を使用します。

1. payer、payee/merchant、issuer/exchange、network/node、public ledger、accountant/controller それぞれについて、想定される表示内容を記述します。
2. 偽の身元情報を使わず、一意の test invoice/merchant コンテキストを作成します。
3. 1回だけ支払い、その後、**自分自身の** receipt、statement、merchant dashboard、wallet/node log、該当する場合は public-chain view を収集します。
4. 金額、timestamp、address/token、account、IP/device、delivery、refund route が observer table と一致するか確認します。
5. Bitcoin では、wallet の coin-control view で address reuse、selected inputs、change、後続の consolidation を確認します。
6. shielded protocol では、実際の pool/path と viewing key が明らかにする内容を確認します。wallet の branding から privacy を推測しないでください。
7. e-cash/Taler では、少額で backup/recovery、refund、redemption をテストし、mint/exchange/federation の境界における記録を文書化します。
8. virtual card/test credential を revoke し、正当な refund 処理を理解した状態で、後続の authorization が失敗することを確認します。
9. 必要な tax/authorization evidence を照合し、暗号化して保持します。

「privacy test」として、循環送金、threshold-splitting、偽の購入、疑わしい refund を決して作成しないでください。

## Authorized red-team accountability drill

exercise の前に、tabletop と technical drill を実施します。

1. operator が、承認済みの各 source path から benign canary を1つずつ起動します。
2. blind testing を意図している場合、target SOC は operator の身元を受け取らずに、検知した内容を記録します。
3. exercise controller は、escrow された map と署名済みの job record から source → engagement → operator を特定します。
4. controller が emergency stop を送信し、operator と infrastructure owner が ROE の制限時間内に shutdown を実演します。
5. provider abuse には、正しい 24/7 contact と authorization reference が提供されます。
6. evidence には、不要な payload content を保持せず、target、time、tool/job、operator が示されます。
7. 別の operator が credential revocation と resource teardown を検証します。

SOC が personal/home infrastructure を簡単に確認できる場合、**または** controller が source を迅速に帰属させて停止できない場合は、readiness review を不合格とします。

## Test record template
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — 接続確認](https://check.torproject.org/)
- [2] [WireGuard — Routing と Network Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ と metadata guidance](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Information Security Testing and Assessment の Technical Guide](https://csrc.nist.gov/pubs/sp/800/115/final)
