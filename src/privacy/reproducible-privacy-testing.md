# 재현 가능한 Privacy Testing

{{#include ../banners/hacktricks-training.md}}

Privacy setup은 연결될 때 완료되는 것이 아닙니다. 주장한 경계가 정상 사용, 장애, 복구 및 teardown 상황에서 테스트되었을 때 완료됩니다. 직접 소유하거나 검사 권한을 부여받은 infrastructure를 대상으로 테스트하세요. 공개 “leak test” 사이트는 또 다른 observer가 됩니다.

## 소규모의 권한이 부여된 테스트 환경 구축

이상적으로는 서로 다른 provider/network에 분리된 다음 세 가지 역할을 사용하세요:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
各テストの前に記録する:

- テスト ID、UTC の開始/終了時刻、operator、authorization;
- endpoint/OS/client のバージョンと configuration hash;
- 予想される IPv4、IPv6、DNS、TLS、account、payment、physical observations;
- inspection 対象のログと、それぞれの clock/time zone;
- pass/fail rule と teardown time.

最初に sensitive identity をテストしてはならない。synthetic account と、tester が所有する無害で一意な canary values を使用する。

## Network-path test

### 1. baseline を取得する

privacy path を有効にする前に、local routes と resolvers を記録する:
```bash
ip route
ip -6 route
resolvectl status
```
macOSでは、`route -n get default`、`netstat -rn -f inet6`、`scutil --dns`を使用します。出力は管理されたevidence storeにのみ保存してください。ローカル識別子が含まれる可能性があります。

### 2. 接続してroutingを検査する

VPN/Tor/workload namespaceを有効にしてから、管理対象の公開アドレスに対して選択されたrouteを確認します：
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
ドキュメントのアドレスをテストサーバーのアドレスに置き換えます。選択した interface/table が設計と一致していることを確認します。

### 3. 両端から観察する

管理下の endpoint の URL を設定し、一意の無害な path をリクエストします：
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
実際に tester が管理する domain、authenticated TLS、そして機密性のない path token を使用します。server log を確認して、以下を調べます。

- source address/ASN と想定される egress
- IPv4 と IPv6 のどちらか
- endpoint から確認できる Host/SNI の挙動
- user agent と application headers
- 正確な時刻と request reuse

分離されているはずの request に、`X-Forwarded-For`、一意な debug headers、または identity-bearing cookies を追加しないでください。

### 4. owned canary で DNS をテストする

query logs を管理できる authoritative test zone を設定します。compartment 経由で一意なランダム label を query します：
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
権威ログを確認します。通常、ログに記録されるのはクライアントではなく recursive resolver です。対象の resolver と、意図した VPN/Tor/application DNS 設計を比較します。ランダムな public DNS leak サイトは必要ありません。

### 5. fail-closed 動作をテストする

所有するエンドポイントを対象にした無害なリクエストループを維持し、その後 privacy path を停止します。ワークロードは物理インターフェースへ切り替わるのではなく、失敗しなければなりません。アドレスファミリーと DNS の両方を確認します。
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
次のタイミングで繰り返す：

- tunnel process のクラッシュ時
- Wi-Fi から Ethernet、または hotspot への切り替え時
- スリープ／復帰時
- DHCP renewal 時
- captive-portal state の変化時
- provider reconnect／key expiry 時

Linux namespace/container では、その tunnel を停止し、他の default route や resolver が存在しないことを確認する：
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Names and commands vary by deployment. コンソールで復旧できない限り、それらをリモートの本番ホストに貼り付けないでください。

### 6. ローカルソケットとパケットを調査する

許可を得たうえで、実際に通信しているプロセス/インターフェースを確認します：
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
`TEST_SERVER_IP` を明示的な所有アドレスに置き換え、無関係なユーザーを広範に捕捉しないでください。物理インターフェースにはトンネル/ブリッジの peer が見える必要があり、clear destination traffic は意図したレイヤーにのみ存在する必要があります。

## Tor and onion-service test

1. Tor Browser で Tor Project の接続チェックにアクセスし、Tor の使用を確認します。これを本人性の証明として扱わないでください。<sup>[[1]](#references)</sup>
2. 一意の canary を付けた所有 HTTPS endpoint にアクセスし、Tor exit が確認され、識別用 cookie がなく、標準の browser context であることを確認します。
3. **New Identity** を選択し、異なる canary で再アクセスして、想定どおりローカル状態が消去されたことを確認します。Exit IP の変更は保証されておらず、New Identity の目的でもありません。
4. onion service には Tor Browser 経由でのみアクセスします。認可済みの外部 scan で service host に public listener がないことを確認し、application response に public hostname/IP が含まれていないことを確認します。
5. origin の outbound DNS/HTTP、template、error page、email/webhook、third-party asset を調査します。直接 fetch があると、origin または operator account が開示される可能性があります。
6. client authorization が有効な場合、credential のないクリーンな Tor Browser では接続できず、credential を持つものでは接続できることを確認します。
7. test authorization key を rotate し、revoked client が onion identity を変更せずにアクセスできなくなることを確認します。

## Browser-compartment test

テストに必要なフィールドのみを記録し、retention period を短くした controlled page を作成します。personal compartment と privacy compartment について、以下を比較します。

- cookie/local storage/service worker と cache;
- browser sync/login state;
- language、time zone、screen/window dimensions、font;
- WebRTC/network candidate;
- permission と extension から見える modification;
- server 上の TLS/HTTP user-agent data。

Tor Browser を「より random」にしようとしないでください。pass condition は、personal browser との差を最大化することではなく、標準の anonymity set との類似性と personal state の不在です。

copy/paste、drag/drop、downloaded file の opening、password-manager suggestion、identity-provider button をテストします。これらは compartment 間の bridge になることがよくあります。

## Operating-system isolation test

### Tails

1. Persistent Storage のない session で、無害な file/canary から開始します。
2. 完全に shut down して reboot し、それが消えていることを確認します。
3. 必要な persistence category を 1 つだけ有効にして繰り返し、無関係な browser/application state が保持されていないことを確認します。
4. portal login 後に Unsafe Browser を sensitive activity に使用できないこと、および Tor application が正常に reconnect することを確認します。

### Whonix/Qubes

1. Gateway/net qube を停止し、Workstation/app qube が IPv4、IPv6、DNS に到達できないことを証明します。
2. 明示的に設定された inter-qube clipboard/file path のみを試行し、その他の shared-folder/device path が存在しないことを確認します。
3. disposable qube で無害な test document を開いて閉じ、その state が消えることを確認します。
4. vault qube に NetVM がなく、template/default change によって取得できないことを確認します。
5. test VM を snapshot/restore し、identity-bearing state が予期せず復元されていないか調査します。

## Communications metadata test

選択した各 messenger について、以下を行います。

1. controlled device 上に test 専用の participant を作成します。
2. registration に必要なもの（phone、app-store account、IP、push service、username、invitation）を記録します。
3. notification preview、linked desktop、wearable、backup を調査しながら、無害な message を 1 件送信します。
4. 独立した path で safety/security code を検証します。
5. receipt/push を無効にするか、Tor/local transport を一度に 1 つ有効にし、reliability/metadata の変化を観察します。
6. test backup を export または restore し、含まれる profile、contact、history を正確に記録します。
7. test device を紛失または revoke し、残りの participant に想定された key/device change が表示されることを確認します。

関係のない人に連絡したり、abusive traffic を生成したりしてテストしないでください。

## File-sanitization test

1. original を hash し、encrypted evidence storage に保存します。
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) の形式固有のプロセスを使用して、クリーニング済みのコピーを作成します。
3. メタデータインベントリを比較します：
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. disposable context で copy を render/open する。hidden content、attachments、links、forms、layers、thumbnails、visual identifiers を確認する。
5. staged copy のみを対象に、既知の canary author/email/path strings を検索する。
6. 最終出力を hash 化し、公開する exact file を second person に verify してもらう。

ExifTool の出力に存在しないことは anonymity の証明ではない。format internals、pixels、prose、distribution records は残る。

## Payment privacy test

許可された最小金額、または公式の test network/sandbox を使用する。

1. payer、payee/merchant、issuer/exchange、network/node、public ledger、accountant/controller それぞれについて、想定される view を記述する。
2. false identity を使わず、固有の test invoice/merchant context を作成する。
3. 一度だけ支払い、その後、該当する場合は **自分自身の** receipt、statement、merchant dashboard、wallet/node log、public-chain view を収集する。
4. amount、timestamp、address/token、account、IP/device、delivery、refund route が observer table と一致するか確認する。
5. Bitcoin では、wallet の coin-control view で address reuse、selected inputs、change、後続の consolidation を確認する。
6. shielded protocols では、実際の pool/path と viewing key が明らかにする内容を確認する。wallet の branding から privacy を推測しない。
7. e-cash/Taler では、少額で backup/recovery、refund、redemption をテストし、mint/exchange/federation boundary records を記録する。
8. virtual card/test credential を revoke し、その後の authorization が失敗することを確認する。同時に、正当な refund handling も理解した状態にする。
9. 必要な tax/authorization evidence を reconcile し、encrypted の状態で保持する。

“privacy test” として、circular transfers、threshold-splitting、fake purchases、疑わしい refunds を決して作成しない。

## Authorized red-team accountability drill

exercise の前に、tabletop と technical drill を実施する。

1. operator が、承認された各 source path から benign な canary を起動する。
2. blind testing を意図している場合、target SOC は operator identity を受け取らずに、検知した内容を記録する。
3. exercise controller が、escrowed map と signed job record から source → engagement → operator を特定する。
4. controller が emergency stop を送信し、operator と infrastructure owner が ROE の時間内に shutdown できることを実証する。
5. provider abuse に、正しい 24/7 contact と authorization reference が提供される。
6. evidence には、不要な payload content を保持せず、target、time、tool/job、operator が示される。
7. second operator が credential revocation と resource teardown を verify する。

SOC が personal/home infrastructure を簡単に確認できる **または** controller が source を迅速に attribute して stop できない場合、readiness review を fail とする。

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

- [1] [Tor Project — Connection check](https://check.torproject.org/)
- [2] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ and metadata guidance](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
{{#include ../banners/hacktricks-training.md}}
