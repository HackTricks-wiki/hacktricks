# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

これらは、macOS にリモートアクセスするための一般的なサービスです。\
これらのサービスは `System Settings` --> `Sharing`<sup>[[1]](#references)</sup> で有効化または無効化できます。

- **VNC**（“Screen Sharing” と呼ばれます）（tcp:5900）
- **SSH**（“Remote Login” と呼ばれます）（tcp:22）
- **Apple Remote Desktop**（ARD）、または “Remote Management”（tcp:3283、tcp:5900）
- **AppleEvent**（“Remote Apple Event” と呼ばれます）（tcp:3031）

次を実行して、有効になっているものがあるか確認します。
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### sharing configuration をローカルで Enumerating

Mac 上で **local code execution** をすでに取得している場合は、listening sockets だけでなく、**configured state** を確認します。`systemsetup` と `launchctl` では通常、サービスが管理上有効になっているかどうかを確認でき、`kickstart` と `system_profiler` では実際の ARD/Sharing configuration の確認に役立ちます。
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) は、macOS 向けにカスタマイズされた [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) の拡張版で、追加機能を提供します。ARD における注目すべき脆弱性は、control screen password の認証方式にあります。この方式では password の最初の 8 文字しか使用しないため、デフォルトの rate limit が存在せず、Hydra や [GoRedShell](https://github.com/ahhh/GoRedShell/) などのツールによる [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) を受けやすくなっています。<sup>[[2]](#references)</sup>

脆弱なインスタンスは、**nmap** の `vnc-info` script を使用して特定できます。`VNC Authentication (2)` をサポートするサービスは、password が 8 文字に切り詰められるため、特に brute force attacks の影響を受けやすくなっています。

privilege escalation、GUI access、user monitoring など、さまざまな administrative tasks のために ARD を有効化するには、次の command を使用します。
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARDは、監視、共有制御、完全制御など、柔軟な制御レベルを提供し、ユーザーパスワードの変更後もセッションが維持されます。Unix commandsを直接送信でき、管理者ユーザーの場合はrootとして実行できます。Task schedulingとRemote Spotlight searchも注目すべき機能であり、複数のマシンにわたって機密ファイルをリモートから低負荷で検索できます。

オペレーターの観点では、**Monterey 12.1+では、管理対象フリートにおけるremote-enablement workflowsが変更されました**。対象のMDMをすでに制御している場合、新しいシステムでremote desktop機能を有効化するには、Appleの`EnableRemoteDesktop` commandが最も簡潔な方法であることが多いです。ホスト上にすでにfootholdがある場合、コマンドラインからARD privilegesを確認または再設定するには、引き続き`kickstart`が役立ちます。

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

最近の`screensharingd` researchにより、Apple Screen Sharingは常にclassic VNC authだけを使用するわけではないことが明らかになりました。新しいbuildでは**RFB `003.889`**を使用し、**security type `36`**をadvertiseします。この場合、最初に**SRP**でauthenticateし、`ccsrp_server_verify_session`が成功した後にのみ**ChaCha20-Poly1305**がinstallされます。公開されたwrite-upでは、このbugは**macOS Tahoe 26.6**（**July 27, 2026**）で修正されたと報告されています。<sup>[[8]](#references)[[9]](#references)</sup>

覚えておくと役立つパターンは、**stale-status parser bypass**です。4-byte length readが成功した後は、oversized/error branchがすべて新しいerrorを返す必要があります。影響を受けるbuildでは、big-endian SRP frame lengthが**`>= 32768`**になると、reject pathが直前の`NetBufferRead` success（`0`）を再利用します。そのため、password proofが実行されず、transport cryptoもinstallされていないにもかかわらず、callerはsessionをauthenticatedとして設定します。未読のbytesはshared socket bufferに残るため、attackerは**malformed SRP dataとpost-auth RFB messagesを同じTCP burst内でpipeline**し、それらを**cleartext authenticated traffic**としてparseさせることができます。<sup>[[8]](#references)</sup>

bypass後は、Apple独自の**file-copy** message **`0x22`**が、`screensharingd`がrootとして実行されるため、**root file read/write primitive**になります。<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: 任意ファイル読み取り
- `kind=2` / `StartFileReceive`: 任意ファイル書き込み
- 異なる `sid` 値により、1つの接続で複数のトランザクションを pipeline 処理できる
- `kind=101` (`NewItem`) では、通常ファイルの場合は byte `14` / `arg[0]` を `0x01` に設定し、payload offset `+42` を **ゼロ以外の big-endian ファイルサイズ** に、payload offset `+0x5a` を目的の Unix mode（crontab を対象にする場合は `0600`）に設定する

書き込み可能なパスを利用した興味深い post-write pivot には、**`/etc/sudoers.d/`**、**`/etc/zshenv`**、**`/Library/LaunchDaemons/`**、**`/var/root/.ssh/authorized_keys`** がある。**SIP は auth bypass や root file read を阻止しない**が、**`/var/at`** など一部の書き込み先はブロックするため、cron ベースの実行は SIP が無効な場合にのみ機能する。デフォルトで SIP が有効なホストでは、即時の code execution ではなく、**「privileged auto-consumed files への root file write」**として考えるべきである。<sup>[[8]](#references)</sup>

同じ research におけるもう1つの SRP の落とし穴として、server は **`A mod N != 0`**（RFC 5054 準拠）を検証する必要があり、単に **`A > 0`** を検証するだけでは不十分である。**`A = N`** を受け入れると、shared secret をゼロに強制でき、password verification が損なわれる可能性がある。<sup>[[8]](#references)[[10]](#references)</sup>

**Detection ideas**

- 最初の SRP frame length が **`>= 32768`** である Security type `36` の sessions
- 成功した SRP proof / cipher install の前に、cleartext **`0x22`** file-copy traffic の処理を開始する sessions
- **TCP/5900** に対する短時間で終了する retry の繰り返しと、1つの burst 内における複数の file-copy `sid` 値
- Screen Sharing exposure 後における **`/etc/zshenv`**、**`/etc/sudoers.d/*`**、**`/Library/LaunchDaemons/*.plist`**、または **`/var/root/.ssh/authorized_keys`** の予期しない作成

### Pentesting Remote Apple Events (RAE / EPPC)

Apple は、modern System Settings ではこの feature を **Remote Application Scripting** と呼んでいる。その内部では、`com.apple.AEServer` service を介して **TCP/3031** 上の **Apple Event Manager** を **EPPC** 経由で remote に公開している。Palo Alto Unit 42 は、valid credentials と有効化された RAE service があれば、operator が remote Mac 上の scriptable applications を操作できるため、これを実用的な **macOS lateral movement** primitive として改めて取り上げた。<sup>[[6]](#references)</sup>

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
対象上ですでに admin/root 権限を取得しており、有効化したい場合:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
別のMacからの基本的な接続テスト：
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
実際には、この悪用ケースはFinderに限定されません。必要なApple eventsを受け付ける**スクリプト対応アプリケーション**は、いずれもリモート攻撃対象となるため、内部のmacOSネットワークで認証情報が窃取された後のRAEは特に興味深いものになります。

#### 最近のScreen-Sharing / ARDの脆弱性（2023～2025年）

| 年 | CVE | コンポーネント | 影響 | 修正対象 |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|セッションの不正なレンダリングにより、*誤った*デスクトップやウィンドウが送信され、機密情報が漏洩する可能性|macOS Sonoma 14.2.1（2023年12月） <sup>[[3]](#references)</sup>|
|2024|CVE-2024-44248|Screen Sharing Server|状態管理の問題により、Screen Sharingへのアクセス権を持つユーザーが**別のユーザーの画面**を閲覧できる可能性|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1（2024年10～12月） <sup>[[7]](#references)</sup>|

**Hardeningのヒント**

* 厳密に必要でない場合は、*Screen Sharing*/*Remote Management*を無効にする。
* macOSを完全にパッチ適用済みの状態に保つ（Appleは通常、直近3つのメジャーリリース向けにセキュリティ修正を提供します）。
* **Strong Password**を使用し、可能な場合は*「VNC viewers may control screen with password」*オプションを**無効**にする。
* TCP 5900/3283をInternetに公開するのではなく、サービスをVPNの背後に配置する。
* Application Firewallルールを追加して、`ARDAgent`をローカルサブネットに制限する：

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Appleが設計したテクノロジーであるBonjourを使用すると、**同じネットワーク上のデバイスが、互いに提供しているサービスを検出できます**。Rendezvous、**Zero Configuration**、またはZeroconfとしても知られるBonjourは、デバイスがTCP/IPネットワークに参加し、**IPアドレスを自動的に選択**して、自身のサービスを他のネットワークデバイスにブロードキャストできるようにします。

Bonjourが提供するZero Configuration Networkingにより、デバイスは次のことが可能になります。

- DHCPサーバーがない場合でも、**IPアドレスを自動的に取得**する。
- DNSサーバーを必要とせずに、**名前からアドレスへの変換**を実行する。
- ネットワーク上で利用可能な**サービスを検出**する。

Bonjourを使用するデバイスは、**169.254/16の範囲からIPアドレスを自己割り当て**し、ネットワーク上でそのアドレスが一意であることを確認します。Macはこのサブネット用のルーティングテーブルエントリを保持しており、`netstat -rn | grep 169`で確認できます。

DNSには、Bonjourは**Multicast DNS（mDNS）プロトコル**を利用します。mDNSは**ポート5353/UDP**上で動作し、**マルチキャストアドレス224.0.0.251**を宛先として、**標準的なDNSクエリ**を使用します。この方法により、ネットワーク上で待ち受けているすべてのデバイスがクエリを受信して応答できるため、それぞれのレコードを更新できます。

ネットワークに参加すると、各デバイスは通常**.local**で終わる名前を自動的に選択します。この名前はホスト名から生成される場合もあれば、ランダムに生成される場合もあります。

ネットワーク内でのサービス検出は、**DNS Service Discovery（DNS-SD）**によって実現されます。DNS SRVレコードの形式を利用するDNS-SDは、**DNS PTRレコード**を使用して複数のサービスを一覧表示できるようにします。特定のサービスを探しているクライアントは、`<Service>.<Domain>`のPTRレコードを要求します。そのサービスが複数のホストから提供されている場合、応答として`<Instance>.<Service>.<Domain>`形式のPTRレコード一覧を受け取ります。

`dns-sd`ユーティリティは、**ネットワークサービスの検出および広告**に使用できます。使用例を以下に示します。

### SSH Servicesの検索

ネットワーク上のSSH Servicesを検索するには、次のコマンドを使用します。
```bash
dns-sd -B _ssh._tcp
```
このコマンドは \_ssh.\_tcp サービスの browsing を開始し、timestamp、flags、interface、domain、service type、instance name などの詳細を出力します。

### HTTP Service の Advertising

HTTP service を advertising するには、次のコマンドを使用します。
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
このコマンドは、パス `/index.html` を使用する、ポート 80 上の「Index」という名前の HTTP service を登録します。

次に、network 上の HTTP service を検索するには:
```bash
dns-sd -B _http._tcp
```
サービスが開始されると、その存在をマルチキャストしてサブネット上のすべてのデバイスに可用性を通知します。これらのサービスに関心のあるデバイスは、リクエストを送信する必要はなく、これらの通知をリッスンするだけで済みます。

よりユーザーフレンドリーなインターフェースとして、Apple App Storeで入手できる **Discovery - DNS-SD Browser** appを使用すると、ローカルネットワーク上で提供されているサービスを可視化できます。

または、`python-zeroconf` libraryを使用して、サービスを参照および検出する custom scriptsを作成できます。[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) scriptは、`_http._tcp.local.` services用のservice browserを作成し、追加または削除されたservicesを出力する方法を示しています：
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### macOS固有のBonjour hunting

macOSネットワークでは、Bonjourはターゲットに直接触れることなく**remote administration surfaces**を見つける最も簡単な方法であることが多い。Apple Remote Desktop自体もBonjourを通じてクライアントを検出できるため、同じdiscovery dataが攻撃者にも役立つ。
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
より広範な **mDNS spoofing、impersonation、cross-subnet discovery** の technique については、専用ページを確認してください：

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### ネットワーク経由での Bonjour の Enumerating

* **Nmap NSE** – 単一の host が advertise している services を discover：

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` script は `_services._dns-sd._udp.local` query を送信し、その後、advertise されている各 service type を enumerate します。

* **mdns_recon** – *misconfigured* mDNS responder を探しながら範囲全体を scan する Python tool（unicast query に応答する device を見つけるのに有用。subnet/WAN を越えて到達可能な device の discovery に利用できます）：

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

これにより、local link の外部で Bonjour 経由の SSH を expose している host が返されます。

### Security considerations と最近の vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder* の logic error により、crafted packet で **denial-of-service** を trigger できた|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) <sup>[[4]](#references)</sup>|
|2025|CVE-2025-31222|High|*mDNSResponder* の correctness issue が **local privilege escalation** に悪用される可能性があった|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) <sup>[[5]](#references)</sup>|

**Mitigation guidance**

1. UDP 5353 を *link-local* scope に制限する – wireless controller、router、host-based firewall で block または rate-limit します。
2. service discovery を必要としない system では Bonjour を完全に disable します：

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Bonjour を内部で必要とする一方、network boundary を決して越えさせてはならない環境では、*AirPlay Receiver* profile restriction (MDM) または mDNS proxy を使用します。
4. **System Integrity Protection (SIP)** を enable し、macOS を up to date に保ちます – 上記の両 vulnerabilities は迅速に patch されましたが、完全な protection には SIP が enable であることが必要でした。

### Bonjour の Disabling

Security 上の懸念やその他の理由で Bonjour を disable する場合、以下の command を使用して off にできます：
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考文献

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [3] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [4] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [5] [NVD – CVE-2025-31222](https://nvd.nist.gov/vuln/detail/CVE-2025-31222)
- [6] [Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - About the security content of macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - About the security content of macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Using the Secure Remote Password (SRP) Protocol for TLS Authentication](https://www.rfc-editor.org/rfc/rfc5054)
- [11] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)

{{#include ../../banners/hacktricks-training.md}}
