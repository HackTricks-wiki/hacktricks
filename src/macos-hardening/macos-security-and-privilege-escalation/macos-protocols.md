# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

macOSへリモートアクセスするための一般的なサービスです。\
これらのサービスは、`System Settings` --> `Sharing` で有効化または無効化できます。

- **VNC**、「Screen Sharing」と呼ばれる（tcp:5900）
- **SSH**、「Remote Login」と呼ばれる（tcp:22）
- **Apple Remote Desktop** (ARD)、または「Remote Management」（tcp:3283、tcp:5900）
- **AppleEvent**、「Remote Apple Event」と呼ばれる（tcp:3031）

以下を実行して、有効になっているものがあるか確認します：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### ローカルで共有設定を列挙する

Mac 上ですでに local code execution を取得している場合は、リスニングソケットだけでなく、**設定された状態を確認**してください。`systemsetup` と `launchctl` では通常、サービスが管理上有効になっているかどうかを確認でき、`kickstart` と `system_profiler` では実際の ARD/Sharing 設定を確認できます。
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD)は、macOS向けに調整され、追加機能を提供する[Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing)の拡張版です。ARDにおける注目すべき脆弱性は、control screen passwordの認証方式にあります。この方式ではパスワードの最初の8文字しか使用しないため、デフォルトのrate limitが存在せず、Hydraや[GoRedShell](https://github.com/ahhh/GoRedShell/)などのツールを使った[brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)に対して脆弱です。<sup>[[3]](#references)</sup>

脆弱なインスタンスは、**nmap**の`vnc-info`スクリプトを使用して特定できます。`VNC Authentication (2)`をサポートするサービスは、8文字のパスワード切り捨てにより、特にbrute force attacksの影響を受けやすくなっています。

privilege escalation、GUI access、user monitoringなどのさまざまな管理タスク用にARDを有効化するには、次のコマンドを使用します：
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARDは、監視、共有制御、完全制御など、柔軟な制御レベルを提供し、ユーザーのパスワード変更後もセッションが維持されます。Unixコマンドを直接送信でき、管理者ユーザーの場合はrootとして実行できます。タスクスケジューリングとRemote Spotlight検索も注目すべき機能であり、複数のマシン上にある機密ファイルをリモートから低負荷で検索できます。

オペレーターの観点では、管理対象フリートにおいて **Monterey 12.1+ changed remote-enablement workflows** です。対象のMDMをすでに制御している場合、新しいシステムでリモートデスクトップ機能を有効化するには、Appleの `EnableRemoteDesktop` コマンドが最も簡潔な方法になることが多くあります。ホスト上にすでにfootholdがある場合、コマンドラインからARDの権限を確認または再設定するには、引き続き `kickstart` が便利です。

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

最近の `screensharingd` researchでは、Apple Screen Sharingが常に従来のVNC authだけを使用するとは限らないことが明らかになりました。新しいbuildでは **RFB `003.889`** を使用し、**security type `36`** をadvertiseします。この場合、最初に **SRP** がauthenticationを行い、`ccsrp_server_verify_session` が成功した後にのみ **ChaCha20-Poly1305** がインストールされます。公開されたwrite-upでは、このbugは **macOS Tahoe 26.6**（**July 27, 2026**）で修正されたと報告されています。<sup>[[8]](#references)[[9]](#references)</sup>

覚えておくと便利なパターンは、**stale-status parser bypass** です。4バイトのlength readが成功した後は、oversized/error branchのすべてが新しいerrorを返さなければなりません。影響を受けるbuildでは、big-endianのSRP frame length **`>= 32768`** によってrejection pathが直前の `NetBufferRead` のsuccess（`0`）を再利用するため、password proofが実行されず、transport cryptoもインストールされていないにもかかわらず、callerはsessionをauthenticatedとして設定します。未読のbytesはshared socket bufferに残るため、attackerは **malformed SRP dataとpost-auth RFB messagesを同じTCP burst内でpipeline** でき、それらを **cleartext authenticated traffic** としてparseさせることができます。<sup>[[8]](#references)</sup>

bypass後は、Apple独自の **file-copy** message **`0x22`** が **root file read/write primitive** になります。これは `screensharingd` がrootとして実行されるためです。<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: 任意ファイル読み取り
- `kind=2` / `StartFileReceive`: 任意ファイル書き込み
- 異なる `sid` 値により、1つの接続で複数のトランザクションを pipeline 処理できる
- `kind=101`（`NewItem`）では、通常ファイルの場合は byte `14` / `arg[0]` を `0x01` に設定し、payload offset `+42` を **ゼロ以外の big-endian ファイルサイズ**に、payload offset `+0x5a` を目的の Unix mode（crontab を対象にする場合は `0600`）に設定する

書き込み可能なパスを利用した興味深い post-write pivot には、**`/etc/sudoers.d/`**、**`/etc/zshenv`**、**`/Library/LaunchDaemons/`**、**`/var/root/.ssh/authorized_keys`** がある。**SIP は auth bypass や root file read を阻止しない**が、**`/var/at`** など一部の書き込み先はブロックするため、cron ベースの実行は SIP が無効な場合にのみ機能する。デフォルトで SIP が有効な host では、即時の code execution ではなく、**「privileged auto-consumed files への root file write」**として考えるべきである。<sup>[[8]](#references)</sup>

同じ research におけるもう1つの SRP の落とし穴は、server が **`A mod N != 0`**（RFC 5054 準拠）を検証しなければならず、単に **`A > 0`** を検証するだけでは不十分な点である。**`A = N`** を受け入れると、shared secret をゼロに強制でき、password verification が損なわれる可能性がある。<sup>[[8]](#references)[[10]](#references)</sup>

**Detection ideas**

- 最初の SRP frame length が **`>= 32768`** である Security type `36` の session
- 成功した SRP proof / cipher install の前に、cleartext **`0x22`** file-copy traffic の処理を開始する session
- **TCP/5900** に対する短時間で終了する retry の繰り返し、および1回の burst 内に複数の file-copy `sid` 値が存在すること
- Screen Sharing exposure の後に、予期しない **`/etc/zshenv`**、**`/etc/sudoers.d/*`**、**`/Library/LaunchDaemons/*.plist`**、または **`/var/root/.ssh/authorized_keys`** が作成されること

### Pentesting Remote Apple Events (RAE / EPPC)

Apple は modern System Settings で、この機能を **Remote Application Scripting** と呼んでいる。内部では、`com.apple.AEServer` service を介して **TCP/3031** 上の **EPPC** 経由で **Apple Event Manager** を remote に公開している。Palo Alto Unit 42 は、valid credentials と有効な RAE service があれば operator が remote Mac 上の scriptable applications を操作できるため、これを実用的な **macOS lateral movement** primitive として改めて取り上げた。<sup>[[6]](#references)</sup>

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
すでにターゲット上で admin/root 権限を取得しており、それを有効にしたい場合：
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
別のMacからの基本的な接続テスト：
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
実際には、この abuse case は Finder に限定されません。必要な Apple events を受け付ける **scriptable application** は、いずれも remote attack surface となるため、内部 macOS ネットワーク上で credential theft が発生した後の RAE は特に興味深い対象となります。

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Incorrect session rendering could cause the *wrong* desktop or window to be transmitted, resulting in leakage of sensitive information|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|A user with screen sharing access may be able to view **another user's screen** because of a state-management issue|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* 必須でない場合は、*Screen Sharing*/*Remote Management* を無効にする。
* macOS を完全に patch 適用済みの状態に保つ（Apple は通常、直近 3 つの major release に対して security fixes を提供する）。
* **Strong Password** を使用し、可能な場合は *“VNC viewers may control screen with password”* オプションを **disabled** にする。
* TCP 5900/3283 を Internet に公開するのではなく、VPN の背後に service を配置する。
* Application Firewall rule を追加し、`ARDAgent` を local subnet に制限する。

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Apple が設計した technology である Bonjour は、**同じ network 上の devices が互いに提供している services を検出できるようにします**。Rendezvous、**Zero Configuration**、または Zeroconf としても知られており、device が TCP/IP network に参加し、**自動的に IP address を選択**して、その services を他の network devices に broadcast できるようにします。

Bonjour が提供する Zero Configuration Networking により、devices は次のことが可能になります。

- **DHCP server がない場合でも IP Address を自動的に取得する。**
- DNS server を必要とせずに **name-to-address translation** を実行する。
- network 上で利用可能な **services を検出する**。

Bonjour を使用する devices は、**169.254/16 range の IP address** を自動的に割り当て、network 上でその一意性を確認します。Mac はこの subnet 用の routing table entry を保持しており、`netstat -rn | grep 169` で確認できます。

DNS では、Bonjour は **Multicast DNS (mDNS) protocol** を利用します。mDNS は **port 5353/UDP** 上で動作し、**multicast address 224.0.0.251** を対象として **standard DNS queries** を使用します。この方法により、network 上で待ち受けているすべての devices が queries を受信して応答できるため、records の更新が容易になります。

network に参加すると、各 device は自分自身の name を選択します。通常は **.local** で終わり、hostname を元にするか、ランダムに生成されます。

network 内での service discovery は **DNS Service Discovery (DNS-SD)** によって実現されます。DNS SRV records の format を利用する DNS-SD は、**DNS PTR records** を使用して複数の services を一覧表示できるようにします。特定の service を探している client は、`<Service>.<Domain>` の PTR record を要求します。その service が複数の hosts から利用可能な場合、`<Instance>.<Service>.<Domain>` 形式の PTR records の list が返されます。

`dns-sd` utility は、**network services の discovery と advertising** に使用できます。使用例を以下に示します。

### Searching for SSH Services

network 上の SSH services を検索するには、次の command を使用します。
```bash
dns-sd -B _ssh._tcp
```
このコマンドは \_ssh.\_tcp サービスの browsing を開始し、timestamp、flags、interface、domain、service type、instance name などの詳細を出力します。

### HTTP Service の Advertising

HTTP service を advertising するには、次を使用できます:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
このコマンドは、パス `/index.html` を使用する、ポート 80 上の「Index」という名前の HTTP service を登録します。

次に、network 上の HTTP service を検索するには:
```bash
dns-sd -B _http._tcp
```
サービスが開始されると、存在をマルチキャストしてサブネット上のすべてのデバイスに利用可能であることを通知します。これらのサービスに関心のあるデバイスは、リクエストを送信する必要はなく、これらの通知を単にリッスンします。

よりユーザーフレンドリーなインターフェースとして、Apple App Storeで入手できる **Discovery - DNS-SD Browser** アプリを使用すると、ローカルネットワーク上で提供されているサービスを可視化できます。

また、`python-zeroconf` libraryを使用してサービスをbrowseおよびdiscoverするcustom scriptsを作成することもできます。[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) scriptは、`_http._tcp.local.` services用のservice browserを作成し、追加または削除されたservicesを出力する方法を示しています。
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
### macOS固有のBonjour探索

macOSネットワークでは、Bonjourはターゲットに直接触れることなく**リモート管理サーフェス**を見つける最も簡単な方法であることが多い。Apple Remote Desktop自体もBonjourを通じてクライアントを検出できるため、同じ検出データが攻撃者にも役立つ。
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
より広範な **mDNS spoofing、impersonation、cross-subnet discovery** の手法については、専用ページを確認してください：

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### ネットワーク経由で Bonjour を列挙する

* **Nmap NSE** – 単一ホストが広告しているサービスを検出します：

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` script は `_services._dns-sd._udp.local` query を送信し、その後、広告されている各 service type を列挙します。

* **mdns_recon** – 範囲全体を scan し、unicast query に応答する *misconfigured* mDNS responder を探す Python tool（subnet/WAN を越えて到達可能な device の発見に有用）：

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

これにより、local link 外部で Bonjour 経由の SSH を公開している host が返されます。

### Security considerations と最近の vulnerabilities（2024-2025）

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder* の logic error により、crafted packet で **denial-of-service** を引き起こせる|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|*mDNSResponder* の correctness issue が **local privilege escalation** に悪用される可能性|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. UDP 5353 を *link-local* scope に制限する – wireless controller、router、host-based firewall で block または rate-limit します。
2. service discovery を必要としない system では Bonjour を完全に disable します：

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Bonjour を内部で必要とする一方、network boundary を越えさせてはならない環境では、*AirPlay Receiver* profile restriction（MDM）または mDNS proxy を使用します。
4. **System Integrity Protection (SIP)** を有効にし、macOS を up to date に保ちます – 上記の両 vulnerabilities は迅速に patch されましたが、完全な protection には SIP が有効であることが必要でした。

### Bonjour の無効化

security 上の懸念やその他の理由で Bonjour を disable する必要がある場合は、次の command を使用して無効化できます：
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考資料

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - macOSでのLateral Movement：独自かつ一般的な手法と実際の事例](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - macOS Sonoma 14.7.2のセキュリティコンテンツについて](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - macOS Tahoe 26.6のセキュリティコンテンツについて](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - TLS AuthenticationにSecure Remote Password (SRP) Protocolを使用する方法](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
