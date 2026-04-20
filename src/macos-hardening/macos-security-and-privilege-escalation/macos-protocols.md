# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

これらは、macOS の代表的なリモートアクセス用サービスです。\
これらのサービスは `System Settings` --> `Sharing` で有効/無効を切り替えられます

- **VNC**, “Screen Sharing” として知られる (tcp:5900)
- **SSH**, “Remote Login” と呼ばれる (tcp:22)
- **Apple Remote Desktop** (ARD), または “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, “Remote Apple Event” として知られる (tcp:3031)

有効になっているものがあるか確認するには、実行します:
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

Macで既にローカルコード実行がある場合は、**待ち受けソケットだけでなく、設定された状態**を確認してください。`systemsetup` と `launchctl` は通常、そのサービスが管理上有効かどうかを示し、`kickstart` と `system_profiler` は実際の ARD/Sharing 設定を確認するのに役立ちます:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### ARDのpentesting

Apple Remote Desktop (ARD) は、macOS向けに調整された [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) の拡張版で、追加機能を備えています。ARD の特筆すべき脆弱性は、control screen password の認証方式にあり、パスワードの先頭 8 文字しか使用しないため、Hydra や [GoRedShell](https://github.com/ahhh/GoRedShell/) のようなツールを使った [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) に対して脆弱です。これは、デフォルトの rate limit が存在しないためです。

脆弱なインスタンスは、**nmap** の `vnc-info` スクリプトで識別できます。`VNC Authentication (2)` をサポートするサービスは、8 文字でのパスワード切り捨てのため、特に brute force attacks に対して脆弱です。

権限昇格、GUI アクセス、ユーザ監視などのさまざまな管理作業のために ARD を有効化するには、次のコマンドを使用します:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD は、観察、共有制御、完全制御を含む多様な制御レベルを提供し、ユーザーのパスワード変更後でもセッションは維持されます。Unix commands を直接送信でき、管理者ユーザーに対しては root として実行できます。タスクスケジューリングと Remote Spotlight search は特に注目すべき機能で、複数のマシンにわたって機密ファイルを低影響でリモート検索するのに役立ちます。

オペレーターの観点では、**Monterey 12.1+ は managed fleets における remote-enablement のワークフローを変更しました**。すでに被害者の MDM を制御しているなら、Apple の `EnableRemoteDesktop` コマンドが、新しいシステムで remote desktop 機能を有効化する最もクリーンな方法であることが多いです。すでにホスト上に foothold があるなら、`kickstart` はコマンドラインから ARD 権限を確認または再構成するのに依然として有用です。

### Pentesting Remote Apple Events (RAE / EPPC)

Apple はこの機能を、現行の System Settings では **Remote Application Scripting** と呼んでいます。内部的には、`com.apple.AEServer` サービスを介して **EPPC** 上の **TCP/3031** で **Apple Event Manager** をリモート公開しています。Palo Alto Unit 42 は、正当な認証情報と有効化された RAE サービスがあれば、オペレーターがリモート Mac 上のスクリプト可能なアプリケーションを操作できるため、これを実用的な **macOS lateral movement** のプリミティブとして改めて指摘しました。

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
対象で既に admin/root を持っていて、それを有効化したい場合:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
別のMacからの基本的な接続テスト:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
実際には、悪用ケースは Finder に限定されません。必要な Apple events を受け入れる **scriptable application** はすべてリモート攻撃面になり得るため、RAE は内部 macOS ネットワークでの credential theft 後に特に興味深いものになります。

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|不正なセッション描画により、*wrong* なデスクトップまたはウィンドウが送信され、機密情報が leak する可能性がある|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|screen sharing アクセスを持つユーザーが、状態管理の問題により**別のユーザーの screen** を閲覧できる可能性がある|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* *Screen Sharing*/*Remote Management* は、厳密に必要でない限り無効化する。
* macOS を完全に patch する（Apple は通常、直近 3 つの major release に対して security fix を提供する）。
* **Strong Password** を使用し、可能であれば *“VNC viewers may control screen with password”* オプションを **無効** にする。
* TCP 5900/3283 を Internet に公開せず、VPN の背後に service を置く。
* Application Firewall の rule を追加して `ARDAgent` を local subnet に制限する:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Apple が設計した技術である Bonjour は、**同じ network 上の device 同士が互いに提供している service を検出できる**ようにします。Rendezvous、**Zero Configuration**、または Zeroconf とも呼ばれ、device が TCP/IP network に参加し、**IP address を自動的に選択**し、他の network device に service をブロードキャストすることを可能にします。

Bonjour が提供する Zero Configuration Networking により、device は次のことができます。

- DHCP server が存在しなくても **IP Address を自動的に取得**する。
- DNS server を必要とせずに **name-to-address translation** を行う。
- network 上で利用可能な **services を発見**する。

Bonjour を使用する device は **169.254/16 range の IP address** を自分で割り当て、network 上でその一意性を確認します。Mac ではこの subnet に対する routing table エントリが保持され、`netstat -rn | grep 169` で確認できます。

DNS では、Bonjour は **Multicast DNS (mDNS) protocol** を利用します。mDNS は **port 5353/UDP** 上で動作し、**standard DNS queries** を使用しつつ、**multicast address 224.0.0.251** を対象にします。この方式により、network 上のすべての listening device が query を受信して応答でき、record の更新が容易になります。

network に参加すると、各 device は自分で name を選択し、通常は **.local** で終わります。この name は hostname から派生することもあれば、ランダムに生成されることもあります。

network 内の service discovery は **DNS Service Discovery (DNS-SD)** によって実現されます。DNS SRV record の形式を活用し、DNS-SD は **DNS PTR records** を使って複数の service の一覧表示を可能にします。特定の service を探す client は `<Service>.<Domain>` の PTR record を要求し、service が複数の host から提供されている場合、`<Instance>.<Service>.<Domain>` 形式の PTR record の list が返されます。

`dns-sd` utility は **network services の discover と advertise** に使用できます。以下に使用例を示します。

### Searching for SSH Services

network 上の SSH services を search するには、次の command を使用します:
```bash
dns-sd -B _ssh._tcp
```
このコマンドは、\_ssh.\_tcp サービスの検索を開始し、タイムスタンプ、フラグ、インターフェース、ドメイン、サービス種別、インスタンス名などの詳細を出力します。

### HTTP Service の広告

HTTP Service を広告するには、次を使用できます:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
このコマンドは、ポート 80 上に `/index.html` のパスを持つ "Index" という名前の HTTP サービスを登録します。

その後、ネットワーク上の HTTP サービスを検索するには:
```bash
dns-sd -B _http._tcp
```
サービスが開始されると、その存在をサブネット上のすべてのデバイスにマルチキャストで通知します。これらのサービスに関心があるデバイスは、リクエストを送信する必要はなく、これらの通知をただ聞いているだけでよいです。

より使いやすいインターフェースとして、Apple App Storeで入手できる **Discovery - DNS-SD Browser** アプリを使うと、ローカルネットワークで提供されているサービスを可視化できます。

別の方法として、`python-zeroconf` ライブラリを使ってサービスをbrowseおよびdiscoverするカスタムスクリプトを作成できます。[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) スクリプトは、`_http._tcp.local.` サービス向けの service browser を作成し、追加または削除されたサービスを表示する例を示しています:
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

macOSネットワークでは、Bonjourは対象に直接触れずに**リモート管理用の面**を見つける最も簡単な方法であることが多いです。Apple Remote Desktop自体もBonjour経由でクライアントを発見できるため、同じ探索データは攻撃者にとっても有用です。
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
より広範な **mDNS spoofing, impersonation, and cross-subnet discovery** techniques については、専用ページを参照してください:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### ネットワーク上の Bonjour の列挙

* **Nmap NSE** – 単一ホストが広告しているサービスを検出する:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` スクリプトは `_services._dns-sd._udp.local` クエリを送信し、その後、広告されている各サービス種別を列挙します。

* **mdns_recon** – 誤設定された mDNS responder を探すために範囲全体をスキャンする Python ツール。ユニキャストクエリに応答するものを探します（サブネット/WAN をまたいで到達可能なデバイスの発見に有用）:

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

これは、ローカルリンク外で Bonjour 経由の SSH を公開しているホストを返します。

### セキュリティ上の考慮事項と最近の脆弱性 (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder* のロジックエラーにより、細工されたパケットで **denial-of-service** を引き起こせた|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (2024年9月) |
|2025|CVE-2025-31222|High|*mDNSResponder* の正当性に関する問題が **local privilege escalation** に悪用される可能性があった|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (2025年5月) |

**緩和策**

1. UDP 5353 を *link-local* スコープに制限する – 無線コントローラ、ルーター、ホストベースのファイアウォールでブロックするか、レート制限する。
2. サービス検出を必要としないシステムでは、Bonjour を完全に無効化する:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. 内部では Bonjour が必要だが、ネットワーク境界を絶対に越えてはならない環境では、*AirPlay Receiver* プロファイル制限 (MDM) か mDNS proxy を使う。
4. **System Integrity Protection (SIP)** を有効にし、macOS を最新の状態に保つ – 上記 2 件の脆弱性は迅速に修正されたが、完全な保護には SIP が有効であることに依存していた。

### Bonjour の無効化

セキュリティ上の懸念やその他の理由で Bonjour を無効化したい場合、次のコマンドでオフにできます:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - macOS Sonoma 14.7.2 のセキュリティコンテンツについて**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
