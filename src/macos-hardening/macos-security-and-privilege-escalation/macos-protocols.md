# macOS ネットワークサービスとプロトコル

{{#include ../../banners/hacktricks-training.md}}

## リモートアクセスサービス

これらはリモートでアクセスするための一般的な macOS サービスです。\
これらのサービスは `System Settings` --> `Sharing` で有効/無効にできます。

- **VNC**、通称「Screen Sharing」 (tcp:5900)
- **SSH**、通称「Remote Login」 (tcp:22)
- **Apple Remote Desktop** (ARD)、または「Remote Management」 (tcp:3283, tcp:5900)
- **AppleEvent**、通称「Remote Apple Event」 (tcp:3031)

有効になっているかどうかを確認するには、次のコマンドを実行します:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD)は、macOS向けに特別に設計された[Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing)の強化版で、追加機能を提供します。ARDの注目すべき脆弱性は、制御画面のパスワードの認証方法で、パスワードの最初の8文字のみを使用するため、[ブルートフォース攻撃](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)に対して脆弱であり、Hydraや[GoRedShell](https://github.com/ahhh/GoRedShell/)のようなツールを使用することで攻撃されやすく、デフォルトのレート制限がないためです。

脆弱なインスタンスは、**nmap**の`vnc-info`スクリプトを使用して特定できます。`VNC Authentication (2)`をサポートするサービスは、8文字のパスワードの切り捨てにより、特にブルートフォース攻撃に対して脆弱です。

特権昇格、GUIアクセス、またはユーザーモニタリングなどのさまざまな管理タスクのためにARDを有効にするには、次のコマンドを使用します:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARDは、観察、共有制御、完全制御を含む多様な制御レベルを提供し、ユーザーパスワードの変更後もセッションが持続します。これにより、Unixコマンドを直接送信し、管理者ユーザーとしてrootで実行することができます。タスクスケジューリングやリモートSpotlight検索は、複数のマシンにわたる機密ファイルのリモートでの低影響検索を容易にする注目すべき機能です。

#### 最近の画面共有 / ARDの脆弱性 (2023-2025)

| 年   | CVE              | コンポーネント               | 影響                                                         | 修正済み                     |
|------|------------------|-----------------------------|--------------------------------------------------------------|------------------------------|
| 2023 | CVE-2023-42940   | 画面共有                   | 不正なセッションレンダリングにより、*誤った*デスクトップまたはウィンドウが送信され、機密情報が漏洩する可能性がある | macOS Sonoma 14.2.1 (2023年12月) |
| 2024 | CVE-2024-23296   | launchservicesd / login    | 成功したリモートログイン後に連鎖可能なカーネルメモリ保護バイパス（実際に悪用されている） | macOS Ventura 13.6.4 / Sonoma 14.4 (2024年3月) |

**ハードニングのヒント**

* 必要ない場合は*画面共有*/*リモート管理*を無効にする。
* macOSを完全にパッチ適用する（Appleは一般的に最新の3つのメジャーリリースに対してセキュリティ修正を提供します）。
* **強力なパスワード**を使用し、可能な限り*「VNCビューワーはパスワードで画面を制御できる」*オプションを**無効**にする。
* サービスをVPNの背後に置き、TCP 5900/3283をインターネットにさらさない。
* `ARDAgent`をローカルサブネットに制限するアプリケーションファイアウォールルールを追加する：

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjourプロトコル

Bonjourは、Appleが設計した技術で、**同じネットワーク上のデバイスが互いに提供するサービスを検出できる**ようにします。Rendezvous、**ゼロコンフィギュレーション**、またはZeroconfとも呼ばれ、デバイスがTCP/IPネットワークに参加し、**自動的にIPアドレスを選択**し、他のネットワークデバイスにサービスをブロードキャストすることを可能にします。

Bonjourが提供するゼロコンフィギュレーションネットワーキングにより、デバイスは以下を実行できます：

- **DHCPサーバーがない場合でも自動的にIPアドレスを取得**する。
- **DNSサーバーを必要とせずに名前からアドレスへの変換**を行う。
- **ネットワーク上のサービスを発見**する。

Bonjourを使用するデバイスは、**169.254/16範囲からIPアドレスを自動的に割り当て**、ネットワーク上での一意性を確認します。Macはこのサブネットのルーティングテーブルエントリを保持し、`netstat -rn | grep 169`で確認できます。

DNSに関して、Bonjourは**マルチキャストDNS（mDNS）プロトコル**を利用します。mDNSは**ポート5353/UDP**で動作し、**標準DNSクエリ**を使用しますが、**マルチキャストアドレス224.0.0.251**をターゲットにします。このアプローチにより、ネットワーク上のすべてのリスニングデバイスがクエリを受信し応答できるようになり、レコードの更新が促進されます。

ネットワークに参加すると、各デバイスは通常**.local**で終わる名前を自動的に選択し、これはホスト名から派生するか、ランダムに生成されることがあります。

ネットワーク内のサービス発見は**DNSサービス発見（DNS-SD）**によって促進されます。DNS SRVレコードの形式を利用し、DNS-SDは**DNS PTRレコード**を使用して複数のサービスのリストを可能にします。特定のサービスを求めるクライアントは`<Service>.<Domain>`のPTRレコードを要求し、サービスが複数のホストから利用可能な場合は`<Instance>.<Service>.<Domain>`形式のPTRレコードのリストを受け取ります。

`dns-sd`ユーティリティは、**ネットワークサービスの発見と広告**に使用できます。以下はその使用例です：

### SSHサービスの検索

ネットワーク上のSSHサービスを検索するには、次のコマンドを使用します：
```bash
dns-sd -B _ssh._tcp
```
このコマンドは、\_ssh.\_tcpサービスのブラウジングを開始し、タイムスタンプ、フラグ、インターフェース、ドメイン、サービスタイプ、およびインスタンス名などの詳細を出力します。

### HTTPサービスの広告

HTTPサービスを広告するには、次のようにします:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
このコマンドは、ポート80で`/index.html`のパスを持つ「Index」という名前のHTTPサービスを登録します。

次に、ネットワーク上のHTTPサービスを検索するには:
```bash
dns-sd -B _http._tcp
```
サービスが開始されると、その存在をマルチキャストしてサブネット上のすべてのデバイスに可用性を通知します。これらのサービスに興味のあるデバイスは、リクエストを送信する必要はなく、単にこれらの通知を聞くだけです。

よりユーザーフレンドリーなインターフェースのために、Apple App Storeで利用可能な**Discovery - DNS-SD Browser**アプリは、ローカルネットワーク上で提供されているサービスを視覚化できます。

また、`python-zeroconf`ライブラリを使用してサービスをブラウズおよび発見するためのカスタムスクリプトを作成することもできます。[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)スクリプトは、`_http._tcp.local.`サービスのためのサービスブラウザを作成し、追加または削除されたサービスを印刷することを示しています。
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
### Bonjourをネットワーク上で列挙する

* **Nmap NSE** – 単一ホストによって広告されたサービスを発見します：

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery`スクリプトは、`_services._dns-sd._udp.local`クエリを送信し、各広告されたサービスタイプを列挙します。

* **mdns_recon** – *misconfigured* mDNSレスポンダーを探すために全範囲をスキャンするPythonツール（サブネット/WANを越えて到達可能なデバイスを見つけるのに便利）：

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

これにより、ローカルリンクの外でBonjourを介してSSHを公開しているホストが返されます。

### セキュリティ考慮事項と最近の脆弱性 (2024-2025)

| 年 | CVE | 深刻度 | 問題 | パッチ適用 |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|中|*mDNSResponder*の論理エラーにより、作成されたパケットが**サービス拒否**を引き起こすことができた|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (2024年9月) |
|2025|CVE-2025-31222|高|*mDNSResponder*の正確性の問題が**ローカル特権昇格**に悪用される可能性がある|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (2025年5月) |

**緩和ガイダンス**

1. UDP 5353を*リンクローカル*スコープに制限する – ワイヤレスコントローラー、ルーター、ホストベースのファイアウォールでブロックまたはレート制限します。
2. サービス発見を必要としないシステムではBonjourを完全に無効にします：

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Bonjourが内部で必要だがネットワーク境界を越えてはならない環境では、*AirPlay Receiver*プロファイル制限（MDM）またはmDNSプロキシを使用します。
4. **System Integrity Protection (SIP)**を有効にし、macOSを最新の状態に保ちます – 上記の両方の脆弱性は迅速にパッチが適用されましたが、完全な保護のためにはSIPが有効であることに依存していました。

### Bonjourを無効にする

セキュリティに関する懸念やその他の理由でBonjourを無効にする必要がある場合、次のコマンドを使用してオフにできます：
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考文献

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)

{{#include ../../banners/hacktricks-training.md}}
