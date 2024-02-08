# macOSネットワークサービスとプロトコル

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい** または **HackTricksをPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## リモートアクセスサービス

これらはリモートでアクセスするための一般的なmacOSサービスです。\
これらのサービスは `システム設定` --> `共有` で有効/無効にできます。

* **VNC**、「Screen Sharing」として知られています（tcp:5900）
* **SSH**、「Remote Login」と呼ばれています（tcp:22）
* **Apple Remote Desktop**（ARD）または「Remote Management」（tcp:3283、tcp:5900）
* **AppleEvent**、「Remote Apple Event」として知られています（tcp:3031）

有効になっているかどうかを確認するには、次を実行します：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### ARDのペンテスト

Apple Remote Desktop (ARD) は、macOS向けにカスタマイズされた[Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing)の強化バージョンであり、追加機能を提供しています。 ARDの顕著な脆弱性は、制御画面パスワードの認証方法であり、パスワードの最初の8文字のみを使用するため、[Hydra](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)や[GoRedShell](https://github.com/ahhh/GoRedShell/)などのツールを使用した[総当たり攻撃](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)に対して脆弱性があります。デフォルトのレート制限がないため、特に`VNC Authentication (2)`をサポートするサービスは、8文字のパスワードの切り捨てにより、総当たり攻撃に特に脆弱です。

**nmap**の`vnc-info`スクリプトを使用して、脆弱なインスタンスを特定できます。`VNC Authentication (2)`をサポートするサービスは、8文字のパスワードの切り捨てにより、総当たり攻撃に特に脆弱です。

特権昇格、GUIアクセス、ユーザーモニタリングなどのさまざまな管理タスクのためにARDを有効にするには、次のコマンドを使用します：
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARDは、観察、共有制御、フル制御など、さまざまな制御レベルを提供し、ユーザーパスワードの変更後もセッションが継続します。管理者ユーザーに対して、Unixコマンドを直接送信し、rootとして実行することができます。タスクスケジューリングやリモートスポットライト検索などの機能があり、複数のマシンで機密ファイルをリモートで検索するのに役立ちます。

## Bonjourプロトコル

Bonjourは、Appleが設計した技術で、**同じネットワーク上のデバイスが提供するサービスを検出**できます。Rendezvous、Zero Configuration、またはZeroconfとしても知られ、TCP/IPネットワークにデバイスを参加させ、**自動的にIPアドレスを選択**し、そのサービスを他のネットワークデバイスにブロードキャストできます。

Bonjourによって提供されるZero Configuration Networkingにより、デバイスは次のことができます：
* **DHCPサーバーが存在しなくてもIPアドレスを自動的に取得**できます。
* DNSサーバーを必要とせずに**名前からアドレスへの変換**を実行できます。
* ネットワーク上で利用可能な**サービスを検出**できます。

Bonjourを使用するデバイスは、**169.254/16の範囲からIPアドレスを自動的に割り当て**、そのネットワーク上での一意性を確認します。Macは、このサブネット用のルーティングテーブルエントリを維持し、`netstat -rn | grep 169`で確認できます。

BonjourはDNSにおいて、**マルチキャストDNS（mDNS）プロトコル**を利用します。mDNSは**ポート5353/UDP**上で動作し、**標準DNSクエリ**を使用しますが、**マルチキャストアドレス224.0.0.251**を対象とします。このアプローチにより、ネットワーク上のすべてのリスニングデバイスがクエリを受信し、応答できるようになり、レコードの更新が容易になります。

ネットワークに参加すると、各デバイスは通常、ホスト名から派生した**.local**で終わる名前を自己選択します。

ネットワーク内でのサービス検出は、**DNS Service Discovery（DNS-SD）**によって容易になります。DNS SRVレコードの形式を活用するDNS-SDは、**DNS PTRレコード**を使用して複数のサービスをリスト化します。特定のサービスを求めるクライアントは、複数のホストから利用可能な場合、`<Instance>.<Service>.<Domain>`という形式のPTRレコードのリストを受け取ります。

`dns-sd`ユーティリティを使用して、**ネットワークサービスの検出と広告**ができます。以下はその使用例です：

### SSHサービスの検索

ネットワーク上でSSHサービスを検索するには、次のコマンドを使用します：
```bash
dns-sd -B _ssh._tcp
```
このコマンドは、_ssh._tcpサービスのブラウジングを開始し、タイムスタンプ、フラグ、インターフェース、ドメイン、サービスタイプ、およびインスタンス名などの詳細を出力します。

### HTTPサービスの広告

HTTPサービスを広告するには、次のコマンドを使用できます：
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
このコマンドは、ポート80で`/index.html`のパスを持つHTTPサービスを「Index」という名前で登録します。

その後、ネットワーク上でHTTPサービスを検索するには:
```bash
dns-sd -B _http._tcp
```
サービスが開始されると、その存在をマルチキャストしてサブネット上のすべてのデバイスに通知します。これらのサービスに興味を持つデバイスはリクエストを送信する必要はなく、単にこれらのアナウンスを聞くだけです。

よりユーザーフレンドリーなインターフェースのために、Apple App Storeで入手可能な**Discovery - DNS-SD Browser**アプリを使用すると、ローカルネットワークで提供されているサービスを視覚化できます。

また、`python-zeroconf`ライブラリを使用してサービスをブラウズおよび検出するためのカスタムスクリプトを作成することもできます。[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)スクリプトは、`_http._tcp.local.`サービス用のサービスブラウザの作成をデモし、追加または削除されたサービスを出力します。
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
### Bonjourの無効化
セキュリティ上の懸念やその他の理由からBonjourを無効にする必要がある場合は、次のコマンドを使用してオフにすることができます:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考文献

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)で**フォロー**する。
* **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
