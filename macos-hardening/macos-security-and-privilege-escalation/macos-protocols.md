# macOS ネットワークサービスとプロトコル

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## リモートアクセスサービス

これらはmacOSをリモートでアクセスするための一般的なサービスです。\
これらのサービスは `システム設定` --> `共有` で有効/無効にできます。

* **VNC**、「スクリーン共有」として知られています (tcp:5900)
* **SSH**、「リモートログイン」と呼ばれます (tcp:22)
* **Apple Remote Desktop** (ARD)、または「リモート管理」として知られています (tcp:3283, tcp:5900)
* **AppleEvent**、「リモートAppleイベント」として知られています (tcp:3031)

以下のコマンドを実行して、有効になっているかどうかを確認します：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### ARDのペネトレーションテスト

（この部分は[**このブログ投稿から取られました**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)）

基本的には、**macOS固有の機能**をいくつか追加した[VNC](https://en.wikipedia.org/wiki/Virtual\_Network\_Computing)の変形版です。\
しかし、**スクリーン共有オプション**は、ただの**基本的なVNC**サーバーです。また、ARDまたはリモート管理オプションには、**コントロールスクリーンのパスワードを設定する**高度な機能があり、これによりARDは**VNCクライアントとの互換性**を持ちます。ただし、この認証方法には、**パスワード**を**8文字の認証バッファ**に**制限する**弱点があり、[Hydra](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)や[GoRedShell](https://github.com/ahhh/GoRedShell/)のようなツールを使用して非常に簡単に**ブルートフォース**することができます（デフォルトでは**レート制限もありません**）。\
**nmap**を使用して**脆弱なスクリーン共有**またはリモート管理のインスタンスを特定できます。スクリプト`vnc-info`を使用し、サービスが`VNC Authentication (2)`をサポートしている場合、彼らは**ブルートフォースに対して脆弱**である可能性が高いです。サービスは、ワイヤー上で送信されるすべてのパスワードを8文字に切り詰めるため、VNC認証を「password」と設定した場合、「passwords」と「password123」の両方が認証されます。

<figure><img src="../../.gitbook/assets/image (9) (3).png" alt=""><figcaption></figcaption></figure>

特権を昇格させる（TCCプロンプトを受け入れる）、GUIでアクセスする、またはユーザーを監視するために有効にしたい場合は、以下の方法で可能です：

{% code overflow="wrap" %}
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
{% endcode %}

**観察**モード、**共有コントロール**、**フルコントロール**の間を切り替えることができ、ユーザーを監視することから、ボタン一つでデスクトップを乗っ取ることまで可能です。さらに、ARDセッションにアクセスできた場合、そのセッションは終了するまで開いたままであり、セッション中にユーザーのパスワードが変更されたとしても継続します。

また、ARDを介して**直接Unixコマンドを送信**することもでき、管理ユーザーであればrootユーザーとして実行するための指定も可能です。このUnixコマンドメソッドを使用して、特定の時間にリモートタスクを実行するようスケジュールすることもできますが、これは指定された時間にネットワーク接続として発生します（ターゲットサーバーに保存されて実行されるのではありません）。最後に、リモートSpotlightは私のお気に入りの機能の一つです。インデックス付きの検索を迅速かつリモートで実行できるため、非常に便利です。これは、検索を複数のマシンで同時に実行でき、CPUの使用率を上げることなく、機密ファイルを素早く検索するのに最適です。

## Bonjourプロトコル

**Bonjour**は、同じネットワーク上にあるコンピューターや**デバイスが他のコンピューターやデバイスが提供するサービスを認識する**ことを可能にするAppleが設計した技術です。Bonjour対応デバイスはTCP/IPネットワークに接続するだけで**IPアドレスを取得**し、そのネットワーク上の他のコンピューターに**提供するサービスを認識させる**ように設計されています。Bonjourは、Rendezvous、**ゼロコンフィギュレーション**、またはZeroconfとしても知られています。\
ゼロコンフィギュレーションネットワーキング、Bonjourが提供するものは以下の通りです：

* DHCPサーバーがなくても**IPアドレスを取得**できる必要があります
* DNSサーバーがなくても**名前からアドレスへの変換**ができる必要があります
* ネットワーク上の**サービスを発見**できる必要があります

デバイスは**169.254/16の範囲でIPアドレスを取得**し、他のデバイスがそのIPアドレスを使用していないかを確認します。使用されていなければ、そのIPアドレスを保持します。Macはこのサブネットのためにルーティングテーブルにエントリを保持しています：`netstat -rn | grep 169`

DNSには**マルチキャストDNS（mDNS）プロトコルが使用されます**。[**mDNS** **サービス**はポート**5353/UDP**でリッスン](../../network-services-pentesting/5353-udp-multicast-dns-mdns.md)し、**通常のDNSクエリ**を使用し、リクエストを単一のIPアドレスに送信する代わりに**マルチキャストアドレス224.0.0.251**を使用します。これらのリクエストをリッスンしているマシンは通常、マルチキャストアドレスに応答するため、すべてのデバイスがテーブルを更新できます。\
各デバイスはネットワークにアクセスする際に**自分の名前を選択**します。デバイスは、ホスト名に基づいているか完全にランダムなものかもしれませんが、**.localで終わる名前**を選びます。

**サービスの発見にはDNSサービスディスカバリー（DNS-SD）**が使用されます。

ゼロコンフィギュレーションネットワーキングの最終要件は、**DNSサービスディスカバリー（DNS-SD）**によって満たされます。DNSサービスディスカバリーはDNS SRVレコードの構文を使用しますが、複数の結果を返すことができるように**DNS PTRレコードを使用します**。クライアントは`<Service>.<Domain>`の名前に対するPTRルックアップを要求し、0個以上のPTRレコードの形式`<Instance>.<Service>.<Domain>`の**リストを受け取ります**。

`dns-sd`バイナリは、**サービスの広告とサービスのルックアップの実行**に使用できます：
```bash
#Search ssh services
dns-sd -B _ssh._tcp

Browsing for _ssh._tcp
DATE: ---Tue 27 Jul 2021---
12:23:20.361  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
12:23:20.362  Add        3   1 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        3  10 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        2  16 local.               _ssh._tcp.           M-C02C934RMD6R
```

```bash
#Announce HTTP service
dns-sd -R "Index" _http._tcp . 80 path=/index.html

#Search HTTP services
dns-sd -B _http._tcp
```
新しいサービスが開始されると、**新しいサービスはその存在をサブネット上の全員にマルチキャストします**。リスナーは尋ねる必要はありませんでした。ただ聞いているだけでした。

現在のローカルネットワークで**提供されているサービス**を見るには、[**このツール**](https://apps.apple.com/us/app/discovery-dns-sd-browser/id1381004916?mt=12)を使用できます。\
または、[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)を使って自分のpythonスクリプトを書くこともできます：
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
Bonjourが**無効**になっている方がより安全だと感じる場合は、次の操作で無効にできます:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考文献

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
