# macOSネットワークサービスとプロトコル

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## リモートアクセスサービス

これらはmacOSのリモートアクセスに使用される一般的なサービスです。\
これらのサービスは「システム環境設定」→「共有」で有効/無効にできます。

* **VNC**（tcp:5900）として知られる「スクリーン共有」
* **SSH**（tcp:22）として呼ばれる「リモートログイン」
* **Apple Remote Desktop**（ARD）または「リモート管理」（tcp:3283、tcp:5900）
* **AppleEvent**（tcp:3031）として知られる「リモートAppleイベント」

有効になっているかどうかを確認するには、次を実行してください：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

（この部分は[**このブログ記事**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)から引用されました）

ARDは、いくつかの**追加のmacOS固有の機能**を備えた、実質的には改変された[VNC](https://en.wikipedia.org/wiki/Virtual\_Network\_Computing)です。\
ただし、**Screen Sharingオプション**は単なる**基本的なVNCサーバー**です。また、高度なARDまたはリモート管理オプションもあり、ARDを**VNCクライアントと互換性のあるものにするために制御画面のパスワードを設定**することができます。ただし、この認証方法には弱点があり、この**パスワード**は**8文字の認証バッファ**に制限されているため、[Hydra](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)や[GoRedShell](https://github.com/ahhh/GoRedShell/)などのツールを使用して非常に簡単に**ブルートフォース攻撃**を行うことができます（デフォルトでは**レート制限はありません**）。\
**Screen Sharing**またはリモート管理の**脆弱なインスタンス**を特定するには、`vnc-info`スクリプトを使用して**nmap**を実行し、サービスが`VNC Authentication (2)`をサポートしている場合、おそらく**ブルートフォース攻撃の脆弱性**があります。サービスは、ワイヤ上で送信されるすべてのパスワードを8文字に切り詰めるため、VNC認証を「password」と設定した場合、「passwords」と「password123」の両方が認証されます。

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

特権のエスカレーション（TCCプロンプトの受け入れ）、GUIでのアクセス、ユーザーの監視を有効にするには、次のコマンドを使用して有効にすることができます：

{% code overflow="wrap" %}
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
{% endcode %}

ユーザーの監視からデスクトップの完全な制御まで、**観察モード**、**共有制御**、**フル制御**の間を切り替えることができます。さらに、ARDセッションにアクセスできた場合、そのセッションはセッションが終了するまで開いたままになります。セッション中にユーザーのパスワードが変更されても同様です。

また、ARDを介して**直接UNIXコマンドを送信**することもできます。管理者ユーザーの場合、rootユーザーを指定してrootとして実行することもできます。さらに、このUNIXコマンドの方法を使用して、特定の時間にリモートタスクをスケジュールすることもできますが、これは指定された時間にネットワーク接続として発生します（対象サーバーに保存され、実行されるのではなく）。最後に、リモートスポットライトは私のお気に入りの機能の1つです。これは本当に素晴らしいもので、低負荷でインデックス付けされた検索を迅速かつリモートで実行できます。これは、クイックで、複数のマシンで同時に検索を実行できるため、機密ファイルの検索には最適であり、CPUの使用率が急上昇することはありません。

## Bonjourプロトコル

**Bonjour**は、同じネットワークにあるコンピュータやデバイスが他のコンピュータやデバイスが提供するサービスについて学ぶことができるようにする、Appleが設計した技術です。Bonjour対応のデバイスは、TCP/IPネットワークに接続されると、IPアドレスを選択し、そのネットワーク上の他のコンピュータに提供するサービスを知らせることができます。Bonjourは、Rendezvous、Zero Configuration、またはZeroconfとも呼ばれることがあります。\
BonjourなどのZero Configuration Networkingは、次の機能を提供します。

* DHCPサーバーがなくても**IPアドレスを取得**できる必要があります。
* DNSサーバーがなくても**名前からアドレスへの変換**を行う必要があります。
* ネットワーク上のサービスを**検出**できる必要があります。

デバイスは、**169.254/16の範囲のIPアドレス**を取得し、他のデバイスがそのIPアドレスを使用していないかどうかを確認します。使用されていない場合、IPアドレスを保持します。Macは、このサブネットのルーティングテーブルにエントリを保持します：`netstat -rn | grep 169`

DNSでは、**マルチキャストDNS（mDNS）プロトコル**が使用されます。[**mDNS** **services**はポート**5353/UDP**でリッスンします](../../network-services-pentesting/5353-udp-multicast-dns-mdns.md)。通常のDNSクエリを使用し、リクエストを単一のIPアドレスに送信する代わりに、マルチキャストアドレス224.0.0.251に送信します。これらのリクエストを受信する任意のマシンは応答し、通常はマルチキャストアドレスに応答するため、すべてのデバイスがテーブルを更新できます。\
各デバイスは、ネットワークにアクセスする際に独自の名前を選択します。デバイスは、ホスト名または完全にランダムな名前に基づく名前を**.localで終わる名前**を選択します。

**サービスの検出にはDNS Service Discovery（DNS-SD）**が使用されます。

Zero Configuration Networkingの最後の要件は、**DNS Service Discovery（DNS-SD）**によって満たされます。DNS Service Discoveryは、DNS SRVレコードの構文を使用しますが、特定のサービスを提供する複数のホストがある場合に複数の結果を返すためにDNS PTRレコードを使用します。クライアントは、`<Service>.<Domain>`の名前のPTRルックアップを要求し、`<Instance>.<Service>.<Domain>`の形式のゼロ個以上のPTRレコードのリストを**受け取ります**。

`dns-sd`バイナリを使用して、サービスの**広告を表示**し、サービスの**検索を実行**できます。
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
新しいサービスが開始されると、**新しいサービスはサブネット上のすべての人にその存在をマルチキャストします**。リスナーは尋ねる必要はありませんでした。ただリスニングするだけでした。

[**このツール**](https://apps.apple.com/us/app/discovery-dns-sd-browser/id1381004916?mt=12)を使用して、現在のローカルネットワークで**提供されているサービス**を確認できます。\
または、[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)を使用して、Pythonで独自のスクリプトを作成することもできます。
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
もしBonjourがより安全であると感じるなら、**無効化**することもできます。以下の手順で行います:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考文献

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
