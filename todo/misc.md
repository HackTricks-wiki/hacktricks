<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したり、HackTricksをPDFでダウンロードしたい場合は** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを発見する
* **💬 [Discordグループに参加](https://discord.gg/hRep4RUj7f)** または [telegramグループに参加](https://t.me/peass) または **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
* **ハッキングトリックを共有するには、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>


Ping応答でのTTL：\
127 = Windows\
254 = Cisco\
Lo demás,algunlinux

$1$- md5\
$2$または$2a$ - Blowfish\
$5$- sha256\
$6$- sha512

サービスの背後に何があるかわからない場合は、HTTP GETリクエストを作成してみてください。

**UDPスキャン**\
nc -nv -u -z -w 1 \<IP> 160-16

特定のポートに空のUDPパケットが送信されます。UDPポートが開いている場合、ターゲットマシンからは応答が送信されません。UDPポートが閉じている場合、ターゲットマシンからはICMPポート到達不能パケットが送信されるはずです。\

UDPポートスキャンはしばしば信頼性が低く、ファイアウォールやルーターがICMP\
パケットをドロップする可能性があります。これにより、スキャンで偽の陽性が発生し、スキャンされたマシンのすべてのUDPポートが開いていると表示されることがよくあります。\
o ほとんどのポートスキャナーはすべての利用可能なポートをスキャンせず、通常はスキャンされる「興味深いポート」の事前設定リストを持っています。

# CTF - Tricks

**Windows**では、ファイルを検索するために**Winzip**を使用します。\
**Alternate data Streams**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## 暗号

**featherduster**\

**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> "_begin \<mode> \<filename>_" で始まり、奇妙な文字\
**Xxencoding** --> "_begin \<mode> \<filename>_" で始まり、B64\

**Vigenere** (frequency analysis) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (offset of characters) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> スペースとタブを使ってメッセージを隠す

# 文字

%E2%80%AE => RTL 文字 (ペイロードを逆に書く)

<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks を PDF でダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com) を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出して、あなたのハッキングテクニックを共有する

</details>
