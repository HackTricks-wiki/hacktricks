<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>


ping応答のTTL:\
127 = Windows\
254 = Cisco\
その他 = 何らかのLinux

$1$- md5\
$2$または$2a$ - Blowfish\
$5$- sha256\
$6$- sha512

サービスの背後に何があるかわからない場合は、HTTP GETリクエストを試みてください。

**UDPスキャン**\
nc -nv -u -z -w 1 \<IP> 160-16

特定のポートに空のUDPパケットが送信されます。UDPポートが開いている場合、ターゲットマシンから返信は送られません。UDPポートが閉じている場合、ターゲットマシンからICMPポート到達不能パケットが送り返されるべきです。\


UDPポートスキャンはしばしば信頼性が低く、ファイアウォールやルーターがICMP\
パケットをドロップすることがあります。これによりスキャンの偽陽性が生じ、スキャンされたマシンで全てのUDPポートが開いていると表示されることがよくあります。\
o 多くのポートスキャナーは利用可能な全ポートをスキャンせず、通常はスキャンされる「興味深いポート」のプリセットリストがあります。

# CTF - コツ

**Windows**では**Winzip**を使用してファイルを検索します。\
**Alternate data Streams**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## 暗号

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> "_begin \<mode> \<filename>_" で始まり、奇妙な文字が含まれる\
**Xxencoding** --> "_begin \<mode> \<filename>_" で始まり、B64を使用する\
\
**Vigenere** (頻度分析) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (文字のオフセット) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> スペースとタブを使用してメッセージを隠す

# 文字

%E2%80%AE => RTL 文字 (ペイロードを逆から書く)


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
