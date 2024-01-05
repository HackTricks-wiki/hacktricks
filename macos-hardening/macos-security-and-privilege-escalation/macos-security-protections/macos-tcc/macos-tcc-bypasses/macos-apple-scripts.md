# macOS Apple Scripts

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## Apple Scripts

タスク自動化のために使用されるスクリプト言語で、**リモートプロセスとのやり取り**に使われます。他のプロセスに**特定のアクションを実行するよう依頼する**ことが非常に簡単です。**マルウェア**はこれらの機能を悪用して、他のプロセスによってエクスポートされた機能を乱用する可能性があります。\
例えば、マルウェアは**ブラウザで開かれたページに任意のJSコードを注入する**ことができます。または、ユーザーに要求された許可を**自動クリック**することもできます。
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
以下はいくつかの例です: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScriptsを使用したマルウェアに関する詳細情報は[**こちら**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)。

AppleScriptsは簡単に"**コンパイル**"することができます。これらのバージョンは`osadecompile`を使用して簡単に"**デコンパイル**"することができます。

しかし、このスクリプトは"読み取り専用"として**エクスポート**することもできます（"エクスポート..."オプションを介して）：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
この場合、`osadecompile`を使用してもコンテンツを逆コンパイルすることはできません。

しかし、この種の実行可能ファイルを理解するために使用できるツールがまだいくつかあります。[**この研究を読むとさらに詳しい情報が得られます**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)。ツール[**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler)と[**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile)は、スクリプトの動作を理解するのに非常に役立ちます。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには、</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
