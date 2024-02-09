# macOS Apple Scripts

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする**
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する

</details>

## Apple Scripts

これは、**リモートプロセスとやり取りする**ために使用されるスクリプト言語です。他のプロセスに**いくつかのアクションを実行するように要求する**ことが非常に簡単になります。**マルウェア**は、他のプロセスがエクスポートした機能を悪用するためにこれらの機能を悪用する可能性があります。\
たとえば、マルウェアは、ブラウザで開いたページに**任意のJSコードを注入**したり、ユーザーに要求された**許可を自動的にクリック**することができます。
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
ここにいくつかの例があります：[https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScriptを使用したマルウェアに関する詳細は[**こちら**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)で確認できます。

Appleスクリプトは簡単に**「コンパイル」**できます。これらのバージョンは`osadecompile`を使用して簡単に**「逆コンパイル」**できます。

ただし、これらのスクリプトは**「読み取り専用」としてエクスポート**することもできます（「エクスポート...」オプションを使用）：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
そしてこの場合、`osadecompile` でもコンパイルされた内容を逆コンパイルすることはできません。

ただし、この種の実行可能ファイルを理解するために使用できるツールがいくつかあります。[**この研究を詳しく読む**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)。ツール [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) と [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) は、スクリプトの動作原理を理解するのに非常に役立ちます。
