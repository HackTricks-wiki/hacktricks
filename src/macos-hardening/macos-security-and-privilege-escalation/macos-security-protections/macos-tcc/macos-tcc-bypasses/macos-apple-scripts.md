# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

これは、**リモートプロセスと対話する**ためのタスク自動化に使用されるスクリプト言語です。他のプロセスに**アクションを実行するように依頼する**のが非常に簡単です。**マルウェア**は、他のプロセスによってエクスポートされた機能を悪用するためにこれらの機能を悪用する可能性があります。\
例えば、マルウェアは**ブラウザで開かれたページに任意のJSコードを注入**することができます。また、ユーザーに要求された許可を**自動的にクリック**することもできます；
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
ここにいくつかの例があります: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
マルウェアに関する詳細情報は[**こちら**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)で見つけることができます。

Appleスクリプトは簡単に「**コンパイル**」できます。これらのバージョンは簡単に「**デコンパイル**」できます `osadecompile`

しかし、これらのスクリプトは「読み取り専用」としても**エクスポート**できます（「エクスポート...」オプションを介して）:

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
この場合、`osadecompile`を使用してもコンテンツはデコンパイルできません。

しかし、この種の実行可能ファイルを理解するために使用できるツールはいくつかあります。[**詳細についてはこの研究をお読みください**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)。ツール[**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler)と[**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile)は、スクリプトの動作を理解するのに非常に役立ちます。

{{#include ../../../../../banners/hacktricks-training.md}}
