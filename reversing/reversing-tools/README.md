<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>


# Wasmデコンパイラ/ Watコンパイラ

オンライン：

* [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使用して、wasm（バイナリ）からwat（クリアテキスト）に**デコンパイル**します。
* [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使用して、watからwasmに**コンパイル**します。
* [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/)を使用してデコンパイルを試すこともできます。

ソフトウェア：

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

# .Netデコンパイラ

[https://github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy)
[Visual Studio Code用のILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode)：どのOSでも使用できます（VSCodeから直接インストールできます。gitをダウンロードする必要はありません。**Extensions**をクリックして**ILSpy**を検索します）。
**デコンパイル**、**変更**、**再コンパイル**が必要な場合は、[**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases)を使用できます（関数内の何かを変更するには、**右クリック -&gt; Modify Method**をクリックします）。
[https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)も試してみることができます。

## DNSpyログ

**DNSpyが情報をファイルに記録する**ために、次の.Netの行を使用できます：
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
## DNSpy デバッグ

DNSpyを使用してコードをデバッグするには、次の手順を実行する必要があります。

まず、**デバッグに関連する** **アセンブリ属性**を変更します：

![](../../.gitbook/assets/image%20%287%29.png)

From:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
/hive/hacktricks/reversing/reversing-tools/README.md

# Reversing Tools

This section provides an overview of various tools that can be used for reverse engineering and analyzing software. These tools are essential for understanding the inner workings of a program and identifying vulnerabilities or weaknesses.

## Disassemblers

Disassemblers are tools that convert machine code into assembly code, allowing you to analyze and understand the low-level instructions of a program. Some popular disassemblers include:

- [IDA Pro](https://www.hex-rays.com/products/ida/)
- [Ghidra](https://ghidra-sre.org/)
- [Radare2](https://rada.re/r/)

## Debuggers

Debuggers are tools that allow you to analyze and manipulate the execution of a program. They provide features such as breakpoints, stepping through code, and inspecting memory. Some popular debuggers include:

- [GDB](https://www.gnu.org/software/gdb/)
- [OllyDbg](http://www.ollydbg.de/)
- [x64dbg](https://x64dbg.com/)

## Decompilers

Decompilers are tools that convert compiled machine code back into a high-level programming language. They can be useful for understanding the logic and structure of a program. Some popular decompilers include:

- [Ghidra](https://ghidra-sre.org/)
- [IDA Pro](https://www.hex-rays.com/products/ida/)
- [RetDec](https://retdec.com/)

## Binary Analysis Frameworks

Binary analysis frameworks provide a set of tools and libraries for analyzing binary files. They often include features such as static and dynamic analysis, vulnerability detection, and exploit development. Some popular binary analysis frameworks include:

- [Angr](https://angr.io/)
- [Binary Ninja](https://binary.ninja/)
- [Radare2](https://rada.re/r/)

## Sandboxes

Sandboxes are isolated environments that allow you to execute and analyze potentially malicious software safely. They provide a controlled environment for observing the behavior of a program without risking damage to your system. Some popular sandboxes include:

- [Cuckoo Sandbox](https://cuckoosandbox.org/)
- [FireEye](https://www.fireeye.com/)

## Other Tools

In addition to the above, there are many other tools available for reverse engineering and analyzing software. Some notable mentions include:

- [Wireshark](https://www.wireshark.org/)
- [Frida](https://frida.re/)
- [Hopper](https://www.hopperapp.com/)

Remember, the choice of tools depends on the specific task at hand and personal preference. It's important to experiment with different tools and find the ones that work best for you.
```text
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
そして、**コンパイル**をクリックします：

![](../../.gitbook/assets/image%20%28314%29%20%281%29.png)

次に、新しいファイルを _**ファイル &gt;&gt; モジュールを保存...**_ に保存します：

![](../../.gitbook/assets/image%20%28261%29.png)

これは必要です。なぜなら、これを行わないと、**実行時**にコードにいくつかの**最適化**が適用され、**デバッグ中にブレークポイントがヒットしない**か、一部の**変数が存在しない**可能性があるからです。

次に、.Netアプリケーションが**IIS**によって**実行**されている場合、次のコマンドで**再起動**できます：
```text
iisreset /noforce
```
次に、デバッグを開始するためには、すべての開いているファイルを閉じ、**デバッグタブ**で**プロセスにアタッチ**を選択する必要があります。

![](../../.gitbook/assets/image%20%28166%29.png)

次に、**w3wp.exe**を選択して**IISサーバー**にアタッチし、**アタッチ**をクリックします。

![](../../.gitbook/assets/image%20%28274%29.png)

プロセスのデバッグが開始されたので、停止してすべてのモジュールをロードします。まず、**デバッグ**メニューの**Break All**をクリックし、次に**デバッグ**メニューの**Windows**から**Modules**をクリックします。

![](../../.gitbook/assets/image%20%28210%29.png)

![](../../.gitbook/assets/image%20%28341%29.png)

**Modules**の中の任意のモジュールをクリックし、**Open All Modules**を選択します。

![](../../.gitbook/assets/image%20%28216%29.png)

**Assembly Explorer**の中の任意のモジュールを右クリックし、**Sort Assemblies**をクリックします。

![](../../.gitbook/assets/image%20%28130%29.png)

# Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

# Debugging DLLs

## IDAを使用する

* **rundll32をロード**する（64ビットはC:\Windows\System32\rundll32.exe、32ビットはC:\Windows\SysWOW64\rundll32.exe）
* **Windbgデバッガ**を選択する
* "**ライブラリのロード/アンロード時に中断**"を選択する

![](../../.gitbook/assets/image%20%2869%29.png)

* 実行の**パラメータ**を設定し、**DLLのパス**と呼び出したい関数を指定します。

![](../../.gitbook/assets/image%20%28325%29.png)

その後、デバッグを開始すると、各DLLがロードされるたびに実行が停止します。rundll32がDLLをロードすると、実行が停止します。

しかし、ロードされたDLLのコードにアクセスする方法はわかりません。

## x64dbg/x32dbgを使用する

* **rundll32をロード**する（64ビットはC:\Windows\System32\rundll32.exe、32ビットはC:\Windows\SysWOW64\rundll32.exe）
* **コマンドラインを変更**する（ _File --&gt; Change Command Line_ ）と、dllのパスと呼び出したい関数を設定します。例："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\14.ridii\_2.dll",DLLMain
* _Options --&gt; Settings_ を変更し、"**DLL Entry**"を選択します。
* それから**実行を開始**し、デバッガは各dllメインで停止します。いずれかの時点で、自分のdllのdll Entryで停止します。そこから、ブレークポイントを設定したい場所を検索します。

win64dbgで実行が何らかの理由で停止された場合、win64dbgウィンドウの上部にある**コードがどこにあるか**が表示されます。

![](../../.gitbook/assets/image%20%28181%29.png)

その後、デバッグしたいdllで実行が停止した場所を確認できます。

# ARM & MIPS

{% embed url="https://github.com/nongiach/arm\_now" %}

# シェルコード

## blobrunnerを使用してシェルコードをデバッグする

[**Blobrunner**](https://github.com/OALabs/BlobRunner)は、メモリ内のスペースにシェルコードを**割り当て**、シェルコードが割り当てられた**メモリアドレス**を示し、実行を**停止**します。
その後、プロセスにデバッガ（Idaまたはx64dbg）を**アタッチ**し、指定されたメモリアドレスに**ブレークポイント**を設定し、実行を**再開**します。これにより、シェルコードをデバッグできます。

リリースのGitHubページには、コンパイルされたリリースが含まれるzipファイルがあります：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
以下のリンクに、Blobrunnerのわずかに変更されたバージョンがあります。コンパイルするには、Visual Studio CodeでC/C++プロジェクトを作成し、コードをコピーして貼り付け、ビルドします。

{% page-ref page="blobrunner.md" %}

## jmp2itを使用してシェルコードをデバッグする

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)は、blobrunnerと非常に似ています。シェルコードをメモリ内のスペースに**割り当て**、**永遠のループ**を開始します。その後、プロセスにデバッガを**アタッチ**し、**再生を開始して2〜5秒待ち、停止**を押すと、**永遠のループ**の中にいます。永遠のループの次の命令にジャンプし、最終的にシェルコードを実行します。

![](../../.gitbook/assets/image%20%28403%29.png)

[リリースページからjmp2itのコンパイル済みバージョンをダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

## Cutterを使用してシェルコードをデバッグする

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)は、radareのGUIです。Cutterを使用すると、シェルコードをエミュレートして動的に検査できます。

Cutterでは、「ファイルを開く」と「シェルコードを開く」の2つのオプションがあります。私の場合、シェルコードをファイルとして開いた場合は正しく逆コンパイルされましたが、シェルコードとして開いた場合は逆コンパイルされませんでした。

![](../../.gitbook/assets/image%20%28254%29.png)

特定の場所でエミュレーションを開始するには、そこにブレークポイントを設定し、おそらくCutterが自動的にそこからエミュレーションを開始します。

![](../../.gitbook/assets/image%20%28402%29.png)

![](../../.gitbook/assets/image%20%28343%29.png)

たとえば、ヘックスダンプ内でスタックを表示できます。

![](../../.gitbook/assets/image%20%28404%29.png)
## シェルコードの難読化を解除し、実行される関数を取得する

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)を試してみるべきです。
これは、シェルコードが使用している**関数**や、シェルコードがメモリ内で**自己復号化**しているかどうかなどを教えてくれます。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbgには、グラフィカルなランチャーもあります。ここで、必要なオプションを選択してシェルコードを実行することができます。

![](../../.gitbook/assets/image%20%28401%29.png)

**Create Dump**オプションは、シェルコードがメモリ内で動的に変更された場合に、最終的なシェルコードをダンプします（デコードされたシェルコードをダウンロードするのに便利です）。**start offset**は、特定のオフセットでシェルコードを開始するのに役立ちます。**Debug Shell**オプションは、scDbgターミナルを使用してシェルコードをデバッグするのに便利です（ただし、前述のオプションのいずれかを使用する方が、Idaまたはx64dbgを使用できるため、より良いです）。

## CyberChefを使用した逆アセンブル

シェルコードファイルを入力としてアップロードし、次のレシピを使用して逆アセンブルします：[https://gchq.github.io/CyberChef/\#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\)](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

# [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この難読化ツールは、すべての命令を`mov`に変更します（本当にクールですね）。また、実行フローを変更するために割り込みも使用します。詳細については、以下を参照してください：

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

運が良ければ、[demovfuscator](https://github.com/kirschju/demovfuscator)がバイナリを復号化します。いくつかの依存関係があります。
```text
apt-get install libcapstone-dev
apt-get install libz3-dev
```
そして、[keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

もしCTFをプレイしている場合、フラグを見つけるためのこの回避策は非常に役立つでしょう：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

# Delphi

Delphiでコンパイルされたバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)を使用できます。

# コース

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（バイナリの逆難読化）

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksのリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudのリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
