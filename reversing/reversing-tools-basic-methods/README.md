# リバースエンジニアリングツールと基本的な手法

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## ImGuiベースのリバースエンジニアリングツール

ソフトウェア：

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasmデコンパイラ/ Watコンパイラ

オンライン：

* [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使用して、wasm（バイナリ）からwat（クリアテキスト）に**デコンパイル**します。
* [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使用して、watからwasmに**コンパイル**します。
* [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/)を使用してデコンパイルすることもできます。

ソフトウェア：

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .Netデコンパイラ

[https://github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy)\
[Visual Studio Code用のILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode)：どのOSでも使用できます（VSCodeから直接インストールできます。gitをダウンロードする必要はありません。**Extensions**をクリックして**ILSpy**を検索します）。\
**デコンパイル**、**変更**、**再コンパイル**が必要な場合は、[**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases)を使用できます（関数内の何かを変更するには、**右クリック->メソッドの変更**）。\
[https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)も試すことができます。

### DNSpyログ

**DNSpyが情報をファイルに記録する**ために、次の.Netの行を使用できます：
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy デバッグ

DNSpyを使用してコードをデバッグするには、次の手順を実行する必要があります。

まず、**デバッグに関連する** **アセンブリ属性**を変更します：

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
/hive/hacktricks/reversing/reversing-tools-basic-methods/README.md

# Reversing Tools Basic Methods

This section provides an overview of some basic methods and tools used in reverse engineering. These techniques are essential for analyzing and understanding the inner workings of software and systems.

## Static Analysis

Static analysis involves examining the code and structure of a program without executing it. This can be done using tools such as disassemblers, decompilers, and hex editors. Static analysis helps in identifying vulnerabilities, understanding the logic of the program, and finding hidden functionality.

### Disassemblers

Disassemblers are tools that convert machine code into assembly code. They allow you to view the low-level instructions of a program, making it easier to understand how it works. Some popular disassemblers include IDA Pro, Ghidra, and Radare2.

### Decompilers

Decompilers are tools that convert compiled code back into a high-level programming language. They can be used to analyze the functionality of a program and understand its logic. Popular decompilers include IDA Pro, Ghidra, and RetDec.

### Hex Editors

Hex editors allow you to view and edit binary files at the hexadecimal level. They are useful for analyzing and modifying the contents of a program's executable file. Some popular hex editors include HxD, Hex Fiend, and Bless.

## Dynamic Analysis

Dynamic analysis involves running a program and observing its behavior in real-time. This can be done using tools such as debuggers, profilers, and memory analyzers. Dynamic analysis helps in understanding how a program interacts with its environment and identifying runtime vulnerabilities.

### Debuggers

Debuggers are tools that allow you to monitor and control the execution of a program. They provide features such as breakpoints, stepping through code, and inspecting variables. Popular debuggers include GDB, WinDbg, and OllyDbg.

### Profilers

Profiling tools help in analyzing the performance of a program by measuring various metrics such as CPU usage, memory usage, and execution time. They can be used to identify bottlenecks and optimize the code. Some popular profilers include Perf, Valgrind, and Xcode Instruments.

### Memory Analyzers

Memory analyzers are tools that help in analyzing the memory usage of a program. They can be used to detect memory leaks, buffer overflows, and other memory-related vulnerabilities. Popular memory analyzers include Valgrind, WinDbg, and IDA Pro.

## Conclusion

These are some of the basic methods and tools used in reverse engineering. By using a combination of static and dynamic analysis techniques, you can gain a deep understanding of how software and systems work, and identify vulnerabilities that can be exploited.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
そして、**コンパイル**をクリックします：

![](<../../.gitbook/assets/image (314) (1) (1).png>)

次に、新しいファイルを _**ファイル >> モジュールを保存...**_ に保存します：

![](<../../.gitbook/assets/image (279).png>)

これは必要です。なぜなら、これを行わない場合、**ランタイム**でいくつかの**最適化**がコードに適用され、**デバッグ中にブレークポイントがヒットしない**か、いくつかの**変数が存在しない**可能性があるからです。

次に、.Netアプリケーションが**IIS**で実行されている場合、次のコマンドで**再起動**できます：
```
iisreset /noforce
```
次に、デバッグを開始するためには、すべての開いているファイルを閉じ、**デバッグタブ**で**プロセスにアタッチ**を選択する必要があります。

![](<../../.gitbook/assets/image (280).png>)

次に、**w3wp.exe**を選択して**IISサーバー**にアタッチし、**アタッチ**をクリックします。

![](<../../.gitbook/assets/image (281).png>)

プロセスのデバッグが開始されたので、それを停止してすべてのモジュールをロードします。まず、_Debug >> Break All_ をクリックし、次に _**Debug >> Windows >> Modules**_ をクリックします。

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

**Modules**の中の任意のモジュールをクリックし、**Open All Modules**を選択します。

![](<../../.gitbook/assets/image (284).png>)

**Assembly Explorer**の中の任意のモジュールを右クリックし、**Sort Assemblies**をクリックします。

![](<../../.gitbook/assets/image (285).png>)

## Javaデコンパイラ

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLLのデバッグ

### IDAを使用する

* **rundll32をロード**します（64ビットはC:\Windows\System32\rundll32.exe、32ビットはC:\Windows\SysWOW64\rundll32.exe）。
* **Windbgデバッガ**を選択します。
* "**ライブラリのロード/アンロード時に中断**"を選択します。

![](<../../.gitbook/assets/image (135).png>)

* 実行の**パラメータ**を設定し、**DLLのパス**と呼び出したい関数を入力します。

![](<../../.gitbook/assets/image (136).png>)

その後、デバッグを開始すると、各DLLがロードされるたびに実行が停止します。rundll32がDLLをロードすると、実行が停止します。

しかし、ロードされたDLLのコードにアクセスする方法はわかりません。

### x64dbg/x32dbgを使用する

* **rundll32をロード**します（64ビットはC:\Windows\System32\rundll32.exe、32ビットはC:\Windows\SysWOW64\rundll32.exe）。
* **コマンドラインを変更**します（ _File --> Change Command Line_ ）し、dllのパスと呼び出したい関数を設定します。例："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* _Options --> Settings_ を変更し、"**DLL Entry**"を選択します。
* それから**実行を開始**します。デバッガは各DLLメインで停止します。いずれかのタイミングで、自分のDLLのDLLエントリで停止します。そこから、ブレークポイントを設定したい場所を検索します。

注意点として、win64dbgで実行が何らかの理由で停止した場合、win64dbgウィンドウの上部にある**どのコードで停止したか**が表示されます。

![](<../../.gitbook/assets/image (137).png>)

そのため、デバッグしたいDLLで実行が停止した場所を確認できます。

## GUIアプリ/ビデオゲーム

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのメモリ内に重要な値が保存されている場所を見つけて変更するための便利なプログラムです。詳細は以下を参照してください。

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## シェルコード

### blobrunnerを使用したシェルコードのデバッグ

[**Blobrunner**](https://github.com/OALabs/BlobRunner)は、シェルコードをメモリ内のスペースに割り当て、シェルコードが割り当てられたメモリアドレスを示し、実行を停止します。\
その後、プロセスにデバッガ（Idaまたはx64dbg）をアタッチし、指定されたメモリアドレスにブレークポイントを設定し、実行を再開します。これにより、シェルコードをデバッグできます。

リリースのGitHubページには、コンパイルされたリリースが含まれるzipファイルがあります：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクに、Blobrunnerのわずかに変更されたバージョンがあります。コンパイルするには、Visual Studio CodeでC/C++プロジェクトを作成し、コードをコピーして貼り付け、ビルドします。

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### jmp2itを使用したシェルコードのデバッグ

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)は、blobrunnerと非常に似ています。シェルコードをメモリ内のスペースに割り当て、**永遠のループ**を開始します。その後、デバッガをプロセスにアタッチし、**再生を開始し、2〜5秒待って停止**し、**永遠のループ**内にいます。永遠のループの次の命令にジャンプし、最終的にシェルコードを実行します。

![](<../../.gitbook/assets/image (397).png>)

[リリースページからjmp2itのコンパイル済みバージョンをダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutterを使用したシェルコードのデバッグ

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)は、radareのGUIです。Cutterを使用すると、シェルコードをエミュレートして動的に検査できます。

Cutterでは、「ファイルを開く」と「シェルコードを開く」の両方が可能です。私の場合、シェルコードをファイルとして開いた場合は正しく逆コンパイルされましたが、シェルコードとして開いた場合は逆コンパイルされませんでした。

![](<../../.gitbook/assets/image (400).png>)

特定の場所でエミュレーションを開始するには、そこにブレークポイントを設定し、おそらくCutterは自動的にそこからエミュレーションを開始します。

![](<../../.gitbook/assets/image (399).png>)

例えば、ヘックスダンプ内でスタックを表示できます。

![](<../../.gitbook/assets/image (402).png>)
### シェルコードの難読化を解除し、実行される関数を取得する

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152)を試してみるべきです。\
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

![](<../../.gitbook/assets/image (398).png>)

**Create Dump**オプションは、シェルコードがメモリ内で動的に変更された場合に、最終的なシェルコードをダンプします（デコードされたシェルコードをダウンロードするのに便利です）。**start offset**は、特定のオフセットでシェルコードを開始するのに役立ちます。**Debug Shell**オプションは、scDbgターミナルを使用してシェルコードをデバッグするのに便利です（ただし、前述のオプションのいずれかを使用する方が、Idaやx64dbgを使用できるため、より良いです）。

### CyberChefを使用した逆アセンブル

シェルコードファイルを入力としてアップロードし、次のレシピを使用して逆アセンブルします：[https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この難読化ツールは、すべての`mov`命令を変更します（本当にクールですね）。また、実行フローを変更するために割り込みも使用します。詳細については、以下を参照してください：

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

運が良ければ、[demovfuscator](https://github.com/kirschju/demovfuscator)がバイナリを復号化します。いくつかの依存関係があります。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
そして、[keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

もし**CTFをプレイしている場合、フラグを見つけるためのこの回避策**は非常に役立つかもしれません：[https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**エントリーポイント**を見つけるには、次のように`::main`で関数を検索します：

![](<../../.gitbook/assets/image (612).png>)

この場合、バイナリの名前はauthenticatorと呼ばれているため、これが興味深いmain関数であることは明らかです。\
呼び出されている**関数の名前**を持っている場合、それらを**インターネット**で検索して、その**入力**と**出力**について学びます。

## **Delphi**

Delphiでコンパイルされたバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)を使用できます

Delphiバイナリをリバースエンジニアリングする場合は、IDAプラグイン[https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)を使用することをおすすめします

単に**ATL+f7**（IDAでPythonプラグインをインポート）を押し、Pythonプラグインを選択します。

このプラグインはバイナリを実行し、デバッグの開始時に関数名を動的に解決します。デバッグを開始した後、再びStartボタン（緑色のボタンまたはf9）を押すと、実際のコードの最初にブレークポイントがヒットします。

また、グラフィックアプリケーションでボタンを押すと、デバッガはそのボタンによって実行される関数で停止します。

## Golang

Golangバイナリをリバースエンジニアリングする場合は、IDAプラグイン[https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)を使用することをおすすめします

単に**ATL+f7**（IDAでPythonプラグインをインポート）を押し、Pythonプラグインを選択します。

これにより、関数の名前が解決されます。

## コンパイルされたPython

このページでは、ELF/EXE形式のPythonコンパイルバイナリからPythonコードを取得する方法が説明されています：

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - ゲームボーイアドバンス

GBAゲームの**バイナリ**を取得した場合、さまざまなツールを使用して**エミュレート**および**デバッグ**することができます：

* [**no$gba**](https://problemkaputt.de/gba.htm)（デバッグバージョンをダウンロード）- インターフェース付きのデバッガが含まれています
* [**mgba** ](https://mgba.io)- CLIデバッガが含まれています
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidraプラグイン
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidraプラグイン

[**no$gba**](https://problemkaputt.de/gba.htm)では、_**Options --> Emulation Setup --> Controls**_\*\* \*\*でGame Boy Advanceの**ボタン**を押す方法がわかります

![](<../../.gitbook/assets/image (578).png>)

押されたとき、各**キーには値**があり、それを識別するための値があります：
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
そうですね、この種のプログラムでは、興味深い部分は**プログラムがユーザーの入力を処理する方法**です。アドレス**0x4000130**には、一般的に見られる関数**KEYINPUT**があります。

![](<../../.gitbook/assets/image (579).png>)

前の画像では、関数が**FUN\_080015a8**から呼び出されていることがわかります（アドレス：_0x080015fa_と_0x080017ac_）。

その関数では、いくつかの初期化操作（重要ではない）の後に、以下のようなコードがあります。
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
このコードが見つかりました：
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
最後のif文は、**`uVar4`**が**最後のキー**にあるかどうかをチェックし、現在のキーではないことを確認しています。これは、ボタンを離すことを意味します（現在のキーは**`uVar1`**に格納されています）。
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
前のコードでは、**uVar1**（**押されたボタンの値**が格納される場所）といくつかの値を比較しています：

* 最初に、**値4**（**SELECT**ボタン）と比較されます：このボタンはチャレンジで画面をクリアします。
* 次に、**値8**（**START**ボタン）と比較されます：このボタンはコードがフラグを取得するために有効かどうかをチェックします。
* この場合、変数**`DAT_030000d8`**は0xf3と比較され、値が同じであればいくつかのコードが実行されます。
* それ以外の場合、いくつかのcont（`DAT_030000d4`）がチェックされます。これはcontであるため、コードに入る直後に1が追加されます。\
8未満の場合、**`DAT_030000d8`**に値を**追加**する何かが行われます（基本的には、contが8未満の間、押されたキーの値をこの変数に追加しています）。

したがって、このチャレンジでは、ボタンの値を知り、**長さが8未満の組み合わせを押して、結果の加算が0xf3になる必要がありました。**

このチュートリアルの参考資料：[**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## ゲームボーイ

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## コース

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（バイナリの逆変換）

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
