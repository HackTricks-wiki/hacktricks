# リバースツールと基本的な手法

{{#include ../../banners/hacktricks-training.md}}

## ImGuiベースのリバースツール

ソフトウェア:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasmデコンパイラ / Watコンパイラ

オンライン:

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使用して、**wasm**（バイナリ）から**wat**（クリアテキスト）に**デコンパイル**します。
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使用して、**wat**から**wasm**に**コンパイル**します。
- [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/)を使用してデコンパイルすることもできます。

ソフトウェア:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NETデコンパイラ

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、**ライブラリ**（.dll）、**Windowsメタデータファイル**（.winmd）、および**実行可能ファイル**（.exe）を含む**複数のフォーマットをデコンパイルおよび検査**するデコンパイラです。デコンパイルされた後、アセンブリはVisual Studioプロジェクト（.csproj）として保存できます。

ここでの利点は、失われたソースコードをレガシーアセンブリから復元する必要がある場合、このアクションが時間を節約できることです。さらに、dotPeekはデコンパイルされたコード全体を便利にナビゲートできるため、**Xamarinアルゴリズム分析**に最適なツールの1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ツールを正確なニーズに合わせて拡張するAPIを備えた.NET Reflectorは、時間を節約し、開発を簡素化します。このツールが提供する逆コンパイルサービスの豊富さを見てみましょう：

- ライブラリやコンポーネントを通じてデータがどのように流れるかの洞察を提供します。
- .NET言語やフレームワークの実装と使用に関する洞察を提供します。
- 使用されているAPIや技術からより多くの機能を引き出すために、文書化されていない機能や公開されていない機能を見つけます。
- 依存関係や異なるアセンブリを見つけます。
- コード、サードパーティコンポーネント、およびライブラリ内のエラーの正確な場所を追跡します。
- あなたが扱うすべての.NETコードのソースをデバッグします。

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode): どのOSでも使用できます（VSCodeから直接インストールできます。gitをダウンロードする必要はありません。**拡張機能**をクリックし、**ILSpy**を検索します）。\
**デコンパイル**、**修正**、および再**コンパイル**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)またはそのアクティブにメンテナンスされているフォークである[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます。（**右クリック -> メソッドを修正**して関数内の何かを変更します）。

### DNSpyロギング

**DNSpyがファイルに情報をログする**ために、このスニペットを使用できます：
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy デバッグ

DNSpy を使用してコードをデバッグするには、次の手順を実行する必要があります。

まず、**デバッグ**に関連する **Assembly 属性** を変更します：

![](<../../images/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
翻訳する内容が提供されていません。翻訳が必要なテキストを提供してください。
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
そして、**compile**をクリックします：

![](<../../images/image (314) (1).png>)

次に、_**File >> Save module...**_を介して新しいファイルを保存します：

![](<../../images/image (602).png>)

これは必要です。なぜなら、これを行わないと、**runtime**中にいくつかの**optimisations**がコードに適用され、デバッグ中に**break-pointが決してヒットしない**か、いくつかの**variablesが存在しない**可能性があるからです。

次に、.NETアプリケーションが**IIS**によって**run**されている場合は、次のコマンドで**restart**できます：
```
iisreset /noforce
```
すべての開いているファイルを閉じて、**Debug Tab**内で**Attach to Process...**を選択します：

![](<../../images/image (318).png>)

次に、**IIS server**にアタッチするために**w3wp.exe**を選択し、**attach**をクリックします：

![](<../../images/image (113).png>)

プロセスのデバッグを開始したので、実行を停止してすべてのモジュールをロードする時間です。まず、_Debug >> Break All_をクリックし、次に_**Debug >> Windows >> Modules**_をクリックします：

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

**Modules**の任意のモジュールをクリックし、**Open All Modules**を選択します：

![](<../../images/image (922).png>)

**Assembly Explorer**の任意のモジュールを右クリックし、**Sort Assemblies**をクリックします：

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64ビットはC:\Windows\System32\rundll32.exe、32ビットはC:\Windows\SysWOW64\rundll32.exe)
- **Windbg**デバッガを選択
- "**Suspend on library load/unload**"を選択

![](<../../images/image (868).png>)

- 実行の**parameters**を設定し、**DLLのパス**と呼び出したい関数を指定します：

![](<../../images/image (704).png>)

次に、デバッグを開始すると、**各DLLがロードされると実行が停止します**。その後、rundll32があなたのDLLをロードすると、実行が停止します。

しかし、ロードされたDLLのコードにどうやってアクセスできますか？この方法では、私はわかりません。

### Using x64dbg/x32dbg

- **Load rundll32** (64ビットはC:\Windows\System32\rundll32.exe、32ビットはC:\Windows\SysWOW64\rundll32.exe)
- **Command Lineを変更** (_File --> Change Command Line_)し、DLLのパスと呼び出したい関数を設定します。例えば："C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_を変更し、**DLL Entry**を選択します。
- その後、**実行を開始**します。デバッガは各DLLのメインで停止し、ある時点で**あなたのDLLのDLL Entryで停止します**。そこから、ブレークポイントを設定したいポイントを検索します。

実行が何らかの理由でwin64dbgで停止した場合、**win64dbgウィンドウの上部**で**どのコードを見ているか**を確認できます：

![](<../../images/image (842).png>)

これにより、デバッグしたいDLLで実行が停止したときに確認できます。

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのメモリ内に重要な値が保存されている場所を見つけて変更するのに役立つプログラムです。詳細は以下を参照してください：

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE)は、GNU Project Debugger (GDB)のフロントエンド/リバースエンジニアリングツールで、ゲームに特化しています。ただし、リバースエンジニアリングに関連する任意の作業にも使用できます。

[**Decompiler Explorer**](https://dogbolt.org/)は、いくつかのデコンパイラへのウェブフロントエンドです。このウェブサービスを使用すると、小さな実行可能ファイルに対する異なるデコンパイラの出力を比較できます。

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner)は、**shellcode**をメモリのスペース内に**割り当て**、**shellcode**が割り当てられた**メモリアドレス**を**示し**、実行を**停止**します。\
その後、プロセスに**デバッガ**（Idaまたはx64dbg）をアタッチし、**指定されたメモリアドレスにブレークポイントを設定**し、実行を**再開**します。これにより、shellcodeのデバッグが行えます。

リリースのGitHubページには、コンパイルされたリリースを含むzipファイルがあります：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクにBlobrunnerのわずかに修正されたバージョンがあります。コンパイルするには、**Visual Studio CodeでC/C++プロジェクトを作成し、コードをコピー＆ペーストしてビルド**します。

{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)は、blobrunnerに非常に似ています。**shellcode**をメモリのスペース内に**割り当て**、**永続ループ**を開始します。その後、プロセスに**デバッガをアタッチ**し、**再生を開始して2-5秒待ち、停止を押す**と、**永続ループ**内に入ります。永続ループの次の命令にジャンプすると、それはshellcodeへの呼び出しになります。最終的に、shellcodeを実行している自分を見つけることができます。

![](<../../images/image (509).png>)

コンパイルされたバージョンは、[リリースページ](https://github.com/adamkramer/jmp2it/releases/)からダウンロードできます。

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)は、radareのGUIです。Cutterを使用すると、shellcodeをエミュレートし、動的に検査できます。

Cutterは「ファイルを開く」と「shellcodeを開く」を許可します。私の場合、shellcodeをファイルとして開くと正しくデコンパイルされましたが、shellcodeとして開くとそうではありませんでした：

![](<../../images/image (562).png>)

エミュレーションを開始したい場所にbpを設定すると、Cutterは自動的にそこからエミュレーションを開始します：

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

例えば、16進ダンプ内でスタックを見ることができます：

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152)を試してみるべきです。\
それは、**どの関数**がshellcodeで使用されているか、またshellcodeが**メモリ内で自分自身をデコード**しているかどうかを教えてくれます。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbgには、選択したオプションを選んでシェルコードを実行できるグラフィカルランチャーもあります。

![](<../../images/image (258).png>)

**Create Dump**オプションは、メモリ内でシェルコードに動的に変更が加えられた場合に最終的なシェルコードをダンプします（デコードされたシェルコードをダウンロードするのに便利です）。**start offset**は、特定のオフセットでシェルコードを開始するのに役立ちます。**Debug Shell**オプションは、scDbgターミナルを使用してシェルコードをデバッグするのに便利ですが、Idaやx64dbgを使用できるため、前述のオプションの方がこの目的には適していると思います。

### CyberChefを使用した逆アセンブル

シェルコードファイルを入力としてアップロードし、次のレシピを使用して逆コンパイルします: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この難読化ツールは、**すべての`mov`命令を修正します**（本当にクールです）。実行フローを変更するために割り込みも使用します。どのように機能するかについての詳細は以下を参照してください:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

運が良ければ、[demovfuscator](https://github.com/kirschju/demovfuscator)がバイナリをデオブfuscateします。いくつかの依存関係があります。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
そして[keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)します（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

**CTFをプレイしている場合、このフラグを見つけるためのこの回避策**は非常に役立つかもしれません: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**エントリーポイント**を見つけるには、`::main`で関数を検索します:

![](<../../images/image (1080).png>)

この場合、バイナリはauthenticatorと呼ばれていたので、これは興味深いメイン関数であることは明らかです。\
呼び出されている**関数**の**名前**を持っているので、**インターネット**でそれらを検索して**入力**と**出力**について学びます。

## **Delphi**

Delphiでコンパイルされたバイナリには、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)を使用できます。

Delphiバイナリをリバースする必要がある場合は、IDAプラグイン[https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)を使用することをお勧めします。

**ATL+f7**を押して（IDAにPythonプラグインをインポート）Pythonプラグインを選択します。

このプラグインは、バイナリを実行し、デバッグの開始時に関数名を動的に解決します。デバッグを開始した後、再度スタートボタン（緑のボタンまたはf9）を押すと、実際のコードの最初にブレークポイントがヒットします。

また、グラフィックアプリケーションでボタンを押すと、デバッガーはそのボタンによって実行された関数で停止するため、非常に興味深いです。

## Golang

Golangバイナリをリバースする必要がある場合は、IDAプラグイン[https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)を使用することをお勧めします。

**ATL+f7**を押して（IDAにPythonプラグインをインポート）Pythonプラグインを選択します。

これにより、関数の名前が解決されます。

## コンパイルされたPython

このページでは、ELF/EXE PythonコンパイルバイナリからPythonコードを取得する方法を見つけることができます:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

GBAゲームの**バイナリ**を取得した場合、さまざまなツールを使用して**エミュレート**および**デバッグ**できます:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_デバッグ版をダウンロード_) - インターフェースを持つデバッガーを含む
- [**mgba** ](https://mgba.io) - CLIデバッガーを含む
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidraプラグイン
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidraプラグイン

[**no$gba**](https://problemkaputt.de/gba.htm)の_**Options --> Emulation Setup --> Controls**_\*\* \*\*では、Game Boy Advanceの**ボタン**を押す方法を確認できます。

![](<../../images/image (581).png>)

押すと、各**キーには識別するための値**があります:
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
この種のプログラムでは、興味深い部分は**プログラムがユーザー入力をどのように処理するか**です。アドレス**0x4000130**には、一般的に見られる関数**KEYINPUT**があります。

![](<../../images/image (447).png>)

前の画像では、関数が**FUN_080015a8**から呼び出されているのがわかります（アドレス: _0x080015fa_ と _0x080017ac_）。

その関数では、いくつかの初期化操作の後（重要ではない）:
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
最後のifは**`uVar4`**が**最後のキー**にあり、現在のキーではないことを確認しています。現在のキーは**`uVar1`**に保存されています。
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
前のコードでは、**uVar1**（**押されたボタンの値**が格納されている場所）をいくつかの値と比較しています：

- 最初に、**値4**（**SELECT**ボタン）と比較されています：このチャレンジでは、このボタンは画面をクリアします。
- 次に、**値8**（**START**ボタン）と比較されています：このチャレンジでは、コードがフラグを取得するのに有効かどうかを確認します。
- この場合、変数**`DAT_030000d8`**は0xf3と比較され、値が同じであればいくつかのコードが実行されます。
- その他のケースでは、いくつかのcont（`DAT_030000d4`）がチェックされます。これは、コードに入った直後に1を加算するためcontです。\
**8未満**の場合、**`DAT_030000d8`**に値を**加算する**ことが行われます（基本的には、contが8未満の間、押されたキーの値をこの変数に加算しています）。

したがって、このチャレンジでは、ボタンの値を知っている必要があり、**結果の合計が0xf3になるように、長さが8未満の組み合わせを押す必要があります。**

**このチュートリアルの参考文献：** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（バイナリの難読化解除）

{{#include ../../banners/hacktricks-training.md}}
