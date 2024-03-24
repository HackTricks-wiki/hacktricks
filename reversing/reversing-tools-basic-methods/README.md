# リバースエンジニアリングツール＆基本的な手法

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や、**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**する
- **ハッキングトリックを共有するために、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## ImGuiベースのリバースエンジニアリングツール

ソフトウェア：

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasmデコンパイラ/Watコンパイラ

オンライン：

- [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)を使用して、wasm（バイナリ）からwat（クリアテキスト）に**デコンパイル**します
- [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/)を使用して、watからwasmに**コンパイル**します
- [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/)を使用してデコンパイルすることもできます

ソフトウェア：

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NETデコンパイラ

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeekは、**ライブラリ**（.dll）、**Windowsメタデータファイル**（.winmd）、および**実行可能ファイル**（.exe）など、複数の形式を**デコンパイルおよび調査**します。デコンパイルされたアセンブリは、Visual Studioプロジェクト（.csproj）として保存できます。

ここでのメリットは、失われたソースコードを復元する必要がある場合、このアクションが時間を節約できることです。さらに、dotPeekは、デコンパイルされたコード全体を便利にナビゲートできるため、**Xamarinアルゴリズム分析**に最適なツールの1つです。

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

包括的なアドインモデルと、ツールを拡張して正確なニーズに合わせるAPIを備えた.NET Reflectorは、時間を節約し、開発を簡素化します。このツールが提供する逆コンパイルサービスの多様性を見てみましょう：

- データがライブラリやコンポーネントを通過する方法に洞察を提供します
- .NET言語やフレームワークの実装と使用方法に洞察を提供します
- 使用されているAPIや技術からより多くの情報を取得するために、未記載および非公開の機能を見つけます
- 依存関係や異なるアセンブリを見つけます
- コード、サードパーティのコンポーネント、およびライブラリのエラーの正確な場所を特定します
- 作業しているすべての.NETコードのソースにデバッグします

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code用ILSpyプラグイン](https://github.com/icsharpcode/ilspy-vscode)：任意のOSで使用できます（VSCodeから直接インストールでき、gitをダウンロードする必要はありません。**Extensions**をクリックして**ILSpy**を検索します）。\
**デコンパイル**、**変更**、そして**再コンパイル**する必要がある場合は、[**dnSpy**](https://github.com/dnSpy/dnSpy/releases)またはそれを積極的にメンテナンスしているフォークの[**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases)を使用できます（関数内の何かを変更するには、**右クリック -> メソッドの変更**）。

### DNSpyログ

**DNSpyが情報をファイルに記録するようにする**には、次のスニペットを使用できます：
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy デバッグ

DNSpyを使用してコードをデバッグするには、次の手順を実行する必要があります：

まず、**デバッグ**に関連する**アセンブリ属性**を変更します：

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
## リバースエンジニアリングツールと基本的な手法

このセクションでは、リバースエンジニアリングに使用される一般的なツールと基本的な手法について説明します。リバースエンジニアリングは、プログラムやファイルを解析して、その動作や構造を理解するプロセスです。リバースエンジニアリングを行うことで、セキュリティ研究や脆弱性診断、マルウェア解析などのさまざまな目的に活用できます。
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
そして**コンパイル**をクリックしてください：

![](<../../.gitbook/assets/image (314) (1) (1).png>)

次に、新しいファイルを _**ファイル >> モジュールを保存...**_ で保存してください：

![](<../../.gitbook/assets/image (279).png>)

これは必要です。なぜなら、これを行わないと、**実行時**にいくつかの**最適化**がコードに適用され、**デバッグ**中に**ブレークポイントがヒットしない**か、一部の**変数が存在しない**可能性があるからです。

その後、.NETアプリケーションが**IIS**によって**実行**されている場合は、次のように**再起動**できます：
```
iisreset /noforce
```
その後、デバッグを開始するためには、すべての開いているファイルを閉じ、**デバッグタブ**内で**プロセスにアタッチ**を選択します：

![](<../../.gitbook/assets/image (280).png>)

次に、**w3wp.exe**を選択して**IISサーバー**にアタッチし、**アタッチ**をクリックします：

![](<../../.gitbook/assets/image (281).png>)

プロセスのデバッグが開始されたので、プロセスを停止してすべてのモジュールをロードする時間です。まず、_Debug >> Break All_をクリックし、次に_Debug >> Windows >> Modules_をクリックします：

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

**モジュール**の中の任意のモジュールをクリックし、**Open All Modules**を選択します：

![](<../../.gitbook/assets/image (284).png>)

**アセンブリエクスプローラ**内の任意のモジュールを右クリックし、**Sort Assemblies**をクリックします：

![](<../../.gitbook/assets/image (285).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### IDAを使用する

* **rundll32をロード**（64ビットはC:\Windows\System32\rundll32.exe、32ビットはC:\Windows\SysWOW64\rundll32.exe）
* **Windbgデバッガー**を選択
* "**ライブラリの読み込み/アンロード時に中断**"を選択

![](<../../.gitbook/assets/image (135).png>)

* **実行のパラメータ**を構成し、**DLLへのパス**と呼び出したい関数を入力します：

![](<../../.gitbook/assets/image (136).png>)

その後、デバッグを開始すると、**各DLLがロードされるたびに実行が停止**されます。そのため、rundll32がDLLをロードすると実行が停止します。

しかし、ロードされたDLLのコードにどのようにアクセスできますか？この方法を使用して、その方法はわかりません。

### x64dbg/x32dbgを使用する

* **rundll32をロード**（64ビットはC:\Windows\System32\rundll32.exe、32ビットはC:\Windows\SysWOW64\rundll32.exe）
* コマンドラインを変更（_File --> Change Command Line_）し、dllのパスと呼び出したい関数を設定します。例： "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* _Options --> Settings_を変更し、「**DLL Entry**」を選択します。
* その後、**実行を開始**し、デバッガーは各dllメインで停止します。いずれかの時点で、**dll Entry of your dll**で実行が停止します。そこから、ブレークポイントを設定したいポイントを検索します。

実行がwin64dbgで何らかの理由で停止されると、**win64dbgウィンドウの上部**にいる**どのコードを見ているか**が表示されます：

![](<../../.gitbook/assets/image (137).png>)

その後、実行が停止されたdll内のコードを確認できます。

## GUIアプリ/ビデオゲーム

[**Cheat Engine**](https://www.cheatengine.org/downloads.php)は、実行中のゲームのメモリ内に重要な値が保存されている場所を見つけ、それらを変更するための便利なプログラムです。詳細は以下を参照してください：

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## シェルコード

### Blobrunnerを使用してシェルコードをデバッグする

[**Blobrunner**](https://github.com/OALabs/BlobRunner)は、メモリ空間内に**シェルコード**を**割り当て**し、シェルコードが割り当てられた**メモリアドレス**を示し、実行を**停止**します。\
その後、プロセスにデバッガー（Idaまたはx64dbg）を**アタッチ**し、指定されたメモリアドレスに**ブレークポイントを設定**し、実行を**再開**します。これにより、シェルコードをデバッグできます。

リリースのGitHubページには、コンパイルされたリリースが含まれるzipファイルがあります：[https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
以下のリンクにBlobrunnerのわずかに変更されたバージョンがあります。コンパイルするには、Visual Studio CodeでC/C++プロジェクトを作成し、コードをコピーして貼り付け、ビルドします。

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### jmp2itを使用してシェルコードをデバッグする

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)はBlobrunnerに非常に似ています。**シェルコード**を**メモリ空間内に割り当て**、**永遠のループ**を開始します。その後、プロセスにデバッガーを**アタッチ**し、**開始して2〜5秒待機してから停止**を押すと、**永遠のループ**内にいます。永遠のループの次の命令にジャンプしてシェルコードを呼び出し、最終的にシェルコードを実行します。

![](<../../.gitbook/assets/image (397).png>)

[リリースページ内でjmp2itのコンパイル済みバージョンをダウンロードできます](https://github.com/adamkramer/jmp2it/releases/)。

### Cutterを使用してシェルコードをデバッグする

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0)はradareのGUIです。Cutterを使用すると、シェルコードをエミュレートして動的に検査できます。

Cutterを使用すると、「ファイルを開く」と「シェルコードを開く」が可能です。私の場合、シェルコードをファイルとして開くと正しく逆コンパイルされましたが、シェルコードとして開くとできませんでした：

![](<../../.gitbook/assets/image (400).png>)

特定の場所でエミュレーションを開始するには、そこにブレークポイントを設定し、おそらくcutterは自動的にそこからエミュレーションを開始します：

![](<../../.gitbook/assets/image (399).png>)

![](<../../.gitbook/assets/image (401).png>)

例えば、ヘックスダンプ内でスタックを表示できます：

![](<../../.gitbook/assets/image (402).png>)

### シェルコードの逆コンパイルと実行される関数の取得

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152)を試してみてください。\
シェルコードが使用している**関数**や、シェルコードがメモリ内で**デコード**されているかどうかなどがわかります。
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbgには、グラフィカルなランチャーも付属しており、希望するオプションを選択してシェルコードを実行することができます。

![](<../../.gitbook/assets/image (398).png>)

**Create Dump** オプションは、メモリ内でシェルコードが動的に変更された場合に最終的なシェルコードをダンプします（デコードされたシェルコードをダウンロードするのに便利です）。**start offset** は特定のオフセットでシェルコードを開始するのに役立ちます。**Debug Shell** オプションは、scDbgターミナルを使用してシェルコードをデバッグするのに役立ちます（ただし、前述のいずれかのオプションの方がこの問題にはより適していると考えています。Idaまたはx64dbgを使用できるため）。

### CyberChefを使用した逆アセンブリ

シェルコードファイルを入力としてアップロードし、次のレシピを使用して逆コンパイルします：[https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

この難読化ツールは、すべての`mov`命令を変更します（本当にクールです）。また、実行フローを変更するために割り込みを使用します。動作の詳細については以下を参照してください：

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

幸運な場合、[demovfuscator](https://github.com/kirschju/demovfuscator)がバイナリを復号化します。いくつかの依存関係があります。
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
そして、[keystoneをインストール](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)してください（`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`）

**CTFをプレイしている場合、このフラグを見つけるためのワークアラウンド**は非常に役立ちます: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**エントリーポイント**を見つけるには、次のように`::main`で関数を検索します:

![](<../../.gitbook/assets/image (612).png>)

この場合、バイナリの名前はauthenticatorと呼ばれていたので、これが興味深いmain関数であることはかなり明らかです。\
**呼び出されている関数の名前**を持っている場合は、それらを**インターネット**で検索して、それらの**入力**と**出力**について学びます。

## **Delphi**

Delphiでコンパイルされたバイナリを逆アセンブルする場合は、[https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)を使用できます

Delphiバイナリを逆アセンブルする必要がある場合は、IDAプラグイン[https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)を使用することをお勧めします

単に**ATL+f7**（IDAでPythonプラグインをインポート）を押し、Pythonプラグインを選択します。

このプラグインはバイナリを実行し、デバッグの開始時に関数名を動的に解決します。デバッグを開始した後は、再度Startボタン（緑色のボタンまたはf9）を押すと、実際のコードの最初にブレークポイントがヒットします。

また、グラフィックアプリケーションでボタンを押すと、そのボタンによって実行される関数でデバッガが停止します。

## Golang

Golangバイナリを逆アセンブルする必要がある場合は、IDAプラグイン[https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)を使用することをお勧めします

単に**ATL+f7**（IDAでPythonプラグインをインポート）を押し、Pythonプラグインを選択します。

これにより、関数の名前が解決されます。

## コンパイルされたPython

このページでは、ELF/EXE PythonコンパイルされたバイナリからPythonコードを取得する方法が見つかります:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - ゲームボーイアドバンス

GBAゲームの**バイナリ**を取得した場合、それを**エミュレート**および**デバッグ**するために異なるツールを使用できます:

* [**no$gba**](https://problemkaputt.de/gba.htm)（_デバッグバージョンをダウンロード_） - インターフェース付きのデバッガを含む
* [**mgba** ](https://mgba.io)- CLIデバッガを含む
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidraプラグイン
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidraプラグイン

[**no$gba**](https://problemkaputt.de/gba.htm)では、_**Options --> Emulation Setup --> Controls**_でGame Boy Advanceの**ボタン**を押す方法がわかります

![](<../../.gitbook/assets/image (578).png>)

押されると、各**キーには値**があり、それを識別するために使用されます:
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
したがって、この種のプログラムでは、興味深いのは**プログラムがユーザー入力を処理する方法**です。アドレス**0x4000130**には、一般的に見られる関数**KEYINPUT**があります。

![](<../../.gitbook/assets/image (579).png>)

前の画像では、その関数が**FUN\_080015a8**（アドレス：_0x080015fa_および_0x080017ac_）から呼び出されていることがわかります。

その関数では、いくつかの初期化操作（重要ではない）の後に：
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
最後のif文は、**`uVar4`** が**最後のキー**にあるかどうかをチェックし、現在のキーではないことを確認しています（現在のキーは**`uVar1`**に保存されています）。
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

* まず、**値4**（**SELECT**ボタン）と比較されます：このボタンはチャレンジでは画面をクリアします
* 次に、**値8**（**START**ボタン）と比較されます：このチャレンジでは、コードがフラグを取得するために有効かどうかをチェックします。
* この場合、変数**`DAT_030000d8`**が0xf3と比較され、値が同じ場合はいくつかのコードが実行されます。
* それ以外の場合、一部のcont（`DAT_030000d4`）がチェックされます。これはcontであるため、コードに入るとすぐに1が追加されます。\
8未満の場合、**`DAT_030000d8`**に**値を追加**する何かが行われます（基本的には、contが8未満である限り、この変数に押されたキーの値を追加しています）。

したがって、このチャレンジでは、ボタンの値を知っていると、**長さが8未満で、結果の加算が0xf3になる組み合わせを押す必要がありました。**

**このチュートリアルの参考資料:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## ゲームボーイ

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## コース

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD)（バイナリの難読化）

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksのPDFをダウンロード**したり、**HackTricksで企業を宣伝**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**したり、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**したりしてください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
