<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じて、ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**@carlospolopm**を**フォロー**する[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

# Wasm Decompilation and Wat Compilation Guide

**WebAssembly**の世界では、**decompiling**と**compiling**のためのツールは開発者にとって不可欠です。このガイドでは、**Wasm（WebAssemblyバイナリ）**と**Wat（WebAssemblyテキスト）**ファイルを扱うためのいくつかのオンラインリソースやソフトウェアを紹介します。

## オンラインツール

- **WasmをWatにdecompile**するためには、[Wabtのwasm2watデモ](https://webassembly.github.io/wabt/demo/wasm2wat/index.html)が便利です。
- WatをWasmに**compiling**するためには、[Wabtのwat2wasmデモ](https://webassembly.github.io/wabt/demo/wat2wasm/)が役立ちます。
- 別のdecompilationオプションは、[web-wasmdec](https://wwwg.github.io/web-wasmdec/)で見つけることができます。

## ソフトウェアソリューション

- より堅牢なソリューションとして、[PNF SoftwareのJEB](https://www.pnfsoftware.com/jeb/demo)が包括的な機能を提供しています。
- オープンソースプロジェクトである[wasmdec](https://github.com/wwwg/wasmdec)もdecompilationタスクに利用できます。

# .Net Decompilation Resources

.Netアセンブリのdecompilingは、次のようなツールを使用して行うことができます：

- [ILSpy](https://github.com/icsharpcode/ILSpy)は、[Visual Studio Code用のプラグイン](https://github.com/icsharpcode/ilspy-vscode)も提供しており、クロスプラットフォームで使用できます。
- **decompilation**、**modification**、**recompilation**を含むタスクには、[dnSpy](https://github.com/0xd4d/dnSpy/releases)が強く推奨されています。メソッドを右クリックして**Modify Method**を選択すると、コードの変更が可能です。
- [JetBrainsのdotPeek](https://www.jetbrains.com/es-es/decompiler/)も、.Netアセンブリのdecompilingに対する別の選択肢です。

## DNSpyを使用したデバッグとロギングの強化

### DNSpy Logging
DNSpyを使用して情報をファイルに記録するには、次の.Netコードスニペットを組み込みます：

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy Debugging
DNSpyを使用した効果的なデバッグのためには、デバッグを妨げる可能性のある最適化が無効になっていることを確認するために、**Assembly属性**を調整するための手順のシーケンスが推奨されます。このプロセスには、`DebuggableAttribute`の設定の変更、アセンブリの再コンパイル、および変更の保存が含まれます。

さらに、**IIS**で実行される.Netアプリケーションをデバッグするには、`iisreset /noforce`を実行してIISを再起動します。デバッグのためにDNSpyをIISプロセスにアタッチするには、DNSpy内で**w3wp.exe**プロセスを選択し、デバッグセッションを開始します。

デバッグ中にロードされたモジュールの包括的な表示を得るためには、DNSpyの**Modules**ウィンドウにアクセスし、すべてのモジュールを開き、アセンブリをソートしてナビゲーションとデバッグを容易にすることが推奨されます。

このガイドは、WebAssemblyと.Netのdecompilationの本質を網羅し、開発者がこれらのタスクを簡単に行えるようにする経路を提供しています。

## **Java Decompiler**
Javaバイトコードをdecompileするために、これらのツールが非常に役立ちます：
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **DLLのデバッグ**
### IDAを使用する
- **Rundll32**は、64ビットおよび32ビットバージョン用に特定のパスからロードされます。
- **Windbg**は、ライブラリのロード/アンロード時に中断するオプションでデバッガとして選択されます。
- 実行パラメータには、DLLパスと関数名が含まれます。このセットアップにより、各DLLのロード時に実行が停止します。

### x64dbg/x32dbgを使用する
- IDAと同様に、**rundll32**がDLLと関数を指定するためのコマンドラインの変更でロードされます。
- 設定は、DLLエントリポイントでのブレークポイント設定を許可するように調整されます。

### 画像
- 実行停止ポイントと構成は、スクリーンショットを通じて示されます。

## **ARM＆MIPS**
- エミュレーションには、[arm_now](https://github.com/nongiach/arm_now)が便利なリソースです。

## **Shellcodes**
### デバッグテクニック
- **Blobrunner**と**jmp2it**は、メモリにシェルコードを割り当て、Idaまたはx64dbgでデバッグするためのツールです。
- Blobrunner [リリース](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [コンパイル済みバージョン](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter**は、GUIベースのシェルコードエミュレーションと検査を提供し、ファイルと直接シェルコードとしてのシェルコード処理の違いを強調します。

### Deobfuscation and Analysis
- **scdbg**は、シェルコードの機能とdeobfuscation機能を提供します。
%%%bash
scdbg.exe -f shellcode # 基本情報
scdbg.exe -f shellcode -r # 分析レポート
scdbg.exe -f shellcode -i -r # インタラクティブフック
scdbg.exe -f shellcode -d # デコードされたシェルコードをダンプ
scdbg.exe -f shellcode /findsc # 開始オフセットを検索
scdbg.exe -f shellcode /foff 0x0000004D # オフセットから実行
%%%

- **CyberChef**を使用してシェルコードを逆アセンブルする：[CyberChefレシピ](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- すべての命令を`mov`で置き換える難読化ツール。
- 有用なリソースには、[YouTubeの説明](https://www.youtube.com/watch?v=2VF_wPkiBJY)と[PDFスライド](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)が含まれます。
- **demovfuscator**は、movfuscatorの難読化を逆転させるかもしれませんが、`libcapstone-dev`や`libz3-dev`などの依存関係が必要であり、[keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md)のインストールが必要です。

## **Delphi**
- Delphiバイナリには、[IDR](https://github.com/crypto2011/IDR)が推奨されています。


# Courses

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Binary deobfuscation\)



<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じて、ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**@carlospolopm**を**フォロー**する[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>
