{{#include ../../banners/hacktricks-training.md}}

# Wasm デコンパイルと Wat コンパイルガイド

**WebAssembly** の領域では、**デコンパイル** と **コンパイル** のためのツールが開発者にとって不可欠です。このガイドでは、**Wasm (WebAssembly バイナリ)** と **Wat (WebAssembly テキスト)** ファイルを扱うためのオンラインリソースとソフトウェアを紹介します。

## オンラインツール

- Wasm を Wat に **デコンパイル** するためには、[Wabt's wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) のツールが便利です。
- Wat を Wasm に **コンパイル** するためには、[Wabt's wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) が役立ちます。
- 別のデコンパイルオプションは、[web-wasmdec](https://wwwg.github.io/web-wasmdec/) で見つけることができます。

## ソフトウェアソリューション

- より堅牢なソリューションとして、[JEB by PNF Software](https://www.pnfsoftware.com/jeb/demo) は広範な機能を提供します。
- オープンソースプロジェクト [wasmdec](https://github.com/wwwg/wasmdec) もデコンパイル作業に利用可能です。

# .Net デコンパイルリソース

.Net アセンブリのデコンパイルは、以下のツールを使用して行うことができます：

- [ILSpy](https://github.com/icsharpcode/ILSpy) は、[Visual Studio Code 用のプラグイン](https://github.com/icsharpcode/ilspy-vscode) も提供しており、クロスプラットフォームでの使用が可能です。
- **デコンパイル**、**修正**、および **再コンパイル** に関する作業には、[dnSpy](https://github.com/0xd4d/dnSpy/releases) が強く推奨されます。メソッドを **右クリック** し、**Modify Method** を選択することでコードの変更が可能です。
- [JetBrains' dotPeek](https://www.jetbrains.com/es-es/decompiler/) は、.Net アセンブリのデコンパイルのための別の選択肢です。

## DNSpy を使用したデバッグとロギングの強化

### DNSpy ロギング

DNSpy を使用してファイルに情報をログするには、以下の .Net コードスニペットを組み込みます：

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy デバッグ

DNSpy を使用した効果的なデバッグのためには、デバッグのために **Assembly 属性** を調整する一連の手順が推奨され、デバッグを妨げる可能性のある最適化が無効にされます。このプロセスには、`DebuggableAttribute` 設定の変更、アセンブリの再コンパイル、および変更の保存が含まれます。

さらに、**IIS** によって実行される .Net アプリケーションをデバッグするために、`iisreset /noforce` を実行して IIS を再起動します。デバッグのために DNSpy を IIS プロセスにアタッチするには、DNSpy 内で **w3wp.exe** プロセスを選択し、デバッグセッションを開始するように指示します。

デバッグ中に読み込まれたモジュールの包括的なビューを得るためには、DNSpy の **Modules** ウィンドウにアクセスし、すべてのモジュールを開いてアセンブリをソートして、ナビゲーションとデバッグを容易にすることが推奨されます。

このガイドは、WebAssembly と .Net デコンパイルの本質を要約し、開発者がこれらの作業を容易にナビゲートできる道筋を提供します。

## **Java デコンパイラ**

Java バイトコードをデコンパイルするために、これらのツールが非常に役立ちます：

- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **DLL のデバッグ**

### IDA を使用

- **Rundll32** は、64 ビットおよび 32 ビットバージョンの特定のパスからロードされます。
- **Windbg** は、ライブラリのロード/アンロード時に一時停止するオプションを有効にしてデバッガとして選択されます。
- 実行パラメータには DLL パスと関数名が含まれます。この設定により、各 DLL のロード時に実行が停止します。

### x64dbg/x32dbg を使用

- IDA と同様に、**rundll32** はコマンドラインの変更を加えて DLL と関数を指定してロードされます。
- DLL エントリでブレークするように設定が調整され、希望する DLL エントリポイントでブレークポイントを設定できます。

### 画像

- 実行停止ポイントと設定は、スクリーンショットを通じて示されています。

## **ARM & MIPS**

- エミュレーションのために、[arm_now](https://github.com/nongiach/arm_now) は便利なリソースです。

## **シェルコード**

### デバッグ技術

- **Blobrunner** と **jmp2it** は、メモリ内にシェルコードを割り当て、Ida または x64dbg でデバッグするためのツールです。
- Blobrunner [リリース](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [コンパイル版](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** は、GUI ベースのシェルコードエミュレーションと検査を提供し、ファイルとしてのシェルコード処理と直接シェルコード処理の違いを強調します。

### デオブフスケーションと分析

- **scdbg** は、シェルコードの機能とデオブフスケーション機能に関する洞察を提供します。
%%%bash
scdbg.exe -f shellcode # 基本情報
scdbg.exe -f shellcode -r # 分析レポート
scdbg.exe -f shellcode -i -r # インタラクティブフック
scdbg.exe -f shellcode -d # デコードされたシェルコードをダンプ
scdbg.exe -f shellcode /findsc # 開始オフセットを見つける
scdbg.exe -f shellcode /foff 0x0000004D # オフセットから実行
%%%

- シェルコードの逆アセンブルに **CyberChef** を使用： [CyberChef レシピ](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**

- すべての命令を `mov` に置き換えるオブフスケータです。
- 有用なリソースには、[YouTube の説明](https://www.youtube.com/watch?v=2VF_wPkiBJY) と [PDF スライド](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf) が含まれます。
- **demovfuscator** は movfuscator のオブフスケーションを逆転させる可能性があり、`libcapstone-dev` と `libz3-dev` のような依存関係が必要で、[keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) をインストールする必要があります。

## **Delphi**

- Delphi バイナリには、[IDR](https://github.com/crypto2011/IDR) が推奨されます。

# コース

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(バイナリデオブフスケーション\)

{{#include ../../banners/hacktricks-training.md}}
