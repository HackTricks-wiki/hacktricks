# Officeファイル分析

{{#include ../../../banners/hacktricks-training.md}}

詳細については、[https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)を参照してください。これは単なる要約です:<sup>[[4]](#references)</sup>

Microsoft Officeドキュメントには、RTFやOLE/CFBFベースのDOC、XLS、PPTなどのレガシー形式や、DOCX、XLSX、PPTXなどの新しい **Office Open XML (OOXML)** 形式が一般的に使用されます。Officeドキュメントにはマクロなどのアクティブコンテンツが含まれる場合があり、フィッシングやマルウェアの一般的な媒介となっています。OOXMLファイルはZIPコンテナであり、解凍することでファイル階層とXMLの内容を調査できます。<sup>[[3]](#references)[[4]](#references)</sup>

OOXMLファイルの構造を調査するため、ドキュメントを解凍するコマンドと出力構造を示します。これらのファイルにデータを隠す技法も文書化されており、CTFチャレンジにおけるデータ隠蔽が継続的に発展していることを示しています。<sup>[[4]](#references)</sup>

分析には、**oletools**と**OfficeDissector**が、OLEおよびOOXMLドキュメントを調査するための包括的なツールセットを提供します。これらのツールは、埋め込まれたマクロの特定と分析に役立ちます。マクロは多くの場合、マルウェアを配布するためのベクトルとして機能し、通常は追加の悪意あるペイロードをダウンロードして実行します。VBAマクロの分析は、Microsoft Officeを使用せずにLibre Officeを利用して実施できます。Libre Officeでは、ブレークポイントやウォッチ変数を使用したデバッグが可能です。<sup>[[4]](#references)</sup>

**oletools**のインストールと使用方法は簡単で、pip経由でインストールし、ドキュメントからマクロを抽出するコマンドが用意されています。Wordでは、自動マクロに`AutoExec`と`AutoOpen`があり、`Document_Open`はオープンイベントプロシージャです。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC の再計算と制御された gzip

Revit RFA モデルは [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（別名 CFBF）として保存されます。シリアライズされたモデルは storage/stream の下にあります:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` の主なレイアウト（Revit 2025 で確認）:

- ヘッダー
- GZIP 圧縮された payload（実際のシリアライズ済みオブジェクトグラフ）
- ゼロパディング
- Error-Correcting Code（ECC）トレーラー

Revit は ECC トレーラーを使用して、stream に対する小さな変更を自動修復します。また、ECC と一致しない stream は拒否します。そのため、圧縮バイトを単純に編集しても変更は保持されません。変更は元に戻されるか、ファイルが拒否されます。デシリアライザーが認識する内容をバイト単位で正確に制御するには、次の操作が必要です:<sup>[[1]](#references)</sup>

- Revit 互換の gzip 実装で再圧縮する（Revit が生成または受け入れる圧縮バイトが、期待されるものと一致するようにするため）。
- パディング済み stream に対して ECC トレーラーを再計算し、変更した stream が自動修復されずに Revit に受け入れられるようにする。

RFA の内容を patch/fuzzing するための実用的な workflow:<sup>[[1]](#references)</sup>

1) OLE compound document を展開する。<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC の規則に従って `Global/Latest` を編集

- `Global/Latest` を分解します。ヘッダーを保持し、payload を gunzip してバイト列を変更した後、Revit 互換の deflate パラメータを使用して再度 gzip します。
- zero-padding を保持し、Revit が新しいバイト列を受け入れられるように ECC trailer を再計算します。
- バイト単位で決定論的に再現する必要がある場合は、研究で実証されているように、Revit の DLL を呼び出して gzip/gunzip の処理と ECC の計算を実行する最小限の wrapper を構築するか、これらのセマンティクスを再現する利用可能な helper を再利用します。

3) OLE compound document を再構築します。<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool は、NTFS の名前に使用できない文字をエスケープして、storages/streams を filesystem に書き出します。必要な stream path は、出力ツリー内の正確な `Global/Latest` です。
- ecosystem plugins を介して cloud storage から RFA を取得する mass attacks を実行する場合は、network injection を試みる前に、パッチ済み RFA がローカルで Revit の integrity checks（gzip/ECC が正しいこと）を通過することを確認してください。

Exploitation insight（gzip payload に配置するバイト列を決めるための参考情報）:<sup>[[1]](#references)</sup>

- Revit の deserializer は 16-bit class index を読み取り、object を構築します。特定の type は non‑polymorphic で vtable を持たないため、destructor handling を悪用すると type confusion が発生し、engine が attacker-controlled pointer を介した indirect call を実行します。
- `AString`（class index `0x1F`）を選択すると、object offset 0 に attacker-controlled heap pointer が配置されます。destructor loop 中、Revit は実質的に次を実行します:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- シリアライズされた graph にこのようなオブジェクトを複数配置し、destructor loop の各 iteration で 1 つの gadget（“weird machine”）が実行されるようにして、conventional な x64 ROP chain への stack pivot を構成します。

Windows x64 の pivot/gadget 構築の詳細はこちら：

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

一般的な ROP のガイダンスはこちら：

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

ツール：<sup>[[1]](#references)</sup>

- CompoundFileTool（OSS）：OLE compound files の展開・再構築用：https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD：reverse/taint 用。trace をコンパクトに保つため、TTD では page heap を無効化します。
- ローカル proxy（例：Fiddler）：plugin traffic 内の RFA を入れ替えることで、テスト用の supply-chain delivery をシミュレートできます。

## References

- [1] [Autodesk Revit RFA File Parsing の crash から完全な exploit RCE を作成（ZDI blog）](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool（GitHub）](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File（CFBF）docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba documentation（GitHub）](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event（Word）（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
