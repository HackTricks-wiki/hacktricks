# Officeファイル解析

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:

Microsoftは多くのOfficeドキュメント形式を作成しており、主に2種類がある: **OLE formats**（RTF、DOC、XLS、PPTなど）と **Office Open XML (OOXML) formats**（DOCX、XLSX、PPTXなど）。これらの形式はマクロを含めることができ、そのためフィッシングやマルウェアの標的となる。OOXMLファイルはzipコンテナとして構成されるため、解凍することでファイル・フォルダ階層やXMLファイルの内容を確認できる。

OOXMLファイル構造を調べるために、ドキュメントを解凍するコマンドと出力構造が示される。これらのファイル内にデータを隠すテクニックが文書化されており、CTFチャレンジにおけるデータ隠蔽の手法が進化し続けていることを示している。

解析には、**oletools** と **OfficeDissector** が OLE および OOXML ドキュメントの調査に使える包括的なツールセットを提供する。これらのツールは埋め込まれたマクロの特定と解析を助ける。マクロはしばしばマルウェア配布のベクターとなり、追加の悪意あるペイロードをダウンロード・実行するのが典型的である。VBAマクロの解析は、Microsoft Office を使わずに Libre Office を利用して行うことができ、ブレークポイントやウォッチ変数を使ったデバッグが可能である。

さらに、**oletools** のインストールと使用は簡単で、pip経由でのインストールやドキュメントからマクロを抽出するためのコマンドが示されている。マクロの自動実行は `AutoOpen`、`AutoExec`、`Document_Open` のような関数によってトリガーされる。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File の悪用：Autodesk Revit RFA – ECC 再計算と制御された gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF)。シリアライズされたモデルは storage/stream の下にあります：

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` の主要なレイアウト（Revit 2025で観察）：

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit は ECC トレーラーを使ってストリームの小さな摂動を自動修復し、ECC と一致しないストリームは拒否します。したがって、圧縮バイトを単純に編集しても永続化しません：変更は戻されるかファイルが拒否されます。デシリアライザが見る内容をバイト単位で正確に制御するには、次を行う必要があります：

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

RFA コンテンツをパッチ/ファズするための実践的なワークフロー：

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC の手順に従って Global\Latest を編集する

- Deconstruct `Global/Latest`: ヘッダを保持し、gunzip でペイロードを展開し、バイトを改変してから Revit 互換の deflate パラメータを使って再度 gzip に戻す。
- zero-padding を保持し、ECC trailer を再計算して新しいバイトが Revit に受け入れられるようにする。
- バイト単位で決定論的な再現が必要な場合は、Revit の DLLs の周りに最小限のラッパーを作成してその gzip/gunzip パスと ECC 計算を呼び出す（研究で示されたように）、またはこれらのセマンティクスを再現する既存のヘルパーを再利用する。

3) OLE compound document を再構築する
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
注意事項:

- CompoundFileToolは、NTFS名で無効な文字をエスケープしてストレージ/ストリームをファイルシステムに書き出します；出力ツリーで目的のストリームパスは正確に `Global/Latest` です。
- クラウドストレージからRFAsをフェッチするエコシステムプラグイン経由で大量攻撃を配布する場合、ネットワーク注入を試みる前にパッチ済みRFAがローカルでRevitの整合性チェック（gzip/ECC が正しい）をまず通過することを確認してください。

Exploitation insight (to guide what bytes to place in the gzip payload):

- The Revit deserializer reads a 16-bit class index and constructs an object. Certain types are non‑polymorphic and lack vtables; abusing destructor handling yields a type confusion where the engine executes an indirect call through an attacker-controlled pointer.
- Picking `AString` (class index `0x1F`) places an attacker-controlled heap pointer at object offset 0. During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- シリアライズされたグラフにこのようなオブジェクトを複数配置し、destructor loop の各イテレーションでひとつの gadget（“weird machine”）が実行されるようにし、stack pivot を通常の x64 ROP chain に接続するよう配置します。

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

ツール:

- CompoundFileTool (OSS) を使って OLE compound files を展開/再構築: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD を reverse/taint 用に使用; トレースをコンパクトに保つために TTD では page heap を無効にする。
- ローカルプロキシ（例: Fiddler）は、プラグインのトラフィック中の RFAs を入れ替えてテスト用に supply-chain 配信をシミュレートできます。

## References

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
