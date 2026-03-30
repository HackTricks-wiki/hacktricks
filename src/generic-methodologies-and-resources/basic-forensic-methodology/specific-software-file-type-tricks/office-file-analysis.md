# Officeファイル分析

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:

Microsoftは多数のOfficeドキュメント形式を作成しており、主に二つのタイプがあります：**OLE formats**（RTF、DOC、XLS、PPTなど）と**Office Open XML (OOXML) formats**（DOCX、XLSX、PPTXなど）。これらの形式はmacrosを含むことがあり、phishingやmalwareの標的になります。OOXMLファイルはzipコンテナとして構成されており、unzippingすることでファイルやフォルダの階層やXMLファイルの内容を確認できます。

OOXMLのファイル構造を調査するために、ドキュメントをunzipするコマンドと出力構造が示されています。これらのファイルにデータを隠すための技術も文書化されており、CTFの課題内でデータ隠蔽の手法が継続的に進化していることを示しています。

解析には、**oletools** と **OfficeDissector** が OLE と OOXML 両方のドキュメントを調査するための包括的なツールセットを提供します。これらのツールは埋め込まれたmacrosの特定と解析を支援し、これらのmacrosはしばしばmalware配布のベクターとして機能し、追加の悪意あるペイロードをダウンロードして実行することが一般的です。VBA macrosの解析は、Libre Officeを使用すればMicrosoft Officeなしで行うことができ、breakpointsやwatch variablesでデバッグできます。

**oletools** のインストールと使用は簡単で、pip経由でのインストールやドキュメントからmacrosを抽出するためのコマンドが示されています。macrosの自動実行は `AutoOpen`、`AutoExec`、`Document_Open` のような関数によってトリガーされます。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File 悪用: Autodesk Revit RFA – ECC の再計算と制御された gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Key layout of `Global\Latest` (observed on Revit 2025):

- ヘッダー
- GZIP-compressed payload (実際のシリアライズされたオブジェクトグラフ)
- Zero padding
- 誤り訂正コード (ECC) トレーラ

Revit は ECC トレーラを使ってストリームの小さな摂動を自動修復し、ECC と一致しないストリームは拒否します。したがって、圧縮済みバイトを単純に編集しても変更は保持されません：変更は元に戻されるか、ファイルが拒否されます。デシリアライザが見るものをバイト単位で正確に制御するには、次を行う必要があります:

- Revit と互換性のある gzip 実装で再圧縮する（Revit が生成/受け入れる圧縮バイトが期待するものと一致するように）。
- パディングされたストリーム上で ECC トレーラを再計算し、Revit が自動修復せずに変更されたストリームを受け入れるようにする。

Practical workflow for patching/fuzzing RFA contents:

1) OLE compound document を展開する
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC の手順で Global\Latest を編集

- Deconstruct `Global/Latest`: ヘッダは保持し、ペイロードを gunzip してバイトを改変し、Revit互換の deflate パラメータを使って再度 gzip する。
- zero-padding を保持し、ECC トレーラを再計算して新しいバイト列が Revit に受け入れられるようにする。
- バイト単位で決定的に再現する必要がある場合は、Revit の DLL に対して最小限のラッパーを構築し、その gzip/gunzip パスと ECC 計算を呼び出す（研究で示されたように）、あるいはこれらの挙動を再現する既存のヘルパーを再利用する。

3) OLE 複合ドキュメントを再構築する
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
注意:

- CompoundFileTool は、NTFS 名で無効な文字をエスケープして storages/streams をファイルシステムに書き出します；出力ツリーで目的のストリームパスは正確に `Global/Latest` です。
- ecosystem plugins を介してクラウドストレージから RFA を取得する大量攻撃を配信する場合、ネットワーク注入を試みる前に、パッチ済み RFA がローカルで Revit の整合性チェック（gzip/ECC が正しいこと）を通過することを確認してください。

Exploitation insight (to guide what bytes to place in the gzip payload):

- Revit のデシリアライザは 16 ビットのクラスインデックスを読み取り、オブジェクトを構築します。特定の型は非多態で vtable を持たず、デストラクタ処理を悪用すると type confusion を引き起こし、エンジンが攻撃者制御のポインタを介した間接呼び出しを実行します。
- `AString` (class index `0x1F`) を選ぶと、オブジェクトのオフセット 0 に攻撃者制御のヒープポインタが配置されます。デストラクタループ中、Revit は実質的に次を実行します：
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- シリアライズされたグラフ内にそのようなオブジェクトを複数配置し、destructor loop の各イテレーションが 1 つの gadget（“weird machine”）を実行するようにし、stack pivot を従来の x64 ROP chain に仕向ける。

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

ツール:

- CompoundFileTool (OSS) — OLE compound files を展開/再構築するため: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD は reverse/taint の解析に使用; TTD で page heap を無効化してトレースをコンパクトに保つ。
- ローカルプロキシ（例: Fiddler）を使い、plugin トラフィック内の RFAs を差し替えてテスト用に supply-chain 配信をシミュレートできる。

## 参考資料

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
