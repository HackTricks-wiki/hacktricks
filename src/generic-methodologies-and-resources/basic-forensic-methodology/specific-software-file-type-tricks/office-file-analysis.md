# Officeファイルの解析

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:

Microsoftは多数のOfficeドキュメント形式を作成しており、主に2種類が存在します：**OLE formats**（RTF、DOC、XLS、PPTなど）と**Office Open XML (OOXML) formats**（DOCX、XLSX、PPTXなど）。これらの形式はマクロを含めることができるため、フィッシングやマルウェアの標的になります。OOXMLファイルはzipコンテナとして構成されており、解凍することでファイルやフォルダの階層やXMLファイルの内容を確認できます。

OOXMLファイル構造を調べるための、ドキュメントを解凍するコマンドとその出力構造が示されています。これらのファイル内でデータを隠す手法も文書化されており、CTFの課題におけるデータ隠蔽の技術が進化し続けていることを示しています。

解析には、**oletools** と **OfficeDissector** が OLE と OOXML の両方のドキュメントを調査するための包括的なツールセットを提供します。これらのツールは、埋め込まれたマクロを特定・解析するのに役立ちます。マクロはしばしばマルウェア配布のベクターとして機能し、追加の悪意あるペイロードをダウンロード・実行することが一般的です。VBAマクロの解析は Microsoft Office を使わなくても Libre Office を利用して行うことが可能で、ブレークポイントやウォッチ変数を使ったデバッグが可能です。

**oletools** のインストールと使用は簡単で、pip経由でのインストールやドキュメントからマクロを抽出するためのコマンドが示されています。マクロの自動実行は `AutoOpen`、`AutoExec`、`Document_Open` のような関数によってトリガーされます。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC 再計算と制御された gzip

Revit RFAモデルは [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF) として保存されます。シリアライズされたモデルは storage/stream の下にあります:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Key layout of `Global\Latest` (observed on Revit 2025):

- ヘッダ
- GZIP-compressed payload (実際のシリアライズされたオブジェクトグラフ)
- ゼロパディング
- 誤り訂正符号 (ECC) トレーラ

Revit は ECC トレーラを使ってストリームの小さな乱れを自動修復しますが、ECC と一致しないストリームは拒否します。したがって、単純に圧縮済みバイトを編集しても変更は保持されません: 変更は元に戻されるかファイルが拒否されます。デシリアライザが見るものをバイト単位で正確に制御するには、次を行う必要があります:

- Revit互換の gzip 実装で再圧縮する（Revit が生成/受け入れる圧縮バイト列が期待するものと一致するように）。
- パディングされたストリームに対して ECC トレーラを再計算し、Revit が自動修復せずに修正されたストリームを受け入れるようにする。

RFA コンテンツの patching/fuzzing における実用的なワークフロー:

1) OLE Compound File ドキュメントを展開する
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Global\Latest を gzip/ECC の手順で編集する

- `Global/Latest` を分解する: ヘッダは保持し、payload を gunzip し、バイトを変更してから Revit-compatible deflate parameters を使って再度 gzip する。
- zero-padding を保持し、ECC trailer を再計算して新しいバイトが Revit によって受け入れられるようにする。
- 決定論的な byte-for-byte の再現が必要な場合は、Revit の DLLs をラップする最小限の wrapper を作成してその gzip/gunzip パスと ECC computation を呼び出す（研究で示されているように）、またはこれらのセマンティクスを再現する既存の helper を再利用する。

3) OLE compound document を再構築する
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
ノート:

- CompoundFileTool は NTFS 名で無効な文字をエスケープして storages/streams をファイルシステムに書き出します；出力ツリーで目的のストリームパスは正確に `Global/Latest` です。
- エコシステムプラグイン経由でクラウドストレージから RFAs を取得するような大規模攻撃を配信する場合、ネットワーク注入を試みる前に、パッチ済みの RFA がローカルで Revit の整合性チェック（gzip/ECC が正しいこと）を通過することを確認してください。

Exploitation insight (to guide what bytes to place in the gzip payload):

- Revit の deserializer は 16-bit の class index を読み取りオブジェクトを構築します。特定の型は non‑polymorphic で vtables を持たず、destructor の扱いを悪用すると type confusion が発生し、エンジンが攻撃者制御のポインタ経由で間接呼び出しを実行します。
- `AString`（class index `0x1F`）を選ぶと、攻撃者制御のヒープポインタがオブジェクトのオフセット 0 に配置されます。destructor ループ中に、Revit は実質的に次を実行します：
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- シリアライズされたグラフにそのようなオブジェクトを複数配置し、destructor loop の各イテレーションがそれぞれ1つの gadget（“weird machine”）を実行するようにし、stack pivot を通常の x64 ROP chain に繋げます。

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:

- CompoundFileTool (OSS) を使って OLE compound files を展開／再構築: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD をリバース／taイント解析に使用；トレースをコンパクトに保つために TTD では page heap を無効化する。
- ローカルプロキシ（例: Fiddler）は、テストのために plugin トラフィック内の RFAs を差し替えて supply-chain 配信をシミュレートできます。

## 参考文献

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
