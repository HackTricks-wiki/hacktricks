# Officeファイル分析

{{#include ../../../banners/hacktricks-training.md}}

詳細については、[https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)を確認してください。これは単なる概要です:<sup>[[4]](#references)</sup>

Microsoft Officeドキュメントは、RTFや、OLE/CFBFベースのDOC、XLS、PPTなどのレガシー形式、またはDOCX、XLSX、PPTXなどの新しい **Office Open XML (OOXML)** 形式であることが一般的です。Officeドキュメントにはマクロなどのアクティブコンテンツが含まれる場合があり、フィッシングやマルウェアの一般的な媒介手段となっています。OOXMLファイルはZIPコンテナであり、解凍することでファイル階層とXMLの内容を調査できます。<sup>[[3]](#references)[[4]](#references)</sup>

OOXMLファイルの構造を調査するため、ドキュメントを解凍するコマンドと出力構造を示します。これらのファイルにデータを隠す技術が文書化されており、CTFチャレンジにおけるデータ隠蔽の継続的な発展が示されています。<sup>[[4]](#references)</sup>

分析には、**oletools** と **OfficeDissector** が、OLEおよびOOXMLドキュメントの両方を調査するための包括的なツールセットを提供します。これらのツールは、埋め込まれたマクロの特定と分析に役立ちます。マクロはマルウェア配布のベクトルとして機能することが多く、通常は追加の悪意あるpayloadをダウンロードして実行します。VBAマクロの分析は、Microsoft OfficeなしでもLibre Officeを利用して実施でき、ブレークポイントやウォッチ変数を使ったデバッグが可能です。<sup>[[4]](#references)</sup>

**oletools** のインストールと使用方法は簡単で、pipによるインストールやドキュメントからのマクロ抽出に使用するコマンドが示されています。Wordでは、自動マクロに `AutoExec` と `AutoOpen` が含まれ、`Document_Open` はopen-event procedureです。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
パスワードで暗号化された Office ドキュメントについては、[grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example)を参照してください。

---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA モデルは、[OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（別名 CFBF）として保存されます。シリアライズされたモデルは、storage/stream の下にあります:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` の主要なレイアウト（Revit 2025 で確認）:

- Header
- GZIP-compressed payload（実際のシリアライズされた object graph）
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit は ECC trailer を使用して、stream に対する小さな変更を自動修復します。また、ECC と一致しない stream は拒否します。そのため、圧縮バイト列を単純に編集しても変更は保持されません。変更は元に戻されるか、ファイルが拒否されます。deserializer が認識する内容を byte-accurate に制御するには、次のことが必要です:<sup>[[1]](#references)</sup>

- Revit-compatible gzip implementation で再圧縮する（Revit が生成または受け入れる圧縮バイト列が、想定されるものと一致するようにする）。
- padded stream に対して ECC trailer を再計算し、Revit が変更済みの stream を自動修復せずに受け入れられるようにする。

RFA の内容を patch/fuzzing するための実用的な workflow:<sup>[[1]](#references)</sup>

1) OLE compound document を展開します。<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC の規則に従って `Global\Latest` を編集する

- `Global/Latest` を分解する: ヘッダーを保持し、payload を gunzip し、バイト列を変更してから、Revit 互換の deflate パラメーターを使用して再度 gzip する。
- zero-padding を保持し、ECC trailer を再計算して、新しいバイト列が Revit に受け入れられるようにする。
- バイト単位で決定論的に再現する必要がある場合は、研究で実証されているように、Revit の DLL を使用して gzip/gunzip の処理と ECC の計算を呼び出す最小限の wrapper を構築するか、これらのセマンティクスを再現する利用可能な helper を再利用する。

3) OLE compound document を再構築する。<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
メモ:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool は、NTFS の名前として無効な文字をエスケープして、storages/streams をファイルシステムに書き込みます。出力ツリーで必要な stream のパスは正確には `Global/Latest` です。
- cloud storage から RFA を取得する ecosystem plugins 経由で mass attacks を実行する場合は、network injection を試みる前に、パッチ済みの RFA がローカルで Revit の integrity checks（gzip/ECC が正しいこと）を通過することを確認してください。

Exploitation insight（gzip payload に配置する bytes の指針）:<sup>[[1]](#references)</sup>

- Revit の deserializer は 16 ビットの class index を読み取り、object を構築します。一部の type は non-polymorphic で vtables を持たないため、destructor handling を悪用すると type confusion が発生し、engine が attacker-controlled pointer を介して indirect call を実行します。
- `AString`（class index `0x1F`）を選択すると、object offset 0 に attacker-controlled heap pointer が配置されます。destructor loop 中、Revit は実質的に次を実行します:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- シリアライズされたグラフ内にこのようなオブジェクトを複数配置し、デストラクタループの各反復で1つの gadget（“weird machine”）が実行されるようにし、従来の x64 ROP chain への stack pivot を構成します。

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
- IDA Pro + WinDBG TTD：reverse/taint 用。トレースをコンパクトに保つため、TTD では page heap を無効化します。
- ローカルプロキシ（例：Fiddler）：テスト用に plugin の通信内の RFA を入れ替えることで、supply-chain delivery をシミュレートできます。

## References

- [1] [Autodesk Revit RFA File Parsing のクラッシュから完全な Exploit RCE を作成する（ZDI blog）](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool（GitHub）](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File（CFBF）docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba documentation（GitHub）](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event（Word）（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
