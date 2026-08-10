# Office file analysis

詳しい情報については [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) を確認してください。これは単なる概要です:<sup>[[4]](#references)</sup>

Microsoft Office ドキュメントは、RTF や OLE/CFBF ベースの DOC、XLS、PPT などのレガシー形式、または DOCX、XLSX、PPTX などの新しい **Office Open XML (OOXML)** 形式として一般的に見られます。Office ドキュメントにはマクロなどのアクティブコンテンツが含まれる場合があり、フィッシングやマルウェアの一般的な媒介となっています。OOXML ファイルは ZIP コンテナであり、解凍することでファイル階層と XML の内容を調査できます。<sup>[[3]](#references)[[4]](#references)</sup>

OOXML ファイルの構造を調査するため、ドキュメントを解凍するコマンドと出力構造が示されています。これらのファイルにデータを隠す技術が文書化されており、CTF challenge におけるデータ隠蔽が継続的に革新されていることが分かります。<sup>[[4]](#references)</sup>

分析には、**oletools** と **OfficeDissector** が OLE および OOXML ドキュメントを調査するための包括的な toolset を提供します。これらの tools は、埋め込まれたマクロの特定と分析に役立ちます。マクロは多くの場合、マルウェア delivery の vector として機能し、通常は追加の悪意ある payload を download して実行します。VBA マクロの分析は、Microsoft Office を使用せずに Libre Office を利用して実施できます。Libre Office では breakpoint と watch variable を使った debugging が可能です。<sup>[[4]](#references)</sup>

**oletools** の installation と usage は簡単で、pip による install およびドキュメントからのマクロ抽出用の commands が提供されています。Word では、自動マクロに `AutoExec` と `AutoOpen` が含まれ、`Document_Open` は open-event procedure です。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA モデルは [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（別名 CFBF）として保存されます。シリアライズされたモデルは storage/stream の下にあります:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` の主な構成（Revit 2025 で確認）:

- Header
- GZIP-compressed payload（実際のシリアライズ済みオブジェクトグラフ）
- Zero padding
- Error-Correcting Code（ECC）trailer

Revit は ECC trailer を使用して stream への小さな変更を自動修復し、ECC と一致しない stream を拒否します。そのため、圧縮バイトを単純に編集しても変更は維持されません。変更が元に戻されるか、ファイルが拒否されます。deserializer が認識する内容をバイト単位で正確に制御するには、次の処理が必要です:<sup>[[1]](#references)</sup>

- Revit-compatible gzip implementation を使用して再圧縮する（Revit が生成または受け入れる圧縮バイトが、期待されるものと一致するようにするため）。
- padded stream に対して ECC trailer を再計算し、Revit が変更後の stream を自動修復なしで受け入れられるようにする。

RFA の内容を patch/fuzzing するための実用的な workflow:<sup>[[1]](#references)</sup>

1) OLE compound document を展開します。<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC の規則に従って `Global\Latest` を編集する

- `Global/Latest` を分解する: ヘッダーを保持し、payload を gunzip し、バイト列を変更してから、Revit 互換の deflate パラメータを使用して再度 gzip する。
- ゼロパディングを保持し、Revit が新しいバイト列を受け入れられるよう ECC trailer を再計算する。
- バイト単位で決定的に再現する必要がある場合は、研究で実証されているように、Revit の DLL を使用して gzip/gunzip の処理と ECC の計算を呼び出す最小限の wrapper を構築するか、これらのセマンティクスを再現する利用可能な helper を再利用する。

3) OLE 複合ドキュメントを再構築する。<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool は、NTFS 名で無効な文字をエスケープして storages/streams を filesystem に書き込みます。必要な stream path は、出力ツリー内で正確に `Global/Latest` です。
- cloud storage から RFA を取得する ecosystem plugins 経由で mass attacks を実行する場合は、network injection を試みる前に、patched RFA がまずローカルで Revit の integrity checks（gzip/ECC が正しいこと）を通過することを確認してください。

Exploitation insight（gzip payload に配置する bytes の指針）:<sup>[[1]](#references)</sup>

- Revit の deserializer は 16-bit class index を読み取り、object を構築します。一部の type は non‑polymorphic で vtable がありません。destructor handling を悪用すると type confusion が発生し、engine が attacker-controlled pointer 経由で indirect call を実行します。
- `AString`（class index `0x1F`）を選択すると、attacker-controlled heap pointer が object offset 0 に配置されます。destructor loop 中、Revit は実質的に次を実行します：
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- シリアライズされた graph 内にこのような object を複数配置し、destructor loop の各 iteration で 1 つの gadget（“weird machine”）が実行されるようにし、conventional x64 ROP chain への stack pivot を構成します。

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
- ローカル proxy（例：Fiddler）を使用すると、テスト用に plugin traffic 内の RFA を置き換え、supply-chain delivery をシミュレートできます。

## References

- [1] [Autodesk Revit RFA File Parsing の crash から完全な exploit RCE を作成する（ZDI blog）](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool（GitHub）](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File（CFBF）docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba documentation（GitHub）](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event（Word）（Microsoft Learn）](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
