# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}


詳細については [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) を確認してください。これは単なる概要です:<sup>[[4]](#references)</sup>

Microsoft は多数の Office document format を作成しており、主な種類として **OLE formats**（RTF、DOC、XLS、PPT など）と **Office Open XML (OOXML) formats**（DOCX、XLSX、PPTX など）があります。これらの format には macros を含めることができるため、phishing や malware の標的になります。OOXML files は zip containers として構成されているため、unzip して調査できます。これにより、file と folder の階層、および XML file の内容を確認できます。

OOXML file の構造を調査するため、document を unzip する command と出力構造が示されています。これらの file 内に data を隠す techniques が文書化されており、CTF challenges における data concealment が継続的に進化していることが分かります。

analysis には、**oletools** と **OfficeDissector** が OLE および OOXML document の調査に対応する包括的な toolset を提供します。これらの tools は、embedded macros の特定と analysis に役立ちます。embedded macros は malware delivery の vector として使われることが多く、通常は追加の malicious payloads を download して execute します。VBA macros の analysis は Microsoft Office なしでも実施でき、Libre Office を利用すれば breakpoints と watch variables による debugging が可能です。

**oletools** の installation と usage は簡単で、pip による install と document から macros を extract する commands が提供されています。macros の automatic execution は、`AutoOpen`、`AutoExec`、`Document_Open` などの functions によって trigger されます。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:<sup>[[1]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Key layout of `Global\Latest` (observed on Revit 2025):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit will auto-repair small perturbations to the stream using the ECC trailer and will reject streams that don’t match the ECC. Therefore, naïvely editing the compressed bytes won’t persist: your changes are either reverted or the file is rejected. To ensure byte-accurate control over what the deserializer sees you must:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Practical workflow for patching/fuzzing RFA contents:<sup>[[1]](#references)</sup>

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC の規則に従って `Global/Latest` を編集

- `Global/Latest` を分解する: ヘッダーを保持し、payload を gunzip し、バイト列を変更してから、Revit 互換の deflate パラメータを使用して再度 gzip する。
- zero-padding を保持し、ECC trailer を再計算して、新しいバイト列が Revit に受け入れられるようにする。
- byte-for-byte の決定的な再現が必要な場合は、研究で実証されているように、Revit の DLL を使用して gzip/gunzip の処理と ECC の計算を呼び出す最小限の wrapper を構築するか、これらのセマンティクスを再現する利用可能な helper を再利用する。

3) OLE compound document を再構築する
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool は、NTFS 名で無効な文字をエスケープして storages/streams を filesystem に書き込みます。必要な stream path は、output tree 内の正確な `Global/Latest` です。
- ecosystem plugins 経由で cloud storage から RFA を取得する mass attacks を実行する場合は、network injection を試みる前に、パッチ済み RFA がローカルで Revit の integrity checks（gzip/ECC が正しいこと）を通過することを確認してください。

Exploitation insight（gzip payload に配置するバイトを決める際の指針）:<sup>[[1]](#references)</sup>

- Revit の deserializer は 16-bit class index を読み取り、object を構築します。一部の types は non‑polymorphic で vtables を持たないため、destructor handling を悪用すると type confusion が発生し、engine が attacker-controlled pointer を介して indirect call を実行します。
- `AString`（class index `0x1F`）を選択すると、object offset 0 に attacker-controlled heap pointer が配置されます。destructor loop 中、Revit は実質的に次を実行します:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- シリアライズされたグラフ内にこのようなオブジェクトを複数配置し、デストラクターループの各反復で1つの gadget（“weird machine”）が実行されるようにして、従来の x64 ROP chain へ stack pivot するよう構成します。

Windows x64 の pivot/gadget 構築の詳細はこちら：

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

一般的な ROP のガイダンスはこちら：

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

ツール：<sup>[[1]](#references)</sup>

- CompoundFileTool（OSS）：OLE compound files の展開と再構築：https://github.com/thezdi/CompoundFileTool
- 逆解析／taint 解析用の IDA Pro + WinDBG TTD。トレースを簡潔に保つため、TTD で page heap を無効化します。
- ローカル proxy（例：Fiddler）。テスト用に plugin の通信内の RFA を置き換えることで、supply-chain による配信をシミュレートできます。

## 参考文献

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
