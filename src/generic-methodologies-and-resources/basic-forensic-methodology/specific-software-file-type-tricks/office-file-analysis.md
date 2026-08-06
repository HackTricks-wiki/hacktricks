# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}


さらなる情報については [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) を確認してください。これは単なる要約です:<sup>[[4]](#references)</sup>

Microsoft は多数の office document format を作成しており、主な種類として **OLE formats**（RTF、DOC、XLS、PPT など）と **Office Open XML (OOXML) formats**（DOCX、XLSX、PPTX など）があります。これらの format には macros を含めることができるため、phishing や malware の標的になります。OOXML files は zip containers として構成されているため、unzip して調査できます。これにより、file と folder の hierarchy、および XML file の contents を確認できます。

OOXML file structures を調査するため、document を unzip する command と output structure が示されています。これらの files に data を隠す techniques が記録されており、CTF challenges における data concealment の innovation が継続していることがわかります。

analysis には、**oletools** と **OfficeDissector** が OLE および OOXML documents の両方を調査するための包括的な toolsets を提供します。これらの tools は、embedded macros の特定と analysis に役立ちます。embedded macros は malware delivery の vectors として利用されることが多く、通常は追加の malicious payloads を download して execute します。VBA macros の analysis は、Microsoft Office を使用せずに Libre Office を利用して実行できます。Libre Office では breakpoints と watch variables による debugging が可能です。

**oletools** の installation と usage は straightforward で、pip 経由で install する commands と、documents から macros を extract する commands が提供されています。macros の automatic execution は、`AutoOpen`、`AutoExec`、`Document_Open` などの functions によって trigger されます。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC再計算と制御されたgzip

Revit RFAモデルは[OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)（別名CFBF）として保存されます。シリアライズされたモデルはstorage/streamの下にあります:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest`の主要なレイアウト（Revit 2025で確認）:

- Header
- GZIP-compressed payload（実際のシリアライズ済みオブジェクトグラフ）
- Zero padding
- Error-Correcting Code（ECC）trailer

RevitはECC trailerを使用して、streamに対する小さな変更を自動修復します。また、ECCと一致しないstreamは拒否します。そのため、圧縮バイトを単純に編集しても変更は保持されません。変更は元に戻されるか、ファイルが拒否されます。デシリアライザーが読み取る内容をbyte-accurateに制御するには、次の操作が必要です:

- Revit互換のgzip実装で再圧縮する（Revitが生成または受け入れる圧縮バイトが、期待されるものと一致するようにするため）。
- padded streamに対してECC trailerを再計算し、Revitが変更されたstreamを自動修復なしで受け入れられるようにする。

RFAの内容をpatching/fuzzingするための実用的なワークフロー:<sup>[[1]](#references)</sup>

1) OLE compound documentを展開する
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC の規則に従って Global\Latest を編集

- `Global/Latest` を分解する: header を保持し、payload を gunzip し、bytes を変更した後、Revit-compatible な deflate parameters を使用して gzip に戻します。
- zero-padding を保持し、Revit が新しい bytes を受け入れられるように ECC trailer を再計算します。
- byte-for-byte の deterministic な再現が必要な場合は、research で実証されているように、Revit の DLLs を使用して gzip/gunzip paths と ECC computation を呼び出す minimal wrapper を構築するか、これらの semantics を再現する利用可能な helper を再利用します。

3) OLE compound document を再構築する
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool は、NTFS の名前として無効な文字をエスケープしながら storages/streams を filesystem に書き込みます。出力 tree で必要な stream path は正確に `Global/Latest` です。
- ecosystem plugins 経由で cloud storage から RFA を取得する mass attacks を実行する場合は、network injection を試みる前に、patched RFA がローカルで Revit の integrity checks（gzip/ECC が正しいこと）をまず通過することを確認してください。

Exploitation insight（gzip payload に配置する bytes の指針）:<sup>[[1]](#references)</sup>

- Revit の deserializer は 16-bit class index を読み取り、object を構築します。一部の type は non-polymorphic で vtable を持たないため、destructor handling を悪用すると type confusion が発生し、engine が attacker-controlled pointer を介した indirect call を実行します。
- `AString`（class index `0x1F`）を選択すると、attacker-controlled heap pointer が object offset 0 に配置されます。destructor loop 中、Revit は実質的に次を実行します:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- シリアライズされた graph 内にこのようなオブジェクトを複数配置し、destructor loop の各反復で1つの gadget（“weird machine”）が実行されるようにして、conventional x64 ROP chain への stack pivot を構成します。

Windows x64 の pivot/gadget 構築の詳細はこちら:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

一般的な ROP のガイダンスはこちら:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

ツール:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) で OLE compound files を展開・再構築: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- 逆解析・taint 解析には IDA Pro + WinDBG TTD。trace をコンパクトに保つため、TTD では page heap を無効にします。
- ローカル proxy（例: Fiddler）を使用すると、plugin traffic 内の RFA をテスト用に入れ替えることで、supply-chain delivery をシミュレートできます。

## 参考文献

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
