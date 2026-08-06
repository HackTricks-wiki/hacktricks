# Office 파일 분석

{{#include ../../../banners/hacktricks-training.md}}


추가 정보는 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)를 확인하세요. 다음은 간단한 요약입니다:<sup>[[4]](#references)</sup>

Microsoft는 여러 Office 문서 형식을 만들었으며, 주요 유형으로 **OLE formats**(RTF, DOC, XLS, PPT 등)과 **Office Open XML (OOXML) formats**(DOCX, XLSX, PPTX 등)이 있습니다. 이러한 형식에는 macros가 포함될 수 있으므로 phishing 및 malware의 대상이 됩니다. OOXML 파일은 zip containers로 구성되어 있어 압축을 해제하여 파일 및 folder hierarchy와 XML 파일 내용을 확인할 수 있습니다.

OOXML 파일 구조를 확인하기 위해 문서의 압축을 해제하는 command와 output structure가 제시되어 있습니다. 이러한 파일에서 data를 숨기는 techniques가 문서화되어 있으며, 이는 CTF challenges에서 data concealment 방식이 계속해서 발전하고 있음을 보여줍니다.

분석을 위해 **oletools**와 **OfficeDissector**는 OLE 및 OOXML 문서를 모두 검사할 수 있는 comprehensive toolsets를 제공합니다. 이러한 tools는 embedded macros를 식별하고 분석하는 데 도움을 주며, embedded macros는 주로 malware delivery를 위한 vectors로 사용되어 추가 malicious payloads를 download하고 execute합니다. VBA macros 분석은 Microsoft Office 없이도 Libre Office를 사용하여 수행할 수 있으며, Libre Office에서는 breakpoints와 watch variables를 이용한 debugging이 가능합니다.

**oletools**의 installation 및 usage는 간단하며, pip를 통해 설치하고 문서에서 macros를 추출하는 commands가 제공됩니다. macros의 automatic execution은 `AutoOpen`, `AutoExec` 또는 `Document_Open`과 같은 functions에 의해 trigger됩니다.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC 재계산 및 제어된 gzip

Revit RFA 모델은 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)(일명 CFBF)로 저장됩니다. 직렬화된 모델은 storage/stream 아래에 있습니다:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest`의 주요 레이아웃(Revit 2025에서 관찰됨):

- Header
- GZIP으로 압축된 payload(실제 직렬화된 object graph)
- Zero padding
- Error-Correcting Code(ECC) trailer

Revit은 ECC trailer를 사용해 stream의 작은 변경을 자동으로 복구하며, ECC와 일치하지 않는 stream은 거부합니다. 따라서 압축된 bytes를 단순히 편집하면 변경 사항이 유지되지 않습니다. 변경 사항이 되돌려지거나 파일이 거부됩니다. Deserializer가 확인하는 내용을 byte-accurate하게 제어하려면 다음을 수행해야 합니다.

- Revit-compatible gzip 구현으로 다시 압축합니다(Revit이 생성하거나 허용하는 compressed bytes가 예상한 값과 일치하도록).
- padded stream에 대해 ECC trailer를 재계산하여 Revit이 수정된 stream을 자동으로 복구하지 않고 허용하도록 합니다.

RFA contents를 patch/fuzzing하기 위한 practical workflow:<sup>[[1]](#references)</sup>

1) OLE compound document 확장하기
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC 규칙에 따라 `Global\Latest` 편집

- `Global/Latest`를 분해합니다. header는 유지하고, payload를 gunzip한 다음 bytes를 변경한 후 Revit 호환 deflate parameters를 사용해 다시 gzip합니다.
- zero-padding을 유지하고 ECC trailer를 다시 계산하여 새 bytes가 Revit에서 허용되도록 합니다.
- byte-for-byte 재현을 결정론적으로 수행해야 한다면, 연구에서 시연된 것처럼 Revit의 DLL을 기반으로 최소한의 wrapper를 작성하여 Revit의 gzip/gunzip 경로와 ECC 계산을 호출하거나, 이러한 semantics를 재현하는 사용 가능한 helper를 재사용합니다.

3) OLE compound document 재구축
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool은 NTFS 이름에 사용할 수 없는 문자에 대한 escaping을 적용하여 storages/streams를 filesystem에 기록합니다. 원하는 stream path는 output tree에서 정확히 `Global/Latest`입니다.
- cloud storage에서 RFA를 가져오는 ecosystem plugins를 통해 mass attacks를 수행할 때는 network injection을 시도하기 전에 patched RFA가 로컬에서 먼저 Revit의 integrity checks를 통과하는지 확인하십시오(gzip/ECC가 올바른지 확인).

Exploitation insight (gzip payload에 배치할 바이트를 결정하는 데 참고):<sup>[[1]](#references)</sup>

- Revit deserializer는 16-bit class index를 읽고 object를 생성합니다. 특정 type은 non-polymorphic이며 vtable이 없습니다. destructor handling을 악용하면 type confusion이 발생하여 engine이 attacker-controlled pointer를 통한 indirect call을 실행합니다.
- `AString` (class index `0x1F`)을 선택하면 object offset 0에 attacker-controlled heap pointer가 배치됩니다. destructor loop 중에 Revit은 사실상 다음을 실행합니다:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 직렬화된 graph에 이러한 object를 여러 개 배치하여 destructor loop의 각 반복이 하나의 gadget("weird machine")을 실행하도록 만들고, 일반적인 x64 ROP chain으로 stack pivot을 수행하도록 구성합니다.

Windows x64 pivot/gadget 제작 세부 사항은 다음을 참조하세요:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

일반적인 ROP 지침은 다음을 참조하세요:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

도구:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS): OLE compound file을 확장하고 재구성하는 도구: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD: reverse/taint 분석용 도구. trace를 간결하게 유지하려면 TTD에서 page heap을 비활성화합니다.
- 로컬 proxy(예: Fiddler)를 사용하면 테스트를 위해 plugin traffic에서 RFA를 교체하여 supply-chain delivery를 시뮬레이션할 수 있습니다.

## References

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
