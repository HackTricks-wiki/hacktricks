# Office 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

추가 정보는 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)를 확인하세요. 다음은 간단한 요약입니다:<sup>[[4]](#references)</sup>

Microsoft Office 문서는 일반적으로 RTF 및 OLE/CFBF 기반 DOC, XLS, PPT와 같은 레거시 형식이나 DOCX, XLSX, PPTX와 같은 새로운 **Office Open XML (OOXML)** 형식으로 나타납니다. Office 문서에는 매크로와 같은 active content가 포함될 수 있으므로, phishing 및 malware를 전달하는 일반적인 수단으로 사용됩니다. OOXML 파일은 ZIP 컨테이너이므로 압축을 해제하여 파일 계층 구조와 XML 콘텐츠를 검사할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

OOXML 파일 구조를 탐색하기 위해 문서의 압축을 해제하는 명령과 출력 구조가 제시됩니다. 이러한 파일에 데이터를 숨기는 기법이 문서화되어 있으며, 이는 CTF challenge에서 데이터를 은닉하는 방법이 계속해서 발전하고 있음을 보여줍니다.<sup>[[4]](#references)</sup>

분석을 위해 **oletools** 및 **OfficeDissector**는 OLE 및 OOXML 문서를 검사할 수 있는 종합적인 toolset을 제공합니다. 이러한 도구는 내장된 매크로를 식별하고 분석하는 데 도움이 됩니다. 내장된 매크로는 malware를 전달하는 vector로 사용되는 경우가 많으며, 일반적으로 추가적인 malicious payload를 다운로드하고 실행합니다. VBA 매크로 분석은 Microsoft Office 없이도 Libre Office를 사용하여 수행할 수 있으며, Libre Office에서는 breakpoint와 watch variable을 사용한 debugging이 가능합니다.<sup>[[4]](#references)</sup>

**oletools**의 설치 및 사용법은 간단하며, pip를 통해 설치하고 문서에서 매크로를 추출하는 명령이 제공됩니다. Word에서 automatic macro에는 `AutoExec` 및 `AutoOpen`이 포함되며, `Document_Open`은 open-event procedure입니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
암호로 보호된 Office 문서는 [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example)를 참조하세요.

---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA 모델은 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)(CFBF라고도 함)로 저장됩니다. 직렬화된 모델은 다음 storage/stream 아래에 있습니다:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest`의 주요 레이아웃(Revit 2025에서 관찰됨):

- Header
- GZIP-compressed payload(실제 직렬화된 object graph)
- Zero padding
- Error-Correcting Code(ECC) trailer

Revit은 ECC trailer를 사용하여 stream에 발생한 작은 변경을 자동으로 복구하며, ECC와 일치하지 않는 stream은 거부합니다. 따라서 압축된 bytes를 단순히 편집하는 것만으로는 변경 사항이 유지되지 않습니다. 변경 사항이 되돌려지거나 파일이 거부됩니다. deserializer가 확인하는 내용을 byte-accurate하게 제어하려면 다음을 수행해야 합니다:<sup>[[1]](#references)</sup>

- Revit과 호환되는 gzip 구현으로 다시 압축합니다(Revit이 생성하거나 수락하는 compressed bytes가 Revit이 예상하는 값과 일치하도록).
- padded stream에 대해 ECC trailer를 다시 계산하여 Revit이 수정된 stream을 자동으로 복구하지 않고 수락하도록 합니다.

RFA contents를 patch/fuzzing하기 위한 실용적인 workflow:<sup>[[1]](#references)</sup>

1) OLE compound document를 확장합니다.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC 규칙에 따라 `Global\Latest` 편집

- `Global/Latest`를 분해합니다. 헤더는 유지하고, payload를 gunzip한 다음 바이트를 변경하고, Revit 호환 deflate parameters를 사용하여 다시 gzip합니다.
- zero-padding을 유지하고 ECC trailer를 다시 계산하여 새 바이트가 Revit에서 허용되도록 합니다.
- byte-for-byte 재현이 필요하다면 Revit의 DLL을 기반으로 최소 wrapper를 만들어 gzip/gunzip 경로와 ECC 계산을 호출하거나(연구에서 시연됨), 이러한 semantics를 재현하는 사용 가능한 helper를 재사용합니다.

3) OLE compound document를 재구성합니다.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool은 NTFS 이름에 사용할 수 없는 문자를 escaping하여 storages/streams를 filesystem에 기록합니다. 출력 트리에서 원하는 stream path는 정확히 `Global/Latest`입니다.
- cloud storage에서 RFA를 가져오는 ecosystem plugins를 통해 mass attacks를 수행할 때는 network injection을 시도하기 전에 패치된 RFA가 로컬에서 Revit의 integrity checks를 먼저 통과하는지 확인해야 합니다(gzip/ECC가 올바른지 확인).

Exploitation insight (gzip payload에 배치할 바이트를 결정하는 데 참고):<sup>[[1]](#references)</sup>

- Revit deserializer는 16비트 class index를 읽고 object를 생성합니다. 특정 type은 non‑polymorphic이며 vtables가 없습니다. destructor handling을 악용하면 type confusion이 발생하여 engine이 attacker-controlled pointer를 통한 indirect call을 실행하게 됩니다.
- `AString`(class index `0x1F`)을 선택하면 object offset 0에 attacker-controlled heap pointer가 배치됩니다. destructor loop 중에 Revit은 사실상 다음을 실행합니다:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 직렬화된 그래프에 이러한 객체를 여러 개 배치하여 destructor loop의 각 반복이 하나의 gadget(“weird machine”)을 실행하도록 하고, conventional x64 ROP chain으로 stack pivot을 구성합니다.

Windows x64 pivot/gadget 구축 세부 사항은 여기에서 확인할 수 있습니다:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

일반적인 ROP 지침은 여기에서 확인할 수 있습니다:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

도구:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS): OLE compound files를 확장/재구성: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- reverse/taint 분석을 위한 IDA Pro + WinDBG TTD; trace를 간결하게 유지하려면 TTD에서 page heap을 비활성화합니다.
- 로컬 proxy(예: Fiddler)는 테스트를 위해 plugin traffic에서 RFA를 교체하여 supply-chain delivery를 시뮬레이션할 수 있습니다.

## References

- [1] [Autodesk Revit RFA File Parsing의 Crash에서 완전한 Exploit RCE 제작 (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) 문서](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba documentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
