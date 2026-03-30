# Office 파일 분석

{{#include ../../../banners/hacktricks-training.md}}


자세한 정보는 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)를 확인하세요. 다음은 요약입니다:

Microsoft는 여러 office 문서 포맷을 만들었으며, 주요 유형 두 가지는 **OLE formats**(예: RTF, DOC, XLS, PPT)과 **Office Open XML (OOXML) formats**(예: DOCX, XLSX, PPTX)입니다. 이들 포맷은 macros를 포함할 수 있어 phishing 및 malware의 표적이 됩니다. OOXML 파일은 zip 컨테이너 구조로 되어 있어 압축을 풀어 파일/폴더 계층과 XML 파일 내용을 확인할 수 있습니다.

OOXML 파일 구조를 조사하기 위해 문서를 unzip하는 명령과 출력 구조가 제공됩니다. 이 파일들에 데이터를 숨기는 기법들이 문서화되어 있으며, CTF 과제에서 데이터 은닉 기법이 계속해서 발전하고 있음을 보여줍니다.

분석을 위해 **oletools**와 **OfficeDissector**는 OLE와 OOXML 문서를 모두 검사할 수 있는 포괄적인 도구 세트를 제공합니다. 이 도구들은 embedded macros를 식별하고 분석하는 데 도움을 주며, 해당 매크로들은 종종 malware 전달 벡터로 사용되어 추가 악성 페이로드를 다운로드하고 실행합니다. VBA macros 분석은 Microsoft Office 없이 Libre Office를 이용해 수행할 수 있으며, breakpoint와 watch variables로 디버깅할 수 있습니다.

**oletools**의 설치와 사용은 간단하며, pip로 설치하고 문서에서 macros를 추출하는 명령이 제공됩니다. 매크로의 자동 실행은 `AutoOpen`, `AutoExec`, `Document_Open` 같은 함수로 트리거됩니다.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

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

Practical workflow for patching/fuzzing RFA contents:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC 규율로 Global\Latest 편집

- `Global/Latest`을 분해: 헤더는 유지하고, payload를 gunzip하여 바이트를 변형한 다음 Revit 호환 deflate 매개변수로 다시 gzip합니다.
- zero-padding을 보존하고 ECC 트레일러를 재계산하여 변경된 바이트가 Revit에서 수용되도록 합니다.
- 결정론적 byte-for-byte 재현이 필요하면, Revit의 DLL을 감싼 최소한의 래퍼를 만들어 그 gzip/gunzip 경로와 ECC 계산을 호출하거나(연구에서 시연된 것처럼), 이러한 동작을 복제하는 기존 헬퍼를 재사용하세요.

3) OLE compound document 재구성
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
- CompoundFileTool writes storages/streams to the filesystem with escaping for characters invalid in NTFS names; the stream path you want is exactly `Global/Latest` in the output tree.
- When delivering mass attacks via ecosystem plugins that fetch RFAs from cloud storage, ensure your patched RFA passes Revit’s integrity checks locally first (gzip/ECC correct) before attempting network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- The Revit deserializer reads a 16-bit class index and constructs an object. Certain types are non‑polymorphic and lack vtables; abusing destructor handling yields a type confusion where the engine executes an indirect call through an attacker-controlled pointer.
- Picking `AString` (class index `0x1F`) places an attacker-controlled heap pointer at object offset 0. During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 직렬화된 그래프에 이러한 객체들을 여러 개 배치하여, destructor loop의 각 반복에서 하나의 gadget(“weird machine”)가 실행되도록 하고, stack pivot을 통해 conventional x64 ROP chain으로 연결하세요.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

도구:

- CompoundFileTool (OSS) to expand/rebuild OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD for reverse/taint; TTD로 page heap을 비활성화하면 트레이스를 작게 유지할 수 있음.
- 로컬 프록시(예: Fiddler)는 plugin 트래픽에서 RFAs를 교체하여 supply-chain 전달을 시뮬레이션하는 데 사용할 수 있음.

## 참고자료

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
