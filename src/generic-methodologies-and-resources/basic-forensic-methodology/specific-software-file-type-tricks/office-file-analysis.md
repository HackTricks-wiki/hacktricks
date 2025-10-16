# Office 파일 분석

{{#include ../../../banners/hacktricks-training.md}}


추가 정보는 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)를 확인하세요. 이것은 요약입니다:

Microsoft는 여러 오피스 문서 포맷을 만들었으며, 주요한 두 가지 유형은 **OLE formats**(예: RTF, DOC, XLS, PPT)와 **Office Open XML (OOXML) formats**(예: DOCX, XLSX, PPTX)입니다. 이 포맷들은 매크로를 포함할 수 있어 피싱 및 멀웨어의 표적이 됩니다. OOXML 파일은 zip 컨테이너 구조로 되어 있어 압축을 풀어 파일/폴더 계층과 XML 파일 내용을 확인할 수 있습니다.

OOXML 파일 구조를 탐색하기 위해 문서의 압축을 푸는 명령과 출력 구조가 제공됩니다. 이러한 파일들에 데이터를 숨기는 기법들이 문서화되어 있으며, 이는 CTF 챌린지 내에서 데이터 은닉 방법의 지속적인 혁신을 보여줍니다.

분석을 위해 **oletools**와 **OfficeDissector**는 OLE 및 OOXML 문서를 검사하기 위한 포괄적인 툴셋을 제공합니다. 이 도구들은 임베디드 매크로를 식별하고 분석하는 데 도움을 주며, 임베디드 매크로는 종종 추가 악성 페이로드를 다운로드하고 실행하는 멀웨어 전달 벡터로 사용됩니다. VBA 매크로의 분석은 Microsoft Office 없이도 Libre Office를 사용해 수행할 수 있으며, Libre Office는 중단점(breakpoints)과 워치 변수(watch variables)를 사용한 디버깅을 허용합니다.

**oletools**의 설치 및 사용은 간단하며, pip로 설치하는 명령과 문서에서 매크로를 추출하는 명령이 제공됩니다. 매크로의 자동 실행은 `AutoOpen`, `AutoExec` 또는 `Document_Open` 같은 함수들에 의해 트리거됩니다.
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

- 헤더
- GZIP-compressed payload (실제 직렬화된 객체 그래프)
- 제로 패딩
- Error-Correcting Code (ECC) 트레일러

Revit는 ECC 트레일러를 사용해 스트림의 작은 변형을 자동 복구하지만, ECC와 일치하지 않는 스트림은 거부합니다. 따라서 압축된 바이트를 단순히 편집해도 변경이 유지되지 않습니다: 변경이 되돌려지거나 파일이 거부됩니다. 역직렬화기가 보는 내용을 바이트 단위로 정확히 제어하려면 다음을 수행해야 합니다:

- Revit과 호환되는 gzip 구현으로 다시 압축(so the compressed bytes Revit produces/accepts match what it expects).
- 패딩된 스트림에 대해 ECC 트레일러를 재계산하여 Revit이 자동 복구 없이 수정된 스트림을 수락하도록 합니다.

Practical workflow for patching/fuzzing RFA contents:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC 규칙에 따라 Global\Latest 편집

- `Global/Latest` 분해: 헤더를 유지하고, payload를 gunzip으로 압축 해제한 다음 바이트를 변형하고 Revit-compatible deflate parameters를 사용해 다시 gzip합니다.
- zero-padding을 보존하고 ECC 트레일러를 재계산하여 새로운 바이트가 Revit에 의해 받아들여지도록 합니다.
- 결정론적 바이트-단위 재현이 필요하면, Revit’s DLLs 주위에 최소 래퍼를 만들어 그 gzip/gunzip 경로와 ECC 계산을 호출하거나(연구에서 시연된 것처럼), 이러한 의미론을 복제하는 사용 가능한 헬퍼를 재사용하십시오.

3) OLE compound document 재구성
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
참고:

- CompoundFileTool는 NTFS 이름에서 유효하지 않은 문자를 이스케이프 처리하여 storages/streams를 파일 시스템에 기록합니다; 출력 트리에서 원하는 스트림 경로는 정확히 `Global/Latest`입니다.
- cloud storage에서 RFA를 가져오는 ecosystem plugins를 통해 대규모 공격을 전달할 때는, 네트워크 주입을 시도하기 전에 패치한 RFA가 로컬에서 Revit의 무결성 검사(예: gzip/ECC correct)를 먼저 통과하는지 확인하세요.

Exploitation insight (to guide what bytes to place in the gzip payload):

- The Revit deserializer reads a 16-bit class index and constructs an object. Certain types are non‑polymorphic and lack vtables; abusing destructor handling yields a type confusion where the engine executes an indirect call through an attacker-controlled pointer.
- Picking `AString` (class index `0x1F`) places an attacker-controlled heap pointer at object offset 0. During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- 여러 개의 그런 객체를 직렬화된 그래프에 배치하여 각 destructor loop 반복이 하나의 gadget(“weird machine”)을 실행하도록 하고, stack pivot을 전형적인 x64 ROP chain으로 구성한다.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

도구:

- CompoundFileTool (OSS) to expand/rebuild OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD for reverse/taint; disable page heap with TTD to keep traces compact.
- 로컬 프록시(예: Fiddler)는 플러그인 트래픽에서 RFAs를 교체하여 공급망 전달을 시뮬레이션하는 데 사용할 수 있다.

## 참고자료

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
