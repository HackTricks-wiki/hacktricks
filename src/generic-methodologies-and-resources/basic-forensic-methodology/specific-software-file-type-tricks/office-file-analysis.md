# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:

자세한 정보는 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)를 참조하세요. 다음은 간단한 요약입니다:

Microsoft has created many office document formats, with two main types being **OLE formats** (like RTF, DOC, XLS, PPT) and **Office Open XML (OOXML) formats** (such as DOCX, XLSX, PPTX). These formats can include macros, making them targets for phishing and malware. OOXML files are structured as zip containers, allowing inspection through unzipping, revealing the file and folder hierarchy and XML file contents.

Microsoft는 여러 office 문서 형식을 만들었으며, 주요 유형 두 가지는 **OLE formats**(예: RTF, DOC, XLS, PPT)와 **Office Open XML (OOXML) formats**(예: DOCX, XLSX, PPTX)입니다. 이들 형식은 매크로를 포함할 수 있어 피싱 및 악성코드의 표적이 됩니다. OOXML 파일은 zip 컨테이너 구조를 가지므로 압축을 풀어 파일 및 폴더 계층과 XML 파일 내용을 확인할 수 있습니다.

To explore OOXML file structures, the command to unzip a document and the output structure are given. Techniques for hiding data in these files have been documented, indicating ongoing innovation in data concealment within CTF challenges.

OOXML 파일 구조를 탐색하기 위해 문서를 unzip하는 명령과 출력 구조가 제공됩니다. 이러한 파일에 데이터를 숨기는 기법들이 문서화되어 있으며, CTF 문제들에서 데이터 은닉 기법이 계속 발전하고 있음을 보여줍니다.

For analysis, **oletools** and **OfficeDissector** offer comprehensive toolsets for examining both OLE and OOXML documents. These tools help in identifying and analyzing embedded macros, which often serve as vectors for malware delivery, typically downloading and executing additional malicious payloads. Analysis of VBA macros can be conducted without Microsoft Office by utilizing Libre Office, which allows for debugging with breakpoints and watch variables.

분석을 위해 **oletools**와 **OfficeDissector**는 OLE 및 OOXML 문서를 검사할 수 있는 포괄적인 도구 세트를 제공합니다. 이들 도구는 임베디드 매크로를 식별하고 분석하는 데 도움을 주며, 매크로는 종종 악성코드 전달 벡터로 사용되어 추가 악성 페이로드를 다운로드하고 실행합니다. VBA 매크로 분석은 Microsoft Office 없이도 Libre Office를 사용해 수행할 수 있으며, breakpoints 및 watch variables로 디버깅할 수 있습니다.

Installation and usage of **oletools** are straightforward, with commands provided for installing via pip and extracting macros from documents. Automatic execution of macros is triggered by functions like `AutoOpen`, `AutoExec`, or `Document_Open`.

**oletools**의 설치 및 사용은 간단하며, pip로 설치하고 문서에서 매크로를 추출하는 명령이 제공됩니다. 매크로의 자동 실행은 `AutoOpen`, `AutoExec`, 또는 `Document_Open` 같은 함수에 의해 트리거됩니다.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File 악용: Autodesk Revit RFA – ECC 재계산 및 제어된 gzip

Revit RFA 모델은 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF)로 저장됩니다. 직렬화된 모델은 storage/stream 아래에 있습니다:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest`의 주요 레이아웃(Observed on Revit 2025):

- Header
- GZIP-compressed payload (실제 직렬화된 객체 그래프)
- Zero padding
- Error-Correcting Code (ECC) 트레일러

Revit은 ECC 트레일러를 사용해 스트림의 작은 변형을 자동 복구하며 ECC와 일치하지 않는 스트림은 거부합니다. 따라서 압축된 바이트를 단순히 편집하면 변경 내용이 유지되지 않습니다: 변경이 되돌려지거나 파일이 거부됩니다. 역직렬화기가 보는 내용을 바이트 단위로 정확히 제어하려면 다음을 해야 합니다:

- Revit 호환 gzip 구현으로 다시 압축(그래야 Revit이 생성/수용하는 압축 바이트가 기대하는 바와 일치합니다).
- 패딩된 스트림 위에서 ECC 트레일러를 재계산하여 Revit이 자동 복구 없이 수정된 스트림을 수락하도록 합니다.

Practical workflow for patching/fuzzing RFA contents:

1) OLE compound document를 확장
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Global\Latest를 gzip/ECC 규칙으로 편집

- Deconstruct `Global/Latest`: 헤더는 유지하고, payload는 gunzip으로 풀어 바이트를 변형한 뒤 Revit과 호환되는 deflate parameters를 사용해 다시 gzip한다.
- zero-padding을 보존하고 ECC 트레일러를 재계산하여 새로운 바이트가 Revit에 의해 수용되도록 한다.
- 결정론적 byte-for-byte 재현이 필요하다면, Revit’s DLLs 주위에 최소한의 래퍼를 만들어 그 gzip/gunzip 경로와 ECC 계산을 호출하거나(연구에서 시연된 바와 같이) 이러한 동작을 복제하는 기존 도구를 재사용하라.

3) OLE compound document를 재구성
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
참고:

- CompoundFileTool은 NTFS 이름으로 유효하지 않은 문자를 이스케이프 처리하여 storages/streams를 파일시스템에 기록합니다; 출력 트리에서 원하는 스트림 경로는 정확히 `Global/Latest` 입니다.
- 클라우드 스토리지에서 RFA를 가져오는 ecosystem plugins를 통해 대량 공격을 배포할 때, 네트워크 주입을 시도하기 전에 패치한 RFA가 로컬에서 Revit의 무결성 검사를 먼저 통과하는지(gzip/ECC가 올바른지) 확인하세요.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Revit deserializer는 16-bit class index를 읽고 객체를 구성합니다. 특정 타입들은 non‑polymorphic하여 vtables가 없고; destructor 처리 방식을 악용하면 엔진이 attacker-controlled 포인터를 통해 간접 호출을 실행하는 type confusion이 발생합니다.
- `AString` (class index `0x1F`)를 선택하면 공격자가 제어하는 힙 포인터가 객체 오프셋 0에 배치됩니다. destructor 루프 동안 Revit은 실질적으로 다음을 실행합니다:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- serialized graph에 이러한 객체들을 여러 개 배치하여 destructor loop의 각 반복이 하나의 gadget(“weird machine”)을 실행하도록 하고, 전통적인 x64 ROP chain으로 stack pivot을 구성한다.

Windows x64 pivot/gadget 빌딩 세부사항은 다음을 참조:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

일반적인 ROP 가이드는 다음을 참조:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

도구:

- CompoundFileTool (OSS) — OLE compound files를 확장/재구성하기 위한 도구: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD (reverse/taint용); TTD로 page heap을 비활성화하여 트레이스를 작게 유지.
- 로컬 프록시(예: Fiddler)는 테스트용으로 plugin 트래픽에서 RFAs를 교체해 supply-chain 전달을 시뮬레이션할 수 있다.

## 참고자료

- [Autodesk Revit RFA 파일 파싱의 크래시로부터 Full Exploit RCE 제작 (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
