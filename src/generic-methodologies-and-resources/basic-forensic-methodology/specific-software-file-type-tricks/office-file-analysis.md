# Office 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

자세한 내용은 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)를 확인하세요. 다음은 간단한 요약입니다:<sup>[[4]](#references)</sup>

Microsoft Office 문서는 RTF 및 OLE/CFBF 기반 DOC, XLS, PPT와 같은 레거시 형식이나 DOCX, XLSX, PPTX와 같은 최신 **Office Open XML (OOXML)** 형식으로 흔히 제공됩니다. Office 문서에는 매크로와 같은 활성 콘텐츠가 포함될 수 있어 피싱 및 malware 유포에 자주 사용됩니다. OOXML 파일은 ZIP 컨테이너이므로 압축을 풀어 파일 계층 구조와 XML 콘텐츠를 살펴볼 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

OOXML 파일 구조를 살펴보기 위해 문서의 압축을 푸는 명령어와 출력 구조가 제시되어 있습니다. 이러한 파일에 데이터를 숨기는 기법도 문서화되어 있으며, 이는 CTF 과제에서 데이터 은닉 기법이 계속 발전하고 있음을 보여 줍니다.<sup>[[4]](#references)</sup>

분석에는 **oletools**와 **OfficeDissector**가 OLE 및 OOXML 문서를 검사하기 위한 종합적인 도구 모음을 제공합니다. 이 도구들은 malware 전달 경로로 자주 사용되는 임베디드 매크로를 식별하고 분석하는 데 도움이 됩니다. 매크로는 일반적으로 추가 악성 페이로드를 다운로드하고 실행합니다. Libre Office를 사용하면 Microsoft Office 없이도 VBA 매크로를 분석할 수 있으며, 중단점과 감시 변수를 이용해 디버깅할 수 있습니다.<sup>[[4]](#references)</sup>

**oletools**는 간단하게 설치하고 사용할 수 있으며, pip를 통한 설치와 문서에서 매크로를 추출하는 명령어가 제공됩니다. Word의 자동 매크로에는 `AutoExec`와 `AutoOpen`이 있으며, `Document_Open`은 문서 열기 이벤트 프로시저입니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

비밀번호로 암호화된 Office 문서는 [문법 기반 오프라인 복구 워크플로](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example)를 참조하세요.

---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC 재계산 및 제어된 gzip

Revit RFA 모델은 [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)(일명 CFBF)로 저장됩니다. 직렬화된 모델은 다음 storage/stream에 있습니다:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest`의 주요 레이아웃(Revit 2025에서 확인):

- Header
- GZIP 압축 페이로드(실제 직렬화된 객체 그래프)
- 0으로 채워진 패딩
- 오류 정정 코드(ECC) 트레일러

Revit은 ECC 트레일러를 사용해 스트림의 작은 변경 사항을 자동으로 복구하며, ECC와 일치하지 않는 스트림은 거부합니다. 따라서 압축된 바이트를 단순히 편집해도 변경 사항이 유지되지 않습니다. 변경 사항이 되돌려지거나 파일이 거부됩니다. 역직렬화기가 보는 내용을 바이트 단위로 정확하게 제어하려면 다음을 수행해야 합니다:<sup>[[1]](#references)</sup>

- Revit과 호환되는 gzip 구현으로 다시 압축합니다(그래야 생성하거나 허용하는 압축 바이트가 Revit이 예상하는 내용과 일치합니다).
- 패딩된 스트림에 대해 ECC 트레일러를 다시 계산합니다. 그러면 Revit이 스트림을 자동으로 복구하지 않고 수정된 스트림을 허용합니다.

RFA 콘텐츠를 패치하거나 fuzzing하기 위한 실용적인 워크플로:<sup>[[1]](#references)</sup>

1) OLE 복합 문서를 확장합니다.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) gzip/ECC 규칙에 맞게 `Global\Latest` 수정

- `Global/Latest`를 분해합니다. 헤더는 유지하고, payload를 gunzip한 뒤 바이트를 수정하고 Revit 호환 deflate 매개변수를 사용해 다시 gzip합니다.
- zero-padding을 유지하고 ECC trailer를 다시 계산해 Revit이 새 바이트를 승인하도록 합니다.
- 바이트 단위로 정확히 재현해야 한다면, 연구에서 시연한 것처럼 Revit DLL을 사용하는 최소한의 wrapper를 만들어 gzip/gunzip 경로와 ECC 계산을 호출하거나, 이러한 의미를 재현하는 사용 가능한 helper를 재사용합니다.

3) OLE 복합 문서를 재구성합니다.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

참고:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool은 NTFS 이름에 사용할 수 없는 문자를 이스케이프하여 스토리지/스트림을 파일시스템에 기록합니다. 원하는 스트림 경로는 출력 트리에서 정확히 `Global/Latest`입니다.
- 클라우드 스토리지에서 RFA를 가져오는 에코시스템 플러그인을 통해 대규모 공격을 수행할 때는 네트워크 주입을 시도하기 전에 패치된 RFA가 로컬에서 Revit의 무결성 검사를 통과하는지(gzip/ECC가 올바른지) 확인하세요.

공격에 악용할 인사이트(어떤 바이트를 gzip 페이로드에 넣을지 참고):<sup>[[1]](#references)</sup>

- Revit 역직렬화기는 16비트 클래스 인덱스를 읽고 객체를 생성합니다. 일부 타입은 다형성이 없고 vtable도 없습니다. 소멸자 처리를 악용하면 타입 혼동이 발생하여 엔진이 공격자가 제어하는 포인터를 통해 간접 호출을 실행합니다.
- `AString`(클래스 인덱스 `0x1F`)을 선택하면 공격자가 제어하는 힙 포인터가 객체 오프셋 0에 배치됩니다. 소멸자 루프에서 Revit은 사실상 다음을 실행합니다:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- 직렬화된 그래프에 이러한 객체를 여러 개 배치하여 소멸자 루프가 반복될 때마다 하나의 gadget(“weird machine”)이 실행되도록 하고, 스택 피벗을 통해 일반적인 x64 ROP 체인으로 이동하도록 구성합니다.

Windows x64 피벗/gadget 구성에 대한 자세한 내용은 여기에서 확인하세요:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

일반적인 ROP 지침은 여기에서 확인하세요:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

도구:<sup>[[1]](#references)</sup>

- OLE 복합 파일을 확장/재구성하는 CompoundFileTool (OSS): https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- 역공학/taint 분석에는 IDA Pro + WinDBG TTD를 사용합니다. 트레이스를 간결하게 유지하려면 TTD에서 page heap을 비활성화하세요.
- 로컬 프록시(예: Fiddler)를 사용하면 테스트 중 플러그인 트래픽의 RFA를 바꿔 공급망 전달을 시뮬레이션할 수 있습니다.

## References

- [1] [Autodesk Revit RFA 파일 파싱 충돌에서 완전한 RCE 익스플로잇 제작 (ZDI 블로그)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE 복합 파일(CFBF) 문서](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF 현장 가이드](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba 문서 (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [자동 매크로 (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open 이벤트(Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
