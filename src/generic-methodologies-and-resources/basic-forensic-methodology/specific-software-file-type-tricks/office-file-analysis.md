# Office 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

자세한 내용은 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)를 참고하세요. 아래는 간략한 요약입니다:<sup>[[2]](#references)</sup>

Microsoft Office 문서는 RTF 및 OLE/CFBF 기반 DOC, XLS, PPT 같은 레거시 형식이나 DOCX, XLSX, PPTX 같은 최신 **Office Open XML (OOXML)** 형식으로 흔히 나타납니다. Office 문서에는 매크로 같은 활성 콘텐츠가 포함될 수 있어, 피싱 및 malware 유포에 자주 사용됩니다. OOXML 파일은 ZIP 컨테이너이므로 압축을 풀어 파일 계층 구조와 XML 콘텐츠를 확인할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

OOXML 파일 구조를 살펴보는 방법으로 문서 압축 해제 명령과 출력 구조가 제시되어 있습니다. 이러한 파일에 데이터를 숨기는 기법도 문서화되어 있어, CTF 과제에서 데이터 은닉 기법이 계속 발전하고 있음을 보여줍니다.<sup>[[2]](#references)</sup>

분석에는 **oletools**와 **OfficeDissector**가 OLE 및 OOXML 문서를 검사할 수 있는 종합적인 도구 모음을 제공합니다. 이 도구들은 malware 전달 수단으로 자주 사용되는 내장 매크로를 식별하고 분석하는 데 도움이 됩니다. 매크로는 일반적으로 추가 악성 payload를 다운로드하고 실행합니다. Microsoft Office 없이도 Libre Office를 사용해 VBA 매크로를 분석할 수 있으며, 중단점과 watch 변수를 이용해 디버깅할 수 있습니다.<sup>[[2]](#references)</sup>

**oletools**는 간단히 설치하고 사용할 수 있으며, pip를 통한 설치 및 문서에서 매크로를 추출하는 명령이 제공됩니다. Word의 자동 매크로에는 `AutoExec`와 `AutoOpen`이 있으며, `Document_Open`은 열기 이벤트 프로시저입니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## VBA 매크로 분석: junk code와 UserForms

## Junk Code

매크로에는 분석을 늦추기 위한 **도달 불가능하거나 관련 없는 코드**가 포함될 수 있습니다. 분기를 역분석하는 데 시간을 들이기 전에 상수 조건을 식별하고 도달 가능한 동작을 추적하세요. 아래 예제에서는 참이 될 수 없는 `If` 조건으로 junk code를 숨깁니다.

![도달 불가능한 조건 분기와 junk code가 포함된 Word 매크로](<../../../images/image (369).png>)

## 매크로 폼

VBA UserForms는 텍스트 상자 등의 컨트롤에 데이터를 저장할 수 있습니다. 폼, 프레임, 페이지는 각각 `Controls` 컬렉션을 노출할 수 있으므로, 눈에 보이는 폼만 확인하지 말고 전체 컨트롤 계층을 열거해야 합니다. 아래 예제에서는 겹쳐진 텍스트 상자에 숨겨진 데이터를 저장합니다.<sup>[[6]](#references)</sup>

동적 분석 중에는 VBA의 `GetObject` 함수로 파일에서 Automation 객체를 가져오거나 이미 실행 중인 Automation 서버에 연결할 수 있습니다. 매크로는 이 객체 접근을 사용해 문서에서 눈에 띄지 않는 데이터에 접근할 수 있으므로, 반환된 객체와 UserForm 컨트롤 트리를 모두 검사하세요.<sup>[[7]](#references)</sup>

![겹쳐진 텍스트 상자에 데이터가 숨겨진 매크로 UserForm](<../../../images/image (344).png>)

암호화된 Office 문서는 [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example)를 참고하세요.

---

OLE/CFBF를 사용하는 Revit RFA 파일은 [ECC recomputation, controlled gzip, and deserializer exploitation](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md)을 참고하세요. 이 parser-exploitation workflow는 Office 문서 초기 분석과 별개입니다.

## References

- [1] [OLE Compound File (CFBF) 문서](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Forensics CTF 현장 가이드](https://trailofbits.github.io/ctf/forensics/)
- [3] [olevba 문서 (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Document.Open 이벤트 (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - 컬렉션, 컨트롤, 객체 (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - `GetObject` 함수](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
