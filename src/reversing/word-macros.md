# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Macros에는 분석을 지연시키기 위한 **도달할 수 없거나 관련 없는 코드**가 포함될 수 있습니다. 분기를 reversing하는 데 시간을 들이기 전에 항상 조건을 확인하고 도달 가능한 동작을 추적하세요. 아래 예제에서는 절대로 참이 될 수 없는 `If` 조건을 사용해 junk code를 숨깁니다.

![도달할 수 없는 조건 분기와 junk code가 포함된 Word macro](<../images/image (369).png>)

## Macro Forms

VBA UserForms는 텍스트 상자와 같은 컨트롤에 데이터를 저장할 수 있습니다. form, frame, page는 각각 `Controls` collection을 노출할 수 있으므로, 분석가는 form에 표시되는 내용에만 의존하지 말고 전체 control hierarchy를 열거해야 합니다. 아래 예제에서는 겹쳐진 텍스트 상자에 숨겨진 데이터를 저장합니다.<sup>[[1]](#references)</sup>

동적 분석 중에 VBA의 `GetObject` function은 파일에서 Automation object를 가져오거나 이미 실행 중인 Automation server에 연결할 수 있습니다. Macros는 이러한 object access를 사용해 표시되는 문서에서 쉽게 확인할 수 없는 데이터에 접근할 수 있으므로, 반환된 object와 UserForm control tree를 모두 검사하세요.<sup>[[2]](#references)</sup>

![겹쳐진 텍스트 상자에 데이터가 숨겨진 macro UserForm](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - 컬렉션, 컨트롤 및 개체(Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - `GetObject` function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
