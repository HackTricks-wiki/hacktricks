# Word 매크로

{{#include ../banners/hacktricks-training.md}}

## Junk Code

매크로에는 분석을 지연시키기 위한 **실행 불가능하거나 관련 없는 코드**가 포함될 수 있습니다. 분기를 역분석하는 데 시간을 들이기 전에 상수 조건을 식별하고 도달 가능한 동작을 추적하세요. 아래 예제에서는 절대 참이 될 수 없는 `If` 조건을 사용해 junk code를 숨깁니다.

![도달할 수 없는 조건부 분기와 junk code가 포함된 Word 매크로](<../images/image (369).png>)

## Macro Forms

VBA UserForms는 텍스트 상자와 같은 컨트롤에 데이터를 저장할 수 있습니다. Form, frame, page가 각각 `Controls` 컬렉션을 노출할 수 있으므로, 분석가는 form에 표시되는 내용에만 의존하지 말고 전체 컨트롤 계층을 열거해야 합니다. 아래 예제에서는 겹쳐진 텍스트 상자에 숨겨진 데이터를 저장합니다.<sup>[[1]](#references)</sup>

![겹쳐진 텍스트 상자에 데이터를 숨긴 매크로 UserForm](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - 컬렉션, 컨트롤 및 객체 (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
