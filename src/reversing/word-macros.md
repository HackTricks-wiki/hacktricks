# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Junk Code

매크로를 reversing하기 어렵게 만들기 위해 **사용되지 않는 정크 코드**를 삽입하는 경우가 매우 흔합니다.\
예를 들어, 다음 이미지에서는 절대로 true가 될 수 없는 `If` 문을 사용해 정크 및 쓸모없는 코드를 실행하는 것을 볼 수 있습니다.

![Word Macros - Junk Code: 예를 들어, 다음 이미지에서는 절대로 true가 될 수 없는 If 문을 사용해 정크 및 쓸모없는 코드를 실행하는 것을 볼 수 있습니다](<../images/image (369).png>)

### Macro Forms

**GetObject** 함수를 사용하면 매크로의 form에서 데이터를 가져올 수 있습니다. 이는 분석을 어렵게 만드는 데 사용될 수 있습니다. 다음은 **텍스트 상자 내부에 데이터를 숨기는** 데 사용되는 매크로 form의 사진입니다(텍스트 상자 안에 다른 텍스트 상자를 숨길 수 있음).

![Junk Code - Macro Forms: GetObject 함수를 사용하면 매크로의 form에서 데이터를 가져올 수 있습니다. 이는 분석을 어렵게 만드는 데 사용될 수 있습니다. 다음은...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
