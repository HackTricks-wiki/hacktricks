# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

원격 프로세스와 상호작용하는 작업 자동화를 위한 스크립팅 언어입니다. 다른 프로세스에 특정 작업을 수행하도록 요청하는 것이 매우 쉽습니다. **악성 소프트웨어**는 이러한 기능을 악용하여 다른 프로세스에서 내보낸 기능을 남용할 수 있습니다.\
예를 들어, 악성 소프트웨어는 **브라우저에서 열린 페이지에 임의의 JS 코드를 주입할 수 있습니다**. 또는 **사용자에게 요청된 일부 허용 권한을 자동으로 클릭할 수 있습니다**;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
여기 몇 가지 예가 있습니다: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScript를 사용한 악성 소프트웨어에 대한 더 많은 정보는 [**여기**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)에서 확인하세요.

Apple 스크립트는 쉽게 "**컴파일**"될 수 있습니다. 이러한 버전은 `osadecompile`로 쉽게 "**디컴파일**"될 수 있습니다.

그러나 이 스크립트는 또한 **"읽기 전용"으로 내보낼 수 있습니다** ( "내보내기..." 옵션을 통해):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
이 경우 `osadecompile`로도 콘텐츠를 디컴파일할 수 없습니다.

그러나 이러한 종류의 실행 파일을 이해하는 데 사용할 수 있는 도구가 여전히 있습니다. [**자세한 내용은 이 연구를 읽어보세요**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). 도구 [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler)와 [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile)는 스크립트가 어떻게 작동하는지 이해하는 데 매우 유용할 것입니다.

{{#include ../../../../../banners/hacktricks-training.md}}
