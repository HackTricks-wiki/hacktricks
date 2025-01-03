{{#include ./banners/hacktricks-training.md}}

# 기본 페이로드

- **간단한 목록:** 각 줄에 항목이 포함된 목록
- **런타임 파일:** 런타임에 읽는 목록(메모리에 로드되지 않음). 큰 목록을 지원하기 위해.
- **대소문자 수정:** 문자열 목록에 일부 변경 적용(변경 없음, 소문자, 대문자, 고유명사 - 첫 글자 대문자, 나머지는 소문자-, 고유명사 - 첫 글자 대문자, 나머지는 그대로-).
- **숫자:** Z 단계 또는 무작위로 X에서 Y까지 숫자 생성.
- **브루트 포스:** 문자 집합, 최소 및 최대 길이.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : DNS 요청을 통해 burpcollab에 명령을 실행하고 출력을 가져오는 페이로드.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ./banners/hacktricks-training.md}}
