# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Basic Payloads

- **Simple List:** 각 줄에 하나의 entry가 포함된 list
- **Runtime File:** runtime에 읽는 list (memory에 로드되지 않음). 큰 list를 지원하기 위한 용도.
- **Case Modification:** 문자열 list에 일부 변경 사항 적용(변경 없음, 소문자로 변환, 대문자로 변환, Proper name - 첫 글자만 대문자이고 나머지는 소문자-, Proper Name -첫 글자만 대문자이고 나머지는 그대로 유지-.
- **Numbers:** Z step 또는 random 방식으로 X부터 Y까지의 숫자 생성.
- **Brute Forcer:** Character set, min 및 max length.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : burpcollab에 DNS requests를 보내 commands를 실행하고 output을 가져오는 Payload.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
