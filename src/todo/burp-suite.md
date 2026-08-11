# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

- **Simple list:** payload로 사용할 문자열의 구성된 목록을 사용합니다.
- **Runtime file:** 런타임에 한 줄당 하나의 payload를 읽습니다. Burp가 전체 파일을 메모리에 로드하지 않으므로 대규모 목록에 유용합니다.
- **Case modification:** 입력 문자열의 대소문자를 변경합니다. 예를 들어 소문자, 대문자, 문장형 대소문자 또는 제목형 대소문자로 변경할 수 있습니다.
- **Numbers:** 구성된 범위 내에서 순차적이거나 무작위인 숫자를 생성합니다.
- **Brute forcer:** 선택한 문자 집합과 최소/최대 길이에 대해 가능한 모든 순열을 생성합니다.<sup>[[1]](#references)</sup>

## Extensions and companion tools

- **Collabfiltrator**는 명령을 실행하고 그 출력을 Burp Collaborator에 대한 DNS 쿼리를 통해 exfiltrate하는 payload를 생성합니다.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter**는 다른 reporting workflow에서 사용할 수 있도록 Burp findings를 내보냅니다.<sup>[[3]](#references)</sup>
- **HTTP Script Generator**는 HTTP requests를 여러 언어의 scripts로 변환합니다.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
