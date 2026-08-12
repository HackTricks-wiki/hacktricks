# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

Burp Intruder에는 다음과 같은 내장 payload generator 및 transformation이 포함되어 있습니다:<sup>[[1]](#references)</sup>

- **Simple list:** 구성된 문자열 목록을 payload로 사용합니다.
- **Runtime file:** runtime에 한 줄당 하나의 payload를 읽습니다. Burp가 파일 전체를 메모리에 로드하지 않으므로 대규모 목록에 유용합니다.
- **Case modification:** 수정되지 않은 값, 소문자 및 대문자 형식, `Propername` (첫 글자는 대문자이고 나머지는 소문자), 또는 `ProperName` (첫 글자는 대문자이고 나머지 문자는 변경되지 않음)을 생성합니다. Burp는 중복 결과를 삭제합니다.
- **Numbers:** 구성된 범위 내에서 순차적 또는 random number를 생성합니다.
- **Brute forcer:** 선택한 character set과 최소/최대 길이에 대해 가능한 모든 permutation을 생성합니다.

## Extensions and companion tools

- **Collabfiltrator**는 commands를 실행하고 Burp Collaborator에 대한 DNS queries를 통해 그 출력을 exfiltrate하는 payload를 생성합니다.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter**는 다른 reporting workflow에서 사용할 수 있도록 Burp findings를 export합니다.<sup>[[3]](#references)</sup>
- **HTTP Script Generator**는 HTTP requests를 여러 언어의 scripts로 변환합니다.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger 문서 - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
