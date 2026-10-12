# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

Burp Intruder에는 다음과 같은 기본 payload 생성기 및 변환 기능이 포함되어 있습니다:<sup>[[1]](#references)</sup>

- **Simple list:** 설정한 문자열 목록을 payload로 사용합니다.
- **Runtime file:** 실행 중에 한 줄씩 payload를 읽습니다. Burp가 파일 전체를 메모리에 로드하지 않으므로 대용량 목록에 유용합니다.
- **Case modification:** 원본 값, 소문자 및 대문자 형식, `Propername`(첫 글자는 대문자, 나머지는 소문자), `ProperName`(첫 글자는 대문자, 나머지 문자는 그대로)을 생성합니다. Burp는 중복 결과를 제거합니다.
- **Numbers:** 설정한 범위 내에서 순차 또는 무작위 숫자를 생성합니다.
- **Brute forcer:** 선택한 문자 집합과 최소/최대 길이에 따라 가능한 모든 조합을 생성합니다.

## Extensions and companion tools

- **Collabfiltrator**는 명령을 실행하고 그 출력을 DNS 쿼리를 통해 Burp Collaborator로 유출하는 payload를 생성합니다.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter**는 다른 보고 워크플로에서 사용할 수 있도록 Burp 결과를 내보냅니다.<sup>[[3]](#references)</sup>
- **HTTP Script Generator**는 HTTP 요청을 여러 언어의 스크립트로 변환합니다.<sup>[[4]](#references)</sup>

## Session Switcher를 사용한 다중 세션 권한 테스트

[Session Switcher](https://github.com/doyensec/burp-session-switcher)는 Burp Suite `2025.5+`용 Java 확장으로, cookies와 일반적이지 않은 headers를 이름이 지정된 credential profile로 저장합니다. Repeater나 가로챈 Proxy 요청 등 편집 가능한 요청 편집기에서 profile을 선택하면 요청의 인증 정보가 대체됩니다. 이는 재전송을 돕는 기능이지 **권한 우회**가 아닙니다. 수평 접근, 수직 역할 경계, tenant 격리, [IDOR/BOLA](../pentesting-web/idor.md)를 확인할 때 [web testing methodology](../pentesting-web/web-vulnerabilities-methodology.md)의 일환으로 동일한 요청을 서로 다른 계정으로 전송하는 데 사용하세요.<sup>[[5]](#references)[[8]](#references)</sup>

### 반복 가능한 identity 차이 테스트 워크플로

다음 워크플로는 리소스/작업과 요청을 수행하는 identity를 별도의 테스트 변수로 유지하여, 오래된 토큰이나 잘못된 브라우저 세션으로 인한 오탐을 줄입니다.<sup>[[5]](#references)[[8]](#references)</sup>

1. 별도의 브라우저 profile 또는 컨테이너에서 각 관련 사용자, 역할, tenant를 대표하는 테스트 계정으로 인증합니다.
2. 한 identity의 cookies와 headers가 포함된 요청을 열고 **Sessions > New**를 선택한 다음 `tenant-a-user` 또는 `tenant-b-admin`처럼 명확한 이름으로 profile을 지정합니다. 모든 테스트 identity에 대해 반복합니다.
3. 후보 요청을 Repeater로 보내고 method, endpoint, parameters, object identifier는 바꾸지 않은 채 선택한 session만 전환하여 재전송합니다. 상태 코드뿐 아니라 응답 데이터와 관찰 가능한 상태 변경도 비교합니다.
4. 객체 수준 검사를 위해 계정 A 소유임을 알고 있는 객체에 대한 요청을 계정 B의 profile을 선택한 상태로 재전송합니다. 기능 수준 검사를 위해 권한이 낮은 profile로 동일한 특권 작업을 재전송합니다.
5. 재인증하거나 토큰이 교체된 후에는 현재 브라우저 요청에서 **Update**를 사용하거나, 비교를 반복하기 전에 Auto Update 규칙을 설정합니다.

### 캡처 및 주입 의미

두 identity의 인증 정보가 혼합된 요청은 비교를 무효화할 수 있으므로 테스트 전에 업데이트/주입 모드를 확인하세요. 현재 기본값은 모든 요청 cookies를 profile에 반영하고, 이미 저장된 일반적이지 않은 headers만 업데이트하며, 선택한 profile의 cookies를 대상 요청에 반영(기존 cookies 제거)하고 profile의 headers를 추가합니다. selector는 정확한 하위 도메인, 최상위 애플리케이션 도메인(기본값), 또는 저장된 모든 profile로 범위를 제한할 수 있습니다.<sup>[[7]](#references)</sup>

- **Mirror**는 전체 cookie 집합이 identity를 정의하고 오래된 대상 cookies를 제거해야 할 때 유용합니다.
- **Update existing**는 브라우저 트래픽에서 관련 없는 cookies나 headers를 가져오지 않고 값의 교체를 반영합니다.
- **Add all**은 profile 또는 요청에 이미 저장된 추가 값을 유지합니다. 이전 session의 identity 관련 데이터가 남지 않는지 확인하세요.
- **Do nothing**은 해당 credential 종류가 관련 없는 경우 profile 업데이트에서 cookies 또는 headers를 제외합니다.

### Proxy 기반 session 동기화

Auto Update 규칙은 Proxy 트래픽을 저장된 profile과 연결해 해당 profile의 cookies/headers를 갱신합니다. 전용 요청 header, profile별 `User-Agent` marker, 식별 cookie, `X-PwnFox-Color`, JWT claim처럼 안정적인 식별자를 사용하세요. 관련 없는 애플리케이션이 profile을 업데이트하지 못하도록 이를 scope/domain/path 조건과 함께 적용합니다. 규칙 하나에 있는 조건은 순서대로 논리적 `AND`로 평가되므로 제한적인 검사를 먼저 배치하세요. `OR`는 동일한 profile을 대상으로 여러 규칙을 만들어 구현합니다. 부정 조건 매칭도 지원됩니다.<sup>[[6]](#references)</sup>

일치하는 각 규칙에서 cookies와 headers에 대해 **Mirror request**, **Add all**, **Update existing**, **Do nothing** 중 하나를 각각 선택합니다. 요청 전용 규칙은 Proxy가 요청을 받으면 실행되며, 응답 상태, 응답 header 또는 응답 본문 조건을 추가하면 응답이 도착한 후에 평가됩니다. highlight color로 일치하는 트래픽을 표시하면 각 브라우저 identity가 의도한 profile만 업데이트하는지 확인하는 데 도움이 됩니다.<sup>[[6]](#references)</sup>

저장된 profile은 Burp project에 보관되며, JSON project-data 내보내기에는 해당 session과 cookies 및 headers가 포함됩니다. 두 파일 모두 유효한 credential 자료로 취급하고 접근을 제한하며, engagement가 끝나면 저장된 확장 데이터를 삭제하세요.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [PortSwigger 문서 - Burp Intruder payload 유형](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Session Switcher 소스 및 사용 문서](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Session Switcher Auto Update 규칙](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Session Switcher 설정](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: Burp Suite에서 다중 세션 권한 테스트 간소화](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
