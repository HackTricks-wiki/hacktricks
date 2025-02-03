# Other Web Tricks

{{#include ./banners/hacktricks-training.md}}

### Host header

여러 번 백엔드는 **Host header**를 신뢰하여 일부 작업을 수행합니다. 예를 들어, 비밀번호 재설정을 위한 **도메인으로 그 값을 사용할 수 있습니다**. 따라서 비밀번호를 재설정하는 링크가 포함된 이메일을 받으면 사용되는 도메인은 Host header에 입력한 것입니다. 그러면 다른 사용자의 비밀번호 재설정을 요청하고 도메인을 자신이 제어하는 것으로 변경하여 그들의 비밀번호 재설정 코드를 훔칠 수 있습니다. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> 사용자가 비밀번호 재설정 링크를 클릭할 때까지 기다릴 필요가 없을 수도 있다는 점에 유의하세요. **스팸 필터나 다른 중개 장치/봇이 이를 클릭하여 분석할 수 있습니다**.

### Session booleans

때때로 일부 검증을 올바르게 완료하면 백엔드는 **세션의 보안 속성에 "True" 값을 가진 부울을 추가합니다**. 그런 다음 다른 엔드포인트는 해당 검사를 성공적으로 통과했는지 알 수 있습니다.\
그러나 **검사를 통과**하고 세션이 보안 속성에서 "True" 값을 부여받으면, **접근 권한이 없어야 하는** 동일한 속성에 의존하는 **다른 리소스에 접근**을 시도할 수 있습니다. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Register functionality

이미 존재하는 사용자로 등록해 보세요. 또한 동등한 문자(점, 많은 공백 및 유니코드)를 사용해 보세요.

### Takeover emails

이메일을 등록한 후, 확인하기 전에 이메일을 변경하세요. 그런 다음, 새 확인 이메일이 첫 번째 등록된 이메일로 전송되면, 어떤 이메일도 인수할 수 있습니다. 또는 두 번째 이메일이 첫 번째 이메일을 확인하도록 활성화할 수 있다면, 어떤 계정도 인수할 수 있습니다.

### Access Internal servicedesk of companies using atlassian

{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

개발자는 프로덕션 환경에서 다양한 디버깅 옵션을 비활성화하는 것을 잊을 수 있습니다. 예를 들어, HTTP `TRACE` 메서드는 진단 목적으로 설계되었습니다. 활성화되면 웹 서버는 `TRACE` 메서드를 사용하는 요청에 대해 수신된 정확한 요청을 응답에 에코하여 응답합니다. 이 동작은 종종 무해하지만 때때로 내부 인증 헤더의 이름과 같은 정보 유출로 이어질 수 있습니다.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ./banners/hacktricks-training.md}}

### Same-Site Scripting

특정 DNS 잘못 구성으로 인해 localhost 또는 127.0.0.1로 해결되는 도메인 또는 서브도메인을 만날 때 발생합니다. 이는 공격자가 RFC2109 (HTTP State Management Mechanism) 동일 출처 제한을 우회하고 따라서 상태 관리 데이터를 탈취할 수 있게 합니다. 또한 교차 사이트 스크립팅을 허용할 수 있습니다. [여기서](https://seclists.org/bugtraq/2008/Jan/270) 더 읽을 수 있습니다.
