# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

여러 경우에 백엔드는 특정 작업을 수행하기 위해 **Host header**를 신뢰합니다. 예를 들어, 그 값을 **password reset을 보낼 도메인**으로 사용할 수 있습니다. 따라서 password reset 링크가 포함된 이메일을 받으면, 사용되는 도메인은 Host header에 입력한 도메인입니다. 그런 다음 다른 사용자의 password reset을 요청하고, 도메인을 자신이 제어하는 도메인으로 변경하여 해당 사용자의 password reset 코드를 탈취할 수 있습니다. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> password reset 링크를 사용자가 클릭할 때까지 기다리지 않아도 token을 얻을 수 있다는 점에 유의하세요. **spam filters 또는 기타 중간 장치/bot이 링크를 분석하기 위해 클릭할 수도 있기 때문입니다**.

### Session booleans

일부 경우 검증을 올바르게 완료하면 백엔드는 **session의 security attribute에 값이 "True"인 boolean을 추가하기만 합니다**. 그러면 다른 endpoint가 해당 검사를 성공적으로 통과했는지 확인할 수 있습니다.\
그러나 **검사를 통과하고** session의 security attribute에 "True" 값이 부여되었다면, 동일한 attribute에 **의존하지만** 자신에게 **접근 권한이 없어야 하는** 다른 resource에 **접근**할 수 있는지 시도해 볼 수 있습니다. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

이미 존재하는 사용자로 register를 시도하세요. 또한 동등한 문자(점, 여러 개의 공백 및 Unicode)를 사용해 보세요.

### Takeover emails

이메일을 register한 다음, 확인하기 전에 이메일을 변경하세요. 그런 다음 새 confirmation email이 처음 register한 이메일로 전송된다면 모든 이메일을 takeover할 수 있습니다. 또는 첫 번째 이메일을 확인하여 두 번째 이메일을 활성화할 수 있다면 모든 account를 takeover할 수도 있습니다.

### Access Internal servicedesk of companies using atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

개발자는 production environment에서 다양한 debugging option을 비활성화하는 것을 잊을 수 있습니다. 예를 들어 HTTP `TRACE` method는 diagnostic purpose를 위해 설계되었습니다. 활성화되어 있으면 web server는 `TRACE` method를 사용하는 request에 응답하면서, 수신한 정확한 request를 response에 그대로 반영합니다. 이 동작은 대개 무해하지만, reverse proxy가 request에 추가할 수 있는 내부 authentication header의 이름과 같은 정보가 노출되는 경우가 있습니다.![게시물 이미지](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![게시물 이미지](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
