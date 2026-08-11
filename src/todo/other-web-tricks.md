# 기타 Web Tricks

{{#include ../banners/hacktricks-training.md}}

## Host header

백엔드는 absolute link를 구성할 때 HTTP `Host` 필드를 신뢰하는 경우가 있습니다. 비밀번호 재설정 이메일이 공격자가 제공한 host를 사용하는 경우, 피해자의 재설정을 요청하면 token이 포함된 link가 공격자가 제어하는 도메인을 통해 전송될 수 있습니다. 각 proxy hop에서 forwarded-host 필드, 중복 Host 처리, absolute-form request target도 테스트하십시오.<sup>[[1]](#references)</sup>

> [!WARNING]
> 사용자의 클릭이 필요하지 않을 수도 있습니다. **메일 보안 scanner, preview service 또는 기타 intermediary가 공격자가 제어하는 link를 자동으로 요청하여**, reset token을 노출할 수 있습니다.

## Session booleans

일부 애플리케이션은 완료된 verification을 session의 boolean으로 기록한 다음, 다른 endpoint가 해당 flag에 의존하도록 합니다. 한 resource에 대해 정상적으로 check를 통과한 후, 동일한 flag가 다른 user, object 또는 workflow를 잘못 authorizate하는지 테스트하십시오. 이는 단순한 IDOR이 아니라 second-order authorization/state-reuse flaw입니다.<sup>[[2]](#references)</sup>

## Registration functionality

이미 존재하는 user로 register해 보십시오. 동등한 문자(점, 여러 개의 공백 및 Unicode)를 사용하는 방법도 시도하십시오.

## Email-change state confusion

email address를 등록한 후 confirm하기 전에 변경하십시오. 새 address에 대한 confirmation이 이전 address로 전송되는지, 또는 이전 token을 confirm하면 새 address가 activate되는지 확인하십시오. Confirmation token은 정확한 account, pending address, purpose 및 current state에 binding되어야 합니다.

## 노출된 Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

HTTP `TRACE` method는 진단을 위해 수신된 request를 loop-back하도록 요청합니다. RFC 9110은 recipient가 reflected content에서 credentials 및 cookies와 같은 민감한 field를 제외하도록 요구하지만, 안전하지 않은 implementation이나 intermediary가 추가한 header로 인해 내부 request transformation이 여전히 노출될 수 있습니다. Browser는 script로 생성된 TRACE request를 차단하므로, 과거의 cross-site tracing attack 역시 보호된 field를 주입할 별도의 방법에 의존합니다.<sup>[[3]](#references)</sup>![TRACE response를 보여주는 이미지](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![post용 이미지](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Host Header Injection으로 모든 사용자의 account를 탈취할 수 있었던 방법](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [잘 알려지지 않은 attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, section 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
