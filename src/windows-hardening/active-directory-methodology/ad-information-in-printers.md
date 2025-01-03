{{#include ../../banners/hacktricks-training.md}}

인터넷에는 **기본/약한** 로그인 자격 증명으로 LDAP가 구성된 프린터의 위험성을 **강조하는** 여러 블로그가 있습니다.\
이는 공격자가 프린터를 **속여서 악성 LDAP 서버에 인증하도록** 할 수 있기 때문입니다 (일반적으로 `nc -vv -l -p 444`면 충분합니다) 그리고 프린터의 **자격 증명을 평문으로** 캡처할 수 있습니다.

또한, 여러 프린터는 **사용자 이름이 포함된 로그**를 가지고 있거나 도메인 컨트롤러에서 **모든 사용자 이름을 다운로드**할 수 있습니다.

이 모든 **민감한 정보**와 일반적인 **보안 부족**은 프린터를 공격자에게 매우 흥미롭게 만듭니다.

이 주제에 대한 몇 가지 블로그:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## 프린터 구성

- **위치**: LDAP 서버 목록은 다음에서 찾을 수 있습니다: `Network > LDAP Setting > Setting Up LDAP`.
- **동작**: 인터페이스는 자격 증명을 다시 입력하지 않고 LDAP 서버 수정을 허용하여 사용자 편의를 목표로 하지만 보안 위험을 초래합니다.
- **악용**: 악용은 LDAP 서버 주소를 제어된 머신으로 리디렉션하고 "연결 테스트" 기능을 활용하여 자격 증명을 캡처하는 것입니다.

## 자격 증명 캡처

**자세한 단계는 원본 [source](https://grimhacker.com/2018/03/09/just-a-printer/)를 참조하십시오.**

### 방법 1: 넷캣 리스너

간단한 넷캣 리스너면 충분할 수 있습니다:
```bash
sudo nc -k -v -l -p 386
```
그러나 이 방법의 성공률은 다릅니다.

### 방법 2: Slapd가 포함된 전체 LDAP 서버

더 신뢰할 수 있는 접근 방식은 전체 LDAP 서버를 설정하는 것입니다. 프린터는 자격 증명 바인딩을 시도하기 전에 널 바인드를 수행하고 쿼리를 실행합니다.

1. **LDAP 서버 설정**: 가이드는 [이 출처](https://www.server-world.info/en/note?os=Fedora_26&p=openldap)에서 단계를 따릅니다.
2. **주요 단계**:
- OpenLDAP 설치.
- 관리자 비밀번호 구성.
- 기본 스키마 가져오기.
- LDAP DB에 도메인 이름 설정.
- LDAP TLS 구성.
3. **LDAP 서비스 실행**: 설정이 완료되면 LDAP 서비스를 다음을 사용하여 실행할 수 있습니다:
```bash
slapd -d 2
```
## 참고 문헌

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}
