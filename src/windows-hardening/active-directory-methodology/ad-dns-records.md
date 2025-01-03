# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

기본적으로 **Active Directory**의 **모든 사용자**는 도메인 또는 포리스트 DNS 존에서 **모든 DNS 레코드**를 **열거**할 수 있으며, 이는 존 전송과 유사합니다(사용자는 AD 환경에서 DNS 존의 자식 객체를 나열할 수 있습니다).

도구 [**adidnsdump**](https://github.com/dirkjanm/adidnsdump)는 내부 네트워크의 정찰 목적을 위해 존의 **모든 DNS 레코드**를 **열거**하고 **내보내기** 할 수 있게 해줍니다.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
자세한 정보는 [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)를 읽으세요.

{{#include ../../banners/hacktricks-training.md}}
