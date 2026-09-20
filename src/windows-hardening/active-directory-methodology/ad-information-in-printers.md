# 프린터의 정보

{{#include ../../banners/hacktricks-training.md}}

인터넷에는 프린터를 **기본/취약한 logon 자격 증명으로 LDAP에 구성해 두는 것의 위험성**을 **강조하는** 여러 블로그가 있습니다.  \
이는 공격자가 **프린터가 rogue LDAP server에 대해 authenticate하도록 유도**할 수 있기 때문입니다(일반적으로 `nc -vv -l -p 389` 또는 `slapd -d 2`면 충분합니다). 이를 통해 프린터의 **자격 증명을 평문으로** 수집할 수 있습니다.

또한 여러 프린터에는 **사용자 이름이 포함된 로그**가 저장되어 있거나, 심지어 Domain Controller에서 **모든 사용자 이름을 다운로드**할 수도 있습니다.

이러한 **민감한 정보**와 일반적인 **보안 부족**으로 인해 프린터는 공격자에게 매우 흥미로운 대상입니다.

이 주제에 대한 몇 가지 입문 블로그입니다.

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## 프린터 구성

- **Location**: LDAP server list는 일반적으로 web interface에서 찾을 수 있습니다(예: *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Behavior**: 많은 embedded web server는 **자격 증명을 다시 입력하지 않고도 LDAP server를 수정**할 수 있습니다(사용 편의성 기능 → 보안 위험).
- **Exploit**: LDAP server address를 공격자가 제어하는 host로 redirect한 다음, *Test Connection* / *Address Book Sync* button을 사용해 프린터가 사용자에게 bind하도록 강제합니다.

---

## 자격 증명 수집

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
소형/구형 MFP는 bind DN과 password가 raw BER stream에 그대로 표시되는 단순한 *simple-bind*를 전송할 수 있습니다. 최신 장치는 일반적으로 먼저 anonymous query를 수행한 다음 bind를 시도하므로 결과가 달라집니다.<sup>[[1]](#references)</sup>

636/3269에서 실행하는 일반 `nc` listener는 TLS ciphertext만 수신합니다. LDAPS를 테스트하려면 TLS를 지원하는 LDAP endpoint가 필요하며, 장치가 server certificate를 올바르게 검증하는 경우 redirection은 실패해야 합니다.

### 방법 2 – Full Rogue LDAP server (권장)

많은 장치가 인증하기 *전에* anonymous search를 수행하므로 실제 LDAP daemon을 구축하면 훨씬 더 안정적인 결과를 얻을 수 있습니다.<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
프린터가 lookup을 수행하면 debug output에 clear-text credentials가 표시됩니다.

> 💡  Responder에는 rogue LDAP 및 SMB authentication services가 포함되어 있습니다. 간단한 LDAP bind는 구성된 password를 노출할 수 있지만, NTLM authentication은 challenge-response material을 생성하므로 두 결과를 모두 clear-text password라고 설명해서는 안 됩니다.

---

## Recent Pass-Back Vulnerabilities (2024-2025)

Pass-back은 *이론적인 문제가 아닙니다* – vendor들은 2024/2025년에도 이 attack class를 정확히 설명하는 advisories를 계속 발표하고 있습니다.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFP의 Firmware ≤ 57.69.91에서는 authenticated admin(또는 default creds가 그대로 남아 있는 경우 누구나)이 다음을 수행할 수 있었습니다:

* **CVE-2024-12510 – LDAP pass-back**: LDAP server address를 변경하고 lookup을 trigger하여, device가 구성된 Windows credentials를 attacker-controlled host로 leak하도록 함.
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* destinations를 통한 동일한 문제로, NetNTLMv2 또는 FTP clear-text creds를 leak함.<sup>[[2]](#references)</sup>

다음과 같은 간단한 listener:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
또는 rogue SMB server (`impacket-smbserver`)만으로도 credentials를 수집할 수 있습니다.

### Canon imageRUNNER / imageCLASS – Advisory 2025년 5월 20일

Canon은 수십 개의 Laser & MFP product line에서 **SMTP/LDAP pass-back** weakness를 확인했습니다. admin access를 가진 attacker는 server configuration을 수정하고 LDAP **또는** SMTP에 저장된 credentials를 가져올 수 있습니다(많은 조직에서 scan-to-mail을 허용하기 위해 privileged account를 사용합니다).<sup>[[3]](#references)</sup>

Vendor guidance에서는 다음을 명시적으로 권장합니다.

1. 가능한 한 빨리 patched firmware로 업데이트합니다.
2. 강력하고 고유한 admin password를 사용합니다.
3. printer integration에 privileged AD account를 사용하지 않습니다.

---

### Brother devices and OEM variants – serial-derived admin access to service credentials

2025년 coordinated disclosure를 통해 영향을 받는 Brother devices에서 특히 유용한 chain이 공개되었습니다. vulnerability set의 일부는 OEM models에도 영향을 주므로, vendor advisory에서 정확한 model을 확인해야 합니다. unauthenticated attacker는 vulnerable firmware에서 HTTP/HTTPS/IPP를 통해 device serial을 획득할 수 있으며, serial은 SNMP 또는 PJL과 같은 management protocols를 통해서도 확인할 수 있습니다. factory password를 변경하지 않았다면 serial로부터 administrator password를 결정적으로 알아낼 수 있습니다. 인증에 성공한 후에는 별도의 pass-back flaw인 CVE-2024-51984를 통해 LDAP 또는 FTP와 같은 configured external-service password가 plaintext로 노출되므로, printer-management access가 재사용 가능한 network credentials로 바뀝니다. Firmware는 service-password disclosure를 수정하지만, 이미 제조된 devices에서는 operator가 serial-derived initial administrator password를 교체해야 합니다.<sup>[[6]](#references)</sup>

Current Metasploit에는 HTTP, SNMP 또는 PJL을 통해 serial을 discovery하고, candidate initial password를 생성하며, 선택적으로 이를 web console에서 검증하는 auxiliary module이 포함되어 있습니다. `DiscoverSerialVia=AUTO`는 지원되는 discovery paths를 시도하며, asset inventory에 이미 serial이 포함되어 있는 경우에는 대신 `TargetSerial`을 제공하십시오.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
권한이 부여된 자산을 검증하는 용도로만 이 결과를 사용하세요. Password가 작동하는지는 정확한 모델과, 특히 factory administrator password가 이미 변경되었는지 여부에 따라 달라집니다.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL 악용, 파일 시스템 액세스, default-creds 확인, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS를 통한 설정 수집(address book 및 LDAP creds 포함) | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | rogue authentication service를 실행하고 SMB callback에서 NetNTLM을 캡처/relay | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | serial을 발견하고, 후보 factory administrator password를 도출하며, web-console access를 검증 | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening & Detection

1. **Patch / firmware-update** MFP를 신속하게 수행하세요(vendor PSIRT bulletin 확인).
2. **factory administrator password 교체** – firmware만으로는 이전에 제조된 영향을 받는 Brother/OEM device에서 serial로 파생된 초기 password가 제거되지 않습니다.<sup>[[6]](#references)</sup>
3. **Least-Privilege Service Accounts** – LDAP/SMB/SMTP에 Domain Admin을 절대 사용하지 말고, *read-only* OU scope로 제한하세요.
4. **Management Access 제한** – printer web/IPP/SNMP interface를 management VLAN에 배치하거나 ACL/VPN 뒤에 두세요.
5. **printer egress 제한** – 각 device가 예상된 DC/LDAP, mail, DNS/NTP, print 및 scan-file destination에만 연결하도록 허용하세요. Pass-back에는 attacker-selected endpoint로의 callback이 필요합니다.
6. **사용하지 않는 Protocol 비활성화** – FTP, Telnet, raw-9100, 구형 SSL cipher.
7. **Audit Logging 활성화** – 일부 device는 LDAP/SMTP failure를 syslog로 기록할 수 있습니다. 예상하지 못한 bind를 상호 연관 분석하세요.
8. **authentication destination 모니터링** – printer가 allowlist 외부의 host로 LDAP, SMB, SMTP 또는 FTP를 시작하면 alert를 생성하세요. 특히 management login 또는 configuration change 직후를 중점적으로 확인하세요.
9. **SNMPv3 사용 또는 SNMP 비활성화** – community `public`은 device 및 serial 정보를 자주 leak합니다.

---



---

## References

- [1] [그저 프린터일 뿐인데… 최악의 상황은 무엇일까?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat을 사용한 Printer를 통한 Domain Credentials 획득](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Penetration Test Engagement 중 Multifunction Printer 악용](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Multiple Brother Devices: Multiple Vulnerabilities (FIXED)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother default administrator authentication bypass module](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
