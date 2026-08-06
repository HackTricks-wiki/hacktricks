# 프린터의 정보

{{#include ../../banners/hacktricks-training.md}}

인터넷에는 **프린터가 기본/취약한 로그인 자격 증명으로 LDAP가 구성된 상태로 방치될 경우의 위험성**을 강조하는 여러 블로그가 있습니다.  \
이는 공격자가 **프린터가 악성 LDAP 서버에 인증하도록 유도**할 수 있기 때문입니다(일반적으로 `nc -vv -l -p 389` 또는 `slapd -d 2`만으로 충분함). 이를 통해 프린터의 **자격 증명을 평문으로** 캡처할 수 있습니다.

또한 여러 프린터에는 **사용자 이름이 포함된 로그**가 저장되며, 심지어 Domain Controller에서 **모든 사용자 이름을 다운로드**할 수 있는 경우도 있습니다.

이러한 **민감한 정보**와 일반적인 **보안 부족**으로 인해 프린터는 공격자에게 매우 흥미로운 대상입니다.

이 주제에 대한 몇 가지 입문용 블로그:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## 프린터 구성

- **위치**: LDAP 서버 목록은 일반적으로 웹 인터페이스에서 찾을 수 있습니다(예: *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **동작**: 많은 임베디드 웹 서버에서는 **자격 증명을 다시 입력하지 않고도** LDAP 서버를 수정할 수 있습니다(사용 편의성 기능 → 보안 위험).
- **Exploit**: LDAP 서버 주소를 공격자가 제어하는 호스트로 리디렉션한 다음 *Test Connection* / *Address Book Sync* 버튼을 사용하여 프린터가 공격자에게 bind하도록 강제합니다.

---

## 자격 증명 캡처

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Small/old MFPs는 netcat이 capture할 수 있는 간단한 *simple-bind*를 clear-text로 전송할 수 있습니다. Modern devices는 일반적으로 먼저 anonymous query를 수행한 다음 bind를 시도하므로 결과가 달라집니다.<sup>[[1]](#references)</sup>

### Method 2 – Full Rogue LDAP server (권장)

많은 devices가 authenticating하기 *전에* anonymous search를 수행하므로, 실제 LDAP daemon을 설정하면 훨씬 더 신뢰할 수 있는 결과를 얻을 수 있습니다:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
프린터가 lookup을 수행하면 debug output에 clear-text credentials가 표시됩니다.

> 💡  `impacket/examples/ldapd.py` (Python rogue LDAP) 또는 `Responder -w -r -f`를 사용하여 LDAP/SMB를 통해 NTLMv2 hashes를 harvest할 수도 있습니다.

---

## 최근 Pass-Back Vulnerabilities (2024-2025)

Pass-back은 *이론적인 문제가 아닙니다* – vendor들은 2024/2025년에도 이 attack class를 정확히 설명하는 advisories를 계속 공개하고 있습니다.

### Xerox VersaLink – CVE-2024-12510 및 CVE-2024-12511

Xerox VersaLink C70xx MFP의 펌웨어 ≤ 57.69.91에서는 인증된 admin(또는 default creds가 그대로 남아 있는 경우 누구나)이 다음을 수행할 수 있었습니다.

* **CVE-2024-12510 – LDAP pass-back**: LDAP server address를 변경하고 lookup을 trigger하여, device가 설정된 Windows credentials를 attacker-controlled host로 leak하도록 함.
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* destinations를 통한 동일한 issue로, NetNTLMv2 또는 FTP clear-text creds를 leak함.<sup>[[2]](#references)</sup>

다음과 같은 간단한 listener:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
또는 rogue SMB server (`impacket-smbserver`)만으로도 credentials를 harvest할 수 있습니다.

### Canon imageRUNNER / imageCLASS – 2025년 5월 20일 권고문

Canon은 수십 개의 Laser 및 MFP product line에서 **SMTP/LDAP pass-back** weakness를 확인했습니다. admin access를 가진 attacker는 server configuration을 수정하고 LDAP **또는** SMTP에 저장된 credentials를 retrieve할 수 있습니다(많은 조직에서 scan-to-mail을 허용하기 위해 privileged account를 사용합니다).<sup>[[3]](#references)</sup>

벤더 guidance에서는 다음을 명시적으로 권장합니다.

1. 패치된 firmware가 제공되는 즉시 업데이트합니다.
2. 강력하고 고유한 admin password를 사용합니다.
3. printer integration에 privileged AD account를 사용하지 않습니다.

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL abuse, file-system access, default-creds check, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS를 통한 configuration 수집(address books 및 LDAP creds 포함) | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | SMB/FTP pass-back에서 NetNTLM hashes capture 및 relay | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | clear-text binds를 수신하는 lightweight rogue LDAP service | `python ldapd.py -debug` |

---

## Hardening & Detection

1. **Patch / firmware-update** MFPs를 신속하게 수행합니다(vendor PSIRT bulletins 확인).
2. **Least-Privilege Service Accounts** – LDAP/SMB/SMTP에 Domain Admin을 사용하지 말고, *read-only* OU scopes로 제한합니다.
3. **Restrict Management Access** – printer web/IPP/SNMP interfaces를 management VLAN에 배치하거나 ACL/VPN 뒤에 둡니다.
4. **Disable Unused Protocols** – FTP, Telnet, raw-9100, 오래된 SSL ciphers를 비활성화합니다.
5. **Enable Audit Logging** – 일부 devices는 LDAP/SMTP failures를 syslog할 수 있으므로, 예상하지 못한 binds를 correlate합니다.
6. 비정상적인 sources에서 발생하는 **Clear-Text LDAP binds**를 monitor합니다(printers는 일반적으로 DCs에만 통신해야 합니다).
7. **SNMPv3 또는 SNMP 비활성화** – community `public`은 device 및 LDAP config를 자주 leak합니다.

---

## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
