# 프린터의 정보

{{#include ../../banners/hacktricks-training.md}}

인터넷에는 **LDAP가 기본/취약한 logon credentials로 설정된 프린터를 방치할 때의 위험성**을 강조하는 블로그가 여러 개 있습니다.  \
이는 공격자가 **프린터가 악성 LDAP 서버에 authenticate하도록 속여**(일반적으로 `nc -vv -l -p 389` 또는 `slapd -d 2`면 충분함) 프린터의 **credentials를 clear-text로 캡처**할 수 있기 때문입니다.

또한 여러 프린터에는 **사용자 이름이 기록된 로그**가 남아 있거나, 심지어 Domain Controller에서 **모든 사용자 이름을 다운로드**할 수 있습니다.

이러한 **민감한 정보**와 일반적인 **보안 부재** 때문에 프린터는 공격자에게 매우 흥미로운 대상입니다.

이 주제에 관한 몇 가지 입문용 블로그:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## 프린터 설정

- **위치**: LDAP 서버 목록은 보통 웹 인터페이스에서 찾을 수 있습니다(예: *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **동작**: 많은 임베디드 웹 서버에서는 **credentials를 다시 입력하지 않고도** LDAP 서버를 수정할 수 있습니다(사용 편의성 기능 → 보안 위험).
- **악용**: LDAP 서버 주소를 공격자가 제어하는 호스트로 바꾼 다음, *Test Connection* / *Address Book Sync* 버튼을 눌러 프린터가 공격자에게 bind하도록 합니다.

---

## Credentials 캡처

### 방법 1 – Netcat 리스너

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

소형/구형 MFP는 bind DN과 password가 raw BER stream에서 보이는 단순한 *simple-bind*를 전송할 수 있습니다. 최신 장치는 보통 먼저 anonymous query를 수행한 다음 bind를 시도하므로 결과는 달라질 수 있습니다.<sup>[[1]](#references)</sup>

636/3269 포트에서 단순한 `nc` 리스너를 사용하면 TLS 암호문만 수신합니다. LDAPS를 테스트하려면 TLS를 지원하는 LDAP endpoint가 필요하며, 장치가 서버 인증서를 올바르게 검증하면 리디렉션은 실패해야 합니다.

### Method 2 – Full Rogue LDAP server (recommended)

많은 장치는 인증 전에 anonymous search를 수행하므로, 실제 LDAP daemon을 실행하면 훨씬 더 안정적인 결과를 얻을 수 있습니다.<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

프린터가 조회를 수행하면 debug 출력에 clear-text credentials가 표시됩니다.

> 💡  Responder에는 rogue LDAP 및 SMB 인증 서비스가 포함되어 있습니다. 간단한 LDAP bind로 설정된 password가 노출될 수 있지만, NTLM authentication에서는 challenge-response 정보가 생성됩니다. 두 경우 모두 clear-text password가 노출된다고 설명하지 마세요.

---

## 최근 Pass-Back 취약점 (2024-2025)

Pass-back은 *이론적인 문제가 아닙니다* — 공급업체들은 2024/2025년에 이 공격 유형을 정확히 설명하는 권고문을 계속 발표하고 있습니다.

### Xerox VersaLink – CVE-2024-12510 및 CVE-2024-12511

Xerox VersaLink C70xx MFP의 펌웨어 ≤ 57.69.91에서는 인증된 admin(또는 기본 credentials가 그대로인 경우 누구나)이 다음을 수행할 수 있었습니다.

* **CVE-2024-12510 – LDAP pass-back**: LDAP server 주소를 변경하고 조회를 트리거하면, 기기가 설정된 Windows credentials를 공격자가 제어하는 host로 leak합니다.
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* 대상을 통해 동일한 문제가 발생해 NetNTLMv2 또는 FTP clear-text credentials가 leak됩니다.<sup>[[2]](#references)</sup>

다음과 같은 간단한 listener를 사용할 수 있습니다.

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

또는 악성 SMB 서버(`impacket-smbserver`)만으로도 자격 증명을 수집할 수 있습니다.  

### Canon imageRUNNER / imageCLASS – 2025년 5월 20일 권고

Canon은 수십 개의 Laser 및 MFP 제품군에서 **SMTP/LDAP pass-back** 취약점을 확인했습니다. 관리자 액세스 권한이 있는 공격자는 서버 구성을 수정해 저장된 LDAP **또는** SMTP 자격 증명을 가져올 수 있습니다(많은 조직에서 스캔 후 이메일 전송 기능을 위해 권한이 높은 계정을 사용합니다).<sup>[[3]](#references)</sup>

공급업체 지침은 다음을 명시적으로 권장합니다.

1. 패치된 펌웨어가 제공되는 즉시 업데이트합니다.
2. 강력하고 고유한 관리자 암호를 사용합니다.
3. 프린터 연동에 권한이 높은 AD 계정을 사용하지 않습니다.

---

### Brother 장치 및 OEM 변형 모델 – 시리얼 번호에서 파생되는 관리자 액세스로 서비스 자격 증명 획득

2025년 공동 공개를 통해 영향을 받는 Brother 장치에서 특히 유용한 공격 체인이 확인되었습니다. 취약점 세트 중 일부는 OEM 모델에도 영향을 미치므로, 공급업체 권고를 확인해 정확한 모델이 영향을 받는지 검증하세요. 인증되지 않은 공격자는 취약한 펌웨어에서 HTTP/HTTPS/IPP를 통해 장치 시리얼 번호를 알아낼 수 있으며, SNMP나 PJL 같은 관리 프로토콜을 통해서도 시리얼 번호를 확인할 수 있습니다. 출고 시 암호를 변경하지 않았다면 시리얼 번호로 관리자 암호를 결정적으로 알아낼 수 있습니다. 인증 후에는 별도의 pass-back 취약점인 CVE-2024-51984를 통해 LDAP 또는 FTP 같은 외부 서비스에 설정된 암호가 평문으로 노출되어, 프린터 관리 액세스가 재사용 가능한 네트워크 자격 증명으로 이어집니다. 펌웨어 업데이트로 서비스 암호 노출 문제는 해결되지만, 이미 제조된 장치에서는 운영자가 시리얼 번호에서 파생된 초기 관리자 암호를 변경해야 합니다.<sup>[[6]](#references)</sup>

현재 Metasploit에는 HTTP, SNMP 또는 PJL을 통해 시리얼 번호를 찾고, 초기 암호 후보를 생성한 다음 웹 콘솔에서 선택적으로 검증하는 auxiliary 모듈이 포함되어 있습니다. `DiscoverSerialVia=AUTO`는 지원되는 검색 경로를 시도하며, 자산 인벤토리에 시리얼 번호가 이미 포함되어 있다면 대신 `TargetSerial`을 지정하세요.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

결과는 승인된 자산을 검증하는 용도로만 사용하세요. 암호가 작동하는지는 정확한 모델에 따라 달라지며, 특히 공장 출하 시 관리자 암호가 이미 변경되었는지가 중요합니다.<sup>[[6]](#references)[[7]](#references)</sup>

---

## 자동화된 Enumeration / Exploitation 도구

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL 악용, 파일 시스템 액세스, default-creds 확인, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS를 통해 설정(주소록 및 LDAP creds 포함) 수집 | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | 악성 인증 서비스를 실행하고 SMB 콜백에서 NetNTLM을 캡처/릴레이 | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | 시리얼 번호를 확인하고, 공장 출하 시 관리자 암호 후보를 도출한 뒤, 웹 콘솔 액세스를 검증 | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## 보안 강화 및 탐지

1. **패치 / 펌웨어 업데이트** – MFP를 신속하게 업데이트하세요(벤더 PSIRT 공지 확인).
2. **공장 출하 시 관리자 암호 변경** – 펌웨어만으로는 이미 제조된 취약 Brother/OEM 기기의 시리얼 번호 기반 초기 암호가 제거되지 않습니다.<sup>[[6]](#references)</sup>
3. **최소 권한 서비스 계정** – LDAP/SMB/SMTP에 Domain Admin을 사용하지 말고, 범위를 *읽기 전용* OU로 제한하세요.
4. **관리 액세스 제한** – 프린터 웹/IPP/SNMP 인터페이스를 관리 VLAN 또는 ACL/VPN 뒤에 배치하세요.
5. **프린터의 아웃바운드 트래픽 제한** – 각 장치가 예상된 DC/LDAP, 메일, DNS/NTP, 인쇄 및 스캔 파일 대상에만 연결하도록 허용하세요. Pass-back을 수행하려면 공격자가 선택한 엔드포인트로 콜백해야 합니다.
6. **사용하지 않는 프로토콜 비활성화** – FTP, Telnet, raw-9100, 오래된 SSL cipher.
7. **감사 로깅 활성화** – 일부 장치는 LDAP/SMTP 실패를 syslog로 전송할 수 있습니다. 예상치 못한 바인드를 연관 분석하세요.
8. **인증 대상 모니터링** – 프린터가 허용 목록에 없는 호스트로 LDAP, SMB, SMTP 또는 FTP 연결을 시작하면 경고를 발생시키세요. 특히 관리 로그인이나 설정 변경 직후를 주의하세요.
9. **SNMPv3 사용 또는 SNMP 비활성화** – `public` 커뮤니티는 장치 및 시리얼 번호 정보를 자주 leak합니다.

---

---

## References

- [1] [프린터일 뿐인데… 최악의 경우 어떤 일이 벌어질 수 있을까?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 복합기: Pass-Back Attack 취약점(수정됨)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 생산용 프린터, 사무실/소규모 사무실 복합기 및 레이저 프린터의 취약점 완화/해결](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat을 사용해 프린터를 통해 도메인 자격 증명 획득하기](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Penetration Test 수행 중 복합기 Exploitation하기](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [다수의 Brother 기기: 다수의 취약점(수정됨)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother 기본 관리자 인증 우회 모듈](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
