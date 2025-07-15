# 프린터의 정보

{{#include ../../banners/hacktricks-training.md}}

인터넷에는 **기본/약한** 로그인 자격 증명으로 LDAP에 구성된 프린터의 위험성을 **강조하는** 여러 블로그가 있습니다. \
이는 공격자가 **프린터를 속여 악성 LDAP 서버에 인증하도록** 할 수 있기 때문입니다 (일반적으로 `nc -vv -l -p 389` 또는 `slapd -d 2`면 충분합니다) 그리고 프린터의 **자격 증명을 평문으로** 캡처할 수 있습니다.

또한, 여러 프린터는 **사용자 이름이 포함된 로그**를 포함하거나 도메인 컨트롤러에서 **모든 사용자 이름을 다운로드**할 수 있습니다.

이 모든 **민감한 정보**와 일반적인 **보안 부족**은 프린터를 공격자에게 매우 흥미롭게 만듭니다.

주제에 대한 몇 가지 소개 블로그:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## 프린터 구성

- **위치**: LDAP 서버 목록은 일반적으로 웹 인터페이스에서 찾을 수 있습니다 (예: *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **동작**: 많은 임베디드 웹 서버는 **자격 증명을 다시 입력하지 않고도** LDAP 서버 수정을 허용합니다 (사용성 기능 → 보안 위험).
- **악용**: LDAP 서버 주소를 공격자가 제어하는 호스트로 리디렉션하고 *Test Connection* / *Address Book Sync* 버튼을 사용하여 프린터가 당신에게 바인딩하도록 강제합니다.

---
## 자격 증명 캡처

### 방법 1 – 넷캣 리스너
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
작고 오래된 MFP는 netcat이 캡처할 수 있는 간단한 *simple-bind*를 평문으로 전송할 수 있습니다. 현대 장치는 일반적으로 인증하기 전에 익명 쿼리를 수행하므로 결과는 다를 수 있습니다.

### 방법 2 – 전체 악성 LDAP 서버 (권장)

많은 장치가 인증하기 *전에* 익명 검색을 수행하기 때문에, 실제 LDAP 데몬을 설정하면 훨씬 더 신뢰할 수 있는 결과를 얻을 수 있습니다:
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
프린터가 조회를 수행할 때 디버그 출력에서 평문 자격 증명을 볼 수 있습니다.

> 💡  `impacket/examples/ldapd.py` (Python rogue LDAP) 또는 `Responder -w -r -f`를 사용하여 LDAP/SMB를 통해 NTLMv2 해시를 수집할 수도 있습니다.

---
## 최근 패스백 취약점 (2024-2025)

패스백은 *이론적인 문제*가 아닙니다 – 공급업체들은 2024/2025년에 이 공격 클래스를 정확히 설명하는 권고를 계속 발표하고 있습니다.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFP의 펌웨어 ≤ 57.69.91는 인증된 관리자(또는 기본 자격 증명이 유지될 경우 누구나)가 다음을 수행할 수 있게 했습니다:

* **CVE-2024-12510 – LDAP 패스백**: LDAP 서버 주소를 변경하고 조회를 트리거하여 장치가 구성된 Windows 자격 증명을 공격자가 제어하는 호스트로 유출하게 합니다.
* **CVE-2024-12511 – SMB/FTP 패스백**: *폴더로 스캔* 목적지를 통해 동일한 문제로 NetNTLMv2 또는 FTP 평문 자격 증명이 유출됩니다.

간단한 리스너 예:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
or a rogue SMB server (`impacket-smbserver`)는 자격 증명을 수집하기에 충분합니다.

### Canon imageRUNNER / imageCLASS – 권고 2025년 5월 20일

Canon은 수십 개의 레이저 및 MFP 제품군에서 **SMTP/LDAP 패스백** 취약점을 확인했습니다. 관리 액세스 권한이 있는 공격자는 서버 구성을 수정하고 LDAP **또는** SMTP에 저장된 자격 증명을 검색할 수 있습니다 (많은 조직이 스캔-투-메일을 허용하기 위해 특권 계정을 사용합니다).

제조업체의 지침은 명시적으로 다음을 권장합니다:

1. 가능한 한 빨리 패치된 펌웨어로 업데이트합니다.
2. 강력하고 고유한 관리자 비밀번호를 사용합니다.
3. 프린터 통합을 위해 특권 AD 계정을 피합니다.

---
## 자동화된 열거 / 악용 도구

| 도구 | 목적 | 예시 |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL 남용, 파일 시스템 접근, 기본 자격 증명 확인, *SNMP 발견* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS를 통해 구성 수집 (주소록 및 LDAP 자격 증명 포함) | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | SMB/FTP 패스백에서 NetNTLM 해시 캡처 및 중계 | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | 평문 바인드를 수신하기 위한 경량의 악성 LDAP 서비스 | `python ldapd.py -debug` |

---
## 강화 및 탐지

1. **패치 / 펌웨어 업데이트** MFP를 신속하게 수행합니다 (제조업체 PSIRT 공지를 확인하십시오).
2. **최소 권한 서비스 계정** – LDAP/SMB/SMTP에 도메인 관리자를 사용하지 마십시오; *읽기 전용* OU 범위로 제한합니다.
3. **관리 액세스 제한** – 프린터 웹/IPP/SNMP 인터페이스를 관리 VLAN에 배치하거나 ACL/VPN 뒤에 두십시오.
4. **사용하지 않는 프로토콜 비활성화** – FTP, Telnet, raw-9100, 구형 SSL 암호.
5. **감사 로깅 활성화** – 일부 장치는 LDAP/SMTP 실패를 syslog할 수 있습니다; 예상치 못한 바인드를 상관관계합니다.
6. **비정상적인 출처에서 평문 LDAP 바인드를 모니터링**합니다 (프린터는 일반적으로 DC와만 통신해야 합니다).
7. **SNMPv3 또는 SNMP 비활성화** – 커뮤니티 `public`은 종종 장치 및 LDAP 구성을 유출합니다.

---
## 참고 문헌

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Xerox VersaLink C7025 MFP 패스백 공격 취약점.” 2025년 2월.
- Canon PSIRT. “레이저 프린터 및 소형 사무실 다기능 프린터에 대한 SMTP/LDAP 패스백에 대한 취약점 완화.” 2025년 5월.

{{#include ../../banners/hacktricks-training.md}}
