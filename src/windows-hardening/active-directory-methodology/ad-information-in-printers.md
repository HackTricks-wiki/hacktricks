# 프린터에 저장된 정보

{{#include ../../banners/hacktricks-training.md}}

저장된 LDAP 자격 증명이 있는 프린터는 서버 설정을 변경한 뒤 악성 엔드포인트에 인증하도록 하면 자격 증명이 노출될 수 있습니다.<sup>[[2]](#references)</sup> 결과는 bind 방식에 따라 다릅니다. 보호되지 않는 simple bind는 비밀번호를 노출하지만, SASL challenge-response bind는 비밀번호를 평문으로 노출하지 않습니다.<sup>[[8]](#references)</sup> [LDAP 인증 및 전송 보안](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks)을 참고하세요.

또한 여러 프린터에는 **사용자 이름이 포함된 로그**가 저장되어 있거나, 심지어 Domain Controller에서 **모든 사용자 이름을 다운로드**할 수 있습니다.

이러한 **민감한 정보**와 흔히 나타나는 **보안 부재** 때문에 프린터는 공격자에게 매우 흥미로운 대상입니다.

이 주제에 대한 입문용 블로그:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## 프린터 설정

- **위치**: LDAP 서버 목록은 보통 웹 인터페이스에서 찾을 수 있습니다(예: *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **동작 방식**: 여러 임베디드 웹 서버는 **자격 증명을 다시 입력하지 않고도** LDAP 서버를 변경할 수 있습니다(사용 편의성 기능 → 보안 위험).
- **공격 방법**: LDAP 서버 주소를 공격자가 제어하는 호스트로 변경한 뒤, *Test Connection* / *Address Book Sync* 버튼을 사용해 프린터가 공격자에게 bind하도록 합니다.

---

## 자격 증명 캡처

### Method 1 – Netcat 리스너

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

A simple BindRequest는 서버가 나중에 로그인을 거부하더라도 BER 스트림에서 bind DN과 password를 노출할 수 있습니다. 익명 조회나 SASL 협상만으로는 저장된 password가 노출되지 않습니다.<sup>[[8]](#references)</sup>

636/3269 포트에서 일반 `nc` 리스너를 실행하면 LDAP bind가 아니라 TLS 핸드셰이크를 확인하게 됩니다. LDAPS에는 TLS를 지원하는 엔드포인트가 필요합니다. 인증서 검증만으로는 pass-back을 막을 수 없습니다. 프린터가 변경된 호스트 이름을 허용하고 새 엔드포인트에 해당 호스트 이름에 유효한 인증서가 있으면 pass-back이 가능하기 때문입니다. 클라이언트는 저장된 자격 증명을 수신할 수 있는 서버도 제한해야 합니다.<sup>[[8]](#references)</sup>

### 방법 2 – 전체 Rogue LDAP 서버(권장)

프린터는 bind를 시도하기 전에 유효한 LDAP 응답을 요구할 수 있습니다.<sup>[[10]](#references)</sup> 전체 LDAP 서버는 이 사전 교환을 처리할 수 있지만, 강력한 SASL 메커니즘이나 의도된 TLS 서버에 고정된 클라이언트가 password를 노출하게 만들 수는 없습니다.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

lookup는 연결이 있었다는 증거이지, password가 노출되었다는 증거는 아닙니다. client가 plaintext password를 포함한 bind를 전송한 경우에만 password가 노출됩니다. 실제 bind 메커니즘과 TLS 상태를 확인하세요.<sup>[[8]](#references)</sup>

> 💡  Responder에는 rogue LDAP 및 SMB 인증 서비스가 포함되어 있습니다. 단순 LDAP bind는 설정된 password를 노출할 수 있지만, NTLM 인증은 challenge-response 데이터를 생성합니다. 두 경우 모두를 clear-text password라고 설명하지 마세요.

### SASL 메커니즘 선택

일부 프린터 LDAP client는 LDAP server가 광고하는 메커니즘 중에서 선택합니다.<sup>[[8]](#references)[[10]](#references)</sup> 조사 결과, 광고된 plaintext SASL 메커니즘을 허용하는 client는 일반적인 NTLM 협상에서는 challenge-response 데이터만 노출되는 상황에서도 password를 전송할 수 있는 것으로 나타났습니다.<sup>[[9]](#references)[[10]](#references)</sup> 이는 **client-policy 실패**이지 모든 SASL bind의 속성이 아닙니다. 더 강력한 메커니즘을 요구하거나 의도된 TLS server를 고정하는 client는 대신 연결을 안전하게 거부해야 합니다.<sup>[[8]](#references)</sup> OpenLDAP은 기본적으로 plaintext를 지원하는 SASL 메커니즘을 비활성화하므로, 기본 설정의 daemon만으로는 프린터에서 이런 동작이 발생한다고 단정할 수 없습니다.<sup>[[11]](#references)</sup>

---

## 최근 Pass-Back 취약점 (2024-2025)

Pass-back은 *이론적인 문제가 아닙니다*. 공급업체들은 2024/2025년에도 이 공격 유형을 정확히 설명하는 보안 권고를 계속 발표하고 있습니다.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFP의 펌웨어 버전 ≤ 57.69.91에서는 인증된 admin(또는 기본 자격 증명이 그대로인 경우 누구나)이 다음을 수행할 수 있었습니다.

* **CVE-2024-12510 – LDAP pass-back**: LDAP server 주소를 변경하고 lookup을 트리거하면, 장치가 설정된 Windows 자격 증명을 공격자가 제어하는 host로 leak합니다.
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* 대상 경로를 통해 발생하는 동일한 문제로, NetNTLMv2 또는 FTP clear-text 자격 증명이 leak됩니다.<sup>[[2]](#references)</sup>

다음과 같은 간단한 listener를 사용할 수 있습니다.

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

또는 불량 SMB 서버(`impacket-smbserver`)만 있어도 credentials를 수집할 수 있습니다.

### Canon imageRUNNER / imageCLASS – 2025년 5월 20일 권고문

Canon은 수십 개의 Laser 및 MFP 제품군에서 **SMTP/LDAP pass-back** 취약점을 확인했습니다. 관리자 권한이 있는 공격자는 서버 설정을 수정해 LDAP **또는** SMTP에 저장된 credentials를 가져올 수 있습니다(많은 조직이 scan-to-mail 기능에 권한이 높은 계정을 사용합니다).<sup>[[3]](#references)</sup>

제조업체 지침에서는 다음을 명시적으로 권장합니다.

1. 패치된 펌웨어가 제공되는 즉시 업데이트합니다.
2. 강력하고 고유한 관리자 비밀번호를 사용합니다.
3. 프린터 통합에 권한이 높은 AD 계정을 사용하지 않습니다.

---

### Brother 기기 및 OEM 변형 모델 – 시리얼 번호로 서비스 credentials에 접근

2025년 공동 공개를 통해 영향을 받는 Brother 기기에서 특히 유용한 공격 체인이 확인되었습니다. 취약점 세트 중 일부는 OEM 모델에도 영향을 미치므로, 해당 모델이 제조업체 권고문에 명시되어 있는지 확인하세요. 취약한 펌웨어에서는 인증되지 않은 공격자가 HTTP/HTTPS/IPP를 통해 기기 시리얼 번호를 알아낼 수 있으며, SNMP나 PJL 같은 관리 프로토콜을 통해서도 시리얼 번호를 확인할 수 있습니다. 공장 출고 비밀번호를 변경하지 않았다면 시리얼 번호로 관리자 비밀번호를 결정적으로 알아낼 수 있습니다. 인증 후에는 별도의 pass-back 취약점인 CVE-2024-51984를 악용해 LDAP 또는 FTP 등의 설정된 외부 서비스 비밀번호를 평문으로 노출시킬 수 있으므로, 프린터 관리 권한을 재사용 가능한 네트워크 credentials로 전환할 수 있습니다. 펌웨어 업데이트로 서비스 비밀번호 노출 문제는 해결되지만, 이미 제조된 기기에서는 시리얼 번호로 도출되는 초기 관리자 비밀번호를 운영자가 변경해야 합니다.<sup>[[6]](#references)</sup>

현재 Metasploit에는 HTTP, SNMP 또는 PJL을 통해 시리얼 번호를 찾고, 초기 비밀번호 후보를 생성한 뒤, 웹 콘솔에 입력해 유효성을 선택적으로 확인하는 auxiliary 모듈이 포함되어 있습니다. `DiscoverSerialVia=AUTO`는 지원되는 검색 경로를 차례로 시도합니다. 자산 목록에 시리얼 번호가 이미 있는 경우에는 대신 `TargetSerial`을 지정하세요.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

결과는 승인된 자산을 검증하는 데만 사용하세요. 비밀번호가 작동하는지는 정확한 모델에 따라 달라지며, 특히 출고 시 관리자 비밀번호가 이미 변경되었는지가 중요합니다.<sup>[[6]](#references)[[7]](#references)</sup>

---

## 자동화된 열거 / Exploitation 도구

| 도구 | 목적 | 예시 |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL 악용, 파일 시스템 접근, 기본 자격 증명 확인, *SNMP 탐색*; [PJL assessment](../../network-services-pentesting/9100-pjl.md) 참고 | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS를 통해 설정(주소록 및 LDAP 자격 증명 포함) 수집 | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | 악성 인증 서비스를 실행하고 SMB 콜백에서 NetNTLM을 캡처/릴레이 | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | 일련 번호를 찾아 후보 출고 시 관리자 비밀번호를 도출하고 웹 콘솔 접근을 확인 | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## 보안 강화 및 탐지

1. **패치 / 펌웨어 업데이트** – MFP를 신속히 업데이트하세요(벤더 PSIRT 공지 확인).
2. **출고 시 관리자 비밀번호 변경** – 펌웨어만으로는 이전에 제조된 취약한 Brother/OEM 장치의 일련 번호 기반 초기 비밀번호가 제거되지 않습니다.<sup>[[6]](#references)</sup>
3. **최소 권한 서비스 계정** – LDAP/SMB/SMTP에 Domain Admin을 사용하지 말고, *읽기 전용* OU 범위로 제한하세요.
4. **관리 접근 제한** – 프린터의 웹/IPP/SNMP 인터페이스를 관리 VLAN 또는 ACL/VPN 뒤에 두세요.
5. **프린터의 외부 연결 제한** – 각 장치가 예상된 DC/LDAP, 메일, DNS/NTP, 인쇄 및 스캔 파일 대상에만 연결하도록 허용하세요. Pass-back을 수행하려면 공격자가 선택한 엔드포인트로 콜백해야 합니다.
6. **사용하지 않는 프로토콜 비활성화** – FTP, Telnet, raw-9100, 구형 SSL 암호화 방식을 비활성화하세요.
7. **감사 로깅 활성화** – 일부 장치는 LDAP/SMTP 실패를 syslog로 기록할 수 있습니다. 예상치 못한 바인드를 연관 분석하세요.
8. **인증 대상 모니터링** – 프린터가 허용 목록에 없는 호스트로 LDAP, SMB, SMTP 또는 FTP 연결을 시작하면 경고를 발생시키세요. 특히 관리 로그인이나 설정 변경 직후의 연결에 주의하세요.
9. **SNMPv3 사용 또는 SNMP 비활성화** – 커뮤니티 문자열 `public`은 장치 및 일련 번호 정보를 자주 leak합니다.

---



---



## References

- [1] [그냥 프린터일 뿐인데… 최악의 경우 무슨 일이 생길 수 있을까요?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 복합기: Pass-Back 공격 취약점(수정됨)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 생산용 프린터, 사무실/소규모 사무실용 복합기 및 레이저 프린터의 취약점 완화/수정](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat을 사용하여 프린터를 통해 도메인 자격 증명 획득하기](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Penetration Test 수행 중 복합기 악용하기](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [다수의 Brother 장치: 다수의 취약점(수정됨)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother 기본 관리자 인증 우회 모듈](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – LDAP 인증 방식 및 보안 메커니즘](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [LDAP passback Docker 서버](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [LDAP pass back 공격 – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – SASL 보안 속성](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
