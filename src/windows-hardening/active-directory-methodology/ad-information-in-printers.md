# Informazioni nelle stampanti

{{#include ../../banners/hacktricks-training.md}}

Su Internet ci sono diversi blog che **mettono in evidenza i pericoli di lasciare le stampanti configurate con LDAP e credenziali di accesso predefinite/deboli**.  \
Questo perché un attacker potrebbe **indurre la stampante ad autenticarsi contro un server LDAP rogue** (in genere è sufficiente un `nc -vv -l -p 389` o `slapd -d 2`) e acquisire le **credenziali della stampante in chiaro**.

Inoltre, diverse stampanti contengono **log con nomi utente** o possono persino **scaricare tutti i nomi utente** dal Domain Controller.

Tutte queste **informazioni sensibili** e la comune **mancanza di sicurezza** rendono le stampanti molto interessanti per gli attacker.

Alcuni blog introduttivi sull'argomento:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configurazione della stampante

- **Posizione**: L'elenco dei server LDAP si trova solitamente nell'interfaccia web (ad es. *Rete ➜ Impostazioni LDAP ➜ Configurazione LDAP*).
- **Comportamento**: Molti web server embedded consentono di modificare il server LDAP **senza reinserire le credenziali** (funzione pensata per la praticità → rischio per la sicurezza).
- **Exploit**: Reindirizza l'indirizzo del server LDAP a un host controllato dall'attacker e usa il pulsante *Test Connection* / *Address Book Sync* per forzare la stampante a eseguire il bind con te.

---

## Acquisizione delle credenziali

### Metodo 1 – Listener Netcat

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

I MFP piccoli/vecchi possono inviare un *simple-bind* il cui bind DN e la password sono visibili nel flusso BER grezzo. I dispositivi moderni di solito eseguono prima una query anonima e poi tentano il bind, quindi i risultati variano.<sup>[[1]](#references)</sup>

Un listener `nc` semplice sulla porta 636/3269 riceve solo ciphertext TLS; per testare LDAPS serve un endpoint LDAP compatibile con TLS e il reindirizzamento dovrebbe fallire se il dispositivo convalida correttamente il certificato del server.

### Metodo 2 – Server LDAP rogue completo (consigliato)

Poiché molti dispositivi eseguono una ricerca anonima *prima* di autenticarsi, avviare un vero daemon LDAP offre risultati molto più affidabili:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Quando la stampante esegue la ricerca, vedrai le credenziali in chiaro nell'output di debug.

> 💡 Responder include servizi di autenticazione LDAP e SMB rogue. Un semplice bind LDAP può esporre la password configurata, mentre l'autenticazione NTLM produce materiale challenge-response; non descrivere entrambi i risultati come una password in chiaro.

---

## Vulnerabilità Pass-Back recenti (2024-2025)

Il Pass-back *non* è un problema teorico: nel 2024/2025 i vendor continuano a pubblicare avvisi che descrivono esattamente questa classe di attacchi.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Il firmware ≤ 57.69.91 delle MFP Xerox VersaLink C70xx consentiva a un admin autenticato (o a chiunque, se erano ancora presenti le credenziali predefinite) di:

* **CVE-2024-12510 – LDAP pass-back**: modificare l'indirizzo del server LDAP e attivare una ricerca, facendo sì che il dispositivo invii le credenziali Windows configurate all'host controllato dall'attaccante.
* **CVE-2024-12511 – SMB/FTP pass-back**: problema identico tramite le destinazioni *scan-to-folder*, che esponeva credenziali NetNTLMv2 o credenziali FTP in chiaro.<sup>[[2]](#references)</sup>

Un semplice listener come:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

o un server SMB rogue (`impacket-smbserver`) sono sufficienti per raccogliere le credenziali.  

### Canon imageRUNNER / imageCLASS – Avviso del 20 maggio 2025

Canon ha confermato una vulnerabilità **SMTP/LDAP pass-back** in decine di linee di prodotti Laser e MFP. Un attacker con accesso admin può modificare la configurazione del server e recuperare le credenziali LDAP **o** SMTP memorizzate (molte organizzazioni usano un account con privilegi per consentire la scansione e l'invio tramite e-mail).<sup>[[3]](#references)</sup>

Le indicazioni del vendor raccomandano esplicitamente di:

1. Aggiornare al firmware corretto non appena disponibile.
2. Usare password admin robuste e univoche.
3. Evitare account AD con privilegi per l'integrazione delle stampanti.

---

### Dispositivi Brother e varianti OEM – accesso admin derivato dal numero di serie alle credenziali dei servizi

Una disclosure coordinata del 2025 ha dimostrato una catena particolarmente utile su dispositivi Brother vulnerabili; alcune parti dell'insieme di vulnerabilità riguardano anche modelli OEM, quindi verificare il modello esatto consultando l'advisory del relativo vendor. Su firmware vulnerabile, un attacker non autenticato può ottenere il numero di serie del dispositivo tramite HTTP/HTTPS/IPP; i numeri di serie potrebbero essere disponibili anche tramite protocolli di gestione come SNMP o PJL. Se la password di fabbrica non è mai stata modificata, dal numero di serie si ricava in modo deterministico la password admin. Dopo essersi autenticati, la vulnerabilità pass-back separata CVE-2024-51984 espone in testo in chiaro le password configurate per servizi esterni, come LDAP o FTP, trasformando l'accesso alla gestione della stampante in credenziali di rete riutilizzabili. Il firmware corregge la divulgazione delle password dei servizi, ma per i dispositivi già prodotti l'operatore deve comunque sostituire la password admin iniziale derivata dal numero di serie.<sup>[[6]](#references)</sup>

Le versioni attuali di Metasploit includono un modulo ausiliario che individua il numero di serie tramite HTTP, SNMP o PJL, genera la possibile password iniziale e, facoltativamente, la verifica sulla console web. `DiscoverSerialVia=AUTO` prova i metodi di individuazione supportati; specificare invece `TargetSerial` se il numero di serie è già presente nell'inventario degli asset.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Usa il risultato solo per convalidare asset autorizzati. Il funzionamento della password dipende dal modello esatto e, soprattutto, dal fatto che la password di amministratore predefinita sia già stata modificata.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Strumenti di enumerazione / exploitation automatizzati

| Strumento | Scopo | Esempio |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso di PostScript/PJL/PCL, accesso al file system, verifica delle credenziali predefinite, *ricognizione SNMP* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Raccolta della configurazione (inclusi rubriche e credenziali LDAP) tramite HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Avvio di servizi di autenticazione rogue e acquisizione/relay di NetNTLM tramite callback SMB | `sudo responder -I eth0 -v` |
| **Modulo ausiliario Brother di Metasploit** | Individuazione di un numero di serie, derivazione della password di amministratore di fabbrica candidata e verifica dell'accesso alla console Web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening e rilevamento

1. **Applicare patch / aggiornare il firmware** degli MFP tempestivamente (consultare i bollettini PSIRT dei vendor).
2. **Sostituire le password di amministratore di fabbrica**: il solo firmware non rimuove le password iniziali derivate dal numero di serie dai dispositivi Brother/OEM interessati già prodotti.<sup>[[6]](#references)</sup>
3. **Account di servizio con privilegi minimi**: non usare mai Domain Admin per LDAP/SMB/SMTP; limitare gli ambiti OU all'accesso *in sola lettura*.
4. **Limitare l'accesso alla gestione**: collocare le interfacce Web/IPP/SNMP delle stampanti in una VLAN di gestione o dietro un ACL/VPN.
5. **Limitare il traffico in uscita delle stampanti**: consentire a ogni dispositivo di contattare solo le destinazioni previste per DC/LDAP, posta, DNS/NTP, stampa e file di scansione. Il pass-back richiede una callback verso un endpoint scelto dall'attaccante.
6. **Disabilitare i protocolli non utilizzati**: FTP, Telnet, raw-9100 e cifrari SSL obsoleti.
7. **Abilitare la registrazione di audit**: alcuni dispositivi possono inviare via syslog gli errori LDAP/SMTP; correlare i bind imprevisti.
8. **Monitorare le destinazioni di autenticazione**: generare un avviso quando una stampante avvia connessioni LDAP, SMB, SMTP o FTP verso un host esterno alla propria allowlist, soprattutto subito dopo un accesso di gestione o una modifica della configurazione.
9. **Usare SNMPv3 o disabilitare SNMP**: la community `public` spesso espone informazioni sul dispositivo e sul numero di serie.

---



---

## References

- [1] [È solo una stampante… Qual è la cosa peggiore che potrebbe succedere?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Stampante multifunzione Xerox Versalink C7025: vulnerabilità dell'attacco pass-back (risolte)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Mitigazione/rimedio delle vulnerabilità per stampanti di produzione, stampanti multifunzione per uffici e piccoli uffici e stampanti laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Ottenere credenziali di dominio tramite una stampante con Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Sfruttare le stampanti multifunzione durante un incarico di penetration test](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Dispositivi Brother multipli: vulnerabilità multiple (RISOLTE)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: modulo per aggirare l'autenticazione di amministratore predefinita Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
