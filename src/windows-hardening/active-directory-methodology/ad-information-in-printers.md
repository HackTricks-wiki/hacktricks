# Informazioni nelle stampanti

{{#include ../../banners/hacktricks-training.md}}

Su Internet sono presenti diversi blog che **evidenziano i pericoli di lasciare le stampanti configurate con LDAP e credenziali di accesso predefinite/deboli**.  \
Questo perché un attacker potrebbe **indurre la stampante ad autenticarsi verso un server LDAP rogue** (in genere è sufficiente un `nc -vv -l -p 389` o `slapd -d 2`) e catturare le **credenziali della stampante in chiaro**.

Inoltre, diverse stampanti contengono **log con nomi utente** o potrebbero persino essere in grado di **scaricare tutti i nomi utente** dal Domain Controller.

Tutte queste **informazioni sensibili** e la comune **mancanza di sicurezza** rendono le stampanti molto interessanti per gli attacker.

Alcuni blog introduttivi sull'argomento:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configurazione della stampante

- **Posizione**: l'elenco dei server LDAP si trova solitamente nell'interfaccia web (ad es. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportamento**: molti web server embedded consentono di modificare i server LDAP **senza reinserire le credenziali** (funzionalità di usabilità → rischio per la sicurezza).
- **Exploit**: reindirizzare l'indirizzo del server LDAP verso un host controllato dall'attacker e usare il pulsante *Test Connection* / *Address Book Sync* per forzare la stampante a eseguire il bind verso di voi.

---

## Cattura delle credenziali

### Metodo 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
MFP piccoli/vecchi possono inviare un semplice *simple-bind* il cui bind DN e la password sono visibili nel raw BER stream. I dispositivi moderni di solito eseguono prima una query anonima e poi tentano il bind, quindi i risultati variano.<sup>[[1]](#references)</sup>

Un listener `nc` semplice sulla porta 636/3269 riceve solo ciphertext TLS; per testare LDAPS è necessario un endpoint LDAP compatibile con TLS e il reindirizzamento dovrebbe fallire quando il dispositivo convalida correttamente il certificato del server.

### Method 2 – Full Rogue LDAP server (consigliato)

Poiché molti dispositivi eseguono una ricerca anonima *prima* dell'autenticazione, configurare un vero demone LDAP produce risultati molto più affidabili:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Quando la stampante esegue la ricerca, vedrai le credenziali in chiaro nell'output di debug.

> 💡  Responder include servizi di autenticazione LDAP e SMB rogue. Un semplice LDAP bind può esporre la password configurata, mentre l'autenticazione NTLM produce materiale challenge-response; non descrivere entrambi i risultati come una password in chiaro.

---

## Vulnerabilità Pass-Back recenti (2024-2025)

Il Pass-Back *non* è un problema teorico: i vendor continuano a pubblicare advisory nel 2024/2025 che descrivono esattamente questa classe di attacchi.

### Xerox VersaLink – CVE-2024-12510 e CVE-2024-12511

I firmware ≤ 57.69.91 delle MFP Xerox VersaLink C70xx consentivano a un amministratore autenticato (o a chiunque, quando erano ancora presenti le credenziali predefinite) di:

* **CVE-2024-12510 – LDAP pass-back**: modificare l'indirizzo del server LDAP e attivare una ricerca, causando il leak delle credenziali Windows configurate verso l'host controllato dall'attaccante.
* **CVE-2024-12511 – SMB/FTP pass-back**: problema identico tramite destinazioni *scan-to-folder*, con il leak di credenziali NetNTLMv2 o FTP in chiaro.<sup>[[2]](#references)</sup>

Un semplice listener come:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
o un rogue SMB server (`impacket-smbserver`) è sufficiente per raccogliere le credenziali.

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon ha confermato una vulnerabilità di **SMTP/LDAP pass-back** in decine di linee di prodotti Laser e MFP. Un attacker con accesso admin può modificare la configurazione del server e recuperare le credenziali memorizzate per LDAP **o** SMTP (molte organizzazioni usano un account privilegiato per consentire la funzionalità scan-to-mail).<sup>[[3]](#references)</sup>

Le indicazioni del vendor raccomandano esplicitamente di:

1. Aggiornare al firmware con patch non appena disponibile.
2. Usare password admin robuste e univoche.
3. Evitare account AD privilegiati per l'integrazione delle stampanti.

---

### Dispositivi Brother e varianti OEM – accesso admin derivato dal seriale alle credenziali dei servizi

Una disclosure coordinata del 2025 ha dimostrato una catena particolarmente utile sui dispositivi Brother interessati; parti del set di vulnerabilità interessano anche i modelli OEM, quindi verifica il modello esatto rispetto all'advisory del vendor. Un attacker non autenticato può ottenere il seriale del dispositivo tramite HTTP/HTTPS/IPP su firmware vulnerabile, mentre i seriali possono essere disponibili anche tramite protocolli di gestione come SNMP o PJL. Se la password di fabbrica non è mai stata modificata, il seriale consente di determinare la password dell'amministratore. Dopo l'autenticazione, la vulnerabilità separata di pass-back CVE-2024-51984 espone in plaintext le password dei servizi esterni configurati, come LDAP o FTP, trasformando l'accesso alla gestione della stampante in credenziali di rete riutilizzabili. Il firmware risolve la disclosure della password del servizio, ma i dispositivi prodotti in precedenza richiedono comunque che l'operatore sostituisca la password iniziale dell'amministratore derivata dal seriale.<sup>[[6]](#references)</sup>

La versione attuale di Metasploit include un modulo auxiliary che individua il seriale tramite HTTP, SNMP o PJL, genera la password iniziale candidata e, facoltativamente, la verifica rispetto alla web console. `DiscoverSerialVia=AUTO` prova i percorsi di discovery supportati; specifica invece `TargetSerial` quando l'inventario degli asset contiene già il seriale.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Usa il risultato solo per convalidare asset autorizzati. Il funzionamento della password dipende dal modello esatto e, soprattutto, dal fatto che la password amministratore di fabbrica sia già stata modificata o meno.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Strumenti di Enumerazione / Exploitation automatizzati

| Strumento | Scopo | Esempio |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso di PostScript/PJL/PCL, accesso al file system, verifica delle credenziali predefinite, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Raccolta della configurazione (inclusi rubriche e credenziali LDAP) tramite HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Esecuzione di servizi di autenticazione rogue e cattura/relay di NetNTLM dai callback SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Individuazione di un seriale, derivazione della password amministratore di fabbrica candidata e verifica dell'accesso alla console web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening e Rilevamento

1. **Applicare tempestivamente patch / aggiornamenti firmware** alle MFP (controllare i bollettini PSIRT del vendor).
2. **Sostituire le password amministratore di fabbrica** – il firmware da solo non rimuove le password iniziali derivate dal seriale dai dispositivi Brother/OEM interessati prodotti in precedenza.<sup>[[6]](#references)</sup>
3. **Account di servizio con privilegi minimi** – non usare mai Domain Admin per LDAP/SMB/SMTP; limitare agli scope OU *sola lettura*.
4. **Limitare l'accesso di gestione** – collocare le interfacce web/IPP/SNMP delle stampanti in una VLAN di gestione o dietro un ACL/VPN.
5. **Limitare l'egress delle stampanti** – consentire a ciascun dispositivo di contattare solo le destinazioni DC/LDAP, posta, DNS/NTP, stampa e file di scansione previste. Il pass-back richiede un callback verso un endpoint selezionato dall'attaccante.
6. **Disabilitare i protocolli non utilizzati** – FTP, Telnet, raw-9100, cipher SSL obsoleti.
7. **Abilitare l'audit logging** – alcuni dispositivi possono inviare tramite syslog gli errori LDAP/SMTP; correlare i bind imprevisti.
8. **Monitorare le destinazioni di autenticazione** – generare un alert quando una stampante avvia connessioni LDAP, SMB, SMTP o FTP verso un host esterno alla propria allowlist, soprattutto subito dopo un accesso di gestione o una modifica della configurazione.
9. **SNMPv3 o disabilitare SNMP** – la community `public` spesso espone informazioni sul dispositivo e sul seriale.

---



---

## References

- [1] [È solo una stampante... Qual è il peggio che potrebbe succedere?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Stampante multifunzione Xerox Versalink C7025: vulnerabilità di attacco Pass-Back (risolte)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [Mitigazione/Risoluzione della vulnerabilità CP2025-004 per stampanti di produzione, stampanti multifunzione per uffici e piccoli uffici e stampanti laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Ottenere credenziali di dominio tramite una stampante con Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting delle stampanti multifunzione durante un incarico di Penetration Test](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Dispositivi Brother multipli: vulnerabilità multiple (RISOLTE)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: modulo di bypass dell'autenticazione dell'amministratore predefinito Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
