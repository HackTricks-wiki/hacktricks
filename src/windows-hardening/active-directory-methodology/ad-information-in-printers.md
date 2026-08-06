# Informazioni nelle stampanti

{{#include ../../banners/hacktricks-training.md}}

Su Internet sono presenti diversi blog che **evidenziano i rischi derivanti dal lasciare le stampanti configurate con LDAP e credenziali di accesso predefinite/deboli**.  \
Questo perché un attaccante potrebbe **ingannare la stampante inducendola ad autenticarsi contro un server LDAP rogue** (in genere è sufficiente un `nc -vv -l -p 389` o `slapd -d 2`) e catturare le **credenziali della stampante in chiaro**.

Inoltre, diverse stampanti possono contenere **log con nomi utente** o potrebbero persino essere in grado di **scaricare tutti i nomi utente** dal Domain Controller.

Tutte queste **informazioni sensibili** e la comune **mancanza di sicurezza** rendono le stampanti molto interessanti per gli attaccanti.

Alcuni blog introduttivi sull'argomento:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configurazione della stampante

- **Posizione**: l'elenco dei server LDAP si trova solitamente nell'interfaccia web (ad es. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportamento**: molti web server embedded consentono di modificare i server LDAP **senza reinserire le credenziali** (funzionalità di usabilità → rischio per la sicurezza).
- **Exploit**: reindirizzare l'indirizzo del server LDAP verso un host controllato dall'attaccante e usare il pulsante *Test Connection* / *Address Book Sync* per costringere la stampante a eseguire il bind verso di voi.

---

## Cattura delle credenziali

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
MFP piccoli/vecchi possono inviare un semplice *simple-bind* in chiaro, che netcat può catturare. I dispositivi moderni di solito eseguono prima una query anonima e poi tentano il bind, quindi i risultati possono variare.<sup>[[1]](#references)</sup>

### Metodo 2 – Full Rogue LDAP server (consigliato)

Poiché molti dispositivi eseguono una ricerca anonima *prima* dell'autenticazione, avviare un vero demone LDAP produce risultati molto più affidabili:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Quando la stampante esegue la ricerca, vedrai le credenziali in chiaro nell'output di debug.

> 💡  Puoi anche usare `impacket/examples/ldapd.py` (Python rogue LDAP) o `Responder -w -r -f` per raccogliere hash NTLMv2 tramite LDAP/SMB.

---

## Vulnerabilità recenti di Pass-Back (2024-2025)

Il pass-back *non* è un problema teorico: i vendor continuano a pubblicare advisory nel 2024/2025 che descrivono esattamente questa classe di attacco.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Il firmware ≤ 57.69.91 delle MFP Xerox VersaLink C70xx permetteva a un amministratore autenticato (o a chiunque, quando le credenziali predefinite erano ancora impostate) di:

* **CVE-2024-12510 – LDAP pass-back**: modificare l'indirizzo del server LDAP e attivare una ricerca, causando il leak delle credenziali Windows configurate dal dispositivo verso l'host controllato dall'attaccante.
* **CVE-2024-12511 – SMB/FTP pass-back**: problema identico tramite le destinazioni *scan-to-folder*, con il leak delle credenziali NetNTLMv2 o FTP in chiaro.<sup>[[2]](#references)</sup>

Un semplice listener come:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
or a rogue SMB server (`impacket-smbserver`) è sufficiente per raccogliere le credenziali.

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon ha confermato una vulnerabilità di **SMTP/LDAP pass-back** in decine di linee di prodotti Laser e MFP. Un attaccante con accesso amministrativo può modificare la configurazione del server e recuperare le credenziali memorizzate per LDAP **o** SMTP (molte organizzazioni utilizzano un account privilegiato per consentire la funzionalità scan-to-mail).<sup>[[3]](#references)</sup>

Le indicazioni del vendor raccomandano esplicitamente di:

1. Aggiornare il firmware con una versione corretta non appena disponibile.
2. Utilizzare password amministrative robuste e univoche.
3. Evitare account AD privilegiati per l'integrazione delle stampanti.

---

## Strumenti di Enumeration / Exploitation automatizzati

| Tool | Scopo | Esempio |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso di PostScript/PJL/PCL, accesso al file system, verifica delle credenziali predefinite, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Raccolta della configurazione (inclusi address book e credenziali LDAP) tramite HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Cattura e relay degli hash NetNTLM tramite SMB/FTP pass-back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Servizio LDAP rogue leggero per ricevere bind in chiaro | `python ldapd.py -debug` |

---

## Hardening & Detection

1. **Patch / firmware-update** tempestivo degli MFP (controllare i bollettini PSIRT del vendor).
2. **Account di servizio con Least Privilege** – non utilizzare mai Domain Admin per LDAP/SMB/SMTP; limitare l'accesso agli scope OU *read-only*.
3. **Limitare l'accesso di gestione** – collocare le interfacce web/IPP/SNMP delle stampanti in una VLAN di gestione oppure dietro un ACL/VPN.
4. **Disabilitare i protocolli non utilizzati** – FTP, Telnet, raw-9100 e cipher SSL meno recenti.
5. **Abilitare l'Audit Logging** – alcuni dispositivi possono inviare tramite syslog gli errori LDAP/SMTP; correlare i bind imprevisti.
6. **Monitorare i bind LDAP in chiaro** provenienti da sorgenti insolite (normalmente le stampanti dovrebbero comunicare solo con i DC).
7. **SNMPv3 o disabilitare SNMP** – la community `public` spesso espone tramite leak la configurazione del dispositivo e di LDAP.

---

## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
