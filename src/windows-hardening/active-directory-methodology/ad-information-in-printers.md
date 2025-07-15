# Informazioni nelle Stampanti

{{#include ../../banners/hacktricks-training.md}}

Ci sono diversi blog su Internet che **mettono in evidenza i pericoli di lasciare le stampanti configurate con LDAP con credenziali di accesso predefinite/deboli**.  \
Questo perché un attaccante potrebbe **ingannare la stampante a autenticarsi contro un server LDAP malevolo** (tipicamente un `nc -vv -l -p 389` o `slapd -d 2` è sufficiente) e catturare le **credenziali della stampante in chiaro**.

Inoltre, diverse stampanti conterranno **log con nomi utente** o potrebbero persino essere in grado di **scaricare tutti i nomi utente** dal Domain Controller.

Tutte queste **informazioni sensibili** e la comune **mancanza di sicurezza** rendono le stampanti molto interessanti per gli attaccanti.

Alcuni blog introduttivi sull'argomento:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## Configurazione della Stampante

- **Posizione**: L'elenco dei server LDAP si trova solitamente nell'interfaccia web (ad es. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Comportamento**: Molti server web incorporati consentono modifiche al server LDAP **senza reinserire le credenziali** (funzione di usabilità → rischio per la sicurezza).
- **Sfruttamento**: Reindirizza l'indirizzo del server LDAP a un host controllato dall'attaccante e utilizza il pulsante *Test Connection* / *Address Book Sync* per costringere la stampante a collegarsi a te.

---
## Cattura delle Credenziali

### Metodo 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Small/old MFPs possono inviare un semplice *simple-bind* in chiaro che netcat può catturare. I dispositivi moderni di solito eseguono prima una query anonima e poi tentano il bind, quindi i risultati variano.

### Method 2 – Full Rogue LDAP server (recommended)

Poiché molti dispositivi emetteranno una ricerca anonima *prima* di autenticarsi, avviare un vero demone LDAP produce risultati molto più affidabili:
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Quando la stampante esegue la sua ricerca, vedrai le credenziali in chiaro nell'output di debug.

> 💡 Puoi anche usare `impacket/examples/ldapd.py` (Python rogue LDAP) o `Responder -w -r -f` per raccogliere hash NTLMv2 tramite LDAP/SMB.

---
## Vulnerabilità Recenti di Pass-Back (2024-2025)

Il pass-back *non* è un problema teorico – i fornitori continuano a pubblicare avvisi nel 2024/2025 che descrivono esattamente questa classe di attacco.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Il firmware ≤ 57.69.91 delle stampanti multifunzione Xerox VersaLink C70xx ha permesso a un amministratore autenticato (o a chiunque quando le credenziali predefinite rimangono) di:

* **CVE-2024-12510 – LDAP pass-back**: cambiare l'indirizzo del server LDAP e attivare una ricerca, causando la perdita delle credenziali Windows configurate verso l'host controllato dall'attaccante.
* **CVE-2024-12511 – SMB/FTP pass-back**: problema identico tramite destinazioni *scan-to-folder*, perdendo credenziali NetNTLMv2 o FTP in chiaro.

Un semplice listener come:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
o un server SMB non autorizzato (`impacket-smbserver`) è sufficiente per raccogliere le credenziali.

### Canon imageRUNNER / imageCLASS – Avviso 20 Maggio 2025

Canon ha confermato una vulnerabilità di **pass-back SMTP/LDAP** in dozzine di linee di prodotti Laser e MFP. Un attaccante con accesso admin può modificare la configurazione del server e recuperare le credenziali memorizzate per LDAP **o** SMTP (molte organizzazioni utilizzano un account privilegiato per consentire la scansione su email).

Le indicazioni del fornitore raccomandano esplicitamente:

1. Aggiornare al firmware corretto non appena disponibile.
2. Utilizzare password admin forti e uniche.
3. Evitare account AD privilegiati per l'integrazione della stampante.

---
## Strumenti di Enumerazione / Sfruttamento Automatizzati

| Strumento | Scopo | Esempio |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso di PostScript/PJL/PCL, accesso al file system, controllo delle credenziali predefinite, *scoperta SNMP* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Raccolta della configurazione (inclusi rubrica e credenziali LDAP) tramite HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Cattura e rilancio degli hash NetNTLM da pass-back SMB/FTP | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Servizio LDAP non autorizzato leggero per ricevere bind in chiaro | `python ldapd.py -debug` |

---
## Indurimento & Rilevamento

1. **Patch / aggiornamento firmware** MFP tempestivamente (controllare i bollettini PSIRT del fornitore).
2. **Account di Servizio con Minimi Privilegi** – non utilizzare mai Domain Admin per LDAP/SMB/SMTP; limitare a scope OU *solo in lettura*.
3. **Limitare l'Accesso alla Gestione** – posizionare le interfacce web/IPP/SNMP della stampante in una VLAN di gestione o dietro un ACL/VPN.
4. **Disabilitare i Protocolli Non Utilizzati** – FTP, Telnet, raw-9100, cifrari SSL obsoleti.
5. **Abilitare il Logging di Audit** – alcuni dispositivi possono sysloggare i fallimenti LDAP/SMTP; correlare bind inaspettati.
6. **Monitorare i bind LDAP in chiaro** da fonti insolite (le stampanti dovrebbero normalmente comunicare solo con i DC).
7. **SNMPv3 o disabilitare SNMP** – la community `public` spesso rivela configurazioni di dispositivo e LDAP.

---
## Riferimenti

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Vulnerabilità degli Attacchi Pass-Back della Xerox VersaLink C7025 MFP.” Febbraio 2025.
- Canon PSIRT. “Mitigazione delle Vulnerabilità contro il Passback SMTP/LDAP per Stampanti Laser e Stampanti Multifunzionali per Piccoli Uffici.” Maggio 2025.

{{#include ../../banners/hacktricks-training.md}}
