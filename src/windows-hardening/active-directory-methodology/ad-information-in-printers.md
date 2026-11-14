# Informazioni nelle stampanti

{{#include ../../banners/hacktricks-training.md}}

Una stampante con credenziali LDAP salvate può esporle se si modifica l’impostazione del server e poi la stampante si autentica a un endpoint malevolo.<sup>[[2]](#references)</sup> Il risultato dipende dal metodo di bind: un simple bind non protetto rivela la password, mentre un bind SASL challenge-response non la rivela in chiaro.<sup>[[8]](#references)</sup> Vedi [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Inoltre, diverse stampanti contengono **log con nomi utente** o potrebbero persino essere in grado di **scaricare tutti i nomi utente** dal Domain Controller.

Tutte queste **informazioni sensibili** e la comune **mancanza di sicurezza** rendono le stampanti molto interessanti per gli attacker.

Alcuni blog introduttivi sull’argomento:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Configurazione della stampante

- **Posizione**: l’elenco dei server LDAP si trova solitamente nell’interfaccia web (ad es. *Rete ➜ Impostazioni LDAP ➜ Configurazione LDAP*).
- **Comportamento**: molti web server embedded consentono di modificare i server LDAP **senza reinserire le credenziali** (funzionalità di usabilità → rischio per la sicurezza).
- **Exploit**: reindirizza l’indirizzo del server LDAP a un host controllato dall’attacker e usa il pulsante *Verifica connessione* / *Sincronizzazione rubrica* per forzare la stampante a eseguire il bind con te.

---

## Acquisizione delle credenziali

### Metodo 1 – Netcat Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Una semplice BindRequest può esporre il bind DN e la password nel flusso BER anche se in seguito il server rifiuta il login. Una ricerca anonima o la sola negoziazione SASL non espongono la password memorizzata.<sup>[[8]](#references)</sup>

Un listener `nc` standard sulle porte 636/3269 vede un handshake TLS, non un bind LDAP. LDAPS richiede un endpoint compatibile con TLS. La sola convalida del certificato non impedisce il pass-back se la stampante accetta un hostname modificato e il nuovo endpoint dispone di un certificato valido per quell’hostname; il client deve anche limitare i server autorizzati a ricevere la credenziale memorizzata.<sup>[[8]](#references)</sup>

### Method 2 – Full Rogue LDAP server (consigliato)

Una stampante potrebbe richiedere una risposta LDAP valida prima di tentare un bind.<sup>[[10]](#references)</sup> Un server LDAP completo può gestire questo scambio preliminare, ma non può indurre un client vincolato a un meccanismo SASL robusto o al server TLS previsto a rivelare la propria password.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Considera una ricerca come prova di una connessione, non come prova della divulgazione di una password. Una password viene esposta solo se il client invia un bind contenente una password in testo in chiaro; verifica il meccanismo di bind effettivo e lo stato TLS.<sup>[[8]](#references)</sup>

> 💡  Responder include servizi di autenticazione rogue LDAP e SMB. Un semplice bind LDAP può esporre la password configurata, mentre l'autenticazione NTLM produce materiale challenge-response; non descrivere entrambi i risultati come password in testo in chiaro.

### Selezione del meccanismo SASL

Alcuni client LDAP delle stampanti scelgono tra i meccanismi pubblicizzati da un server LDAP.<sup>[[8]](#references)[[10]](#references)</sup> Le ricerche hanno dimostrato che un client disposto ad accettare un meccanismo SASL in testo in chiaro pubblicizzato potrebbe inviare una password, mentre la consueta negoziazione NTLM avrebbe restituito solo dati challenge-response.<sup>[[9]](#references)[[10]](#references)</sup> Si tratta di un **errore nelle policy del client**, non di una caratteristica di tutti i bind SASL: un client che richiede un meccanismo più robusto o verifica che il server TLS sia quello previsto dovrebbe invece rifiutare la connessione.<sup>[[8]](#references)</sup> OpenLDAP disabilita per impostazione predefinita i meccanismi SASL in grado di trasmettere password in testo in chiaro, quindi un daemon standard non dimostra che questo comportamento sia presente su una stampante.<sup>[[11]](#references)</sup>

---

## Vulnerabilità pass-back recenti (2024-2025)

Il pass-back *non è un problema teorico*: nel 2024/2025 i vendor continuano a pubblicare avvisi che descrivono esattamente questa classe di attacco.

### Xerox VersaLink – CVE-2024-12510 e CVE-2024-12511

Il firmware ≤ 57.69.91 delle MFP Xerox VersaLink C70xx consentiva a un amministratore autenticato (o a chiunque, se erano ancora presenti le credenziali predefinite) di:

* **CVE-2024-12510 – LDAP pass-back**: modificare l'indirizzo del server LDAP e avviare una ricerca, facendo sì che il dispositivo esponesse le credenziali Windows configurate all'host controllato dall'attaccante.
* **CVE-2024-12511 – SMB/FTP pass-back**: problema analogo tramite le destinazioni *scan-to-folder*, con esposizione di credenziali NetNTLMv2 o FTP in testo in chiaro.<sup>[[2]](#references)</sup>

Un semplice listener, ad esempio:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

o un server SMB rogue (`impacket-smbserver`) è sufficiente per raccogliere le credenziali.  

### Canon imageRUNNER / imageCLASS – Avviso del 20 maggio 2025

Canon ha confermato una vulnerabilità **SMTP/LDAP pass-back** in decine di linee di prodotti Laser e MFP. Un attaccante con accesso admin può modificare la configurazione del server e recuperare le credenziali LDAP **o** SMTP memorizzate (molte organizzazioni usano un account privilegiato per consentire la scansione e l'invio tramite e-mail).<sup>[[3]](#references)</sup>

Le indicazioni del vendor raccomandano esplicitamente di:

1. Aggiornare il firmware alla versione corretta non appena disponibile.
2. Usare password admin robuste e univoche.
3. Evitare account AD privilegiati per l'integrazione delle stampanti.

---

### Dispositivi Brother e varianti OEM – accesso admin derivato dal numero di serie alle credenziali dei servizi

Una disclosure coordinata del 2025 ha dimostrato una catena particolarmente utile sui dispositivi Brother interessati; parte dell'insieme di vulnerabilità riguarda anche i modelli OEM, quindi verificate il modello esatto rispetto all'advisory del relativo vendor. Su firmware vulnerabili, un attaccante non autenticato può ottenere il numero di serie del dispositivo tramite HTTP/HTTPS/IPP; i numeri di serie possono essere disponibili anche tramite protocolli di gestione come SNMP o PJL. Se la password di fabbrica non è mai stata modificata, dal numero di serie si ricava in modo deterministico la password admin. Dopo l'autenticazione, la vulnerabilità pass-back separata CVE-2024-51984 espone in chiaro le password configurate per servizi esterni, come LDAP o FTP, trasformando l'accesso alla gestione della stampante in credenziali di rete riutilizzabili. Il firmware corregge la divulgazione delle password dei servizi, ma per i dispositivi già prodotti l'operatore deve comunque sostituire la password admin iniziale derivata dal numero di serie.<sup>[[6]](#references)</sup>

La versione attuale di Metasploit include un modulo ausiliario che individua il numero di serie tramite HTTP, SNMP o PJL, genera la possibile password iniziale e, facoltativamente, la verifica tramite la console web. `DiscoverSerialVia=AUTO` prova i metodi di individuazione supportati; specificate invece `TargetSerial` se il numero di serie è già presente nell'inventario degli asset.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Usa il risultato solo per convalidare asset autorizzati. La password funziona o meno in base al modello esatto e, soprattutto, al fatto che la password amministratore di fabbrica sia già stata modificata.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Strumenti automatizzati di enumerazione / sfruttamento

| Strumento | Scopo | Esempio |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuso di PostScript/PJL/PCL, accesso al file system, verifica delle credenziali predefinite, *ricognizione SNMP*; vedi [valutazione PJL](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Recupera configurazioni (incluse rubriche e credenziali LDAP) tramite HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Avvia servizi di autenticazione rogue e acquisisce/inoltra NetNTLM tramite callback SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Individua un numero di serie, ricava la password amministratore di fabbrica candidata e verifica l'accesso alla console web | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening e rilevamento

1. **Applica le patch / aggiorna il firmware** degli MFP tempestivamente (consulta i bollettini PSIRT del vendor).
2. **Sostituisci le password amministratore di fabbrica**: il firmware da solo non rimuove le password iniziali derivate dal numero di serie dai dispositivi Brother/OEM interessati già prodotti.<sup>[[6]](#references)</sup>
3. **Account di servizio con privilegi minimi**: non usare mai Domain Admin per LDAP/SMB/SMTP; limita gli ambiti OU all'accesso *in sola lettura*.
4. **Limita l'accesso di gestione**: colloca le interfacce web/IPP/SNMP della stampante in una VLAN di gestione o proteggile con un'ACL/VPN.
5. **Limita il traffico in uscita della stampante**: consenti a ogni dispositivo di contattare solo le destinazioni previste per DC/LDAP, posta, DNS/NTP, stampa e file di scansione. Il pass-back richiede una callback a un endpoint scelto dall'attaccante.
6. **Disabilita i protocolli inutilizzati**: FTP, Telnet, raw-9100, cifrari SSL obsoleti.
7. **Abilita la registrazione degli eventi di audit**: alcuni dispositivi possono inviare tramite syslog gli errori LDAP/SMTP; correla i bind imprevisti.
8. **Monitora le destinazioni di autenticazione**: genera un avviso quando una stampante avvia connessioni LDAP, SMB, SMTP o FTP verso un host non incluso nella sua allowlist, soprattutto subito dopo un accesso di gestione o una modifica della configurazione.
9. **SNMPv3 o disabilita SNMP**: la community `public` spesso espone informazioni sul dispositivo e sul numero di serie.

---



---



## References

- [1] [È solo una stampante… Qual è la cosa peggiore che potrebbe succedere?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Stampante multifunzione Xerox Versalink C7025: vulnerabilità di Pass-Back Attack (risolte)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Mitigazione/ripristino delle vulnerabilità per stampanti di produzione, stampanti multifunzione per uffici e piccoli uffici e stampanti laser](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Ottenere credenziali di dominio tramite una stampante con Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Sfruttare le stampanti multifunzione durante un incarico di penetration test](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Più dispositivi Brother: vulnerabilità multiple (RISOLTE)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: modulo di bypass dell'autenticazione amministratore predefinita Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – Metodi di autenticazione e meccanismi di sicurezza LDAP](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [Server Docker per LDAP passback](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [Attacco LDAP pass back – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – Proprietà di sicurezza SASL](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
