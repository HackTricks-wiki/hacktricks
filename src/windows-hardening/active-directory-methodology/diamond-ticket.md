# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Come un golden ticket**, un diamond ticket è un TGT che può essere usato per **accedere a qualsiasi servizio come qualsiasi utente**. Un golden ticket viene forgiato completamente offline, cifrato con l'hash krbtgt del dominio e poi inserito in una sessione di accesso per essere usato. Poiché i controller di dominio non tengono traccia dei TGT che hanno (o non hanno) emesso legittimamente, accettano senza problemi i TGT cifrati con il proprio hash krbtgt.<sup>[[1]](#references)</sup>

Esistono due tecniche comuni per rilevare l'uso dei golden ticket:

- Cercare TGS-REQ senza un AS-REQ corrispondente.
- Cercare TGT con valori assurdi, come la durata predefinita di 10 anni di Mimikatz.

Un **diamond ticket** viene creato **modificando i campi di un TGT legittimo emesso da un DC**. Per farlo, si **richiede** un **TGT**, lo si **decifra** con l'hash krbtgt del dominio, si **modificano** i campi desiderati del ticket e poi lo si **cifra nuovamente**. In questo modo si **superano i due limiti menzionati sopra** di un golden ticket, perché:<sup>[[1]](#references)</sup>

- I TGS-REQ avranno un AS-REQ precedente.
- Il TGT è stato emesso da un DC, quindi conterrà tutti i dettagli corretti previsti dalla policy Kerberos del dominio. Anche se questi possono essere riprodotti accuratamente in un golden ticket, l'operazione è più complessa e soggetta a errori.

### Requisiti e workflow

- **Materiale crittografico**: la chiave AES256 krbtgt (preferibile) o l'hash NTLM, per decifrare e firmare nuovamente il TGT.
- **Blob TGT legittimo**: ottenuto con `/tgtdeleg`, `asktgt`, `s4u` o esportando i ticket dalla memoria.
- **Dati di contesto**: RID dell'utente target, RID/SID dei gruppi e, facoltativamente, attributi PAC ricavati da LDAP.
- **Chiavi dei servizi** (solo se si prevede di creare nuovamente ticket di servizio): chiave AES dello SPN del servizio da impersonare.

1. Ottenere un TGT per un utente controllato tramite AS-REQ (`/tgtdeleg` di Rubeus è pratico perché induce il client a eseguire lo scambio Kerberos GSS-API senza credenziali).
2. Decifrare il TGT restituito con la chiave krbtgt e modificare gli attributi PAC (utente, gruppi, informazioni di accesso, SID, attestazioni del dispositivo ecc.).
3. Cifrare/firmare nuovamente il ticket con la stessa chiave krbtgt e inserirlo nella sessione di accesso corrente (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Facoltativamente, ripetere il processo su un ticket di servizio fornendo un blob TGT valido e la chiave del servizio target, per rimanere furtivi sul traffico di rete.

### Tradecraft aggiornata di Rubeus (2024+)

Il lavoro recente di Huntress ha modernizzato l'azione `diamond` di Rubeus integrando i miglioramenti `/ldap` e `/opsec`, che in precedenza erano disponibili solo per i golden/silver ticket. `/ldap` ora recupera il contesto PAC reale interrogando LDAP **e** montando SYSVOL per estrarre gli attributi di account e gruppi, oltre alla policy Kerberos/password (ad es. `GptTmpl.inf`); `/opsec` fa invece sì che il flusso AS-REQ/AS-REP corrisponda a quello di Windows, eseguendo lo scambio di preautenticazione in due passaggi e imponendo AES soltanto e valori KDCOptions realistici. Questo riduce notevolmente gli indicatori evidenti, come campi PAC mancanti o durate non conformi alla policy.<sup>[[3]](#references)</sup>

```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
  /opsec /nowrap
```

- `/ldap` (con `/ldapuser` e `/ldappassword` opzionali) interroga AD e SYSVOL per replicare i dati delle policy PAC dell'utente bersaglio.
- `/opsec` forza un nuovo tentativo AS-REQ simile a quello di Windows, azzerando i flag rumorosi e usando solo AES256.
- `/tgtdeleg` evita di entrare in possesso della password in chiaro o della chiave NTLM/AES della vittima, restituendo comunque un TGT decrittabile.

### Rigenerazione dei ticket di servizio

Lo stesso aggiornamento di Rubeus ha aggiunto la possibilità di applicare la tecnica diamond ai blob TGS. Passando a `diamond` un **TGT codificato in base64** (ottenuto da `asktgt`, `/tgtdeleg` o da un TGT contraffatto in precedenza), lo **SPN del servizio** e la **chiave AES del servizio**, puoi creare ticket di servizio realistici senza interagire con il KDC, ottenendo di fatto un silver ticket più furtivo.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Questo flusso di lavoro è ideale quando controlli già una chiave di service account (ad es., estratta con `lsadump::lsa /inject` o `secretsdump.py`) e vuoi generare un TGS una tantum che corrisponda perfettamente ai criteri AD, alle tempistiche e ai dati PAC, senza generare nuovo traffico AS/TGS.<sup>[[3]](#references)</sup>

### Scambi di PAC in stile Sapphire (2025)

Una variante più recente, a volte chiamata **sapphire ticket**, combina la base del «real TGT» di Diamond con **S4U2self+U2U** per sottrarre un PAC con privilegi elevati e inserirlo nel proprio TGT. Invece di inventare SID aggiuntivi, richiedi un ticket S4U2self U2U per un utente con privilegi elevati, con `sname` che punta al richiedente con privilegi ridotti; il KRB_TGS_REQ include il TGT del richiedente in `additional-tickets` e imposta `ENC-TKT-IN-SKEY`, consentendo di decrittare il service ticket con la chiave di quell'utente. Quindi estrai il PAC con privilegi elevati e lo inserisci nel tuo TGT legittimo prima di firmarlo nuovamente con la chiave krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket ora include il supporto sapphire in `ticketer.py` tramite `-impersonate` + `-request` (scambio live con il KDC):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` accetta un nome utente o un SID; `-request` richiede credenziali valide di un utente e materiale della chiave krbtgt (AES/NTLM) per decrittografare/modificare i ticket.

Indicatori OPSEC chiave quando si usa questa variante:<sup>[[5]](#references)</sup>

- TGS-REQ conterrà `ENC-TKT-IN-SKEY` e `additional-tickets` (il TGT della vittima): una combinazione rara nel traffico normale.
- `sname` spesso corrisponde all'utente che effettua la richiesta (accesso self-service) e l'Event ID 4769 mostra lo stesso SPN/utente come chiamante e destinazione.
- Aspettati voci 4768/4769 abbinate, con lo stesso computer client ma CNAMES diversi (richiedente con pochi privilegi vs. proprietario privilegiato del PAC).

### Note su OPSEC e rilevamento

- Le euristiche tradizionali degli hunter (TGS senza AS, durata di anni) si applicano ancora ai golden ticket, ma i diamond ticket emergono soprattutto quando **il contenuto del PAC o la mappatura dei gruppi sembrano impossibili**. Popola ogni campo del PAC (ore di accesso, percorsi del profilo utente, ID dei dispositivi) affinché i confronti automatizzati non segnalino subito la contraffazione.<sup>[[3]](#references)</sup>
- **Non aggiungere gruppi/RID in eccesso**. Se ti servono solo `512` (Domain Admins) e `519` (Enterprise Admins), fermati lì e assicurati che l'account di destinazione appartenga plausibilmente a quei gruppi anche in altre parti di AD. Un numero eccessivo di `ExtraSids` è un indizio rivelatore.
- Gli scambi in stile Sapphire lasciano tracce U2U: `ENC-TKT-IN-SKEY` + `additional-tickets`, oltre a un `sname` che punta a un utente (spesso il richiedente) nell'evento 4769, seguito da un accesso 4624 proveniente dal ticket contraffatto. Correlare questi campi invece di cercare solo lacune no-AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft ha iniziato a eliminare gradualmente l'**emissione di service ticket RC4** a causa di CVE-2026-20833; imporre etype solo AES sul KDC rafforza il dominio ed è in linea con gli strumenti diamond/sapphire (`/opsec` forza già AES). La presenza di RC4 nei PAC contraffatti risalterà sempre di più.<sup>[[6]](#references)</sup>
- Il progetto Splunk Security Content distribuisce telemetria attack-range per i diamond ticket e rilevamenti come *Windows Domain Admin Impersonation Indicator*, che correla sequenze insolite di Event ID 4768/4769/4624 e modifiche ai gruppi PAC. Riprodurre quel dataset (o generarne uno personalizzato con i comandi sopra) aiuta a convalidare la copertura SOC per T1558.001 e fornisce al contempo logiche di allerta concrete da eludere.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Pietre preziose: la nuova generazione di attacchi Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: adoriamo giocare con i ticket (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Ritagliare di nuovo il Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Dati di attacco e rilevamenti dei Diamond Ticket (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Il lato oscuro delle gemme: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Applicazione dell'uso di ticket di servizio RC4 per CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
