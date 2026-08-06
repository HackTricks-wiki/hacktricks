# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Come un golden ticket**, un diamond ticket è un TGT che può essere utilizzato per **accedere a qualsiasi servizio come qualsiasi utente**. Un golden ticket viene forgiato completamente offline, crittografato con l'hash krbtgt di quel dominio e quindi inserito in una sessione di logon per essere utilizzato. Poiché i domain controller non tengono traccia dei TGT che hanno emesso legittimamente, accetteranno senza problemi i TGT crittografati con il proprio hash krbtgt.<sup>[[1]](#references)</sup>

Esistono due tecniche comuni per rilevare l'utilizzo dei golden ticket:

- Cercare TGS-REQ che non hanno un AS-REQ corrispondente.
- Cercare TGT che presentano valori anomali, come la durata predefinita di 10 anni di Mimikatz.

Un **diamond ticket** viene creato **modificando i campi di un TGT legittimo emesso da un DC**. Questo si ottiene **richiedendo** un **TGT**, **decrittografandolo** con l'hash krbtgt del dominio, **modificando** i campi desiderati del ticket e quindi **ricrittografandolo**. Questo **supera le due limitazioni precedentemente descritte** di un golden ticket perché:<sup>[[1]](#references)</sup>

- I TGS-REQ avranno un AS-REQ precedente.
- Il TGT è stato emesso da un DC, quindi conterrà tutti i dettagli corretti secondo la policy Kerberos del dominio. Sebbene questi possano essere forgiati accuratamente in un golden ticket, il processo è più complesso e soggetto a errori.

### Requisiti e workflow

- **Materiale crittografico**: la chiave AES256 di krbtgt (preferibile) o l'hash NTLM, necessari per decrittografare e firmare nuovamente il TGT.
- **Blob TGT legittimo**: ottenuto con `/tgtdeleg`, `asktgt`, `s4u` oppure esportando i ticket dalla memoria.
- **Dati di contesto**: il RID dell'utente target, i RID/SID dei gruppi e, facoltativamente, gli attributi PAC derivati da LDAP.
- **Chiavi dei servizi** (solo se prevedi di ricreare service ticket): la chiave AES dello SPN del servizio da impersonare.

1. Ottieni un TGT per qualsiasi utente controllato tramite AS-REQ (`/tgtdeleg` di Rubeus è comodo perché costringe il client a eseguire il Kerberos GSS-API dance senza credenziali).
2. Decrittografa il TGT restituito con la chiave krbtgt e modifica gli attributi PAC (utente, gruppi, informazioni di logon, SID, device claims, ecc.).
3. Ricrittografa/firma il ticket con la stessa chiave krbtgt e iniettalo nella sessione di logon corrente (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Facoltativamente, ripeti il processo su un service ticket fornendo un blob TGT valido insieme alla chiave del servizio target, per rimanere stealthy sulla rete.

### Tradecraft Rubeus aggiornato (2024+)

L'attività recente di Huntress ha modernizzato l'azione `diamond` all'interno di Rubeus trasferendo i miglioramenti `/ldap` e `/opsec`, che in precedenza esistevano solo per i golden/silver ticket. `/ldap` ora recupera il contesto PAC reale interrogando LDAP e montando SYSVOL per estrarre gli attributi degli account/gruppi oltre alla policy Kerberos/password (ad esempio, `GptTmpl.inf`), mentre `/opsec` fa corrispondere il flusso AS-REQ/AS-REP a quello di Windows eseguendo lo scambio di preautenticazione in due passaggi e imponendo AES-only + KDCOptions realistici. Questo riduce drasticamente gli indicatori evidenti, come campi PAC mancanti o durate non coerenti con la policy.<sup>[[3]](#references)</sup>
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
- `/ldap` (con `/ldapuser` e `/ldappassword` opzionali) interroga AD e SYSVOL per replicare i dati della policy PAC dell'utente target.
- `/opsec` forza un retry AS-REQ simile a quello di Windows, azzerando i flag rumorosi e attenendosi ad AES256.
- `/tgtdeleg` evita di accedere alla password in chiaro o alla chiave NTLM/AES della vittima, restituendo comunque un TGT decrittografabile.

### Ritaglio dei service ticket

Lo stesso aggiornamento di Rubeus ha aggiunto la possibilità di applicare la diamond technique ai blob TGS. Passando a `diamond` un **TGT codificato in base64** (da `asktgt`, `/tgtdeleg` o un TGT precedentemente forgiato), lo **SPN del servizio** e la **chiave AES del servizio**, è possibile creare service ticket realistici senza interagire con il KDC, ottenendo di fatto un silver ticket più furtivo.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Questo workflow è ideale quando hai già il controllo di una service account key (ad esempio, ottenuta con `lsadump::lsa /inject` o `secretsdump.py`) e vuoi creare un TGS una tantum che corrisponda perfettamente alle policy di AD, alle tempistiche e ai dati PAC, senza generare nuovo traffico AS/TGS.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Una variante più recente, talvolta chiamata **sapphire ticket**, combina la base del "real TGT" di Diamond con **S4U2self+U2U** per sottrarre un PAC privilegiato e inserirlo nel proprio TGT. Invece di inventare SID aggiuntivi, richiedi un ticket U2U S4U2self per un utente con privilegi elevati, in cui `sname` punta al requester con privilegi inferiori; il KRB_TGS_REQ include il TGT del requester in `additional-tickets` e imposta `ENC-TKT-IN-SKEY`, consentendo di decrittografare il service ticket con la chiave di quell'utente. A questo punto estrai il PAC privilegiato e lo inserisci nel tuo TGT legittimo prima di firmarlo nuovamente con la chiave di krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket ora include il supporto sapphire tramite `-impersonate` + `-request` (scambio live con il KDC):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` accetta un nome utente o un SID; `-request` richiede credenziali valide di un utente, oltre al materiale della chiave di krbtgt (AES/NTLM) per decrittografare/applicare patch ai ticket.

Principali indicatori OPSEC quando si usa questa variante:<sup>[[5]](#references)</sup>

- TGS-REQ conterrà `ENC-TKT-IN-SKEY` e `additional-tickets` (il TGT della vittima), una combinazione rara nel traffico normale.
- `sname` spesso è uguale all'utente richiedente (accesso self-service) ed Event ID 4769 mostra il chiamante e la destinazione come lo stesso SPN/utente.
- Sono previste voci 4768/4769 abbinate con lo stesso computer client ma CNAME diversi (richiedente con privilegi ridotti rispetto al proprietario privilegiato del PAC).

### Note su OPSEC e rilevamento

- Le euristiche tradizionali degli hunter (TGS senza AS, durate decennali) si applicano ancora ai golden ticket, ma i diamond ticket emergono soprattutto quando il **contenuto del PAC o la mappatura dei gruppi appare impossibile**. Compila ogni campo del PAC (ore di accesso, percorsi dei profili utente, ID dei dispositivi) affinché i confronti automatizzati non segnalino immediatamente la falsificazione.<sup>[[3]](#references)</sup>
- **Non sovraccaricare i gruppi/RID**. Se ti servono solo `512` (Domain Admins) e `519` (Enterprise Admins), fermati lì e assicurati che l'account di destinazione appartenga plausibilmente a quei gruppi anche nel resto di AD. Un numero eccessivo di `ExtraSids` è un chiaro indicatore.
- Gli swap in stile Sapphire lasciano fingerprint U2U: `ENC-TKT-IN-SKEY` + `additional-tickets`, oltre a un `sname` che punta a un utente (spesso il richiedente) nell'evento 4769, seguito da un logon 4624 originato dal ticket falsificato. Correla questi campi invece di cercare soltanto le anomalie senza AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft ha iniziato a eliminare gradualmente l'**emissione di service ticket RC4** a causa di CVE-2026-20833; imporre etype esclusivamente AES sul KDC rafforza il dominio e si allinea agli strumenti per diamond/sapphire (/opsec forza già AES). L'inserimento di RC4 nei PAC falsificati risulterà sempre più evidente.<sup>[[6]](#references)</sup>
- Il progetto Security Content di Splunk distribuisce telemetria di attack range per i diamond ticket, oltre a rilevamenti come *Windows Domain Admin Impersonation Indicator*, che correla sequenze insolite di Event ID 4768/4769/4624 e modifiche ai gruppi del PAC. Riprodurre quel dataset (o generarne uno proprio con i comandi sopra) aiuta a convalidare la copertura del SOC per T1558.001, fornendo al contempo una logica concreta degli alert da eludere.<sup>[[4]](#references)</sup>

## Riferimenti

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
