# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Come un golden ticket**, un diamond ticket è un TGT che può essere usato per **accedere a qualsiasi servizio come qualsiasi utente**. Un golden ticket viene forgiato completamente offline, cifrato con l'hash krbtgt del dominio e poi inserito in una sessione di accesso per essere usato. Poiché i controller di dominio non tengono traccia dei TGT che hanno legittimamente emesso, accettano senza problemi i TGT cifrati con il proprio hash krbtgt.<sup>[[1]](#references)</sup>

Esistono due tecniche comuni per rilevare l'uso dei golden ticket:

- Cercare TGS-REQ senza un AS-REQ corrispondente.
- Cercare TGT con valori sospetti, come la durata predefinita di 10 anni di Mimikatz.

Un **diamond ticket** viene creato **modificando i campi di un TGT legittimo emesso da un DC**. Per farlo, si **richiede** un **TGT**, lo si **decifra** con l'hash krbtgt del dominio, si **modificano** i campi desiderati del ticket e poi lo si **cifra nuovamente**. In questo modo si **superano i due limiti menzionati sopra** dei golden ticket perché:<sup>[[1]](#references)</sup>

- I TGS-REQ saranno preceduti da un AS-REQ.
- Il TGT è stato emesso da un DC, quindi contiene tutti i dettagli corretti previsti dalla policy Kerberos del dominio. Anche se è possibile falsificarli accuratamente in un golden ticket, è più complesso e si rischia maggiormente di commettere errori.

### Requisiti e flusso di lavoro

- **Materiale crittografico**: la chiave krbtgt AES256 (preferibile) o l'hash NTLM, necessari per decifrare e firmare nuovamente il TGT.
- **Blob TGT legittimo**: ottenuto con `/tgtdeleg`, `asktgt`, `s4u` o esportando i ticket dalla memoria.
- **Dati contestuali**: il RID dell'utente bersaglio, i RID/SID dei gruppi e, facoltativamente, gli attributi PAC ricavati da LDAP.
- **Chiavi del servizio** (solo se si intende creare nuovamente i ticket di servizio): la chiave AES dello SPN del servizio da impersonare.

1. Ottenere un TGT per qualsiasi utente sotto il proprio controllo tramite AS-REQ (Rubeus `/tgtdeleg` è comodo perché induce il client a eseguire lo scambio Kerberos GSS-API senza credenziali).
2. Decifrare il TGT restituito con la chiave krbtgt e modificare gli attributi PAC (utente, gruppi, informazioni di accesso, SID, attestazioni del dispositivo ecc.).
3. Cifrare e firmare nuovamente il ticket con la stessa chiave krbtgt e inserirlo nella sessione di accesso corrente (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Facoltativamente, ripetere la procedura su un ticket di servizio fornendo un blob TGT valido insieme alla chiave del servizio bersaglio, per operare in modo più furtivo in rete.

### Tecniche operative aggiornate di Rubeus (2024+)

Il lavoro recente di Huntress ha modernizzato l'azione `diamond` di Rubeus integrando i miglioramenti `/ldap` e `/opsec`, che prima erano disponibili solo per i golden/silver ticket. `/ldap` ora recupera il contesto PAC reale interrogando LDAP **e** montando SYSVOL per estrarre gli attributi di account/gruppo e le policy Kerberos/password (ad esempio, `GptTmpl.inf`), mentre `/opsec` fa corrispondere il flusso AS-REQ/AS-REP a quello di Windows eseguendo lo scambio di preautenticazione in due passaggi e imponendo solo AES e valori KDCOptions realistici. Ciò riduce notevolmente gli indicatori evidenti, come i campi PAC mancanti o durate non conformi alle policy.<sup>[[3]](#references)</sup>

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

- `/ldap` (con `/ldapuser` e `/ldappassword` opzionali) interroga AD e SYSVOL per replicare i dati delle policy PAC dell'utente target.
- `/opsec` forza un nuovo tentativo di AS-REQ simile a quello di Windows, azzerando i flag rumorosi e usando solo AES256.
- `/tgtdeleg` evita di accedere alla password in chiaro o alla chiave NTLM/AES della vittima, restituendo comunque un TGT decrittabile.

### Ritaglio dei service ticket

Lo stesso aggiornamento di Rubeus ha aggiunto la possibilità di applicare la tecnica diamond ai blob TGS. Fornendo a `diamond` un **TGT codificato in base64** (da `asktgt`, `/tgtdeleg` o un TGT precedentemente contraffatto), lo **SPN del servizio** e la **chiave AES del servizio**, puoi creare service ticket realistici senza contattare il KDC: in pratica, un silver ticket più furtivo.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Questo flusso di lavoro è ideale quando hai già il controllo di una chiave di service account (ad es., estratta con `lsadump::lsa /inject` o `secretsdump.py`) e vuoi creare un TGS una tantum che corrisponda perfettamente ai criteri AD, alle tempistiche e ai dati PAC, senza generare nuovo traffico AS/TGS.<sup>[[3]](#references)</sup>

### Scambi PAC in stile Sapphire (2025)

Una variante più recente, talvolta chiamata **sapphire ticket**, combina la base "real TGT" di Diamond con **S4U2self+U2U** per sottrarre un PAC privilegiato e inserirlo nel proprio TGT. Invece di inventare SID aggiuntivi, si richiede un ticket U2U S4U2self per un utente con privilegi elevati, dove `sname` punta al richiedente con privilegi bassi; il KRB_TGS_REQ include il TGT del richiedente in `additional-tickets` e imposta `ENC-TKT-IN-SKEY`, consentendo di decrittare il service ticket con la chiave di quell'utente. Si estrae quindi il PAC privilegiato e lo si inserisce nel proprio TGT legittimo prima di firmarlo nuovamente con la chiave krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket ora include il supporto Sapphire in `ticketer.py` tramite `-impersonate` + `-request` (scambio live con il KDC):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` accetta un nome utente o un SID; `-request` richiede credenziali utente valide e materiale della chiave krbtgt (AES/NTLM) per decrittografare/modificare i ticket.

Indicatori OPSEC chiave quando si usa questa variante:<sup>[[5]](#references)</sup>

- TGS-REQ includerà `ENC-TKT-IN-SKEY` e `additional-tickets` (il TGT della vittima), elementi rari nel traffico normale.
- `sname` spesso corrisponde all'utente richiedente (accesso self-service) e l'Event ID 4769 mostra il chiamante e il target come lo stesso SPN/utente.
- Aspettati voci 4768/4769 abbinate con lo stesso computer client ma CNAMES diversi (richiedente con pochi privilegi rispetto al proprietario del PAC con privilegi elevati).

### Note su OPSEC e rilevamento

- Le euristiche tradizionali degli hunter (TGS senza AS, durate di decenni) si applicano ancora ai golden ticket, ma i diamond ticket emergono soprattutto quando il **contenuto del PAC o la mappatura dei gruppi sembrano impossibili**. Compila ogni campo PAC (orari di accesso, percorsi del profilo utente, ID dispositivo) in modo che i confronti automatici non rilevino immediatamente la falsificazione.<sup>[[3]](#references)</sup>
- **Non assegnare gruppi/RID in eccesso**. Se ti servono solo `512` (Domain Admins) e `519` (Enterprise Admins), fermati lì e assicurati che l'account target appartenga plausibilmente a quei gruppi anche in altre parti di AD. Un numero eccessivo di `ExtraSids` è un indizio rivelatore.
- Gli scambi in stile Sapphire lasciano tracce U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` e un `sname` che punta a un utente (spesso il richiedente) nell'evento 4769, seguiti da un logon 4624 proveniente dal ticket contraffatto. Correlare questi campi invece di cercare solo lacune no-AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft ha iniziato a eliminare gradualmente l'emissione di ticket di servizio **RC4** a causa di CVE-2026-20833; imporre etype solo AES sul KDC rafforza il dominio e si allinea agli strumenti diamond/sapphire (/opsec impone già AES). L'uso di RC4 nei PAC contraffatti risulterà sempre più evidente.<sup>[[6]](#references)</sup>
- Il progetto Security Content di Splunk distribuisce telemetria attack-range per diamond ticket e rilevamenti come *Windows Domain Admin Impersonation Indicator*, che correlano sequenze insolite di Event ID 4768/4769/4624 e modifiche ai gruppi PAC. Riprodurre quel dataset (o generarne uno proprio con i comandi sopra) aiuta a convalidare la copertura SOC per T1558.001, fornendo al contempo logiche di alert concrete da eludere.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Pietre preziose: la nuova generazione di attacchi Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: adoriamo giocare con i ticket (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Riforgiare il Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Dati e rilevamenti dell'attacco Diamond Ticket (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Il lato oscuro dei gioielli: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Applicazione delle policy sui ticket di servizio RC4 per CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
