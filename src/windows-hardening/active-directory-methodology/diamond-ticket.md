# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Come un golden ticket**, un diamond ticket è un TGT che può essere usato per **accedere a qualsiasi servizio come qualsiasi utente**. Un golden ticket viene forgiato completamente offline, criptato con l'hash krbtgt di quel dominio, e poi inserito in una sessione di logon per l'uso. Poiché i domain controllers non tracciano i TGT che essi hanno emesso legittimamente, accetteranno volentieri TGT criptati con il proprio hash krbtgt.

Ci sono due tecniche comuni per rilevare l'uso di golden tickets:

- Cercare TGS-REQ che non hanno una corrispondente AS-REQ.
- Cercare TGT che hanno valori anomali, come la durata predefinita di 10 anni di Mimikatz.

Un **diamond ticket** viene creato **modificando i campi di un TGT legittimo che è stato emesso da un DC**. Questo si ottiene richiedendo un **TGT**, **decriptandolo** con l'hash krbtgt del dominio, **modificando** i campi desiderati del ticket e quindi **ri-criptandolo**. Questo **supera i due limiti sopra menzionati** di un golden ticket perché:

- Le TGS-REQ avranno una AS-REQ precedente.
- Il TGT è stato emesso da un DC, il che significa che avrà tutti i dettagli corretti secondo la policy Kerberos del dominio. Anche se questi possono essere forgiati correttamente in un golden ticket, è più complesso e soggetto a errori.

### Requirements & workflow

- **Materiale crittografico**: la chiave krbtgt AES256 (preferita) o l'hash NTLM per decriptare e ri-firmare il TGT.
- **Legitimate TGT blob**: ottenuto con `/tgtdeleg`, `asktgt`, `s4u`, o esportando i ticket dalla memoria.
- **Context data**: il RID dell'utente target, i RIDs/SIDs dei gruppi e (opzionalmente) attributi PAC derivati da LDAP.
- **Service keys** (solo se si intende rigenerare service tickets): chiave AES dello SPN di servizio da impersonare.

1. Ottenere un TGT per un qualsiasi utente controllato tramite AS-REQ (Rubeus `/tgtdeleg` è comodo perché costringe il client a eseguire il Kerberos GSS-API dance senza credenziali).
2. Decriptare il TGT restituito con la chiave krbtgt, patchare gli attributi PAC (utente, gruppi, informazioni di logon, SIDs, claim del dispositivo, ecc.).
3. Ri-criptare/firmare il ticket con la stessa chiave krbtgt e iniettarlo nella sessione di logon corrente (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opzionalmente, ripetere il processo su un service ticket fornendo un TGT blob valido più la chiave del servizio target per rimanere stealthy sulla rete.

### Aggiornamenti Rubeus tradecraft (2024+)

Recenti lavori di Huntress hanno modernizzato l'azione `diamond` all'interno di Rubeus portando le migliorie `/ldap` e `/opsec` che prima esistevano solo per golden/silver tickets. `/ldap` ora estrae il contesto PAC reale interrogando LDAP e montando SYSVOL per ottenere attributi account/gruppo oltre alla policy Kerberos/password (es., `GptTmpl.inf`), mentre `/opsec` fa corrispondere il flusso AS-REQ/AS-REP a Windows eseguendo lo scambio di preauth in due passaggi e imponendo solo AES + KDCOptions realistici. Questo riduce drasticamente indicatori evidenti come campi PAC mancanti o lifetime non coerenti con la policy.
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
- `/ldap` (con opzionale `/ldapuser` & `/ldappassword`) interroga AD e SYSVOL per replicare i dati della policy PAC dell'utente target.
- `/opsec` forza un retry AS-REQ in stile Windows, azzerando flag rumorosi e attenendosi a AES256.
- `/tgtdeleg` evita di toccare la password in cleartext o la chiave NTLM/AES della vittima pur restituendo un TGT decifrabile.

### Service-ticket recutting

La stessa refresh di Rubeus ha aggiunto la capacità di applicare la tecnica diamond ai blob TGS. Fornendo a `diamond` un **base64-encoded TGT** (da `asktgt`, `/tgtdeleg`, o un TGT precedentemente forged), lo **service SPN**, e la **service AES key**, puoi mint realistic service tickets senza toccare il KDC—di fatto un stealthier silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Questo workflow è ideale quando controlli già una service account key (ad es., dumpata con `lsadump::lsa /inject` o `secretsdump.py`) e vuoi generare un TGS ad hoc che corrisponda perfettamente alla policy AD, alle timeline e ai dati PAC senza inviare nuovo traffico AS/TGS.

### Sapphire-style PAC swaps (2025)

Una variante più recente, talvolta chiamata **sapphire ticket**, combina la base "real TGT" di Diamond con **S4U2self+U2U** per rubare un PAC privilegiato e inserirlo nel proprio TGT. Invece di inventare SIDs aggiuntivi, richiedi un ticket U2U S4U2self per un utente ad alto privilegio dove il `sname` punta al richiedente a basso privilegio; la KRB_TGS_REQ trasporta il TGT del richiedente in `additional-tickets` e imposta `ENC-TKT-IN-SKEY`, permettendo al service ticket di essere decriptato con la chiave di quell'utente. Estrai quindi il PAC privilegiato e lo innesti nel tuo TGT legittimo prima di rifirmare con la chiave krbtgt.

Impacket's `ticketer.py` ora include il supporto sapphire tramite `-impersonate` + `-request` (scambio live con KDC):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` accetta un username o SID; `-request` richiede credenziali utente attive più il materiale chiave krbtgt (AES/NTLM) per decriptare/patchare i ticket.

Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — raro nel traffico normale.
- `sname` spesso è uguale all'utente richiedente (accesso self-service) e Event ID 4769 mostra chiamante e destinazione come lo stesso SPN/utente.
- Aspettati voci abbinate 4768/4769 con lo stesso computer client ma CNAMES diversi (richiedente a basso privilegio vs. proprietario PAC privilegiato).

### OPSEC & detection notes

- Le tradizionali euristiche dei hunter (TGS without AS, decade-long lifetimes) si applicano ancora ai golden tickets, ma i diamond tickets emergono principalmente quando il **PAC content or group mapping looks impossible**. Compila ogni campo del PAC (logon hours, user profile paths, device IDs) in modo che le comparazioni automatiche non segnalino immediatamente la falsificazione.
- **Non sovraccaricare i gruppi/RIDs**. Se ti servono solo `512` (Domain Admins) e `519` (Enterprise Admins), fermati lì e assicurati che l'account target appartenga plausibilmente a quei gruppi anche altrove in AD. Eccessivi `ExtraSids` sono un indizio evidente.
- Sapphire-style swaps lasciano impronte U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` più un `sname` che punta a un utente (spesso il richiedente) in 4769, e un successivo logon 4624 originato dal ticket falsificato. Correla quei campi invece di cercare solo gap no-AS-REQ.
- Microsoft ha iniziato a eliminare progressivamente **RC4 service ticket issuance** a causa di CVE-2026-20833; forzare etypes AES-only sul KDC rende il dominio più sicuro e si allinea con il tooling diamond/sapphire (/opsec already forces AES). Mescolare RC4 nei PAC falsificati risulterà sempre più evidente.
- Il progetto Security Content di Splunk distribuisce telemetria di attack-range per diamond tickets oltre a rilevazioni come *Windows Domain Admin Impersonation Indicator*, che correla sequenze anomale Event ID 4768/4769/4624 e cambi di gruppi nel PAC. Riprodurre quel dataset (o generarne uno proprio con i comandi sopra) aiuta a validare la copertura SOC per T1558.001 fornendo al contempo logiche di allerta concrete da eludere.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
