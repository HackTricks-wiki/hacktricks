# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket è un TGT che può essere usato per **accedere a qualsiasi servizio come qualsiasi utente**. Un golden ticket viene forgiato completamente offline, criptato con l'hash krbtgt di quel dominio, e poi inserito in una logon session per l'uso. Poiché i domain controller non tracciano i TGT che hanno emesso legittimamente, accetteranno volentieri TGT criptati con il proprio hash krbtgt.

Ci sono due tecniche comuni per rilevare l'uso dei golden ticket:

- Cerca TGS-REQ che non hanno una corrispondente AS-REQ.
- Cerca TGT che hanno valori anomali, come la durata predefinita di 10 anni di Mimikatz.

Un **diamond ticket** viene creato **modificando i campi di un TGT legittimo che è stato emesso da un DC**. Questo si ottiene **richiedendo** un **TGT**, **decifrando** il ticket con l'hash krbtgt del dominio, **modificando** i campi desiderati del ticket e poi **ricriptandolo**. Questo **supera i due limiti menzionati** di un golden ticket perché:

- I TGS-REQ avranno una AS-REQ precedente.
- Il TGT è stato emesso da un DC, il che significa che avrà tutti i dettagli corretti dalla Kerberos policy del dominio. Anche se questi possono essere forgiati con precisione in un golden ticket, è più complesso e soggetto a errori.

### Requisiti e workflow

- **Materiale crittografico**: la chiave krbtgt AES256 (preferita) o l'hash NTLM per decifrare e ri-firmare il TGT.
- **Blob TGT legittimo**: ottenuto con `/tgtdeleg`, `asktgt`, `s4u`, o esportando i ticket dalla memoria.
- **Dati di contesto**: il RID dell'utente target, RIDs/SIDs dei gruppi, e (opzionalmente) attributi PAC derivati da LDAP.
- **Service keys** (solo se prevedi di rigenerare service ticket): chiave AES dello SPN del servizio da impersonare.

1. Ottieni un TGT per qualsiasi utente controllato via AS-REQ (Rubeus `/tgtdeleg` è comodo perché costringe il client a eseguire lo scambio Kerberos GSS-API senza credenziali).
2. Decifra il TGT restituito con la chiave krbtgt, applica patch agli attributi PAC (utente, gruppi, info di accesso, SIDs, device claims, ecc.).
3. Ricripta/firmare il ticket con la stessa chiave krbtgt e iniettalo nella sessione di accesso corrente (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Opzionalmente, ripeti il processo su un service ticket fornendo un blob TGT valido più la chiave del servizio target per rimanere stealthy sulla rete.

### Tradecraft aggiornato di Rubeus (2024+)

Recenti lavori di Huntress hanno modernizzato l'azione `diamond` all'interno di Rubeus portando le migliorie `/ldap` e `/opsec` che precedentemente esistevano solo per i golden/silver tickets. `/ldap` ora auto-popola attributi PAC accurati direttamente da AD (profilo utente, orari di accesso, sidHistory, domain policies), mentre `/opsec` rende il flusso AS-REQ/AS-REP indistinguibile da un client Windows eseguendo la sequenza di pre-auth in due fasi e imponendo crypto solo AES. Questo riduce drasticamente indicatori ovvi come device ID vuoti o finestre di validità irrealistiche.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) interroga AD e SYSVOL per replicare i dati di policy PAC dell'utente target.
- `/opsec` forza un ritentativo AS-REQ in stile Windows, azzerando i flag rumorosi e attenendosi ad AES256.
- `/tgtdeleg` ti tiene lontano dalla password in cleartext o dalla chiave NTLM/AES della vittima, pur restituendo un TGT decifrabile.

### Service-ticket recutting

Lo stesso refresh di Rubeus ha aggiunto la possibilità di applicare la diamond technique ai blob TGS. Fornendo a `diamond` un **base64-encoded TGT** (da `asktgt`, `/tgtdeleg`, o un TGT precedentemente forgiato), il **service SPN**, e la **service AES key**, puoi coniare service ticket realistici senza toccare il KDC — effettivamente un silver ticket più furtivo.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
This workflow è ideale quando controlli già una service account key (es., ottenuta con `lsadump::lsa /inject` o `secretsdump.py`) e vuoi creare un TGS one-off che corrisponda perfettamente alla policy di AD, alle tempistiche e ai dati PAC senza emettere nuovo traffico AS/TGS.

### Sapphire-style PAC swaps (2025)

A newer twist sometimes called a **sapphire ticket** combina la base "real TGT" di Diamond con **S4U2self+U2U** per rubare un PAC privilegiato e inserirlo nel tuo TGT. Invece di inventare SIDs aggiuntivi, richiedi un ticket U2U S4U2self per un utente ad alto privilegio, estrai quel PAC e lo innesti nel tuo TGT legittimo prima di rifirmarlo con la krbtgt key. Perché U2U imposta `ENC-TKT-IN-SKEY`, il flusso risultante sul wire sembra uno scambio utente-a-utente legittimo.

Minimal Linux-side reproduction with Impacket's patched `ticketer.py` (adds sapphire support):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Key OPSEC tells when using this variant:

- TGS-REQ porterà `ENC-TKT-IN-SKEY` e `additional-tickets` (il TGT della vittima) — raro nel traffico normale.
- `sname` spesso corrisponde all'utente richiedente (accesso self-service) e l'Event ID 4769 mostra chiamante e target come lo stesso SPN/utente.
- Aspettati voci abbinate 4768/4769 con lo stesso computer client ma CNAMES diversi (richiedente low-priv vs. proprietario PAC privilegiato).

### OPSEC & detection notes

- Le tradizionali euristiche dei hunter (TGS without AS, decade-long lifetimes) si applicano ancora ai golden tickets, ma i diamond tickets emergono principalmente quando il **contenuto del PAC o il mapping dei gruppi sembra impossibile**. Compila ogni campo del PAC (logon hours, user profile paths, device IDs) in modo che i confronti automatici non segnalino immediatamente la falsificazione.
- **Non sovra-iscrivere gruppi/RIDs**. Se hai bisogno solo di `512` (Domain Admins) e `519` (Enterprise Admins), fermati lì e assicurati che l'account target appartenga plausibilmente a quei gruppi altrove in AD. Eccessivi `ExtraSids` sono un indizio evidente.
- Sapphire-style swaps lasciano impronte U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` in 4769, e un successivo logon 4624 proveniente dal ticket contraffatto. Correlate quei campi invece di cercare solo gap no-AS-REQ.
- Microsoft ha iniziato a eliminare gradualmente l'emissione di **RC4 service ticket** a causa di CVE-2026-20833; imporre etypes AES-only sul KDC sia indurisce il dominio sia si allinea con gli strumenti diamond/sapphire (/opsec già forza AES). Mischiare RC4 in PAC falsificati risalterà sempre di più.
- Splunk's Security Content project distribuisce telemetry di attack-range per diamond tickets oltre a rilevazioni come *Windows Domain Admin Impersonation Indicator*, che correla sequenze insolite di Event ID 4768/4769/4624 e cambi nei gruppi PAC. Riprodurre quel dataset (o generarne uno proprio con i comandi sopra) aiuta a convalidare la copertura SOC per T1558.001 fornendoti logiche di allerta concrete da eludere.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
