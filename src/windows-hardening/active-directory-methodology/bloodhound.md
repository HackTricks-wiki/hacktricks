# BloodHound और अन्य Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: यह पेज Active Directory relationships को **enumerate** और **visualise** करने वाली कुछ सबसे उपयोगी utilities को एक साथ प्रस्तुत करता है। Stealthy **Active Directory Web Services (ADWS)** channel के माध्यम से collection के लिए ऊपर दिए गए reference को देखें।

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) एक advanced **AD viewer & editor** है, जो निम्नलिखित कार्य करने देता है:

* Directory tree को GUI के माध्यम से browse करना
* Object attributes और security descriptors को edit करना
* Offline analysis के लिए snapshot बनाना और compare करना

### त्वरित उपयोग

1. Tool शुरू करें और किसी भी domain credentials के साथ `dc01.corp.local` से connect करें।
2. `File ➜ Create Snapshot` के माध्यम से एक offline snapshot बनाएं।
3. Permission drifts का पता लगाने के लिए `File ➜ Compare` के साथ दो snapshots को compare करें।

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) किसी domain से बड़ी मात्रा में artefacts (ACLs, GPOs, trusts, CA templates …) extract करता है और एक **Excel report** तैयार करता है।
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (ग्राफ़ विज़ुअलाइज़ेशन)

[BloodHound](https://github.com/SpecterOps/BloodHound) graph theory का उपयोग करके on-prem AD, Entra ID और OpenGraph के माध्यम से ingest किए गए किसी भी अतिरिक्त attack-surface data के अंदर छिपे privilege relationships को उजागर करता है।<sup>[[1]](#references)</sup>

### तैनाती (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – native या PowerShell variant
* `RustHound-CE` – Linux, macOS, और Windows के लिए cross-platform CE collector
* `NetExec --bloodhound` – Linux से quick LDAP-driven collection
* `AzureHound` – Entra ID enumeration
* **SoaPy + BOFHound** – ADWS collection (ऊपर दिए गए link को देखें)

> BloodHound CE `v8+` में OpenGraph आने के बाद collector output format बदल गया। Legacy BloodHound या पुराने CE installs से upgrade करने के बाद, data import करने से पहले current collectors के साथ discovery फिर से चलाएँ।<sup>[[1]](#references)</sup>

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
The collectors JSON generate करते हैं, जिसे BloodHound GUI के माध्यम से ingest किया जाता है।

#### SharpHound from a non-domain-joined Windows host

यदि आपका operator VM target domain से joined नहीं है, तो DNS को किसी DC पर point करें, एक **network-only** shell शुरू करें, verify करें कि आप किसी DC पर `SYSVOL`/`NETLOGON` देख सकते हैं, और फिर remote domain के विरुद्ध collect करें:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
यह disposable jump boxes या ऐसी operator workstations के लिए उपयोगी है जिन्हें domain-joined नहीं होना चाहिए।

#### Linux/macOS से cross-platform collection
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` एक अच्छा default है जब आपको non-Windows host से CE-compatible output चाहिए।<sup>[[2]](#references)</sup> `NetExec` तब सुविधाजनक है जब आप इसे पहले से LDAP validation या spraying के लिए उपयोग कर रहे हों और quick graph import चाहते हों। Non-AD datasets के लिए, BloodHound OpenGraph को [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) जैसे collectors के साथ extend किया जा सकता है।<sup>[[1]](#references)</sup>

### ADPathFinder (OpenGraph path prioritisation)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) BloodHound CE/OpenGraph के ऊपर काम करता है, जब graph इतना बड़ा हो कि manually pivot करना कठिन हो। यह केवल यह पूछने के बजाय कि क्या एक principal एक target तक पहुंच सकता है, कई low-privileged users और computers से high-value objects तक shortest paths calculate करता है, समान edges का पुनः उपयोग करने वाले paths को group करता है, और उस shared choke point को सामने लाता है जिसे सबसे पहले remediate किया जाना चाहिए।<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
`MSSQLHound` और `ConfigManBearPig` data import करने के बाद, एक finding [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md), और [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) को cross कर सकती है, बजाय इसके कि उन्हें अलग-अलग leads के रूप में छोड़ा जाए।<sup>[[4]](#references)</sup> साझा path का उदाहरण:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- हर edge पर **effective security context** को track करें। जैसे ही कोई transition privileged domain identity के रूप में execute होता है, path domain-critical बन जाता है, भले ही वह किसी normal user से शुरू हुआ हो।
- Grouped findings **choke-point remediation** के लिए आदर्श हैं: एक SQL impersonation permission, linked-server trust, certificate-template abuse path या SCCM assignment हटाने से एक साथ कई shortest paths समाप्त हो सकते हैं।
- **graph context** के आधार पर "medium" findings को फिर से प्राथमिकता दें। SMB signing disabled, WebClient exposure, delegation mistakes या NTLM-relayable SQL servers को उच्च प्राथमिकता दें, जब compromised node के पास Domain Admins, Domain Controllers, CAs या SCCM site servers तक onward paths हों।
- यदि आपके पास `NTDS.dit` output और hashcat potfile भी है, तो `--pwd` cracked passwords को BloodHound properties के साथ correlate करता है। इससे आप जल्दी अलग कर सकते हैं कि कौन-से credentials सामान्य password reuse से जुड़े हैं और कौन-से privileged, Kerberoastable, AS-REP roastable या path-relevant accounts से cracked हुए हैं।

### Privilege और logon-right collection

Windows **token privileges** (जैसे `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) DACL checks को bypass कर सकते हैं, इसलिए उन्हें पूरे domain में map करने से वे local LPE edges दिखाई देते हैं जिन्हें ACL-only graphs miss कर देते हैं। **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` और उनके `SeDeny*` counterparts) token बनने से पहले LSA द्वारा enforce किए जाते हैं, और deny rules को precedence मिलती है। इसलिए वे lateral movement (RDP/SMB/scheduled task/service logon) को महत्वपूर्ण रूप से नियंत्रित करते हैं।<sup>[[3]](#references)</sup>

**जब संभव हो, collectors को elevated चलाएँ**: UAC interactive admins के लिए `NtFilterToken` के माध्यम से filtered token बनाता है, जिससे sensitive privileges हटा दिए जाते हैं और admin SIDs को deny-only के रूप में mark किया जाता है। यदि आप non-elevated shell से privileges enumerate करते हैं, तो high-value privileges दिखाई नहीं देंगे और BloodHound उन edges को ingest नहीं कर पाएगा।<sup>[[3]](#references)</sup>

अब दो complementary SharpHound collection strategies उपलब्ध हैं:<sup>[[3]](#references)</sup>

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. LDAP (`(objectCategory=groupPolicyContainer)`) के माध्यम से GPOs enumerate करें और प्रत्येक `gPCFileSysPath` पढ़ें।
2. SYSVOL से `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` fetch करें और `[Privilege Rights]` section को parse करें, जो privilege/logon-right names को SIDs से map करता है।
3. OUs/sites/domains पर `gPLink` के माध्यम से GPO links resolve करें, linked containers में computers की सूची बनाएँ और उन rights को संबंधित machines से attribute करें।
4. लाभ: यह normal user के साथ काम करता है और quiet रहता है; कमी: केवल GPO के माध्यम से push किए गए rights दिखाई देते हैं (local tweaks miss हो जाते हैं)।

- **LSA RPC enumeration (noisy, accurate):**
- target पर local admin वाले context से Local Security Policy खोलें और प्रत्येक privilege/logon right के लिए `LsaEnumerateAccountsWithUserRight` call करें, ताकि RPC के माध्यम से assigned principals enumerate किए जा सकें।
- लाभ: यह locally या GPO के बाहर set किए गए rights भी capture करता है; कमी: noisy network traffic और प्रत्येक host पर admin requirement।

**इन edges से सामने आने वाला example abuse path:** `CanRDP` ➜ वह host जहाँ आपके user के पास `SeBackupPrivilege` भी है ➜ filtered tokens से बचने के लिए elevated shell शुरू करें ➜ restrictive DACLs के बावजूद `SAM` और `SYSTEM` hives पढ़ने के लिए backup semantics का उपयोग करें ➜ उन्हें exfiltrate करें और local Administrator NT hash recover करने के लिए `secretsdump.py` offline चलाएँ, फिर lateral movement/privilege escalation करें।<sup>[[3]](#references)</sup>

### BloodHound के साथ Kerberoasting को प्राथमिकता देना

Roasting को targeted रखने के लिए graph context का उपयोग करें:

1. ADWS-compatible collector के साथ एक बार collect करें और offline काम करें:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP import करें, compromised principal को owned mark करें और admin/infra rights वाले SPN accounts सामने लाने के लिए built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) चलाएँ।
3. blast radius के आधार पर SPNs को प्राथमिकता दें; cracking से पहले `pwdLastSet`, `lastLogon` और allowed encryption types की समीक्षा करें।
4. केवल selected tickets request करें, उन्हें offline crack करें, फिर नए access के साथ BloodHound में दोबारा query करें:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) **Group Policy Objects** को enumerate करता है और misconfigurations को highlight करता है।
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory की **health-check** करता है और risk scoring के साथ एक HTML report generate करता है।
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## संदर्भ

- [1] [BloodHound Community Edition v8 ने OpenGraph के साथ लॉन्च किया: Active Directory और Entra ID से आगे Identity Attack Paths](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [ACLs से आगे: BloodHound के साथ Windows Privilege Escalation Paths की Mapping](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: BloodHound CE में OpenGraph Attack Path Mapping](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
