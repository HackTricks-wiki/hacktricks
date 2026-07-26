# BloodHound और अन्य Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: यह page Active Directory relationships को **enumerate** और **visualise** करने वाली कुछ सबसे उपयोगी utilities को एक साथ प्रस्तुत करता है। Stealthy **Active Directory Web Services (ADWS)** channel पर collection के लिए ऊपर दिए गए reference को देखें।

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) एक advanced **AD viewer & editor** है, जो निम्नलिखित की अनुमति देता है:

* directory tree को GUI के माध्यम से browse करना
* object attributes और security descriptors को edit करना
* offline analysis के लिए snapshot बनाना / compare करना

### Quick usage

1. Tool शुरू करें और किसी भी domain credentials से `dc01.corp.local` से connect करें।
2. `File ➜ Create Snapshot` के माध्यम से एक offline snapshot बनाएं।
3. Permission drifts का पता लगाने के लिए `File ➜ Compare` से दो snapshots को compare करें।

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) domain से बड़ी संख्या में artefacts (ACLs, GPOs, trusts, CA templates …) extract करता है और एक **Excel report** तैयार करता है।
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (ग्राफ़ विज़ुअलाइज़ेशन)

[BloodHound](https://github.com/SpecterOps/BloodHound) ग्राफ़ सिद्धांत का उपयोग करके on-prem AD, Entra ID और OpenGraph के ज़रिए ingest किए गए किसी भी अतिरिक्त attack-surface data के अंदर छिपे privilege relationships को उजागर करता है।

### तैनाती (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – native या PowerShell variant
* `RustHound-CE` – Linux, macOS और Windows के लिए cross-platform CE collector
* `NetExec --bloodhound` – Linux से quick LDAP-driven collection
* `AzureHound` – Entra ID enumeration
* **SoaPy + BOFHound** – ADWS collection (ऊपर दिए गए link को देखें)

> OpenGraph के आने पर BloodHound CE `v8+` ने collector output format बदल दिया। Legacy BloodHound या पुराने CE installs से upgrade करने के बाद, data import करने से पहले current collectors के साथ discovery दोबारा चलाएँ।

#### सामान्य SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Collectors JSON generate करते हैं, जिसे BloodHound GUI के माध्यम से ingest किया जाता है।

#### non-domain-joined Windows host से SharpHound

यदि आपका operator VM target domain से joined नहीं है, तो DNS को किसी DC की ओर point करें, एक **network-only** shell शुरू करें, सत्यापित करें कि आप किसी DC पर `SYSVOL`/`NETLOGON` देख सकते हैं, और फिर remote domain के विरुद्ध collect करें:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
यह disposable jump boxes या operator workstations के लिए उपयोगी है, जिन्हें domain-joined नहीं होना चाहिए।

#### Linux/macOS से Cross-platform collection
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` एक non-Windows host से CE-compatible output चाहिए होने पर अच्छा default है। जब आप LDAP validation या spraying के लिए पहले से `NetExec` इस्तेमाल कर रहे हों और quick graph import चाहते हों, तब `NetExec` सुविधाजनक है। Non-AD datasets के लिए, BloodHound OpenGraph को [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) जैसे collectors के साथ extend किया जा सकता है।

### ADPathFinder (OpenGraph path prioritisation)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) तब BloodHound CE/OpenGraph के ऊपर काम करता है, जब graph इतना बड़ा हो कि manually pivot करना कठिन हो। यह केवल यह पूछने के बजाय कि कोई एक principal किसी एक target तक पहुंच सकता है या नहीं, कई low-privileged users और computers से high-value objects तक shortest paths की गणना करता है, समान edges का पुनः उपयोग करने वाले paths को group करता है, और उस shared choke point को सामने लाता है जिसका remediation सबसे पहले किया जाना चाहिए।
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
`MSSQLHound` और `ConfigManBearPig` का data import करने पर, एक finding [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) और [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) को अलग-अलग leads के रूप में छोड़ने के बजाय आपस में जोड़ सकता है। साझा path का उदाहरण:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- हर edge पर **effective security context** को ट्रैक करें। जैसे ही कोई transition privileged domain identity के रूप में execute होता है, path domain-critical बन जाता है, भले ही इसकी शुरुआत किसी normal user से हुई हो।
- Grouped findings **choke-point remediation** के लिए आदर्श हैं: एक SQL impersonation permission, linked-server trust, certificate-template abuse path या SCCM assignment हटाने से एक साथ कई shortest paths समाप्त हो सकते हैं।
- **graph context** के आधार पर "medium" findings को फिर से प्राथमिकता दें। SMB signing disabled, WebClient exposure, delegation mistakes या NTLM-relayable SQL servers को अधिक priority दें, जब compromised node से Domain Admins, Domain Controllers, CAs या SCCM site servers तक onward paths मौजूद हों।
- यदि आपके पास `NTDS.dit` output और hashcat potfile भी है, तो `--pwd` cracked passwords को BloodHound properties के साथ correlate करता है। इससे आप जल्दी अलग कर सकते हैं कि कौन-से credentials सामान्य password reuse से मिले हैं और कौन-से privileged, Kerberoastable, AS-REP roastable या path-relevant accounts के cracked creds हैं।

### Privilege & logon-right collection

Windows **token privileges** (जैसे, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) DACL checks को bypass कर सकते हैं, इसलिए इन्हें पूरे domain में map करने से local LPE edges सामने आते हैं, जिन्हें केवल ACL-based graphs नहीं दिखा पाते। **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` और इनके `SeDeny*` counterparts) token बनने से पहले LSA द्वारा enforce किए जाते हैं, और deny rules को precedence मिलता है। इसलिए ये lateral movement (RDP/SMB/scheduled task/service logon) को महत्वपूर्ण रूप से नियंत्रित करते हैं।

**जब संभव हो, collectors को elevated context में run करें**: UAC interactive admins के लिए (`NtFilterToken` के माध्यम से) filtered token बनाता है, जिसमें sensitive privileges हटा दिए जाते हैं और admin SIDs को deny-only के रूप में mark किया जाता है। यदि आप non-elevated shell से privileges enumerate करते हैं, तो high-value privileges दिखाई नहीं देंगे और BloodHound उन edges को ingest नहीं करेगा।

अब SharpHound collection की दो complementary strategies उपलब्ध हैं:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. LDAP (`(objectCategory=groupPolicyContainer)`) के माध्यम से GPOs enumerate करें और प्रत्येक `gPCFileSysPath` पढ़ें।
2. SYSVOL से `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` fetch करें और `[Privilege Rights]` section को parse करें, जो privilege/logon-right names को SIDs से map करता है।
3. OUs/sites/domains पर मौजूद `gPLink` के माध्यम से GPO links resolve करें, linked containers में computers की सूची बनाएं और उन machines को rights assign करें।
4. लाभ: यह normal user के साथ काम करता है और quiet रहता है; नुकसान: केवल GPO के माध्यम से pushed rights दिखाई देते हैं (local tweaks छूट जाते हैं)।

- **LSA RPC enumeration (noisy, accurate):**
- Target पर local admin वाले context से Local Security Policy खोलें और प्रत्येक privilege/logon right के लिए `LsaEnumerateAccountsWithUserRight` call करें, ताकि RPC के माध्यम से assigned principals enumerate किए जा सकें।
- लाभ: यह locally या GPO के बाहर set किए गए rights को भी capture करता है; नुकसान: noisy network traffic और प्रत्येक host पर admin requirement।

**इन edges से सामने आने वाला abuse path का उदाहरण:** `CanRDP` ➜ वह host जहाँ आपके user के पास `SeBackupPrivilege` भी है ➜ filtered tokens से बचने के लिए elevated shell शुरू करें ➜ restrictive DACLs के बावजूद `SAM` और `SYSTEM` hives पढ़ने के लिए backup semantics का उपयोग करें ➜ उन्हें exfiltrate करें और local Administrator NT hash recover करने के लिए offline `secretsdump.py` चलाएं, फिर lateral movement/privilege escalation करें।

### Prioritising Kerberoasting with BloodHound

Roasting को targeted रखने के लिए graph context का उपयोग करें:

1. ADWS-compatible collector के साथ एक बार collect करें और offline काम करें:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP import करें, compromised principal को owned के रूप में mark करें और admin/infra rights वाले SPN accounts सामने लाने के लिए built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) चलाएं।
3. Blast radius के आधार पर SPNs को प्राथमिकता दें; cracking से पहले `pwdLastSet`, `lastLogon` और allowed encryption types की समीक्षा करें।
4. केवल selected tickets request करें, उन्हें offline crack करें, फिर नई access के साथ BloodHound पर दोबारा query चलाएं:
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

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory का **health-check** करता है और risk scoring के साथ एक HTML report तैयार करता है।
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## संदर्भ

- [BloodHound Community Edition v8 का OpenGraph के साथ लॉन्च: Active Directory और Entra ID से आगे Identity Attack Paths](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [ACLs से आगे: BloodHound के साथ Windows Privilege Escalation Paths की Mapping](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: BloodHound CE में OpenGraph Attack Path Mapping](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
