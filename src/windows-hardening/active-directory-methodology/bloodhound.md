# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: यह page कुछ सबसे उपयोगी utilities को **enumerate** और **visualise** करने के लिए group करता है Active Directory relationships.  stealthy **Active Directory Web Services (ADWS)** channel पर collection के लिए ऊपर दिए गए reference को check करें।

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) एक advanced **AD viewer & editor** है जो अनुमति देता है:

* directory tree को GUI के जरिए browse करना
* object attributes & security descriptors को edit करना
* offline analysis के लिए snapshot creation / comparison

### Quick usage

1. tool start करें और किसी भी domain credentials के साथ `dc01.corp.local` से connect करें।
2. `File ➜ Create Snapshot` के जरिए एक offline snapshot बनाएं।
3. permission drifts को spot करने के लिए `File ➜ Compare` के साथ दो snapshots compare करें।

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) domain से artifacts का एक बड़ा set extract करता है (ACLs, GPOs, trusts, CA templates …) और एक **Excel report** बनाता है।
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (ग्राफ विज़ुअलाइज़ेशन)

[BloodHound](https://github.com/SpecterOps/BloodHound) ग्राफ थ्योरी का उपयोग करके on-prem AD, Entra ID, और OpenGraph के माध्यम से ingest किए गए किसी भी अतिरिक्त attack-surface data के अंदर छिपे privilege relationships को उजागर करता है।

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### कलेक्टर्स

* `SharpHound.exe` / `Invoke-BloodHound` – native या PowerShell variant
* `RustHound-CE` – Linux, macOS, और Windows के लिए cross-platform CE collector
* `NetExec --bloodhound` – Linux से quick LDAP-driven collection
* `AzureHound` – Entra ID enumeration
* **SoaPy + BOFHound** – ADWS collection (ऊपर दिए गए link को देखें)

> BloodHound CE `v8+` ने OpenGraph आने पर collector output format बदल दिया। Legacy BloodHound या पुराने CE installs से upgrade करने के बाद, data import करने से पहले current collectors के साथ discovery फिर से run करें।

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
कलेक्टर्स JSON उत्पन्न करते हैं जिसे BloodHound GUI के जरिए ingest किया जाता है।

#### गैर-domain-joined Windows host से SharpHound

अगर आपकी operator VM target domain से joined नहीं है, तो DNS को एक DC की ओर point करें, एक **network-only** shell शुरू करें, verify करें कि आप DC पर `SYSVOL`/`NETLOGON` देख सकते हैं, और फिर remote domain के against collect करें:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
यह disposable jump boxes या operator workstations के लिए उपयोगी है जिन्हें domain-joined नहीं होना चाहिए।

#### Cross-platform collection from Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` एक अच्छा default है जब आपको non-Windows host से CE-compatible output चाहिए। `NetExec` सुविधाजनक है जब आप पहले से इसे LDAP validation या spraying के लिए इस्तेमाल कर रहे हों और एक quick graph import चाहते हों। Non-AD datasets के लिए, BloodHound OpenGraph को [ShareHound](../../network-services-pentesting/pentesting-smb/README.md) जैसे collectors के साथ extend किया जा सकता है।

### Privilege & logon-right collection

Windows **token privileges** (e.g., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) DACL checks को bypass कर सकते हैं, इसलिए इन्हें domain-wide map करने से local LPE edges सामने आते हैं जिन्हें ACL-only graphs miss कर देते हैं। **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` और उनके `SeDeny*` counterparts) को LSA token के अस्तित्व में आने से पहले enforce करता है, और denies को precedence मिलती है, इसलिए ये lateral movement (RDP/SMB/scheduled task/service logon) को सीधे प्रभावित करते हैं।

**Collectors elevated mode में चलाएं** जब संभव हो: UAC interactive admins के लिए filtered token बनाता है (`NtFilterToken` के जरिए), जिससे sensitive privileges हट जाते हैं और admin SIDs deny-only के रूप में mark हो जाते हैं। अगर आप non-elevated shell से privileges enumerate करते हैं, तो high-value privileges दिखाई नहीं देंगे और BloodHound उन edges को ingest नहीं करेगा।

अब दो complementary SharpHound collection strategies उपलब्ध हैं:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. LDAP के over GPOs enumerate करें (`(objectCategory=groupPolicyContainer)`) और हर `gPCFileSysPath` पढ़ें।
2. `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` को SYSVOL से fetch करें और `[Privilege Rights]` section parse करें, जो privilege/logon-right names को SIDs से map करता है।
3. `gPLink` के जरिए OUs/sites/domains पर GPO links resolve करें, linked containers में computers list करें, और rights को उन machines से attribute करें।
4. फायदा: normal user के साथ काम करता है और quiet है; नुकसान: केवल GPO से push किए गए rights दिखते हैं (local tweaks miss हो जाते हैं)।

- **LSA RPC enumeration (noisy, accurate):**
- Target पर local admin context से Local Security Policy खोलें और हर privilege/logon right के लिए `LsaEnumerateAccountsWithUserRight` call करें ताकि RPC के जरिए assigned principals enumerate हो सकें।
- फायदा: locally या GPO के बाहर set किए गए rights भी capture करता है; नुकसान: noisy network traffic और हर host पर admin requirement।

**इन edges से दिखाई देने वाला example abuse path:** `CanRDP` ➜ host जहाँ आपके user के पास `SeBackupPrivilege` भी है ➜ filtered tokens से बचने के लिए elevated shell शुरू करें ➜ restrictive DACLs के बावजूद backup semantics का उपयोग करके `SAM` और `SYSTEM` hives पढ़ें ➜ exfiltrate करें और `secretsdump.py` को offline चलाकर local Administrator NT hash recover करें ताकि lateral movement/privilege escalation हो सके।

### Prioritising Kerberoasting with BloodHound

Graph context का उपयोग करके roasting को targeted रखें:

1. एक बार ADWS-compatible collector के साथ collect करें और offline काम करें:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP import करें, compromised principal को owned mark करें, और built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) चलाकर admin/infra rights वाले SPN accounts सामने लाएं।
3. SPNs को blast radius के हिसाब से prioritise करें; cracking से पहले `pwdLastSet`, `lastLogon`, और allowed encryption types review करें।
4. केवल selected tickets request करें, offline crack करें, फिर नए access के साथ BloodHound को re-query करें:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) **Group Policy Objects** enumerate करता है और misconfigurations highlight करता है।
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory का **health-check** करता है और risk scoring के साथ एक HTML report generate करता है।
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## संदर्भ

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
