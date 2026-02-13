# BloodHound & अन्य Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> नोट: यह पृष्ठ Active Directory संबंधों को **enumerate** और **visualise** करने के लिए कुछ सबसे उपयोगी यूटिलिटीज़ का समूह प्रस्तुत करता है। छिपे हुए **Active Directory Web Services (ADWS)** चैनल के माध्यम से संग्रह के लिए ऊपर दिए गए संदर्भ को देखें।

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) एक उन्नत **AD viewer & editor** है जो निम्न की अनुमति देता है:

* GUI के माध्यम से directory tree ब्राउज़ करना
* object attributes & security descriptors का संपादन
* ऑफ़लाइन विश्लेषण के लिए Snapshot बनाना / तुलना करना

### त्वरित उपयोग

1. टूल शुरू करें और किसी भी domain credentials के साथ `dc01.corp.local` से कनेक्ट करें।
2. `File ➜ Create Snapshot` के माध्यम से एक ऑफ़लाइन स्नैपशॉट बनाएं।
3. अनुमतियों में बदलाव देखने के लिए दो स्नैपशॉट्स की तुलना `File ➜ Compare` से करें।

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) एक domain से ACLs, GPOs, trusts, CA templates … जैसे कई आर्टिफैक्ट निकालेगा और एक **Excel report** तैयार करता है।
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (ग्राफ दृश्यकरण)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) ग्राफ सिद्धांत + Neo4j का उपयोग करके on-prem AD & Azure AD के भीतर छिपे हुए विशेषाधिकार संबंधों का खुलासा करता है।

### परिनियोजन (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### संग्रहकर्ता

* `SharpHound.exe` / `Invoke-BloodHound` – नेटिव या PowerShell वेरिएंट
* `AzureHound` – Azure AD एन्यूमरेशन
* **SoaPy + BOFHound** – ADWS संग्रह (ऊपर दिए लिंक देखें)

#### सामान्य SharpHound मोड्स
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
The collectors generate JSON which is ingested via the BloodHound GUI.

### Privilege & logon-right collection

Windows **token privileges** (e.g., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) DACL चेक्स को बायपास कर सकती हैं, इसलिए इन्हें डोमेन-स्तर पर मैप करना उन लोकल LPE edges को उजागर करता है जिन्हें ACL-only ग्राफ़ मिस करते हैं। **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` और उनके `SeDeny*` समकक्ष) को LSA द्वारा तब लागू किया जाता है जब तक कि टोकन मौजूद भी न हो, और deny का precedence होता है, इसलिए ये lateral movement (RDP/SMB/scheduled task/service logon) को वास्‍तविक रूप से सीमित करते हैं।

जब संभव हो तो collectors को elevated चलाएँ: UAC interactive admins के लिए एक filtered token बनाता है (via `NtFilterToken`), संवेदनशील privileges को हटाकर और admin SIDs को deny-only के रूप में मार्क करके। यदि आप non-elevated shell से privileges enumerate करते हैं तो हाई-वैल्यु privileges अदृश्य होंगे और BloodHound उन edges को ingest नहीं करेगा।

अब दो complementary SharpHound collection strategies मौजूद हैं:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. LDAP पर GPOs enumerate करें (`(objectCategory=groupPolicyContainer)`) और प्रत्येक `gPCFileSysPath` पढ़ें।
2. SYSVOL से `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` फ़ेच करके `[Privilege Rights]` सेक्शन को पार्स करें जो privilege/logon-right नामों को SIDs से मैप करता है।
3. OUs/sites/domains पर `gPLink` के जरिए GPO links resolve करें, लिंक्ड containers में कंप्यूटर सूचीबद्ध करें, और उन मशीनों को rights attribute करें।
4. लाभ: एक सामान्य user के साथ काम करता है और शांत होता है; कमी: केवल GPO के माध्यम से पुश किए गए rights ही दिखते हैं (लोकल ट्वीक मिस हो जाते हैं)।

- **LSA RPC enumeration (noisy, accurate):**
- टार्गेट पर local admin वाले context से, Local Security Policy खोलकर हर privilege/logon right के लिए `LsaEnumerateAccountsWithUserRight` कॉल करके RPC के जरिए assigned principals enumerate करें।
- लाभ: लोकली या GPO के बाहर सेट किए गए rights को कैप्चर करता है; कमी: नेटवर्क ट्रैफ़िक noisy होता है और हर होस्ट पर admin आवश्यकता होती है।

**Example abuse path surfaced by these edges:** `CanRDP` ➜ वह host जहाँ आपका user भी `SeBackupPrivilege` रखता है ➜ filtered tokens से बचने के लिए elevated shell स्टार्ट करें ➜ restrictive DACLs के बावजूद backup semantics का उपयोग करके `SAM` और `SYSTEM` hives पढ़ें ➜ exfiltrate करके offline `secretsdump.py` चलाएँ ताकि local Administrator NT hash रिकवर कर के lateral movement/privilege escalation किया जा सके।

### Prioritising Kerberoasting with BloodHound

Use graph context to keep roasting targeted:

1. Collect once with an ADWS-compatible collector and work offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP import करें, compromised principal को owned के रूप में मार्क करें, और built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) चलाकर SPN accounts जिनके पास admin/infra rights हैं surface करें।
3. SPNs को blast radius के हिसाब से प्राथमिकता दें; cracking से पहले `pwdLastSet`, `lastLogon`, और allowed encryption types की समीक्षा करें।
4. केवल चुने हुए tickets request करें, offline crack करें, फिर नए access के साथ BloodHound को re-query करें:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) **Group Policy Objects** को enumerate करता है और misconfigurations को हाइलाइट करता है।
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory का **हेल्थ-चेक** करता है और जोखिम स्कोरिंग के साथ एक HTML रिपोर्ट उत्पन्न करता है.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## संदर्भ

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, और Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [ACLs के परे: Windows Privilege Escalation Paths को BloodHound के साथ मैप करना](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
