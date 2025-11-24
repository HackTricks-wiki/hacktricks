# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: यह पृष्ठ Active Directory संबंधों को **सूचीबद्ध** और **दृश्यमान** करने के लिए सबसे उपयोगी यूटिलिटीज़ को समूहित करता है। चुपचाप चलने वाले **Active Directory Web Services (ADWS)** चैनल के माध्यम से संग्रहण के लिए ऊपर दिए गए संदर्भ को देखें।

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) एक उन्नत **AD viewer & editor** है जो निम्न की अनुमति देता है:

* directory tree को GUI के माध्यम से ब्राउज़ करना
* object attributes & security descriptors का संपादन
* offline analysis के लिए snapshot बनाना / तुलनात्मक अध्ययन

### Quick usage

1. टूल शुरू करें और किसी भी domain credentials के साथ `dc01.corp.local` से कनेक्ट करें।
2. `File ➜ Create Snapshot` के माध्यम से एक offline snapshot बनाएं।
3. अनुमति परिवर्तन (permission drifts) पहचानने के लिए `File ➜ Compare` से दो snapshots की तुलना करें।

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) domain से ACLs, GPOs, trusts, CA templates … जैसे बड़े सेट के artefacts निकालता है और एक **Excel report** उत्पन्न करता है।
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (ग्राफ विज़ुअलाइज़ेशन)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) ग्राफ सिद्धांत + Neo4j का उपयोग करके on-prem AD & Azure AD के भीतर छिपे हुए privilege relationships को उजागर करता है।

### तैनाती (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### कलेक्टर्स

* `SharpHound.exe` / `Invoke-BloodHound` – नेटिव या PowerShell वेरिएंट
* `AzureHound` – Azure AD एन्यूमरेशन
* **SoaPy + BOFHound** – ADWS संग्रह (ऊपर लिंक देखें)

#### सामान्य SharpHound मोड्स
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
The collectors JSON उत्पन्न करते हैं, जिसे BloodHound GUI के माध्यम से ingest किया जाता है।

---

## Kerberoasting को BloodHound के साथ प्राथमिकता देना

Graph context शोर-गुल और बेतरतीब roasting से बचने के लिए महत्वपूर्ण है। एक हल्का workflow:

1. **Collect everything once** ADWS-compatible collector (e.g. RustHound-CE) का उपयोग करके ताकि आप offline में काम कर सकें और DC को फिर से छुए बिना paths का rehearsal कर सकें:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Import the ZIP, mark the compromised principal as owned**, फिर built-in queries चलाएँ जैसे *Kerberoastable Users* और *Shortest Paths to Domain Admins*. यह तुरंत SPN-bearing accounts को उजागर करता है जिनके पास उपयोगी group memberships हैं (Exchange, IT, tier0 service accounts, आदि)।
3. **Prioritise by blast radius** – shared infrastructure को नियंत्रित करने वाले या admin rights वाले SPNs पर ध्यान दें, और cracking cycles खर्च करने से पहले `pwdLastSet`, `lastLogon`, और allowed encryption types की जाँच करें।
4. **Request only the tickets you care about**. NetExec जैसे tools चयनित `sAMAccountName`s को target कर सकते हैं ताकि हर LDAP ROAST request का एक स्पष्ट justification हो:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, फिर तुरंत BloodHound को नए अधिकारों के साथ post-exploitation की योजना बनाने के लिए पुनः क्वेरी करें।

यह तरीका सिग्नल-टू-नॉइज़ अनुपात को उच्च रखता है, पहचान योग्य मात्रा को कम करता है (no mass SPN requests), और सुनिश्चित करता है कि हर cracked ticket अर्थपूर्ण privilege escalation चरणों में बदल जाए।

## Group3r

[Group3r](https://github.com/Group3r/Group3r) **Group Policy Objects** की सूची बनाता है और गलत कॉन्फ़िगरेशन को हाइलाइट करता है।
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory का **स्वास्थ्य-जाँच** करता है और जोखिम स्कोरिंग के साथ HTML रिपोर्ट बनाता है।
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## संदर्भ

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
