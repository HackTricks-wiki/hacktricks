# BloodHound & अन्य Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> नोट: यह पृष्ठ कुछ सबसे उपयोगी उपयोगिताओं को **enumerate** और **visualise** Active Directory संबंधों के लिए समूहित करता है।  चुपके से **Active Directory Web Services (ADWS)** चैनल के माध्यम से संग्रह के लिए ऊपर दिए गए संदर्भ की जांच करें।

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) एक उन्नत **AD viewer & editor** है जो अनुमति देता है:

* निर्देशिका पेड़ का GUI ब्राउज़िंग
* ऑब्जेक्ट विशेषताओं और सुरक्षा विवरणों का संपादन
* ऑफ़लाइन विश्लेषण के लिए स्नैपशॉट निर्माण / तुलना

### त्वरित उपयोग

1. उपकरण शुरू करें और किसी भी डोमेन क्रेडेंशियल के साथ `dc01.corp.local` से कनेक्ट करें।
2. `File ➜ Create Snapshot` के माध्यम से एक ऑफ़लाइन स्नैपशॉट बनाएं।
3. अनुमति परिवर्तनों को देखने के लिए `File ➜ Compare` के साथ दो स्नैपशॉट की तुलना करें।

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) एक डोमेन से एक बड़े सेट के आर्टिफैक्ट (ACLs, GPOs, trusts, CA templates …) को निकालता है और एक **Excel रिपोर्ट** उत्पन्न करता है।
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (ग्राफ दृश्यांकन)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) ग्राफ सिद्धांत + Neo4j का उपयोग करके ऑन-प्रेम AD और Azure AD के भीतर छिपे हुए विशेषाधिकार संबंधों को प्रकट करता है।

### तैनाती (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – मूल या PowerShell संस्करण
* `AzureHound` – Azure AD गणना
* **SoaPy + BOFHound** – ADWS संग्रह (ऊपर लिंक देखें)

#### सामान्य SharpHound मोड
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
कलेक्टर्स JSON उत्पन्न करते हैं जिसे BloodHound GUI के माध्यम से ग्रहण किया जाता है।

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) **Group Policy Objects** की गणना करता है और गलत कॉन्फ़िगरेशन को उजागर करता है।
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory का **स्वास्थ्य-चेक** करता है और जोखिम स्कोरिंग के साथ एक HTML रिपोर्ट उत्पन्न करता है।
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
