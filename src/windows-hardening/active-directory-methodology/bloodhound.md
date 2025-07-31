# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> KUMBUKA: Ukurasa huu unakusanya baadhi ya zana muhimu zaidi za **kuorodhesha** na **kuonyesha** uhusiano wa Active Directory. Kwa ukusanyaji kupitia njia ya siri ya **Active Directory Web Services (ADWS)** angalia rejea hapo juu.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ni mtazamaji wa **AD** wa hali ya juu na mhariri ambao unaruhusu:

* Kuangalia mti wa directory kwa GUI
* Kuedit mwelekeo wa vitu na maelezo ya usalama
* Uundaji wa picha za wakati / kulinganisha kwa uchambuzi wa mbali

### Matumizi ya haraka

1. Anza chombo na uungane na `dc01.corp.local` kwa akidi yoyote ya domain.
2. Unda picha ya mbali kupitia `File ➜ Create Snapshot`.
3. Linganisha picha mbili kwa `File ➜ Compare` ili kugundua mabadiliko ya ruhusa.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) inatoa seti kubwa ya vitu kutoka kwa domain (ACLs, GPOs, imani, templeti za CA …) na inazalisha **ripoti ya Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (kuonyesha grafu)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) inatumia nadharia ya grafu + Neo4j kufichua uhusiano wa mamlaka yaliyofichika ndani ya AD ya ndani na Azure AD.

### Usanidi (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Wakusanyaji

* `SharpHound.exe` / `Invoke-BloodHound` – toleo la asili au PowerShell
* `AzureHound` – uainishaji wa Azure AD
* **SoaPy + BOFHound** – ukusanyaji wa ADWS (angalia kiungo kilichopo juu)

#### Njia za kawaida za SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Wakusanyaji wanazalisha JSON ambayo inachukuliwa kupitia GUI ya BloodHound.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) inataja **Group Policy Objects** na kuonyesha makosa ya usanidi.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) inafanya **ukaguzi wa afya** wa Active Directory na kuunda ripoti ya HTML yenye alama za hatari.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
