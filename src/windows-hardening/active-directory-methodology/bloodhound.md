# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Ova stranica grupiše neke od najkorisnijih alata za **enumeraciju** i **vizualizaciju** odnosa u Active Directory-ju. Za prikupljanje preko stealthy **Active Directory Web Services (ADWS)** kanala, pogledajte referencu iznad.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) je napredni **AD preglednik i uređivač** koji omogućava:

* GUI pretraživanje stabla direktorijuma
* Uređivanje atributa objekata i sigurnosnih deskriptora
* Kreiranje / poređenje snimaka za analizu van mreže

### Brza upotreba

1. Pokrenite alat i povežite se na `dc01.corp.local` sa bilo kojim domena kredencijalima.
2. Kreirajte offline snimak putem `File ➜ Create Snapshot`.
3. Poređajte dva snimka sa `File ➜ Compare` da biste uočili promene u dozvolama.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) izvlači veliki set artefakata iz domena (ACL-ovi, GPO-ovi, poverenja, CA šabloni …) i proizvodi **Excel izveštaj**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (grafička vizualizacija)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) koristi teoriju grafova + Neo4j da otkrije skrivene privilegije unutar on-prem AD i Azure AD.

### Implementacija (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – nativna ili PowerShell varijanta
* `AzureHound` – Azure AD enumeracija
* **SoaPy + BOFHound** – ADWS kolekcija (vidi link na vrhu)

#### Uobičajeni SharpHound režimi
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Kolektori generišu JSON koji se unosi putem BloodHound GUI-a.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeriše **Group Policy Objects** i ističe pogrešne konfiguracije.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) vrši **proveru zdravlja** Active Directory-a i generiše HTML izveštaj sa ocenom rizika.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
