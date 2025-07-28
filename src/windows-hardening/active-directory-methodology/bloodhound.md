# BloodHound & Ander Aktiewe Gidsen van Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> LET WEL: Hierdie bladsy groepeer sommige van die nuttigste nutsmiddels om **te enumerate** en **te visualiseer** Aktiewe Directory verhoudings. Vir versameling oor die stealthy **Active Directory Web Services (ADWS)** kanaal, kyk na die verwysing hierbo.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) is 'n gevorderde **AD kyker & redigeerder** wat toelaat:

* GUI-browsing van die gidsboom
* Redigering van objekattributen & sekuriteitsbeskrywings
* Snapshot skepping / vergelyking vir offline analise

### Vinnige gebruik

1. Begin die hulpmiddel en verbind met `dc01.corp.local` met enige domein akrediteer.
2. Skep 'n offline snapshot via `File ➜ Create Snapshot`.
3. Vergelyk twee snapshots met `File ➜ Compare` om toestemming verskille op te spoor.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) onttrek 'n groot stel artefakte uit 'n domein (ACLs, GPOs, trusts, CA templates …) en produseer 'n **Excel verslag**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graf visualisering)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) gebruik grafteorie + Neo4j om verborge privilige verhoudings binne op-prem AD & Azure AD te onthul.

### Ontplooiing (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Versamelaars

* `SharpHound.exe` / `Invoke-BloodHound` – inheemse of PowerShell variasie
* `AzureHound` – Azure AD enumerasie
* **SoaPy + BOFHound** – ADWS versameling (sien skakel bo)

#### Algemene SharpHound modi
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Die versamelaars genereer JSON wat via die BloodHound GUI ingeneem word.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) evalueer **Group Policy Objects** en beklemtoon miskonfigurasies.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) voer 'n **gesondheidskontrole** van Active Directory uit en genereer 'n HTML-verslag met risiko telling.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
