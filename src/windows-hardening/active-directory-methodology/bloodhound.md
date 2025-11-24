# BloodHound & Ander Active Directory Enumerasie-gereedskap

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Hierdie bladsy groepeer sommige van die nuttigste hulpmiddels om **Active Directory** verhoudings te **ontleed** en te **visualiseer**. Vir versameling oor die onopvallende **Active Directory Web Services (ADWS)** kanaal raadpleeg die verwysing hierbo.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) is 'n gevorderde **AD viewer & editor** wat toelaat:

* GUI-blaai deur die gidsboom
* Redigering van objekkenmerke & sekuriteitsomskrywings
* Snapshot-skepping / vergelyking vir vanlyn-analise

### Vinnige gebruik

1. Begin die tool en koppel aan `dc01.corp.local` met enige domeinskredensiale.
2. Skep 'n vanlyn snapshot via `File ➜ Create Snapshot`.
3. Vergelyk twee snapshots met `File ➜ Compare` om toegangsregverskuiwings te bespeur.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) onttrek 'n groot stel artefakte uit 'n domein (ACLs, GPOs, trusts, CA templates …) en produseer 'n **Excel-verslag**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (grafiekvisualisering)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) gebruik graafteorie + Neo4j om verborge privilegieverhoudings binne on-prem AD & Azure AD te openbaar.

### Ontplooiing (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Versamelaars

* `SharpHound.exe` / `Invoke-BloodHound` – inheemse of PowerShell-weergawe
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – ADWS-versameling (sien skakel bo)

#### Algemene SharpHound-modusse
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Die collectors genereer JSON wat via die BloodHound GUI geïmporteer word.

---

## Prioritisering van Kerberoasting met BloodHound

Grafkonteks is noodsaaklik om luidrugtige, willekeurige roasting te vermy. ’n liggewig werkvloeistroom:

1. **Versamel alles eenmalig** met 'n ADWS-compatibele collector (bv. RustHound-CE) sodat jy offline kan werk en paaie kan oefen sonder om die DC weer aan te raak:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Importeer die ZIP, merk die gekompromitteerde principal as owned**, en voer dan ingeboude navrae uit soos *Kerberoastable Users* en *Shortest Paths to Domain Admins*. Dit beklemtoon onmiddellik SPN-draende rekeninge met nuttige groepslidmaatskappe (Exchange, IT, tier0 service accounts, ens.).
3. **Prioritiseer volgens blast radius** – fokus op SPNs wat gedeelde infrastruktuur beheer of admin-regte het, en kontroleer `pwdLastSet`, `lastLogon`, en toegelate enkripsietipes voordat jy cracking cycles bestee.
4. **Versoek slegs die tickets waarin jy belangstel**. Gereedskap soos NetExec kan gekose `sAMAccountName`s teiken sodat elke LDAP ROAST request 'n duidelike regverdiging het:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, voer dan onmiddellik 'n hernavraag by BloodHound uit om post-exploitation met die nuwe privileges te beplan.

Hierdie benadering behou 'n hoë sein-tot-ruisverhouding, verminder die opspoorbare volume (geen massiewe SPN-aanvrage nie), en verseker dat elke cracked ticket omskakel na betekenisvolle privilege escalation-stappe.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) lys **Group Policy Objects** op en beklemtoon miskonfigurasies.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) voer 'n **gesondheidskontrole** van Active Directory uit en genereer 'n HTML-verslag met risikoskorering.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Verwysings

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
