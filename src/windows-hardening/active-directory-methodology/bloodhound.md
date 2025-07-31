# BloodHound & Andere Active Directory Enumerationswerkzeuge

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> HINWEIS: Diese Seite gruppiert einige der nützlichsten Dienstprogramme zur **Enumeration** und **Visualisierung** von Active Directory-Beziehungen. Für die Sammlung über den stealthy **Active Directory Web Services (ADWS)**-Kanal siehe den obigen Verweis.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ist ein fortgeschrittener **AD-Viewer & Editor**, der Folgendes ermöglicht:

* GUI-Browsing des Verzeichnisbaums
* Bearbeitung von Objektattributen & Sicherheitsbeschreibungen
* Erstellung / Vergleich von Snapshots für die Offline-Analyse

### Schnelle Nutzung

1. Starten Sie das Tool und verbinden Sie sich mit `dc01.corp.local` mit beliebigen Domänenanmeldeinformationen.
2. Erstellen Sie einen Offline-Snapshot über `Datei ➜ Snapshot erstellen`.
3. Vergleichen Sie zwei Snapshots mit `Datei ➜ Vergleichen`, um Berechtigungsabweichungen zu erkennen.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrahiert eine große Menge an Artefakten aus einer Domäne (ACLs, GPOs, Vertrauensstellungen, CA-Vorlagen …) und erstellt einen **Excel-Bericht**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (Graphvisualisierung)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) verwendet Graphentheorie + Neo4j, um versteckte Berechtigungsbeziehungen in lokalem AD und Azure AD offenzulegen.

### Bereitstellung (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Sammler

* `SharpHound.exe` / `Invoke-BloodHound` – native oder PowerShell-Variante
* `AzureHound` – Azure AD Enumeration
* **SoaPy + BOFHound** – ADWS-Sammlung (siehe Link oben)

#### Häufige SharpHound-Modi
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Die Sammler erzeugen JSON, das über die BloodHound-GUI aufgenommen wird.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeriert **Group Policy Objects** und hebt Fehlkonfigurationen hervor.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) führt einen **Gesundheitscheck** von Active Directory durch und erstellt einen HTML-Bericht mit Risikobewertung.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
