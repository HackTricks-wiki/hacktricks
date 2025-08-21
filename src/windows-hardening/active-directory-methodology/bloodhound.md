# BloodHound & Altri Strumenti di Enumerazione di Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Questa pagina raggruppa alcune delle utility più utili per **enumerare** e **visualizzare** le relazioni di Active Directory. Per la raccolta attraverso il canale stealthy **Active Directory Web Services (ADWS)** controlla il riferimento sopra.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) è un avanzato **visualizzatore e editor di AD** che consente:

* Navigazione GUI dell'albero della directory
* Modifica degli attributi degli oggetti e dei descrittori di sicurezza
* Creazione / confronto di snapshot per analisi offline

### Utilizzo rapido

1. Avvia lo strumento e connettiti a `dc01.corp.local` con qualsiasi credenziale di dominio.
2. Crea uno snapshot offline tramite `File ➜ Create Snapshot`.
3. Confronta due snapshot con `File ➜ Compare` per individuare le variazioni di permessi.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) estrae un ampio set di artefatti da un dominio (ACL, GPO, trust, modelli CA …) e produce un **report Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualizzazione grafica)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) utilizza la teoria dei grafi + Neo4j per rivelare relazioni di privilegio nascoste all'interno di AD on-prem e Azure AD.

### Distribuzione (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Raccoltori

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa o PowerShell
* `AzureHound` – enumerazione di Azure AD
* **SoaPy + BOFHound** – raccolta ADWS (vedi link in alto)

#### Modalità comuni di SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
I collezionisti generano JSON che viene acquisito tramite l'interfaccia grafica di BloodHound.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** e mette in evidenza le configurazioni errate.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) esegue un **health-check** di Active Directory e genera un report HTML con punteggio di rischio.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
