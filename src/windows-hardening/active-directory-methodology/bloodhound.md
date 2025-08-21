# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> ΣΗΜΕΙΩΣΗ: Αυτή η σελίδα ομαδοποιεί μερικά από τα πιο χρήσιμα εργαλεία για **enumerate** και **visualise** τις σχέσεις του Active Directory. Για συλλογή μέσω του stealthy **Active Directory Web Services (ADWS)** καναλιού, ελέγξτε την αναφορά παραπάνω.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) είναι ένας προηγμένος **AD viewer & editor** που επιτρέπει:

* GUI browsing του δέντρου καταλόγου
* Επεξεργασία χαρακτηριστικών αντικειμένων & ασφάλειας
* Δημιουργία / σύγκριση στιγμιότυπων για offline ανάλυση

### Quick usage

1. Ξεκινήστε το εργαλείο και συνδεθείτε στο `dc01.corp.local` με οποιαδήποτε διαπιστευτήρια τομέα.
2. Δημιουργήστε ένα offline στιγμιότυπο μέσω `File ➜ Create Snapshot`.
3. Συγκρίνετε δύο στιγμιότυπα με `File ➜ Compare` για να εντοπίσετε αποκλίσεις δικαιωμάτων.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) εξάγει ένα μεγάλο σύνολο αντικειμένων από έναν τομέα (ACLs, GPOs, trusts, CA templates …) και παράγει μια **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (γραφική απεικόνιση)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) χρησιμοποιεί τη θεωρία γραφημάτων + Neo4j για να αποκαλύψει κρυφές σχέσεις προνομίων μέσα σε on-prem AD & Azure AD.

### Ανάπτυξη (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – εγγενής ή PowerShell παραλλαγή
* `AzureHound` – Azure AD καταμέτρηση
* **SoaPy + BOFHound** – ADWS συλλογή (δείτε τον σύνδεσμο στην κορυφή)

#### Κοινές λειτουργίες SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Οι συλλέκτες δημιουργούν JSON που εισάγεται μέσω του BloodHound GUI.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) καταγράφει **Group Policy Objects** και επισημαίνει κακές ρυθμίσεις.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) εκτελεί έναν **έλεγχο υγείας** του Active Directory και δημιουργεί μια αναφορά HTML με βαθμολογία κινδύνου.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
