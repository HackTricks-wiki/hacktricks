# BloodHound & Άλλα Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> ΣΗΜΕΙΩΣΗ: Αυτή η σελίδα ομαδοποιεί μερικά από τα πιο χρήσιμα εργαλεία για να **enumerate** και **οπτικοποιήσουν** τις σχέσεις του Active Directory. Για συλλογή μέσω του κρυφού **Active Directory Web Services (ADWS)** καναλιού ελέγξτε την αναφορά παραπάνω.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) είναι ένας προηγμένος **AD viewer & editor** που επιτρέπει:

* GUI περιήγηση στο δέντρο καταλόγου
* Επεξεργασία attributes αντικειμένων & security descriptors
* Δημιουργία snapshot / σύγκριση για offline ανάλυση

### Γρήγορη χρήση

1. Ξεκινήστε το εργαλείο και συνδεθείτε στο `dc01.corp.local` με οποιαδήποτε διαπιστευτήρια domain.
2. Δημιουργήστε ένα offline snapshot μέσω `File ➜ Create Snapshot`.
3. Συγκρίνετε δύο snapshots με `File ➜ Compare` για να εντοπίσετε αποκλίσεις δικαιωμάτων.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) εξάγει ένα μεγάλο σύνολο artefacts από ένα domain (ACLs, GPOs, trusts, CA templates …) και παράγει μια **αναφορά Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (οπτικοποίηση γράφου)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) χρησιμοποιεί τη θεωρία γράφων + Neo4j για να αποκαλύψει κρυφές σχέσεις προνομίων εντός on-prem AD & Azure AD.

### Ανάπτυξη (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Συλλέκτες

* `SharpHound.exe` / `Invoke-BloodHound` – native ή PowerShell παραλλαγή
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – ADWS collection (βλέπε σύνδεσμο στην κορυφή)

#### Συνηθισμένες λειτουργίες SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Οι collectors παράγουν JSON το οποίο εισάγεται μέσω του BloodHound GUI.

---

## Ιεράρχηση του Kerberoasting με BloodHound

Το πλαίσιο του γράφου είναι ζωτικής σημασίας για να αποφευχθεί το θορυβώδες, αδιακρίτως roasting. Μια ελαφριά ροή εργασίας:

1. **Συλλέξτε τα πάντα μία φορά** χρησιμοποιώντας έναν ADWS-compatible collector (π.χ. RustHound-CE) ώστε να μπορείτε να δουλέψετε offline και να εξασκηθείτε στις διαδρομές χωρίς να αγγίξετε ξανά τον DC:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Import the ZIP, mark the compromised principal as owned**, στη συνέχεια τρέξτε ενσωματωμένα ερωτήματα όπως *Kerberoastable Users* και *Shortest Paths to Domain Admins*. Αυτό επισημαίνει άμεσα λογαριασμούς που φέρουν SPN με χρήσιμες συμμετοχές σε ομάδες (Exchange, IT, tier0 service accounts, κ.λπ.).
3. **Prioritise by blast radius** – εστιάστε σε SPNs που ελέγχουν κοινή υποδομή ή έχουν δικαιώματα admin, και ελέγξτε τα `pwdLastSet`, `lastLogon`, και τους επιτρεπόμενους τύπους κρυπτογράφησης πριν ξοδέψετε cracking cycles.
4. **Request only the tickets you care about**. Εργαλεία όπως το NetExec μπορούν να στοχεύσουν επιλεγμένα `sAMAccountName`s ώστε κάθε LDAP ROAST request να έχει σαφή αιτιολόγηση:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, κάντε άμεσα εκ νέου ερώτημα στο BloodHound για να σχεδιάσετε post-exploitation με τα νέα προνόμια.

Αυτή η προσέγγιση διατηρεί υψηλή την αναλογία σήματος προς θόρυβο, μειώνει τον ανιχνεύσιμο όγκο (χωρίς μαζικά αιτήματα SPN) και εξασφαλίζει ότι κάθε cracked ticket μεταφράζεται σε ουσιαστικά βήματα privilege escalation.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) καταγράφει τα **Group Policy Objects** και επισημαίνει κακοδιαμορφώσεις.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Εκτελεί έναν **έλεγχο υγείας** του Active Directory και δημιουργεί μια αναφορά HTML με αξιολόγηση κινδύνου.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Αναφορές

- [HackTheBox Mirage: Αλυσιδωτή NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, και Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
