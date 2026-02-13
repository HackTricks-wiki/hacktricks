# BloodHound & Άλλα Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> ΣΗΜΕΙΩΣΗ: Αυτή η σελίδα ομαδοποιεί μερικά από τα πιο χρήσιμα εργαλεία για **enumerate** και **visualise** τις σχέσεις του Active Directory. Για συλλογή μέσω του stealthy **Active Directory Web Services (ADWS)** channel δείτε την αναφορά πιο πάνω.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) είναι ένα προηγμένο **AD viewer & editor** που επιτρέπει:

* Περιήγηση με GUI στο δέντρο του καταλόγου
* Επεξεργασία των attributes αντικειμένων & των security descriptors
* Δημιουργία / σύγκριση snapshots για ανάλυση εκτός σύνδεσης

### Γρήγορη χρήση

1. Εκκινήστε το εργαλείο και συνδεθείτε στο `dc01.corp.local` με οποιαδήποτε domain διαπιστευτήρια.
2. Δημιουργήστε ένα offline snapshot μέσω `File ➜ Create Snapshot`.
3. Συγκρίνετε δύο snapshots με `File ➜ Compare` για να εντοπίσετε αποκλίσεις δικαιωμάτων.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) εξάγει ένα μεγάλο σύνολο artefacts από ένα domain (ACLs, GPOs, trusts, CA templates …) και παράγει μια **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (οπτικοποίηση γράφων)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) χρησιμοποιεί θεωρία γράφων + Neo4j για να αποκαλύψει κρυφές σχέσεις προνομίων μέσα σε on-prem AD & Azure AD.

### Ανάπτυξη (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Συλλέκτες

* `SharpHound.exe` / `Invoke-BloodHound` – native ή παραλλαγή PowerShell
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – συλλογή ADWS (βλ. σύνδεσμο στην κορυφή)

#### Συνήθεις λειτουργίες του SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Οι συλλέκτες δημιουργούν JSON που εισάγεται μέσω του BloodHound GUI.

### Συλλογή προνομίων & δικαιωμάτων σύνδεσης

Τα Windows **token privileges** (π.χ. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) μπορούν να παρακάμψουν ελέγχους DACL, οπότε η απεικόνισή τους σε επίπεδο domain αποκαλύπτει τοπικές ακμές LPE που χάνουν τα γραφήματα μόνο με βάση ACL. Τα **logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` και τα αντιστοίχως `SeDeny*`) εφαρμόζονται από το LSA πριν καν υπάρξει token, και οι αρνήσεις έχουν προτεραιότητα, οπότε ουσιαστικά περιορίζουν την πλευρική κίνηση (RDP/SMB/scheduled task/service logon).

Εκτελέστε τους συλλέκτες με αυξημένα δικαιώματα όταν είναι δυνατό: το UAC δημιουργεί ένα filtered token για τους interactive admins (μέσω `NtFilterToken`), αφαιρώντας ευαίσθητα privileges και σημειώνοντας τα admin SIDs ως deny-only. Αν καταγράψετε προνόμια από ένα μη-ανυψωμένο shell, τα υψηλής αξίας privileges θα είναι αόρατα και το BloodHound δεν θα εισάγει τις ακμές.

Υπάρχουν τώρα δύο συμπληρωματικές στρατηγικές συλλογής SharpHound:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Απαριθμήστε GPOs μέσω LDAP (`(objectCategory=groupPolicyContainer)`) και διαβάστε κάθε `gPCFileSysPath`.
2. Ανακτήστε το `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` από το SYSVOL και κάντε parse την ενότητα `[Privilege Rights]` που αντιστοιχεί ονόματα privilege/logon-right σε SIDs.
3. Επίλυση συνδέσμων GPO μέσω `gPLink` σε OUs/sites/domains, απαρίθμηση υπολογιστών στους συνδεδεμένους containers, και απόδοση των rights σε αυτούς τους μηχανήματα.
4. Πλεονέκτημα: λειτουργεί με έναν κανονικό χρήστη και είναι αθόρυβο· μειονέκτημα: βλέπει μόνο rights που προωθούνται μέσω GPO (τοπικές τροποποιήσεις χάνoνται).

- **LSA RPC enumeration (noisy, accurate):**
- Από ένα context με local admin στον στόχο, ανοίξτε το Local Security Policy και καλέστε `LsaEnumerateAccountsWithUserRight` για κάθε privilege/logon right για να απαριθμήσετε τους ανατεθειμένους principals μέσω RPC.
- Πλεονέκτημα: καταγράφει rights ορισμένα τοπικά ή έξω από GPO· μειονέκτημα: θορυβώδης δικτυακή κίνηση και ανάγκη admin σε κάθε host.

**Παράδειγμα διαδρομής κατάχρησης που αποκαλύπτεται από αυτές τις ακμές:** `CanRDP` ➜ host όπου ο χρήστης σας έχει επίσης `SeBackupPrivilege` ➜ ξεκινήστε ένα elevated shell για να αποφύγετε τα filtered tokens ➜ χρησιμοποιήστε backup semantics για να διαβάσετε τα hives `SAM` και `SYSTEM` παρά τους περιοριστικούς DACLs ➜ εξαγάγετε και τρέξτε `secretsdump.py` εκτός σύνδεσης για να ανακτήσετε το NT hash του τοπικού Administrator για lateral movement/privilege escalation.

### Προτεραιοποίηση Kerberoasting με BloodHound

Χρησιμοποιήστε το context του γραφήματος για να στοχεύετε το roasting:

1. Συλλέξτε μία φορά με έναν ADWS-compatible collector και δουλέψτε εκτός σύνδεσης:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Import το ZIP, σημαδέψτε τον συμβιωμένο principal ως owned, και τρέξτε τις ενσωματωμένες queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) για να αποκαλύψετε SPN accounts με admin/infra δικαιώματα.
3. Προτεραιοποιήστε SPNs ανά blast radius· ελέγξτε `pwdLastSet`, `lastLogon`, και τους επιτρεπόμενους τύπους κρυπτογράφησης πριν το cracking.
4. Ζητήστε μόνο επιλεγμένα tickets, σπάστε τα εκτός σύνδεσης, και μετά επανα-ερωτήστε το BloodHound με τα νέα δικαιώματα:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) απαριθμεί **Group Policy Objects** και επισημαίνει λανθασμένες ρυθμίσεις.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) πραγματοποιεί έναν **έλεγχο υγείας** του Active Directory και δημιουργεί μια αναφορά HTML με βαθμολόγηση κινδύνου.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Αναφορές

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
