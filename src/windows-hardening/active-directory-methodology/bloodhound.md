# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> ΣΗΜΕΙΩΣΗ: Αυτή η σελίδα συγκεντρώνει μερικά από τα πιο χρήσιμα utilities για την **enumerate** και **visualise** των σχέσεων στο Active Directory. Για συλλογή μέσω του stealthy καναλιού **Active Directory Web Services (ADWS)**, δείτε την παραπάνω αναφορά.

---

## AD Explorer

Το [AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) είναι ένας προηγμένος **AD viewer & editor** που επιτρέπει:

* Περιήγηση στο δέντρο του directory μέσω GUI
* Επεξεργασία attributes αντικειμένων και security descriptors
* Δημιουργία / σύγκριση snapshots για offline ανάλυση

### Γρήγορη χρήση

1. Εκκινήστε το tool και συνδεθείτε στο `dc01.corp.local` με οποιαδήποτε domain credentials.
2. Δημιουργήστε ένα offline snapshot μέσω του `File ➜ Create Snapshot`.
3. Συγκρίνετε δύο snapshots με το `File ➜ Compare` για να εντοπίσετε permission drifts.

---

## ADRecon

Το [ADRecon](https://github.com/adrecon/ADRecon) εξάγει ένα μεγάλο σύνολο artefacts από ένα domain (ACLs, GPOs, trusts, CA templates …) και δημιουργεί ένα **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (οπτικοποίηση γράφου)

Το [BloodHound](https://github.com/SpecterOps/BloodHound) χρησιμοποιεί τη θεωρία γράφων για να αποκαλύψει κρυφές σχέσεις προνομίων μέσα σε on-prem AD, Entra ID και οποιαδήποτε επιπλέον δεδομένα attack-surface εισάγετε μέσω του OpenGraph.<sup>[[1]](#references)</sup>

### Ανάπτυξη (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Συλλέκτες

* `SharpHound.exe` / `Invoke-BloodHound` – native ή PowerShell variant
* `RustHound-CE` – cross-platform CE collector για Linux, macOS και Windows
* `NetExec --bloodhound` – γρήγορη συλλογή μέσω LDAP από Linux
* `AzureHound` – απαρίθμηση Entra ID
* **SoaPy + BOFHound** – συλλογή μέσω ADWS (δείτε το link στην κορυφή)

> Το BloodHound CE `v8+` άλλαξε τη μορφή εξόδου του collector όταν ενσωματώθηκε το OpenGraph. Μετά την αναβάθμιση από legacy BloodHound ή παλαιότερες εγκαταστάσεις CE, εκτελέστε ξανά το discovery με current collectors πριν από την εισαγωγή των δεδομένων.<sup>[[1]](#references)</sup>

#### Συνήθεις λειτουργίες SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Οι collectors δημιουργούν JSON, το οποίο γίνεται ingest μέσω του BloodHound GUI.

#### SharpHound από Windows host που δεν είναι συνδεδεμένο σε domain

Αν το operator VM σας δεν είναι joined στο target domain, ρυθμίστε το DNS ώστε να δείχνει σε έναν DC, εκκινήστε ένα **network-only** shell, επαληθεύστε ότι μπορείτε να δείτε τα `SYSVOL`/`NETLOGON` σε έναν DC και, στη συνέχεια, εκτελέστε τη συλλογή έναντι του remote domain:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Αυτό είναι χρήσιμο για προσωρινά jump boxes ή σταθμούς εργασίας χειριστών που δεν θα πρέπει να είναι συνδεδεμένοι στο domain.

#### Συλλογή μεταξύ πλατφορμών από Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` είναι μια καλή προεπιλογή όταν θέλετε έξοδο συμβατή με το CE από host που δεν είναι Windows.<sup>[[2]](#references)</sup> Το `NetExec` είναι πρακτικό όταν το χρησιμοποιείτε ήδη για LDAP validation ή spraying και θέλετε ένα γρήγορο graph import. Για non-AD datasets, το BloodHound OpenGraph μπορεί να επεκταθεί με collectors όπως το [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (προτεραιοποίηση διαδρομών OpenGraph)

Το [ADPathFinder](https://github.com/NetSPI/AD-PathFinder) λειτουργεί πάνω από το BloodHound CE/OpenGraph όταν το graph είναι υπερβολικά μεγάλο για χειροκίνητο pivot. Αντί να εξετάζει μόνο αν ένας principal μπορεί να φτάσει σε έναν target, υπολογίζει τις συντομότερες διαδρομές από πολλούς low-privileged users και computers προς high-value objects, ομαδοποιεί τις διαδρομές που επαναχρησιμοποιούν τα ίδια edges και εμφανίζει το κοινό choke point που πρέπει να αποκατασταθεί πρώτο.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Με τα δεδομένα των `MSSQLHound` και `ConfigManBearPig` εισαγμένα, ένα εύρημα μπορεί να συνδέσει τα [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) και [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), αντί να τα αφήσει ως ξεχωριστές ενδείξεις.<sup>[[4]](#references)</sup> Παράδειγμα κοινής διαδρομής:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Παρακολουθείτε το **effective security context** σε κάθε ακμή. Μια διαδρομή γίνεται κρίσιμη για το domain μόλις μία μετάβαση εκτελεστεί ως privileged domain identity, ακόμη και αν ξεκίνησε από κανονικό χρήστη.
- Τα ομαδοποιημένα ευρήματα είναι ιδανικά για **choke-point remediation**: η αφαίρεση μίας permission για SQL impersonation, ενός linked-server trust, μίας διαδρομής abuse certificate-template ή μίας ανάθεσης SCCM μπορεί να καταργήσει πολλές shortest paths ταυτόχρονα.
- Επαναξιολογήστε τα ευρήματα "medium" με βάση το **graph context**. Το απενεργοποιημένο SMB signing, η έκθεση του WebClient, τα λάθη delegation ή οι SQL servers που μπορούν να υποστούν NTLM relay αξίζουν υψηλότερη προτεραιότητα όταν ο compromised node έχει onward paths προς Domain Admins, Domain Controllers, CAs ή SCCM site servers.
- Αν διαθέτετε επίσης output από `NTDS.dit` και ένα hashcat potfile, το `--pwd` συσχετίζει τα cracked passwords με τις BloodHound properties, ώστε να ξεχωρίζετε γρήγορα τη συνήθη επαναχρησιμοποίηση password από cracked creds σε privileged, Kerberoastable, AS-REP roastable ή path-relevant accounts.

### Συλλογή privilege & logon-right

Τα Windows **token privileges** (π.χ. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) μπορούν να παρακάμψουν ελέγχους DACL, επομένως η χαρτογράφησή τους σε ολόκληρο το domain αποκαλύπτει local LPE edges που δεν εμφανίζονται σε graphs βασισμένα μόνο σε ACL. Τα **logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` και τα αντίστοιχα `SeDeny*`) εφαρμόζονται από το LSA πριν υπάρξει καν token, ενώ οι deny ρυθμίσεις έχουν προτεραιότητα. Επομένως, ελέγχουν ουσιαστικά το lateral movement (RDP/SMB/scheduled task/service logon).<sup>[[3]](#references)</sup>

**Εκτελείτε τους collectors με elevated privileges** όταν είναι δυνατό: το UAC δημιουργεί filtered token για interactive admins (μέσω `NtFilterToken`), αφαιρώντας sensitive privileges και χαρακτηρίζοντας τα admin SIDs ως deny-only. Αν κάνετε enumerate τα privileges από non-elevated shell, τα high-value privileges δεν θα είναι ορατά και το BloodHound δεν θα ingest τα edges.<sup>[[3]](#references)</sup>

Πλέον υπάρχουν δύο συμπληρωματικές στρατηγικές συλλογής με SharpHound:<sup>[[3]](#references)</sup>

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Κάντε enumerate τα GPOs μέσω LDAP (`(objectCategory=groupPolicyContainer)`) και διαβάστε το `gPCFileSysPath` του καθενός.
2. Κάντε fetch το `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` από το SYSVOL και κάντε parse την ενότητα `[Privilege Rights]`, η οποία αντιστοιχίζει privilege/logon-right names σε SIDs.
3. Κάντε resolve τα GPO links μέσω του `gPLink` σε OUs/sites/domains, εμφανίστε τους υπολογιστές στα linked containers και αποδώστε τα δικαιώματα σε αυτά τα machines.
4. Πλεονέκτημα: λειτουργεί με normal user και είναι quiet· μειονέκτημα: βλέπει μόνο rights που προωθούνται μέσω GPO (οι local tweaks δεν εντοπίζονται).

- **LSA RPC enumeration (noisy, accurate):**
- Από context με local admin στο target, ανοίξτε το Local Security Policy και καλέστε το `LsaEnumerateAccountsWithUserRight` για κάθε privilege/logon right, ώστε να κάνετε enumerate τους assigned principals μέσω RPC.
- Πλεονέκτημα: καταγράφει rights που έχουν οριστεί locally ή εκτός GPO· μειονέκτημα: noisy network traffic και απαίτηση admin σε κάθε host.

**Παράδειγμα abuse path που αποκαλύπτεται από αυτά τα edges:** `CanRDP` ➜ host όπου ο user σας έχει επίσης `SeBackupPrivilege` ➜ εκκινήστε elevated shell για να αποφύγετε τα filtered tokens ➜ χρησιμοποιήστε backup semantics για να διαβάσετε τα `SAM` και `SYSTEM` hives παρά τα restrictive DACLs ➜ κάντε exfiltrate και εκτελέστε το `secretsdump.py` offline για να ανακτήσετε το local Administrator NT hash για lateral movement/privilege escalation.<sup>[[3]](#references)</sup>

### Ιεράρχηση του Kerberoasting με BloodHound

Χρησιμοποιήστε το graph context ώστε το roasting να παραμένει στοχευμένο:

1. Κάντε συλλογή μία φορά με ADWS-compatible collector και εργαστείτε offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Κάντε import το ZIP, σημειώστε τον compromised principal ως owned και εκτελέστε τα ενσωματωμένα queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) για να εντοπίσετε SPN accounts με admin/infra rights.
3. Δώστε προτεραιότητα στα SPNs με βάση το blast radius· ελέγξτε τα `pwdLastSet`, `lastLogon` και τα επιτρεπόμενα encryption types πριν από το cracking.
4. Ζητήστε μόνο τα επιλεγμένα tickets, κάντε crack offline και, στη συνέχεια, εκτελέστε ξανά query στο BloodHound με τη νέα πρόσβαση:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

Το [Group3r](https://github.com/Group3r/Group3r) κάνει enumerate τα **Group Policy Objects** και επισημαίνει misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

Το [PingCastle](https://www.pingcastle.com/documentation/) εκτελεί έναν **έλεγχο υγείας** του Active Directory και δημιουργεί μια αναφορά HTML με βαθμολόγηση κινδύνου.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Αναφορές

- [1] [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: OpenGraph Attack Path Mapping in BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
