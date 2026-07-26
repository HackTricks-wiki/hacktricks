# BloodHound & Άλλα Εργαλεία Enumeration του Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> ΣΗΜΕΙΩΣΗ: Αυτή η σελίδα συγκεντρώνει ορισμένα από τα πιο χρήσιμα utilities για **enumerate** και **visualise** τις σχέσεις του Active Directory. Για collection μέσω του stealthy καναλιού **Active Directory Web Services (ADWS)**, δείτε την παραπάνω αναφορά.

---

## AD Explorer

Το [AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) είναι ένας προηγμένος **AD viewer & editor**, ο οποίος επιτρέπει:

* Περιήγηση στο directory tree μέσω GUI
* Επεξεργασία attributes αντικειμένων και security descriptors
* Δημιουργία / σύγκριση snapshots για offline analysis

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

Το [BloodHound](https://github.com/SpecterOps/BloodHound) χρησιμοποιεί τη θεωρία γράφων για να αποκαλύψει κρυφές σχέσεις προνομίων μέσα σε on-prem AD, Entra ID και οποιαδήποτε επιπλέον δεδομένα attack surface εισάγετε μέσω OpenGraph.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Συλλέκτες

* `SharpHound.exe` / `Invoke-BloodHound` – native ή PowerShell variant
* `RustHound-CE` – cross-platform CE collector για Linux, macOS και Windows
* `NetExec --bloodhound` – γρήγορη συλλογή μέσω LDAP από Linux
* `AzureHound` – enumeration του Entra ID
* **SoaPy + BOFHound** – συλλογή μέσω ADWS (δείτε το link στην κορυφή)

> Το BloodHound CE `v8+` άλλαξε το format εξόδου του collector όταν ενσωματώθηκε το OpenGraph. Μετά την αναβάθμιση από legacy BloodHound ή παλαιότερες εγκαταστάσεις CE, εκτελέστε ξανά discovery με τους τρέχοντες collectors πριν κάνετε import τα δεδομένα.

#### Συνήθεις λειτουργίες SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Οι collectors δημιουργούν JSON, το οποίο εισάγεται μέσω του BloodHound GUI.

#### SharpHound από Windows host που δεν είναι ενταγμένο σε domain

Αν το operator VM δεν είναι ενταγμένο στο target domain, ρύθμισε το DNS ώστε να δείχνει σε έναν DC, εκκίνησε ένα **network-only** shell, επαλήθευσε ότι μπορείς να δεις τα `SYSVOL`/`NETLOGON` σε έναν DC και, στη συνέχεια, κάνε collect στο remote domain:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Αυτό είναι χρήσιμο για προσωρινά jump boxes ή operator workstations που δεν θα πρέπει να είναι domain-joined.

#### Συλλογή πολλαπλών πλατφορμών από Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
Το `RustHound-CE` είναι μια καλή προεπιλογή όταν θέλετε έξοδο συμβατή με το CE από host εκτός Windows. Το `NetExec` είναι πρακτικό όταν το χρησιμοποιείτε ήδη για LDAP validation ή spraying και θέλετε μια γρήγορη εισαγωγή στο graph. Για datasets εκτός AD, το BloodHound OpenGraph μπορεί να επεκταθεί με collectors όπως το [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### ADPathFinder (ιεράρχηση διαδρομών OpenGraph)

Το [ADPathFinder](https://github.com/NetSPI/AD-PathFinder) λειτουργεί πάνω από το BloodHound CE/OpenGraph όταν το graph είναι πολύ μεγάλο για χειροκίνητο pivoting. Αντί να εξετάζει μόνο αν ένα principal μπορεί να αποκτήσει πρόσβαση σε έναν στόχο, υπολογίζει τις συντομότερες διαδρομές από πολλούς χρήστες και υπολογιστές με χαμηλά δικαιώματα προς αντικείμενα υψηλής αξίας, ομαδοποιεί τις διαδρομές που επαναχρησιμοποιούν τα ίδια edges και αναδεικνύει το κοινό bottleneck που πρέπει να αποκατασταθεί πρώτο.
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Με τα δεδομένα των `MSSQLHound` και `ConfigManBearPig` εισαγμένα, ένα εύρημα μπορεί να διατρέχει τα [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) και [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), αντί να τα αφήνει ως ξεχωριστά leads. Παράδειγμα κοινής διαδρομής:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Παρακολουθείτε το **effective security context** σε κάθε ακμή. Μια διαδρομή γίνεται κρίσιμη για το domain μόλις μία μετάβαση εκτελεστεί ως privileged domain identity, ακόμη κι αν ξεκίνησε από έναν κανονικό χρήστη.
- Τα ομαδοποιημένα ευρήματα είναι ιδανικά για **choke-point remediation**: η αφαίρεση μίας permission για SQL impersonation, ενός linked-server trust, μίας certificate-template abuse path ή μίας SCCM assignment μπορεί να καταργήσει πολλές συντομότερες διαδρομές ταυτόχρονα.
- Επαναξιολογήστε τα "medium" ευρήματα με **graph context**. Το απενεργοποιημένο SMB signing, η έκθεση του WebClient, τα delegation mistakes ή οι NTLM-relayable SQL servers αξίζουν υψηλότερη προτεραιότητα όταν ο compromised node έχει onward paths προς Domain Admins, Domain Controllers, CAs ή SCCM site servers.
- Αν έχετε επίσης output από `NTDS.dit` και ένα hashcat potfile, το `--pwd` συσχετίζει τα cracked passwords με τις ιδιότητες του BloodHound, ώστε να ξεχωρίζετε γρήγορα το συνηθισμένο password reuse από cracked creds σε privileged, Kerberoastable, AS-REP roastable ή path-relevant accounts.

### Συλλογή privilege & logon-rights

Τα Windows **token privileges** (π.χ. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) μπορούν να παρακάμψουν τους ελέγχους DACL, επομένως η χαρτογράφησή τους σε ολόκληρο το domain αποκαλύπτει local LPE edges που δεν εμφανίζονται σε ACL-only graphs. Τα **logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` και τα αντίστοιχα `SeDeny*`) εφαρμόζονται από το LSA πριν υπάρξει καν token, ενώ οι deny κανόνες έχουν προτεραιότητα. Επομένως περιορίζουν ουσιαστικά το lateral movement (RDP/SMB/scheduled task/service logon).

**Εκτελείτε τους collectors με elevated δικαιώματα** όταν είναι δυνατό: το UAC δημιουργεί filtered token για interactive admins (μέσω `NtFilterToken`), αφαιρώντας sensitive privileges και επισημαίνοντας τα admin SIDs ως deny-only. Αν απαριθμήσετε privileges από non-elevated shell, τα high-value privileges δεν θα είναι ορατά και το BloodHound δεν θα κάνει ingest τα edges.

Υπάρχουν πλέον δύο συμπληρωματικές στρατηγικές συλλογής στο SharpHound:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Απαριθμήστε τα GPOs μέσω LDAP (`(objectCategory=groupPolicyContainer)`) και διαβάστε το `gPCFileSysPath` κάθε GPO.
2. Ανακτήστε το `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` από το SYSVOL και κάντε parse την ενότητα `[Privilege Rights]`, η οποία αντιστοιχίζει privilege/logon-right names σε SIDs.
3. Επιλύστε τα GPO links μέσω του `gPLink` σε OUs/sites/domains, εμφανίστε τους υπολογιστές στα linked containers και αποδώστε τα rights σε αυτά τα machines.
4. Πλεονέκτημα: λειτουργεί με normal user και είναι quiet· μειονέκτημα: βλέπει μόνο τα rights που εφαρμόζονται μέσω GPO (τυχόν local tweaks δεν εντοπίζονται).

- **LSA RPC enumeration (noisy, accurate):**
- Από context με local admin στο target, ανοίξτε το Local Security Policy και καλέστε το `LsaEnumerateAccountsWithUserRight` για κάθε privilege/logon right, ώστε να απαριθμήσετε μέσω RPC τα principals στα οποία έχουν εκχωρηθεί.
- Πλεονέκτημα: καταγράφει rights που έχουν οριστεί locally ή εκτός GPO· μειονέκτημα: noisy network traffic και απαίτηση για admin σε κάθε host.

**Παράδειγμα abuse path που αποκαλύπτεται από αυτά τα edges:** `CanRDP` ➜ host όπου ο user σας έχει επίσης `SeBackupPrivilege` ➜ εκκίνηση elevated shell για αποφυγή filtered tokens ➜ χρήση backup semantics για ανάγνωση των hives `SAM` και `SYSTEM` παρά τα restrictive DACLs ➜ exfiltration και εκτέλεση του `secretsdump.py` offline για ανάκτηση του local Administrator NT hash με σκοπό lateral movement/privilege escalation.

### Prioritising Kerberoasting με BloodHound

Χρησιμοποιήστε graph context ώστε το roasting να παραμένει στοχευμένο:

1. Κάντε μία συλλογή με ADWS-compatible collector και εργαστείτε offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Κάντε import το ZIP, σημειώστε το compromised principal ως owned και εκτελέστε τα built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) για να εντοπίσετε SPN accounts με admin/infra rights.
3. Δώστε προτεραιότητα στα SPNs με βάση το blast radius· ελέγξτε τα `pwdLastSet`, `lastLogon` και τα επιτρεπόμενα encryption types πριν από το cracking.
4. Ζητήστε μόνο τα επιλεγμένα tickets, κάντε crack offline και, στη συνέχεια, εκτελέστε νέο query στο BloodHound με το νέο access:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

Το [Group3r](https://github.com/Group3r/Group3r) απαριθμεί **Group Policy Objects** και επισημαίνει misconfigurations.
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

- [BloodHound Community Edition v8 κυκλοφορεί με OpenGraph: Identity Attack Paths πέρα από τα Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Πέρα από τα ACLs: Χαρτογράφηση Windows Privilege Escalation Paths με το BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: Χαρτογράφηση OpenGraph Attack Paths στο BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
