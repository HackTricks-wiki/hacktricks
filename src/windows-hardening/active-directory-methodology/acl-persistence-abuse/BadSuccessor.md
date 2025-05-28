# Κατάχρηση ACLs/ACEs του Active Directory

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Delegated Managed Service Accounts (dMSAs) είναι ένας εντελώς νέος τύπος AD principal που εισήχθη με το Windows Server 2025. Είναι σχεδιασμένα να αντικαταστήσουν τους παλιούς λογαριασμούς υπηρεσιών επιτρέποντας μια “μετανάστευση” με ένα κλικ που αντιγράφει αυτόματα τα Service Principal Names (SPNs), τις συμμετοχές σε ομάδες, τις ρυθμίσεις αντιπροσώπευσης και ακόμη και τα κρυπτογραφικά κλειδιά του παλιού λογαριασμού στο νέο dMSA, παρέχοντας στις εφαρμογές μια απρόσκοπτη μετάβαση και εξαλείφοντας τον κίνδυνο Kerberoasting.

Οι ερευνητές της Akamai διαπίστωσαν ότι ένα μόνο χαρακτηριστικό — **`msDS‑ManagedAccountPrecededByLink`** — λέει στο KDC ποιος παλιός λογαριασμός “διαδέχεται” ένα dMSA. Εάν ένας επιτιθέμενος μπορεί να γράψει αυτό το χαρακτηριστικό (και να αλλάξει το **`msDS‑DelegatedMSAState` → 2**), το KDC θα δημιουργήσει ευχαρίστως ένα PAC που **κληρονομεί κάθε SID του επιλεγμένου θύματος**, επιτρέποντας αποτελεσματικά στο dMSA να προσποιείται οποιονδήποτε χρήστη, συμπεριλαμβανομένων των Domain Admins.

## Τι ακριβώς είναι ένα dMSA;

* Βασισμένο στην τεχνολογία **gMSA** αλλά αποθηκευμένο ως η νέα κλάση AD **`msDS‑DelegatedManagedServiceAccount`**.
* Υποστηρίζει μια **μετανάστευση opt-in**: η κλήση `Start‑ADServiceAccountMigration` συνδέει το dMSA με τον παλιό λογαριασμό, παραχωρεί στον παλιό λογαριασμό δικαιώματα εγγραφής στο `msDS‑GroupMSAMembership`, και αλλάζει το `msDS‑DelegatedMSAState` = 1.
* Μετά την `Complete‑ADServiceAccountMigration`, ο υπερκερασμένος λογαριασμός απενεργοποιείται και το dMSA γίνεται πλήρως λειτουργικό; οποιοσδήποτε υπολογιστής που χρησιμοποιούσε προηγουμένως τον παλιό λογαριασμό είναι αυτόματα εξουσιοδοτημένος να αντλήσει τον κωδικό πρόσβασης του dMSA.
* Κατά την αυθεντικοποίηση, το KDC ενσωματώνει μια ένδειξη **KERB‑SUPERSEDED‑BY‑USER** ώστε οι πελάτες Windows 11/24H2 να προσπαθούν διαφανώς ξανά με το dMSA.

## Απαιτήσεις για επίθεση
1. ** Τουλάχιστον ένας Windows Server 2025 DC** ώστε να υπάρχουν η κλάση LDAP του dMSA και η λογική KDC.
2. **Οποιαδήποτε δικαιώματα δημιουργίας αντικειμένων ή εγγραφής χαρακτηριστικών σε ένα OU** (οποιοδήποτε OU) – π.χ. `Create msDS‑DelegatedManagedServiceAccount` ή απλά **Create All Child Objects**. Η Akamai διαπίστωσε ότι το 91% των πραγματικών ενοικιαστών παραχωρούν τέτοιες “αθώες” άδειες OU σε μη διαχειριστές.
3. Δυνατότητα εκτέλεσης εργαλείων (PowerShell/Rubeus) από οποιονδήποτε υπολογιστή που έχει συνδεθεί στο domain για να ζητήσει Kerberos tickets.
*Δεν απαιτείται έλεγχος του θύματος χρήστη; η επίθεση δεν αγγίζει ποτέ τον στόχο λογαριασμό απευθείας.*

## Βήμα προς βήμα: BadSuccessor*κλιμάκωση προνομίων

1. **Εντοπίστε ή δημιουργήστε ένα dMSA που ελέγχετε**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Επειδή δημιουργήσατε το αντικείμενο μέσα σε ένα OU που μπορείτε να γράψετε, κατέχετε αυτόματα όλα τα χαρακτηριστικά του.

2. **Προσομοιώστε μια “ολοκληρωμένη μετανάστευση” σε δύο εγγραφές LDAP**:
- Ορίστε `msDS‑ManagedAccountPrecededByLink = DN` οποιουδήποτε θύματος (π.χ. `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Ορίστε `msDS‑DelegatedMSAState = 2` (ολοκλήρωση μετανάστευσης).

Εργαλεία όπως **Set‑ADComputer, ldapmodify**, ή ακόμη και **ADSI Edit** λειτουργούν; δεν απαιτούνται δικαιώματα διαχειριστή τομέα.

3. **Ζητήστε ένα TGT για το dMSA** — το Rubeus υποστηρίζει τη σημαία `/dmsa`:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

Το επιστρεφόμενο PAC περιέχει τώρα το SID 500 (Διαχειριστής) συν τις ομάδες Domain Admins/Enterprise Admins.

## Συγκέντρωση όλων των κωδικών πρόσβασης χρηστών

Κατά τη διάρκεια νόμιμων μεταναστεύσεων, το KDC πρέπει να επιτρέπει στο νέο dMSA να αποκρυπτογραφεί **εισιτήρια που εκδόθηκαν στον παλιό λογαριασμό πριν από την μετάβαση**. Για να αποφευχθεί η διακοπή ζωντανών συνεδριών, τοποθετεί τόσο τα τρέχοντα κλειδιά όσο και τα προηγούμενα κλειδιά μέσα σε ένα νέο ASN.1 blob που ονομάζεται **`KERB‑DMSA‑KEY‑PACKAGE`**.

Επειδή η ψεύτικη μετανάστευσή μας ισχυρίζεται ότι το dMSA διαδέχεται το θύμα, το KDC αντιγράφει πιστά το κλειδί RC4‑HMAC του θύματος στη λίστα **previous‑keys** – ακόμη και αν το dMSA δεν είχε ποτέ έναν “προηγούμενο” κωδικό πρόσβασης. Αυτό το κλειδί RC4 είναι μη αλατισμένο, επομένως είναι ουσιαστικά το NT hash του θύματος, δίνοντας στον επιτιθέμενο **δυνατότητα offline cracking ή “pass‑the‑hash”**.

Επομένως, η μαζική σύνδεση χιλιάδων χρηστών επιτρέπει σε έναν επιτιθέμενο να εκφορτώσει hashes “σε κλίμακα”, μετατρέποντας το **BadSuccessor σε έναν μηχανισμό κλιμάκωσης προνομίων και παραβίασης διαπιστευτηρίων**.

## Εργαλεία

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## Αναφορές

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)


{{#include ../../../banners/hacktricks-training.md}}
