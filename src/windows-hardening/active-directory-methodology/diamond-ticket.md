# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket είναι ένα TGT το οποίο μπορεί να χρησιμοποιηθεί για να **έχει πρόσβαση σε οποιαδήποτε υπηρεσία ως οποιοσδήποτε χρήστης**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Ψάξτε για TGS-REQs που δεν έχουν αντίστοιχο AS-REQ.
- Αναζητήστε TGTs που έχουν αστείες τιμές, όπως το default 10-year lifetime του Mimikatz.

A **diamond ticket** κατασκευάζεται με το **τροποποιήσεις των πεδίων ενός νόμιμου TGT που εκδόθηκε από έναν DC**. Αυτό επιτυγχάνεται με το **αιτηθείτε** ένα **TGT**, **αποκρυπτογραφήστε** το με το krbtgt hash του domain, **τροποποιήστε** τα επιθυμητά πεδία του ticket, και στη συνέχεια **επαν-κρυπτογραφήστε το**. Αυτό **υπερπηδάει τις δύο προαναφερθείσες αδυναμίες** ενός golden ticket επειδή:

- TGS-REQs θα έχουν ένα προγενέστερο AS-REQ.
- Το TGT εκδόθηκε από έναν DC που σημαίνει ότι θα έχει όλες τις σωστές λεπτομέρειες από την Kerberos policy του domain. Αν και αυτά μπορούν να παραχαραχτούν με ακρίβεια σε ένα golden ticket, είναι πιο περίπλοκο και επιρρεπές σε λάθη.

### Requirements & workflow

- **Cryptographic material**: το krbtgt AES256 key (προτιμητέο) ή το NTLM hash για να αποκρυπτογραφήσετε και να ξανα-υπογράψετε το TGT.
- **Legitimate TGT blob**: αποκτήθηκε με `/tgtdeleg`, `asktgt`, `s4u`, ή εξάγοντας tickets από τη μνήμη.
- **Context data**: το target user RID, group RIDs/SIDs, και (προαιρετικά) LDAP-derived PAC attributes.
- **Service keys** (μόνο αν σκοπεύετε να re-cut service tickets): AES key της service SPN που θα υποδυθείτε.

1. Αποκτήστε ένα TGT για οποιονδήποτε ελεγχόμενο χρήστη μέσω AS-REQ (Rubeus `/tgtdeleg` είναι βολικό γιατί αναγκάζει τον client να εκτελέσει το Kerberos GSS-API dance χωρίς credentials).
2. Αποκρυπτογραφήστε το επιστρεφόμενο TGT με το krbtgt key, τροποποιήστε/patch τα PAC attributes (user, groups, logon info, SIDs, device claims, κ.λπ.).
3. Επαν-κρυπτογραφήστε/υπογράψτε το ticket με το ίδιο krbtgt key και εισάγετέ το στην τρέχουσα συνεδρία σύνδεσης (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Προαιρετικά, επαναλάβετε τη διαδικασία σε ένα service ticket παρέχοντας ένα έγκυρο TGT blob μαζί με το target service key για να παραμείνετε αθόρυβοι στο δίκτυο.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) κάνει ερωτήματα στο AD και στο SYSVOL για να καθρεφτίσει τα δεδομένα πολιτικής PAC του χρήστη-στόχου.
- `/opsec` αναγκάζει μια Windows-like AS-REQ retry, μηδενίζοντας τα noisy flags και χρησιμοποιώντας AES256.
- `/tgtdeleg` κρατάει τα χέρια σας μακριά από το cleartext password ή το NTLM/AES key του θύματος, ενώ εξακολουθεί να επιστρέφει ένα TGT που μπορεί να αποκρυπτογραφηθεί.

### Service-ticket recutting

Η ίδια ανανέωση του Rubeus πρόσθεσε τη δυνατότητα εφαρμογής της τεχνικής diamond σε TGS blobs. Τροφοδοτώντας το `diamond` με ένα **base64-encoded TGT** (από `asktgt`, `/tgtdeleg`, ή ένα προηγουμένως forged TGT), το **service SPN**, και το **service AES key**, μπορείτε να mint ρεαλιστικά service tickets χωρίς να αγγίξετε τον KDC — ουσιαστικά ένα πιο stealthier silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Αυτή η ροή εργασίας είναι ιδανική όταν ήδη ελέγχετε ένα κλειδί λογαριασμού υπηρεσίας (π.χ., αποσπασμένο με `lsadump::lsa /inject` ή `secretsdump.py`) και θέλετε να κόψετε ένα εφάπαξ TGS που ταιριάζει τέλεια με την πολιτική του AD, τα χρονοδιαγράμματα και τα δεδομένα PAC χωρίς να εκδώσετε νέο AS/TGS traffic.

### OPSEC & σημειώσεις ανίχνευσης

- Οι παραδοσιακοί κανόνες ανίχνευσης (TGS χωρίς AS, διάρκειες ζωής δεκαετίας) εξακολουθούν να ισχύουν για golden tickets, αλλά τα diamond tickets κυρίως εμφανίζονται όταν το **περιεχόμενο του PAC ή η αντιστοίχιση ομάδων φαίνεται αδύνατη**. Συμπληρώστε κάθε πεδίο του PAC (logon hours, user profile paths, device IDs) ώστε οι αυτοματοποιημένες συγκρίσεις να μην επισημάνουν αμέσως την πλαστογράφηση.
- **Μην υπερσυνδρομήσετε ομάδες/RIDs**. Εάν χρειάζεστε μόνο `512` (Domain Admins) και `519` (Enterprise Admins), σταματήστε εκεί και βεβαιωθείτε ότι ο λογαριασμός-στόχος ανήκει εύλογα σε αυτές τις ομάδες σε κάποιο άλλο σημείο του AD. Η υπερβολική χρήση `ExtraSids` προδίδει την πλαστογράφηση.
- Το Security Content project της Splunk διανέμει attack-range telemetry για diamond tickets καθώς και ανιχνεύσεις όπως το Windows Domain Admin Impersonation Indicator, το οποίο συσχετίζει ασυνήθιστες ακολουθίες Event ID 4768/4769/4624 και αλλαγές στις ομάδες του PAC. Η επανεκτέλεση αυτού του dataset (ή η δημιουργία δικού σας με τις παραπάνω εντολές) βοηθά στην επικύρωση της κάλυψης SOC για T1558.001 ενώ σας παρέχει συγκεκριμένη λογική ειδοποίησης για να αποφύγετε.

## Αναφορές

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
