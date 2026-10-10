# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Όπως ένα golden ticket**, ένα diamond ticket είναι ένα TGT που μπορεί να χρησιμοποιηθεί για **πρόσβαση σε οποιαδήποτε υπηρεσία ως οποιοσδήποτε χρήστης**. Ένα golden ticket πλαστογραφείται εξ ολοκλήρου offline, κρυπτογραφείται με το hash krbtgt του domain και έπειτα εισάγεται σε μια συνεδρία σύνδεσης για χρήση. Επειδή οι domain controllers δεν παρακολουθούν ποια TGT έχουν εκδώσει νόμιμα, αποδέχονται χωρίς πρόβλημα TGT που είναι κρυπτογραφημένα με το δικό τους hash krbtgt.<sup>[[1]](#references)</sup>

Υπάρχουν δύο συνήθεις τεχνικές για τον εντοπισμό της χρήσης golden tickets:

- Αναζητήστε TGS-REQs χωρίς αντίστοιχο AS-REQ.
- Αναζητήστε TGT με παράλογες τιμές, όπως την προεπιλεγμένη διάρκεια ζωής 10 ετών του Mimikatz.

Ένα **diamond ticket** δημιουργείται **τροποποιώντας τα πεδία ενός νόμιμου TGT που εκδόθηκε από DC**. Αυτό επιτυγχάνεται **ζητώντας** ένα **TGT**, **αποκρυπτογραφώντας** το με το hash krbtgt του domain, **τροποποιώντας** τα επιθυμητά πεδία του ticket και έπειτα **κρυπτογραφώντας το ξανά**. Έτσι **ξεπερνιούνται οι δύο προαναφερθείσες αδυναμίες** ενός golden ticket, επειδή:<sup>[[1]](#references)</sup>

- Τα TGS-REQs θα έχουν ένα προηγούμενο AS-REQ.
- Το TGT εκδόθηκε από DC, επομένως θα περιέχει όλα τα σωστά στοιχεία από την πολιτική Kerberos του domain. Παρότι μπορούν να πλαστογραφηθούν με ακρίβεια και σε ένα golden ticket, αυτό είναι πιο περίπλοκο και επιρρεπές σε λάθη.

### Προϋποθέσεις & ροή εργασίας

- **Κρυπτογραφικό υλικό**: το κλειδί krbtgt AES256 (προτιμάται) ή το hash NTLM, για την αποκρυπτογράφηση και την εκ νέου υπογραφή του TGT.
- **Νόμιμο blob TGT**: αποκτάται με `/tgtdeleg`, `asktgt`, `s4u` ή με εξαγωγή ticket από τη μνήμη.
- **Δεδομένα περιβάλλοντος**: το RID του χρήστη-στόχου, τα RID/SID των ομάδων και, προαιρετικά, χαρακτηριστικά PAC που προέρχονται από LDAP.
- **Κλειδιά υπηρεσίας** (μόνο αν σκοπεύετε να δημιουργήσετε ξανά service tickets): το κλειδί AES του SPN της υπηρεσίας που θα γίνει impersonate.

1. Αποκτήστε ένα TGT για οποιονδήποτε ελεγχόμενο χρήστη μέσω AS-REQ (το `/tgtdeleg` του Rubeus είναι βολικό, επειδή αναγκάζει τον client να εκτελέσει τη διαδικασία Kerberos GSS-API χωρίς διαπιστευτήρια).
2. Αποκρυπτογραφήστε το TGT που επιστράφηκε με το κλειδί krbtgt και τροποποιήστε τα χαρακτηριστικά PAC (χρήστης, ομάδες, πληροφορίες σύνδεσης, SID, device claims κ.λπ.).
3. Κρυπτογραφήστε/υπογράψτε ξανά το ticket με το ίδιο κλειδί krbtgt και εισαγάγετέ το στην τρέχουσα συνεδρία σύνδεσης (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Προαιρετικά, επαναλάβετε τη διαδικασία σε ένα service ticket, παρέχοντας ένα έγκυρο blob TGT μαζί με το κλειδί της υπηρεσίας-στόχου, για να παραμείνετε stealthy στο δίκτυο.

### Ενημερωμένες τεχνικές Rubeus (2024+)

Πρόσφατη δουλειά της Huntress εκσυγχρόνισε την ενέργεια `diamond` στο Rubeus, μεταφέροντας τις βελτιώσεις `/ldap` και `/opsec` που προηγουμένως υπήρχαν μόνο για golden/silver tickets. Το `/ldap` αντλεί πλέον πραγματικό πλαίσιο PAC κάνοντας ερωτήματα LDAP **και** προσαρτώντας το SYSVOL, ώστε να εξαγάγει χαρακτηριστικά λογαριασμών/ομάδων καθώς και την πολιτική Kerberos/κωδικών πρόσβασης (π.χ. `GptTmpl.inf`), ενώ το `/opsec` κάνει τη ροή AS-REQ/AS-REP να μοιάζει με εκείνη των Windows, εκτελώντας την ανταλλαγή preauth δύο βημάτων και επιβάλλοντας αποκλειστική χρήση AES και ρεαλιστικά KDCOptions. Έτσι μειώνονται σημαντικά οι προφανείς ενδείξεις, όπως πεδία PAC που λείπουν ή διάρκεια ζωής που δεν συμφωνεί με την πολιτική.<sup>[[3]](#references)</sup>

```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
  /opsec /nowrap
```

- `/ldap` (με προαιρετικά `/ldapuser` και `/ldappassword`) υποβάλλει ερωτήματα στο AD και στο SYSVOL για να αντιγράψει τα δεδομένα πολιτικής PAC του χρήστη-στόχου.
- Το `/opsec` επιβάλλει επανάληψη AS-REQ που προσομοιώνει τη συμπεριφορά των Windows, μηδενίζοντας flags που δημιουργούν θόρυβο και χρησιμοποιώντας μόνο AES256.
- Το `/tgtdeleg` δεν αγγίζει τον κωδικό πρόσβασης σε cleartext ή το κλειδί NTLM/AES του θύματος, ενώ εξακολουθεί να επιστρέφει ένα αποκρυπτογραφήσιμο TGT.

### Αναδημιουργία service ticket

Η ίδια ανανέωση του Rubeus πρόσθεσε τη δυνατότητα εφαρμογής της τεχνικής diamond σε TGS blobs. Παρέχοντας στο `diamond` ένα **TGT κωδικοποιημένο σε base64** (από `asktgt`, `/tgtdeleg` ή ένα TGT που έχει ήδη πλαστογραφηθεί), το **service SPN** και το **service AES key**, μπορείτε να δημιουργήσετε ρεαλιστικά service tickets χωρίς να επικοινωνήσετε με τον KDC — ουσιαστικά ένα πιο stealthy silver ticket.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Αυτή η ροή εργασίας είναι ιδανική όταν ελέγχετε ήδη ένα κλειδί λογαριασμού υπηρεσίας (π.χ. αντλημένο με `lsadump::lsa /inject` ή `secretsdump.py`) και θέλετε να δημιουργήσετε ένα εφάπαξ TGS που να ταιριάζει απόλυτα με την πολιτική AD, τα χρονικά όρια και τα δεδομένα PAC, χωρίς να δημιουργήσετε νέα κίνηση AS/TGS.<sup>[[3]](#references)</sup>

### Ανταλλαγές PAC τύπου Sapphire (2025)

Μια νεότερη παραλλαγή, που μερικές φορές αποκαλείται **sapphire ticket**, συνδυάζει τη βάση «real TGT» του Diamond με **S4U2self+U2U**, ώστε να υποκλέψει ένα προνομιούχο PAC και να το τοποθετήσει στο δικό σας TGT. Αντί να επινοείτε επιπλέον SIDs, ζητάτε ένα U2U S4U2self ticket για έναν χρήστη με υψηλά προνόμια, όπου το `sname` στοχεύει τον αιτούντα με χαμηλά προνόμια· το KRB_TGS_REQ περιέχει το TGT του αιτούντος στο `additional-tickets` και ορίζει το `ENC-TKT-IN-SKEY`, επιτρέποντας την αποκρυπτογράφηση του service ticket με το κλειδί αυτού του χρήστη. Έπειτα, εξάγετε το προνομιούχο PAC και το ενσωματώνετε στο νόμιμο TGT σας, πριν το υπογράψετε ξανά με το κλειδί krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Το `ticketer.py` του Impacket υποστηρίζει πλέον sapphire μέσω των `-impersonate` + `-request` (ζωντανή ανταλλαγή με KDC):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` δέχεται username ή SID· το `-request` απαιτεί ενεργά user creds και υλικό κλειδιού krbtgt (AES/NTLM) για αποκρυπτογράφηση/τροποποίηση των tickets.

Βασικές ενδείξεις OPSEC κατά τη χρήση αυτής της παραλλαγής:<sup>[[5]](#references)</sup>

- Το TGS-REQ θα περιέχει `ENC-TKT-IN-SKEY` και `additional-tickets` (το TGT του θύματος) — σπάνιο σε κανονική κίνηση.
- Το `sname` συχνά ισούται με τον χρήστη που υποβάλλει το αίτημα (πρόσβαση self-service) και το Event ID 4769 δείχνει τον καλούντα και τον στόχο ως το ίδιο SPN/user.
- Αναμένετε ζεύγη εγγραφών 4768/4769 με τον ίδιο υπολογιστή-πελάτη, αλλά διαφορετικά CNAMES (αιτών με χαμηλά προνόμια έναντι προνομιούχου κατόχου PAC).

### Σημειώσεις OPSEC και εντοπισμού

- Οι παραδοσιακές ευρετικές αναζήτησης (TGS χωρίς AS, διάρκεια ισχύος δεκαετιών) εξακολουθούν να ισχύουν για τα golden tickets, αλλά τα diamond tickets εντοπίζονται κυρίως όταν το **περιεχόμενο PAC ή η αντιστοίχιση ομάδων μοιάζει αδύνατη**. Συμπληρώστε κάθε πεδίο PAC (ώρες σύνδεσης, διαδρομές προφίλ χρήστη, ID συσκευών), ώστε οι αυτοματοποιημένες συγκρίσεις να μην επισημάνουν αμέσως την πλαστογράφηση.<sup>[[3]](#references)</sup>
- **Μην προσθέτετε υπερβολικά πολλές ομάδες/RID**. Αν χρειάζεστε μόνο τα `512` (Domain Admins) και `519` (Enterprise Admins), σταματήστε εκεί και βεβαιωθείτε ότι ο λογαριασμός-στόχος ανήκει εύλογα σε αυτές τις ομάδες σε άλλα σημεία του AD. Τα υπερβολικά `ExtraSids` προδίδουν την ενέργεια.
- Οι αλλαγές τύπου Sapphire αφήνουν ίχνη U2U: `ENC-TKT-IN-SKEY` + `additional-tickets`, μαζί με `sname` που παραπέμπει σε χρήστη (συχνά στον αιτούντα) στο 4769, και ένα επακόλουθο logon 4624 που προέρχεται από το πλαστό ticket. Συσχετίστε αυτά τα πεδία αντί να αναζητάτε μόνο κενά no-AS-REQ.<sup>[[5]](#references)</sup>
- Η Microsoft άρχισε να καταργεί σταδιακά την **έκδοση service ticket μέσω RC4** λόγω του CVE-2026-20833· η επιβολή etypes μόνο AES στο KDC ενισχύει το domain και ευθυγραμμίζεται με τα εργαλεία diamond/sapphire (το /opsec επιβάλλει ήδη AES). Η ανάμειξη RC4 σε πλαστά PAC θα ξεχωρίζει ολοένα και περισσότερο.<sup>[[6]](#references)</sup>
- Το έργο Security Content της Splunk διανέμει τηλεμετρία attack-range για diamond tickets, καθώς και detections όπως το *Windows Domain Admin Impersonation Indicator*, το οποίο συσχετίζει ασυνήθιστες ακολουθίες Event ID 4768/4769/4624 και αλλαγές ομάδων PAC. Η αναπαραγωγή αυτού του dataset (ή η δημιουργία δικού σας με τις παραπάνω εντολές) βοηθά στην επικύρωση της κάλυψης του SOC για το T1558.001, ενώ σας δίνει συγκεκριμένη λογική ειδοποιήσεων προς αποφυγή.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Πολύτιμοι λίθοι: Η νέα γενιά επιθέσεων Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Μας αρέσει να παίζουμε με tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Αναδιαμόρφωση του Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Δεδομένα επιθέσεων και detections για Diamond Ticket (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Η σκιώδης πλευρά των πολύτιμων λίθων: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Επιβολή service ticket RC4 για το CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
