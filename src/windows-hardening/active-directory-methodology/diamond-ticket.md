# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Όπως ένα golden ticket**, ένα diamond ticket είναι ένα TGT που μπορεί να χρησιμοποιηθεί για **πρόσβαση σε οποιαδήποτε υπηρεσία ως οποιονδήποτε χρήστη**. Ένα golden ticket κατασκευάζεται εντελώς offline, κρυπτογραφημένο με το krbtgt hash εκείνου του domain, και στη συνέχεια εισάγεται σε μια συνεδρία σύνδεσης για χρήση. Επειδή οι domain controllers δεν παρακολουθούν TGTs που έχουν νόμιμα εκδώσει, θα δέχονται με ευχαρίστηση TGTs που είναι κρυπτογραφημένα με το δικό τους krbtgt hash.

Υπάρχουν δύο κοινές τεχνικές για την ανίχνευση της χρήσης golden tickets:

- Αναζητήστε TGS-REQs που δεν έχουν αντίστοιχο AS-REQ.
- Αναζητήστε TGTs με ύποπτες τιμές, όπως η προεπιλεγμένη διάρκεια ζωής 10 ετών του Mimikatz.

Ένα **diamond ticket** δημιουργείται με την **τροποποίηση των πεδίων ενός νόμιμου TGT που εκδόθηκε από DC**. Αυτό επιτυγχάνεται **αιτώντας** ένα **TGT**, **αποκρυπτογραφώντας** το με το krbtgt hash του domain, **τροποποιώντας** τα επιθυμητά πεδία του ticket και στη συνέχεια **επαν-κρυπτογραφώντας** το. Αυτό **υπερνικά τα δύο προαναφερθέντα μειονεκτήματα** ενός golden ticket επειδή:

- Οι TGS-REQs θα έχουν προηγούμενο AS-REQ.
- Το TGT εκδόθηκε από DC, πράγμα που σημαίνει ότι θα έχει όλες τις σωστές λεπτομέρειες από την Kerberos policy του domain. Αν και αυτά μπορούν να πλαστογραφηθούν με ακρίβεια σε ένα golden ticket, είναι πιο περίπλοκο και επιρρεπές σε λάθη.

### Απαιτήσεις & workflow

- **Κρυπτογραφικό υλικό**: το krbtgt AES256 key (προτιμητέο) ή NTLM hash για να αποκρυπτογραφήσετε και να επανυπογράψετε το TGT.
- **Legitimate TGT blob**: αποκτάται με `/tgtdeleg`, `asktgt`, `s4u`, ή εξάγοντας tickets από τη μνήμη.
- **Δεδομένα περιβάλλοντος**: το RID του στοχευόμενου χρήστη, group RIDs/SIDs, και (προαιρετικά) LDAP-derived PAC attributes.
- **Service keys** (μόνο εάν σκοπεύετε να επαν-εκδώσετε service tickets): AES key του service SPN που θα προσποιηθείτε.

1. Αποκτήστε ένα TGT για οποιονδήποτε ελεγχόμενο χρήστη μέσω AS-REQ (Rubeus `/tgtdeleg` είναι βολικό επειδή εξαναγκάζει τον client να εκτελέσει τη διαδικασία Kerberos GSS-API χωρίς διαπιστευτήρια).
2. Αποκρυπτογραφήστε το επιστρεφόμενο TGT με το krbtgt key, τροποποιήστε τα PAC attributes (user, groups, logon info, SIDs, device claims, κ.λπ.).
3. Επανακρυπτογραφήστε/υπογράψτε το ticket με το ίδιο krbtgt key και εισάγετέ το στην τρέχουσα συνεδρία σύνδεσης (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Προαιρετικά, επαναλάβετε τη διαδικασία σε ένα service ticket παρέχοντας ένα έγκυρο TGT blob μαζί με το κλειδί της στοχευόμενης υπηρεσίας για να παραμείνετε διακριτικοί στην επικοινωνία δικτύου.

### Updated Rubeus tradecraft (2024+)

Πρόσφατη δουλειά από την Huntress εκσυγχρόνισε τη δράση `diamond` μέσα στο Rubeus μεταφέροντας τις βελτιώσεις `/ldap` και `/opsec` που προηγουμένως υπήρχαν μόνο για golden/silver tickets. Το `/ldap` πλέον συμπληρώνει αυτόματα ακριβή PAC attributes απευθείας από AD (user profile, logon hours, sidHistory, domain policies), ενώ το `/opsec` κάνει τη ροή AS-REQ/AS-REP αδιάκριτη από έναν Windows client εκτελώντας τη διπλόβημα ακολουθία pre-auth και επιβάλλοντας AES-only κρυπτογράφηση. Αυτό μειώνει δραματικά εμφανείς ενδείξεις όπως κενά device IDs ή μη ρεαλιστικά παράθυρα ισχύος.
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
- `/ldap` (με προαιρετικά `/ldapuser` & `/ldappassword`) εκτελεί query σε AD και SYSVOL για να αντικατοπτρίσει τα δεδομένα πολιτικής PAC του χρήστη-στόχου.
- `/opsec` αναγκάζει μια Windows-όμοια επανπροσπάθεια AS-REQ, μηδενίζοντας τα θορυβώδη flags και παραμένοντας στο AES256.
- `/tgtdeleg` αποφεύγει να χειριστεί το cleartext password ή το NTLM/AES key του θύματος, ενώ εξακολουθεί να επιστρέφει ένα decryptable TGT.

### Αναδιαμόρφωση service-ticket

Η ίδια ανανέωση του Rubeus πρόσθεσε τη δυνατότητα να εφαρμοστεί η diamond technique σε TGS blobs. Τροφοδοτώντας το `diamond` με μια **base64-encoded TGT** (από `asktgt`, `/tgtdeleg`, ή ένα προηγουμένως forged TGT), το **service SPN**, και το **service AES key**, μπορείτε να δημιουργήσετε ρεαλιστικά service tickets χωρίς να πειράξετε το KDC — ουσιαστικά ένα πιο stealthy silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Αυτή η ροή εργασίας είναι ιδανική όταν έχετε ήδη τον έλεγχο ενός κλειδιού λογαριασμού υπηρεσίας (π.χ., εξαγόμενο με `lsadump::lsa /inject` ή `secretsdump.py`) και θέλετε να κόψετε ένα μοναδικό TGS που ταιριάζει τέλεια με την πολιτική του AD, τα χρονοδιαγράμματα και τα δεδομένα PAC χωρίς να δημιουργήσετε νέα AS/TGS κίνηση.

### Sapphire-style PAC swaps (2025)

Ένας νεότερος ελιγμός, που μερικές φορές ονομάζεται **sapphire ticket**, συνδυάζει τη βάση "real TGT" του Diamond με **S4U2self+U2U** για να κλέψει ένα privileged PAC και να το τοποθετήσει στο δικό σας TGT. Αντί να εφεύρετε επιπλέον SIDs, ζητάτε ένα U2U S4U2self ticket για έναν χρήστη με υψηλά προνόμια, εξάγετε εκείνο το PAC και το ενσωματώνετε στο νόμιμο TGT σας πριν το επανα-υπογράψετε με το κλειδί krbtgt. Επειδή το U2U θέτει `ENC-TKT-IN-SKEY`, η προκύπτουσα ροή δικτύου μοιάζει με νόμιμη ανταλλαγή χρήστη-προς-χρήστη.

Ελάχιστη αναπαραγωγή από την πλευρά του Linux με το patched `ticketer.py` του Impacket (adds sapphire support):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — rare in normal traffic.
- `sname` often equals the requesting user (πρόσβαση αυτοεξυπηρέτησης) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (αιτών με χαμηλά προνόμια έναντι κατόχου PAC με προνόμια).

### OPSEC & detection notes

- Οι παραδοσιακές hunter heuristics (TGS without AS, decade-long lifetimes) εξακολουθούν να εφαρμόζονται στα golden tickets, αλλά τα diamond tickets εμφανίζονται κυρίως όταν το **περιεχόμενο του PAC ή η αντιστοίχιση ομάδων φαίνεται αδύνατη**. Συμπληρώστε κάθε πεδίο του PAC (logon hours, user profile paths, device IDs) ώστε οι αυτοματοποιημένες συγκρίσεις να μην σηματοδοτούν αμέσως την παραχάραξη.
- **Μην υπερεκχωρείτε ομάδες/RIDs**. Αν χρειάζεστε μόνο `512` (Domain Admins) και `519` (Enterprise Admins), σταματήστε εκεί και βεβαιωθείτε ότι ο λογαριασμός στόχος ανήκει εύλογα σε αυτές τις ομάδες και αλλού στο AD. Η υπερβολική χρήση των `ExtraSids` προδίδει.
- Οι ανταλλαγές τύπου Sapphire αφήνουν αποτυπώματα U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` στο 4769, και ένα επακόλουθο 4624 logon που προέρχεται από το πλαστό ticket. Συσχετίστε αυτά τα πεδία αντί να ψάχνετε μόνο για κενά χωρίς AS-REQ.
- Η Microsoft ξεκίνησε τη σταδιακή κατάργηση της **έκδοσης RC4 service ticket** λόγω του CVE-2026-20833· η επιβολή αποκλειστικών AES etypes στο KDC τόσο σκληραίνει το domain όσο και ευθυγραμμίζεται με τα εργαλεία για diamond/sapphire (/opsec ήδη επιβάλλει AES). Η ανάμειξη RC4 σε πλαστά PACs θα γίνεται ολοένα πιο εμφανής.
- Το Splunk's Security Content project διανέμει telemetry attack-range για diamond tickets καθώς και ανιχνεύσεις όπως *Windows Domain Admin Impersonation Indicator*, που συσχετίζει μη φυσιολογικές ακολουθίες Event ID 4768/4769/4624 και αλλαγές σε ομάδες PAC. Η επανάληψη αυτού του dataset (ή η δημιουργία δικού σας με τις εντολές παραπάνω) βοηθά στην επικύρωση της κάλυψης SOC για T1558.001 ενώ σας δίνει συγκεκριμένη λογική ειδοποίησης για να την αποφύγετε.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
