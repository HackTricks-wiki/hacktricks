# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Όπως ένα golden ticket**, ένα diamond ticket είναι ένα TGT που μπορεί να χρησιμοποιηθεί για **πρόσβαση σε οποιαδήποτε υπηρεσία ως οποιοσδήποτε χρήστης**. Ένα golden ticket δημιουργείται εξ ολοκλήρου offline, κρυπτογραφείται με το krbtgt hash του domain και στη συνέχεια εισάγεται σε μια logon session για χρήση. Επειδή οι domain controllers δεν παρακολουθούν τα TGT που έχουν εκδώσει νόμιμα, αποδέχονται χωρίς πρόβλημα TGT που είναι κρυπτογραφημένα με το δικό τους krbtgt hash.<sup>[[1]](#references)</sup>

Υπάρχουν δύο συνηθισμένες τεχνικές για τον εντοπισμό χρήσης golden tickets:

- Αναζητήστε TGS-REQs που δεν έχουν αντίστοιχο AS-REQ.
- Αναζητήστε TGTs με παράλογες τιμές, όπως τη default διάρκεια 10 ετών του Mimikatz.

Ένα **diamond ticket** δημιουργείται με **τροποποίηση των πεδίων ενός νόμιμου TGT που εκδόθηκε από DC**. Αυτό επιτυγχάνεται με **αίτηση** ενός **TGT**, **αποκρυπτογράφηση** με το krbtgt hash του domain, **τροποποίηση** των επιθυμητών πεδίων του ticket και στη συνέχεια **επανακρυπτογράφηση**. Αυτό **ξεπερνά τα δύο προαναφερθέντα μειονεκτήματα** ενός golden ticket επειδή:<sup>[[1]](#references)</sup>

- Τα TGS-REQs θα έχουν ένα προηγούμενο AS-REQ.
- Το TGT εκδόθηκε από DC, επομένως θα περιέχει όλες τις σωστές λεπτομέρειες από την Kerberos policy του domain. Παρότι αυτές μπορούν να πλαστογραφηθούν με ακρίβεια σε ένα golden ticket, η διαδικασία είναι πιο σύνθετη και επιρρεπής σε λάθη.

### Απαιτήσεις & workflow

- **Cryptographic material**: το krbtgt AES256 key (προτιμητέο) ή NTLM hash, ώστε να γίνει decrypt και re-sign του TGT.
- **Legitimate TGT blob**: λαμβάνεται με `/tgtdeleg`, `asktgt`, `s4u` ή με export tickets από τη μνήμη.
- **Context data**: το RID του target user, group RIDs/SIDs και, προαιρετικά, PAC attributes που προέρχονται από LDAP.
- **Service keys** (μόνο αν σκοπεύετε να κάνετε re-cut service tickets): το AES key του service SPN που θα γίνει impersonate.

1. Αποκτήστε ένα TGT για οποιονδήποτε controlled user μέσω AS-REQ (`/tgtdeleg` του Rubeus είναι βολικό, επειδή εξαναγκάζει τον client να εκτελέσει το Kerberos GSS-API dance χωρίς credentials).
2. Κάντε decrypt το TGT που επιστράφηκε με το krbtgt key, τροποποιήστε τα PAC attributes (user, groups, logon info, SIDs, device claims κ.λπ.).
3. Κάντε re-encrypt/sign στο ticket με το ίδιο krbtgt key και inject το στην τρέχουσα logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Προαιρετικά, επαναλάβετε τη διαδικασία σε ένα service ticket παρέχοντας ένα valid TGT blob μαζί με το target service key, ώστε να παραμείνετε stealthy στο wire.

### Updated Rubeus tradecraft (2024+)

Πρόσφατη εργασία της Huntress εκσυγχρόνισε το `diamond` action στο Rubeus, μεταφέροντας τις βελτιώσεις `/ldap` και `/opsec`, οι οποίες προηγουμένως υπήρχαν μόνο για golden/silver tickets. Το `/ldap` πλέον λαμβάνει πραγματικό PAC context εκτελώντας queries στο LDAP **και** κάνοντας mount το SYSVOL για την εξαγωγή account/group attributes, καθώς και Kerberos/password policy (π.χ. `GptTmpl.inf`), ενώ το `/opsec` κάνει τη ροή AS-REQ/AS-REP να ταιριάζει με τα Windows, εκτελώντας το preauth exchange σε δύο βήματα και επιβάλλοντας AES-only + ρεαλιστικά KDCOptions. Αυτό μειώνει δραστικά εμφανείς ενδείξεις, όπως ελλιπή PAC fields ή lifetimes που δεν ταιριάζουν με την policy.<sup>[[3]](#references)</sup>
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
- Το `/ldap` (με προαιρετικά `/ldapuser` και `/ldappassword`) κάνει queries στο AD και το SYSVOL για να αντικατοπτρίσει τα δεδομένα πολιτικής PAC του target user.
- Το `/opsec` επιβάλλει ένα retry του AS-REQ όπως στα Windows, μηδενίζει τα θορυβώδη flags και χρησιμοποιεί αποκλειστικά AES256.
- Το `/tgtdeleg` αποφεύγει την πρόσβαση στον cleartext κωδικό πρόσβασης ή στο NTLM/AES key του victim, ενώ εξακολουθεί να επιστρέφει ένα TGT που μπορεί να γίνει decrypt.

### Recutting service-ticket

Το ίδιο Rubeus refresh πρόσθεσε τη δυνατότητα εφαρμογής της diamond technique σε TGS blobs. Παρέχοντας στο `diamond` ένα **TGT κωδικοποιημένο σε base64** (από `asktgt`, `/tgtdeleg` ή ένα TGT που έχει γίνει forge προηγουμένως), το **service SPN** και το **service AES key**, μπορείτε να δημιουργήσετε ρεαλιστικά service tickets χωρίς να αγγίξετε το KDC — ουσιαστικά ένα πιο stealthy silver ticket.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Αυτή η ροή εργασίας είναι ιδανική όταν έχετε ήδη τον έλεγχο ενός κλειδιού λογαριασμού υπηρεσίας (π.χ. μέσω dump με `lsadump::lsa /inject` ή `secretsdump.py`) και θέλετε να δημιουργήσετε ένα εφάπαξ TGS που να ταιριάζει απόλυτα με την πολιτική του AD, τα χρονικά όρια και τα δεδομένα PAC, χωρίς να δημιουργήσετε νέα κίνηση AS/TGS.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Μια νεότερη παραλλαγή, που μερικές φορές αποκαλείται **sapphire ticket**, συνδυάζει τη βάση «πραγματικού TGT» του Diamond με **S4U2self+U2U**, ώστε να κλέψει ένα privileged PAC και να το εισαγάγει στο δικό σας TGT. Αντί να επινοήσετε επιπλέον SIDs, ζητάτε ένα U2U S4U2self ticket για έναν χρήστη με υψηλά προνόμια, όπου το `sname` στοχεύει τον requester με χαμηλά προνόμια· το KRB_TGS_REQ μεταφέρει το TGT του requester στο `additional-tickets` και ορίζει το `ENC-TKT-IN-SKEY`, επιτρέποντας την αποκρυπτογράφηση του service ticket με το κλειδί αυτού του χρήστη. Στη συνέχεια, εξάγετε το privileged PAC και το ενσωματώνετε στο νόμιμο TGT σας, πριν το υπογράψετε ξανά με το κλειδί του krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Το `ticketer.py` του Impacket υποστηρίζει πλέον sapphire μέσω των `-impersonate` + `-request` (live KDC exchange):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- Το `-impersonate` δέχεται username ή SID· το `-request` απαιτεί live user creds μαζί με krbtgt key material (AES/NTLM) για την αποκρυπτογράφηση/τροποποίηση των tickets.

Βασικές ενδείξεις OPSEC κατά τη χρήση αυτής της παραλλαγής:<sup>[[5]](#references)</sup>

- Το TGS-REQ θα περιέχει `ENC-TKT-IN-SKEY` και `additional-tickets` (το victim TGT) — κάτι σπάνιο στη φυσιολογική κίνηση.
- Το `sname` συχνά ισούται με τον requesting user (self-service access) και το Event ID 4769 εμφανίζει τον caller και τον target ως το ίδιο SPN/user.
- Αναμένετε ζεύγη καταχωρίσεων 4768/4769 με τον ίδιο client computer αλλά διαφορετικά CNAMES (low-priv requester έναντι privileged PAC owner).

### Σημειώσεις OPSEC & detection

- Τα παραδοσιακά hunter heuristics (TGS χωρίς AS, διάρκειες δεκαετιών) εξακολουθούν να ισχύουν για τα golden tickets, όμως τα diamond tickets εντοπίζονται κυρίως όταν το **PAC content ή το group mapping φαίνεται αδύνατο**. Συμπληρώστε κάθε PAC field (logon hours, user profile paths, device IDs), ώστε οι automated comparisons να μην επισημάνουν αμέσως το forgery.<sup>[[3]](#references)</sup>
- **Μην κάνετε oversubscribe groups/RIDs**. Αν χρειάζεστε μόνο τα `512` (Domain Admins) και `519` (Enterprise Admins), σταματήστε εκεί και βεβαιωθείτε ότι ο target account ανήκει εύλογα σε αυτές τις groups κάπου αλλού στο AD. Τα υπερβολικά `ExtraSids` αποτελούν giveaway.
- Οι swaps τύπου Sapphire αφήνουν U2U fingerprints: `ENC-TKT-IN-SKEY` + `additional-tickets`, καθώς και ένα `sname` που δείχνει σε user (συχνά τον requester) στο 4769, και ένα follow-up 4624 logon που προέρχεται από το forged ticket. Συσχετίστε αυτά τα πεδία αντί να αναζητάτε μόνο κενά no-AS-REQ.<sup>[[5]](#references)</sup>
- Η Microsoft άρχισε να καταργεί σταδιακά την **RC4 service ticket issuance** λόγω του CVE-2026-20833· η επιβολή AES-only etypes στο KDC ενισχύει το domain και ευθυγραμμίζεται με τα diamond/sapphire tooling (`/opsec` επιβάλλει ήδη AES). Η ανάμειξη του RC4 σε forged PACs θα ξεχωρίζει ολοένα περισσότερο.<sup>[[6]](#references)</sup>
- Το project Security Content της Splunk διανέμει attack-range telemetry για diamond tickets, μαζί με detections όπως το *Windows Domain Admin Impersonation Indicator*, το οποίο συσχετίζει ασυνήθιστες ακολουθίες Event ID 4768/4769/4624 και αλλαγές group στο PAC. Η αναπαραγωγή αυτού του dataset (ή η δημιουργία δικού σας με τις παραπάνω commands) βοηθά στην επικύρωση της SOC κάλυψης για το T1558.001, ενώ σας παρέχει συγκεκριμένο alert logic προς αποφυγή.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
