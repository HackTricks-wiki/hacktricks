# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Τι είναι το ADWS;

Active Directory Web Services (ADWS) είναι **ενεργοποιημένο από προεπιλογή σε κάθε Domain Controller από τα Windows Server 2008 R2** και ακούει στο TCP **9389**. Παρά το όνομα, **δεν εμπλέκεται HTTP**. Αντίθετα, η υπηρεσία εκθέτει δεδομένα σε στυλ LDAP μέσω ενός στοίβου ιδιόκτητων .NET framing πρωτοκόλλων:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Επειδή η κίνηση εγκλείεται μέσα σε αυτά τα δυαδικά SOAP frames και ταξιδεύει μέσω μιας ασυνήθιστης θύρας, **η enumeration μέσω ADWS είναι πολύ λιγότερο πιθανό να ελεγχθεί, φιλτραριστεί ή να εντοπιστεί από signatures σε σχέση με την κλασική LDAP/389 & 636 κίνηση**. Για τους χειριστές αυτό σημαίνει:

* Stealthier recon – οι Blue teams συχνά επικεντρώνονται σε LDAP queries.
* Freedom to collect από **non-Windows hosts (Linux, macOS)** tunnelling 9389/TCP μέσω SOCKS proxy.
* The same data you would obtain via LDAP (users, groups, ACLs, schema, etc.) και η δυνατότητα να εκτελέσετε **writes** (π.χ. `msDs-AllowedToActOnBehalfOfOtherIdentity` για **RBCD**).

Οι αλληλεπιδράσεις ADWS υλοποιούνται πάνω σε WS-Enumeration: κάθε query ξεκινά με ένα μήνυμα `Enumerate` που ορίζει το LDAP filter/attributes και επιστρέφει ένα `EnumerationContext` GUID, ακολουθούμενο από ένα ή περισσότερα μηνύματα `Pull` που ρέουν έως το παράθυρο αποτελεσμάτων που ορίζεται από τον server. Τα contexts λήγουν μετά από ~30 λεπτά, οπότε τα εργαλεία πρέπει είτε να σελιδοποιούν τα αποτελέσματα είτε να χωρίζουν τα φίλτρα (prefix queries ανά CN) για να αποφύγουν την απώλεια κατάστασης. Όταν ζητάτε security descriptors, καθορίστε τον έλεγχο `LDAP_SERVER_SD_FLAGS_OID` για να παραλείψετε τα SACLs, διαφορετικά το ADWS απλά παραλείπει το attribute `nTSecurityDescriptor` από την SOAP απάντησή του.

> ΣΗΜΕΙΩΣΗ: Το ADWS χρησιμοποιείται επίσης από πολλά RSAT GUI/PowerShell εργαλεία, οπότε η κίνηση μπορεί να συγχωνευτεί με νόμιμη admin δραστηριότητα.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) είναι μια **πλήρης επανεφαρμογή του ADWS protocol stack σε καθαρό Python**. Κατασκευάζει τα NBFX/NBFSE/NNS/NMF frames byte-for-byte, επιτρέποντας συλλογή από Unix-like συστήματα χωρίς να απαιτείται το .NET runtime.

### Key Features

* Υποστηρίζει **proxying through SOCKS** (χρήσιμο από C2 implants).
* Λεπτομερή search filters όμοια με LDAP `-q '(objectClass=user)'`.
* Προαιρετικές **write** operations (`--set` / `--delete`).
* **BOFHound output mode** για άμεση εισαγωγή στο BloodHound.
* Το flag `--parse` για μορφοποίηση timestamps / `userAccountControl` όταν απαιτείται ανθρώπινη αναγνώσιμότητα.

### Targeted collection flags & write operations

Το SoaPy συνοδεύεται από επιμελημένα switches που αναπαράγουν τα πιο κοινά LDAP hunting tasks μέσω ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, καθώς και raw `--query` / `--filter` knobs για custom pulls. Συνδυάστε αυτά με write primitives όπως `--rbcd <source>` (sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging για στοχευμένο Kerberoasting) και `--asrep` (flip `DONT_REQ_PREAUTH` στο `userAccountControl`).

Παράδειγμα στοχευμένης SPN αναζήτησης που επιστρέφει μόνο `samAccountName` και `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Χρησιμοποιήστε τον ίδιο host/credentials για να αξιοποιήσετε αμέσως τα ευρήματα: dump RBCD-capable objects με `--rbcds`, στη συνέχεια εφαρμόστε `--rbcd 'WEBSRV01$' --account 'FILE01$'` για να στήσετε ένα Resource-Based Constrained Delegation chain (βλ. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) για την πλήρη πορεία εκμετάλλευσης).

### Εγκατάσταση (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork του `ldapdomaindump` που αντικαθιστά LDAP queries με ADWS calls στο TCP/9389 για να μειώσει τα LDAP-signature hits.
* Πραγματοποιεί έναν αρχικό έλεγχο προσβασιμότητας στην πόρτα 9389 εκτός εάν δοθεί το `--force` (παραλείπει το probe αν τα port scans είναι noisy/filtered).
* Δοκιμασμένο ενάντια σε Microsoft Defender for Endpoint και CrowdStrike Falcon με επιτυχημένο bypass στο README.

### Εγκατάσταση
```bash
pipx install .
```
### Χρήση
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Η τυπική έξοδος καταγράφει τον έλεγχο προσβασιμότητας στη θύρα 9389, το ADWS bind και την έναρξη/λήξη του dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Ένας πρακτικός πελάτης για ADWS σε Golang

Όπως και το soapy, το [sopa](https://github.com/Macmod/sopa) υλοποιεί το πρωτόκολλο ADWS (MS-NNS + MC-NMF + SOAP) σε Golang, παρέχοντας παραμέτρους γραμμής εντολών για την έκδοση κλήσεων ADWS όπως:

* **Αναζήτηση και ανάκτηση αντικειμένων** - `query` / `get`
* **Κύκλος ζωής αντικειμένου** - `create [user|computer|group|ou|container|custom]` και `delete`
* **Επεξεργασία ιδιοτήτων** - `attr [add|replace|delete]`
* **Διαχείριση λογαριασμών** - `set-password` / `change-password`
* και άλλα όπως `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, κ.λπ.

### Κύρια σημεία χαρτογράφησης πρωτοκόλλου

* Οι αναζητήσεις τύπου LDAP εκτελούνται μέσω **WS-Enumeration** (`Enumerate` + `Pull`) με προβολή ιδιοτήτων, έλεγχο εύρους (Base/OneLevel/Subtree) και σελιδοποίηση.
* Η ανάκτηση ενός μεμονωμένου αντικειμένου χρησιμοποιεί **WS-Transfer** `Get`; οι αλλαγές ιδιοτήτων χρησιμοποιούν `Put`; οι διαγραφές `Delete`.
* Η ενσωματωμένη δημιουργία αντικειμένων χρησιμοποιεί **WS-Transfer ResourceFactory**; τα προσαρμοσμένα αντικείμενα χρησιμοποιούν **IMDA AddRequest** βασισμένο σε πρότυπα YAML.
* Οι λειτουργίες κωδικών πρόσβασης είναι ενέργειες **MS-ADCAP** (`SetPassword`, `ChangePassword`).

### Μη αυθεντικοποιημένη ανακάλυψη μεταδεδομένων (mex)

Το ADWS εκθέτει WS-MetadataExchange χωρίς διαπιστευτήρια, που είναι ένας γρήγορος τρόπος για να επαληθεύσετε την έκθεση πριν από την αυθεντικοποίηση:
```bash
sopa mex --dc <DC>
```
### DNS/DC ανακάλυψη & σημειώσεις στοχοποίησης Kerberos

Το Sopa μπορεί να επιλύσει τους DCs μέσω SRV αν το `--dc` παραλειφθεί και δοθεί το `--domain`. Εκτελεί ερωτήματα με αυτή τη σειρά και χρησιμοποιεί τον στόχο με την υψηλότερη προτεραιότητα:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Σε λειτουργικό επίπεδο, προτιμήστε έναν resolver ελεγχόμενο από το DC για να αποφύγετε αποτυχίες σε τμηματοποιημένα περιβάλλοντα:

* Χρησιμοποιήστε `--dns <DC-IP>` ώστε **όλες** οι SRV/PTR/forward lookups να γίνονται μέσω του DC DNS.
* Χρησιμοποιήστε `--dns-tcp` όταν το UDP είναι μπλοκαρισμένο ή οι απαντήσεις SRV είναι μεγάλες.
* Εάν το Kerberos είναι ενεργοποιημένο και το `--dc` είναι μια IP, το sopa εκτελεί ένα **reverse PTR** για να αποκτήσει ένα FQDN για σωστό στοχεύσιμο SPN/KDC. Εάν το Kerberos δεν χρησιμοποιείται, δεν γίνεται PTR lookup.

Παράδειγμα (IP + Kerberos, εξαναγκασμένο DNS μέσω του DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Επιλογές στοιχείων αυθεντικοποίησης

Εκτός από τα plaintext passwords, το sopa υποστηρίζει **NT hashes**, **Kerberos AES keys**, **ccache**, και **PKINIT certificates** (PFX ή PEM) για την αυθεντικοποίηση ADWS. Το Kerberos υπονοείται όταν χρησιμοποιείτε `--aes-key`, `-c` (ccache) ή επιλογές βάσει πιστοποιητικών.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Δημιουργία προσαρμοσμένων αντικειμένων μέσω προτύπων

Για αυθαίρετες κλάσεις αντικειμένων, η εντολή `create custom` καταναλώνει ένα YAML πρότυπο που αντιστοιχεί σε ένα IMDA `AddRequest`:

* `parentDN` και `rdn` ορίζουν τον container και το σχετικό DN.
* `attributes[].name` υποστηρίζει `cn` ή με namespace `addata:cn`.
* `attributes[].type` δέχεται `string|int|bool|base64|hex` ή ρητό `xsd:*`.
* Να **μην** συμπεριλάβετε `ad:relativeDistinguishedName` ή `ad:container-hierarchy-parent`; το sopa τα εισάγει.
* Οι τιμές `hex` μετατρέπονται σε `xsd:base64Binary`; χρησιμοποιήστε `value: ""` για να ορίσετε κενές συμβολοσειρές.

## SOAPHound – Συλλογή Υψηλού Όγκου ADWS (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) είναι ένας .NET collector που κρατά όλες τις LDAP αλληλεπιδράσεις μέσα στο ADWS και παράγει BloodHound v4-compatible JSON. Δημιουργεί μια πλήρη cache των `objectSid`, `objectGUID`, `distinguishedName` και `objectClass` μία φορά (`--buildcache`), και μετά την επαναχρησιμοποιεί για υψηλού όγκου `--bhdump`, `--certdump` (ADCS), ή `--dnsdump` (AD-integrated DNS) ενέργειες, έτσι ώστε μόνο ~35 κρίσιμα attributes να φεύγουν ποτέ από τον DC. Το AutoSplit (`--autosplit --threshold <N>`) διασπά αυτόματα τα queries ανά CN prefix για να παραμείνει κάτω από το 30-λεπτο EnumerationContext timeout σε μεγάλα forests.

Τυπική ροή εργασίας σε VM χειριστή ενταγμένο στο domain:
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
Τα εξαγόμενα JSON slots εισάγονται απευθείας σε ροές εργασίας SharpHound/BloodHound — δείτε [BloodHound methodology](bloodhound.md) για ιδέες οπτικοποίησης downstream. Το AutoSplit καθιστά το SOAPHound ανθεκτικό σε forests με εκατομμύρια αντικείμενα, διατηρώντας παράλληλα τον αριθμό ερωτημάτων χαμηλότερο σε σχέση με τα ADExplorer-style snapshots.

## Αθόρυβη ροή συλλογής AD

Η παρακάτω ροή εργασίας δείχνει πώς να enumerate **domain & ADCS objects** μέσω ADWS, να τα μετατρέψετε σε BloodHound JSON και να κυνηγήσετε certificate-based attack paths — όλα από Linux:

1. **Tunnel 9389/TCP** από το target network στο μηχάνημά σας (π.χ. via Chisel, Meterpreter, SSH dynamic port-forward, κ.λπ.). Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` ή χρησιμοποιήστε το SoaPy’s `--proxyHost/--proxyPort`.

2. **Συλλέξτε το root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Συλλογή αντικειμένων σχετικών με ADCS από το Configuration NC:**
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

### Εγγραφή του `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Συνδυάστε αυτό με `s4u2proxy`/`Rubeus /getticket` για μια πλήρη **Resource-Based Constrained Delegation** αλυσίδα (βλ. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Περίληψη Εργαλείων

| Σκοπός | Εργαλείο | Σημειώσεις |
|--------|---------|-----------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, ανάγνωση/εγγραφή |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Μετατρέπει αρχεία καταγραφής SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Μπορεί να προωθηθεί μέσω του ίδιου SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client για διεπαφή με γνωστά ADWS endpoints - επιτρέπει enumeration, δημιουργία αντικειμένων, τροποποιήσεις attributes και αλλαγές κωδικών πρόσβασης |

## Αναφορές

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
