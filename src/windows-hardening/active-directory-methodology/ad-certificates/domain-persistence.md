# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια περίληψη των τεχνικών διαρκούς παρουσίας τομέα που μοιράστηκαν στο [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Ελέγξτε το για περισσότερες λεπτομέρειες.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Πώς μπορείτε να καταλάβετε ότι ένα πιστοποιητικό είναι πιστοποιητικό CA;

Μπορεί να προσδιοριστεί ότι ένα πιστοποιητικό είναι πιστοποιητικό CA εάν πληρούνται αρκετές προϋποθέσεις:

- Το πιστοποιητικό είναι αποθηκευμένο στον διακομιστή CA, με το ιδιωτικό του κλειδί ασφαλισμένο από το DPAPI της μηχανής ή από υλικό όπως TPM/HSM αν το λειτουργικό σύστημα το υποστηρίζει.
- Τα πεδία Issuer και Subject του πιστοποιητικού ταιριάζουν με το διακριτό όνομα του CA.
- Μια επέκταση "CA Version" είναι παρούσα στα πιστοποιητικά CA αποκλειστικά.
- Το πιστοποιητικό δεν έχει πεδία Extended Key Usage (EKU).

Για να εξαγάγετε το ιδιωτικό κλειδί αυτού του πιστοποιητικού, το εργαλείο `certsrv.msc` στον διακομιστή CA είναι η υποστηριζόμενη μέθοδος μέσω της ενσωματωμένης GUI. Παρ' όλα αυτά, αυτό το πιστοποιητικό δεν διαφέρει από άλλα που είναι αποθηκευμένα στο σύστημα. Έτσι, μέθοδοι όπως η [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) μπορούν να εφαρμοστούν για την εξαγωγή.

Το πιστοποιητικό και το ιδιωτικό κλειδί μπορούν επίσης να αποκτηθούν χρησιμοποιώντας το Certipy με την ακόλουθη εντολή:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Αφού αποκτηθεί το πιστοποιητικό CA και το ιδιωτικό του κλειδί σε μορφή `.pfx`, εργαλεία όπως το [ForgeCert](https://github.com/GhostPack/ForgeCert) μπορούν να χρησιμοποιηθούν για τη δημιουργία έγκυρων πιστοποιητικών:
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
> Ο χρήστης που στοχεύεται για πλαστογράφηση πιστοποιητικού πρέπει να είναι ενεργός και ικανός να αυθεντικοποιείται στο Active Directory για να επιτύχει η διαδικασία. Η πλαστογράφηση ενός πιστοποιητικού για ειδικούς λογαριασμούς όπως ο krbtgt είναι αναποτελεσματική.

Αυτό το πλαστό πιστοποιητικό θα είναι **έγκυρο** μέχρι την ημερομηνία λήξης που έχει καθοριστεί και **όσο το πιστοποιητικό της ρίζας CA είναι έγκυρο** (συνήθως από 5 έως **10+ χρόνια**). Είναι επίσης έγκυρο για **μηχανές**, οπότε σε συνδυασμό με το **S4U2Self**, ένας επιτιθέμενος μπορεί να **διατηρήσει επιμονή σε οποιαδήποτε μηχανή τομέα** όσο το πιστοποιητικό CA είναι έγκυρο.\
Επιπλέον, τα **πιστοποιητικά που παράγονται** με αυτή τη μέθοδο **δεν μπορούν να ανακληθούν** καθώς η CA δεν είναι ενήμερη γι' αυτά.

## Εμπιστοσύνη σε Rogue CA Πιστοποιητικά - DPERSIST2

Το αντικείμενο `NTAuthCertificates` ορίζεται για να περιέχει ένα ή περισσότερα **πιστοποιητικά CA** εντός του χαρακτηριστικού `cacertificate`, το οποίο χρησιμοποιεί το Active Directory (AD). Η διαδικασία επαλήθευσης από τον **ελεγκτή τομέα** περιλαμβάνει τον έλεγχο του αντικειμένου `NTAuthCertificates` για μια καταχώρηση που ταιριάζει με την **CA που καθορίζεται** στο πεδίο Εκδότη του αυθεντικοποιητικού **πιστοποιητικού**. Η αυθεντικοποίηση προχωρά εάν βρεθεί ταίριασμα.

Ένα αυτο-υπογεγραμμένο πιστοποιητικό CA μπορεί να προστεθεί στο αντικείμενο `NTAuthCertificates` από έναν επιτιθέμενο, εφόσον έχει έλεγχο αυτού του αντικειμένου AD. Κανονικά, μόνο τα μέλη της ομάδας **Enterprise Admin**, μαζί με τους **Domain Admins** ή **Administrators** στο **δενδρικό τομέα ρίζας**, έχουν άδεια να τροποποιούν αυτό το αντικείμενο. Μπορούν να επεξεργαστούν το αντικείμενο `NTAuthCertificates` χρησιμοποιώντας το `certutil.exe` με την εντολή `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, ή χρησιμοποιώντας το [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Αυτή η δυνατότητα είναι ιδιαίτερα σχετική όταν χρησιμοποιείται σε συνδυασμό με μια προηγουμένως περιγραφείσα μέθοδο που περιλαμβάνει το ForgeCert για τη δυναμική δημιουργία πιστοποιητικών.

## Κακόβουλη Λανθασμένη Ρύθμιση - DPERSIST3

Οι ευκαιρίες για **επιμονή** μέσω **τροποποιήσεων περιγραφής ασφαλείας των στοιχείων AD CS** είναι πολλές. Οι τροποποιήσεις που περιγράφονται στην ενότητα "[Domain Escalation](domain-escalation.md)" μπορούν να υλοποιηθούν κακόβουλα από έναν επιτιθέμενο με ανυψωμένη πρόσβαση. Αυτό περιλαμβάνει την προσθήκη "δικαιωμάτων ελέγχου" (π.χ., WriteOwner/WriteDACL κ.λπ.) σε ευαίσθητα στοιχεία όπως:

- Το **αντικείμενο υπολογιστή AD του CA server**
- Ο **RPC/DCOM server του CA server**
- Οποιοδήποτε **καταγωγικό αντικείμενο ή κοντέινερ AD** στο **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (για παράδειγμα, το κοντέινερ Πρότυπα Πιστοποιητικών, το κοντέινερ Αρχών Πιστοποίησης, το αντικείμενο NTAuthCertificates κ.λπ.)
- **Ομάδες AD που έχουν δικαιώματα ελέγχου AD CS** από προεπιλογή ή από τον οργανισμό (όπως η ενσωματωμένη ομάδα Cert Publishers και οποιοδήποτε από τα μέλη της)

Ένα παράδειγμα κακόβουλης υλοποίησης θα περιλάμβανε έναν επιτιθέμενο, ο οποίος έχει **ανυψωμένα δικαιώματα** στο τομέα, να προσθέτει την άδεια **`WriteOwner`** στο προεπιλεγμένο πρότυπο πιστοποιητικού **`User`**, με τον επιτιθέμενο να είναι ο κύριος για το δικαίωμα. Για να εκμεταλλευτεί αυτό, ο επιτιθέμενος θα άλλαζε πρώτα την ιδιοκτησία του προτύπου **`User`** σε αυτόν. Ακολούθως, η **`mspki-certificate-name-flag`** θα ρυθμιζόταν σε **1** στο πρότυπο για να επιτρέψει το **`ENROLLEE_SUPPLIES_SUBJECT`**, επιτρέποντας σε έναν χρήστη να παρέχει ένα Subject Alternative Name στην αίτηση. Στη συνέχεια, ο επιτιθέμενος θα μπορούσε να **εγγραφεί** χρησιμοποιώντας το **πρότυπο**, επιλέγοντας ένα όνομα **τομεακού διαχειριστή** ως εναλλακτικό όνομα, και να χρησιμοποιήσει το αποκτηθέν πιστοποιητικό για αυθεντικοποίηση ως DA.

{{#include ../../../banners/hacktricks-training.md}}
