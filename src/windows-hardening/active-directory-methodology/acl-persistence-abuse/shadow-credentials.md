# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**Δείτε την αρχική ανάρτηση για [όλες τις πληροφορίες σχετικά με αυτή την τεχνική](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Ως **σύνοψη**: αν μπορείτε να γράψετε στην **ιδιότητα msDS-KeyCredentialLink** ενός χρήστη/υπολογιστή, μπορείτε να ανακτήσετε το **NT hash αυτού του αντικειμένου**.

Στην ανάρτηση, περιγράφεται μια μέθοδος για τη ρύθμιση **δημόσιων-ιδιωτικών κλειδιών πιστοποίησης** για την απόκτηση ενός μοναδικού **Service Ticket** που περιλαμβάνει το NTLM hash του στόχου. Αυτή η διαδικασία περιλαμβάνει το κρυπτογραφημένο NTLM_SUPPLEMENTAL_CREDENTIAL εντός του Privilege Attribute Certificate (PAC), το οποίο μπορεί να αποκρυπτογραφηθεί.

### Requirements

Για να εφαρμοστεί αυτή η τεχνική, πρέπει να πληρούνται ορισμένες προϋποθέσεις:

- Απαιτείται τουλάχιστον ένας Windows Server 2016 Domain Controller.
- Ο Domain Controller πρέπει να έχει εγκατεστημένο ένα ψηφιακό πιστοποιητικό αυθεντικοποίησης διακομιστή.
- Η Active Directory πρέπει να είναι στο Windows Server 2016 Functional Level.
- Απαιτείται ένας λογαριασμός με εκχωρημένα δικαιώματα για να τροποποιήσει την ιδιότητα msDS-KeyCredentialLink του αντικειμένου στόχου.

## Abuse

Η κατάχρηση του Key Trust για αντικείμενα υπολογιστών περιλαμβάνει βήματα πέρα από την απόκτηση ενός Ticket Granting Ticket (TGT) και του NTLM hash. Οι επιλογές περιλαμβάνουν:

1. Δημιουργία ενός **RC4 silver ticket** για να ενεργεί ως προνομιούχοι χρήστες στον προοριζόμενο υπολογιστή.
2. Χρήση του TGT με **S4U2Self** για την προσποίηση **προνομιούχων χρηστών**, απαιτώντας τροποποιήσεις στο Service Ticket για να προστεθεί μια κατηγορία υπηρεσίας στο όνομα της υπηρεσίας.

Ένα σημαντικό πλεονέκτημα της κατάχρησης του Key Trust είναι ο περιορισμός του στην ιδιωτική κλειδαριά που δημιουργείται από τον επιτιθέμενο, αποφεύγοντας την εκχώρηση σε δυνητικά ευάλωτους λογαριασμούς και μη απαιτώντας τη δημιουργία ενός λογαριασμού υπολογιστή, κάτι που θα μπορούσε να είναι δύσκολο να αφαιρεθεί.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Βασίζεται στο DSInternals παρέχοντας μια διεπαφή C# για αυτή την επίθεση. Το Whisker και το Python αντίστοιχό του, **pyWhisker**, επιτρέπουν την επεξεργασία της ιδιότητας `msDS-KeyCredentialLink` για την απόκτηση ελέγχου στους λογαριασμούς Active Directory. Αυτά τα εργαλεία υποστηρίζουν διάφορες λειτουργίες όπως η προσθήκη, η καταχώριση, η αφαίρεση και η εκκαθάριση κλειδιών πιστοποίησης από το αντικείμενο στόχου.

**Λειτουργίες του Whisker** περιλαμβάνουν:

- **Add**: Δημιουργεί ένα ζεύγος κλειδιών και προσθέτει μια κλειδαριά πιστοποίησης.
- **List**: Εμφανίζει όλες τις καταχωρίσεις κλειδιών πιστοποίησης.
- **Remove**: Διαγράφει μια συγκεκριμένη κλειδαριά πιστοποίησης.
- **Clear**: Διαγράφει όλες τις κλειδαριές πιστοποίησης, ενδεχομένως διαταράσσοντας τη νόμιμη χρήση WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Επεκτείνει τη λειτουργικότητα του Whisker σε **συστήματα βασισμένα σε UNIX**, αξιοποιώντας το Impacket και το PyDSInternals για ολοκληρωμένες δυνατότητες εκμετάλλευσης, συμπεριλαμβανομένων των λιστών, προσθήκης και αφαίρεσης KeyCredentials, καθώς και εισαγωγής και εξαγωγής τους σε μορφή JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

Το ShadowSpray στοχεύει να **εκμεταλλευτεί τις άδειες GenericWrite/GenericAll που μπορεί να έχουν ευρείες ομάδες χρηστών σε αντικείμενα τομέα** για να εφαρμόσει ευρέως τα ShadowCredentials. Περιλαμβάνει την είσοδο στον τομέα, την επαλήθευση του λειτουργικού επιπέδου του τομέα, την καταμέτρηση αντικειμένων τομέα και την προσπάθεια προσθήκης KeyCredentials για την απόκτηση TGT και την αποκάλυψη NT hash. Οι επιλογές καθαρισμού και οι αναδρομικές τακτικές εκμετάλλευσης ενισχύουν τη χρησιμότητά του.

## Αναφορές

- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
- [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
- [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
