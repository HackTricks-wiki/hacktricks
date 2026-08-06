# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή <a href="#3f17" id="3f17"></a>

**Ελέγξτε το original post για [όλες τις πληροφορίες σχετικά με αυτή την τεχνική](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Ως **σύνοψη**: αν μπορείτε να γράψετε στην ιδιότητα **msDS-KeyCredentialLink** ενός user/computer, μπορείτε να ανακτήσετε το **NT hash αυτού του object**.<sup>[[1]](#references)</sup>

Στο post περιγράφεται μια μέθοδος για τη ρύθμιση **public-private key authentication credentials**, ώστε να αποκτηθεί ένα μοναδικό **Service Ticket** που περιλαμβάνει το NTLM hash του target. Η διαδικασία περιλαμβάνει το κρυπτογραφημένο NTLM_SUPPLEMENTAL_CREDENTIAL μέσα στο Privilege Attribute Certificate (PAC), το οποίο μπορεί να αποκρυπτογραφηθεί.<sup>[[1]](#references)</sup>

### Απαιτήσεις

Για την εφαρμογή αυτής της τεχνικής, πρέπει να πληρούνται ορισμένες προϋποθέσεις:<sup>[[1]](#references)</sup>

- Απαιτείται τουλάχιστον ένας Windows Server 2016 Domain Controller.
- Ο Domain Controller πρέπει να έχει εγκατεστημένο digital certificate για server authentication.
- Το Active Directory πρέπει να βρίσκεται στο Windows Server 2016 Functional Level.
- Απαιτείται ένας account με delegated rights για τροποποίηση του msDS-KeyCredentialLink attribute του target object.

## Abuse

Το abuse του Key Trust για computer objects περιλαμβάνει βήματα πέρα από την απόκτηση ενός Ticket Granting Ticket (TGT) και του NTLM hash. Οι επιλογές περιλαμβάνουν:<sup>[[1]](#references)</sup>

1. Δημιουργία ενός **RC4 silver ticket** για να ενεργείτε ως privileged users στο intended host.
2. Χρήση του TGT με **S4U2Self** για impersonation **privileged users**, με απαραίτητες τροποποιήσεις στο Service Ticket ώστε να προστεθεί ένα service class στο service name.

Ένα σημαντικό πλεονέκτημα του Key Trust abuse είναι ότι περιορίζεται στο private key που δημιουργεί ο attacker, αποφεύγοντας delegation σε δυνητικά ευάλωτα accounts και χωρίς να απαιτείται η δημιουργία computer account, το οποίο μπορεί να είναι δύσκολο να αφαιρεθεί.<sup>[[1]](#references)</sup>

## Εργαλεία

### [**Whisker**](https://github.com/eladshamir/Whisker)

Βασίζεται στο DSInternals και παρέχει ένα C# interface για αυτή την επίθεση. Τα Whisker και το Python counterpart του, **pyWhisker**, επιτρέπουν τον χειρισμό του `msDS-KeyCredentialLink` attribute για την απόκτηση control σε Active Directory accounts. Αυτά τα εργαλεία υποστηρίζουν διάφορες λειτουργίες, όπως προσθήκη, εμφάνιση, αφαίρεση και εκκαθάριση key credentials από το target object.

Οι λειτουργίες του **Whisker** περιλαμβάνουν:

- **Add**: Δημιουργεί ένα key pair και προσθέτει ένα key credential.
- **List**: Εμφανίζει όλες τις key credential entries.
- **Remove**: Διαγράφει ένα指定 key credential.
- **Clear**: Διαγράφει όλα τα key credentials, διακόπτοντας πιθανώς τη νόμιμη χρήση του WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Επεκτείνει τη λειτουργικότητα του Whisker σε **UNIX-based systems**, αξιοποιώντας τα Impacket και PyDSInternals για ολοκληρωμένες δυνατότητες exploitation, όπως η καταχώριση, η προσθήκη και η αφαίρεση KeyCredentials, καθώς και η εισαγωγή και εξαγωγή τους σε μορφή JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

Το ShadowSpray στοχεύει στην **εκμετάλλευση δικαιωμάτων GenericWrite/GenericAll που ενδέχεται να έχουν ευρείες ομάδες χρηστών σε αντικείμενα του domain**, ώστε να εφαρμόζει μαζικά ShadowCredentials. Περιλαμβάνει σύνδεση στο domain, επαλήθευση του functional level του domain, απαρίθμηση των αντικειμένων του domain και προσπάθεια προσθήκης KeyCredentials για απόκτηση TGT και αποκάλυψη NT hash. Οι επιλογές εκκαθάρισης και οι τακτικές recursive exploitation ενισχύουν τη χρησιμότητά του.

## Αναφορές

- [1] [Shadow Credentials: Κατάχρηση του Key Trust Account Mapping για takeover λογαριασμών](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Εργαλείο για takeover λογαριασμών AD μέσω χειρισμού του msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Εργαλείο για μαζική εφαρμογή Shadow Credentials σε ένα domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python έκδοση του εργαλείου Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
