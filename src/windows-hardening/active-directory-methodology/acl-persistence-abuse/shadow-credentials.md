# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή <a href="#3f17" id="3f17"></a>

**Δείτε την αρχική δημοσίευση για [όλες τις πληροφορίες σχετικά με αυτή την τεχνική](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Συνοπτικά, ο έλεγχος του **`msDS-KeyCredentialLink`** ενός χρήστη ή υπολογιστή μπορεί να επιτρέψει σε έναν attacker να προσθέσει ένα key credential, να κάνει authenticate ως το συγκεκριμένο object με PKINIT και —όταν ο KDC και ο λογαριασμός υποστηρίζουν τις απαραίτητες ροές— να χρησιμοποιήσει το ticket που προκύπτει με `S4U2Self`/user-to-user για να ανακτήσει το NT hash του object.<sup>[[1]](#references)</sup>

Η δημοσίευση περιγράφει μια μέθοδο ρύθμισης **public-private key authentication credentials** για την απόκτηση ενός μοναδικού **Service Ticket** που περιλαμβάνει το NTLM hash του στόχου. Η διαδικασία βασίζεται στο κρυπτογραφημένο NTLM_SUPPLEMENTAL_CREDENTIAL μέσα στο Privilege Attribute Certificate (PAC), το οποίο μπορεί να αποκρυπτογραφηθεί.<sup>[[1]](#references)</sup>

### Προϋποθέσεις

Για να εφαρμοστεί αυτή η τεχνική, πρέπει να πληρούνται ορισμένες προϋποθέσεις:<sup>[[1]](#references)</sup>

- Απαιτείται τουλάχιστον ένας Windows Server 2016 Domain Controller.
- Στον Domain Controller πρέπει να είναι εγκατεστημένο ένα digital certificate για server authentication.
- Το directory schema πρέπει να περιλαμβάνει το `msDS-KeyCredentialLink`. Οι πρακτικές απαιτήσεις πλατφόρμας που περιγράφονται στην έρευνα είναι ένας Windows Server 2016 ή νεότερος DC και ένα PKINIT-capable certificate στον KDC. Επαληθεύστε το schema και τον συνδυασμό DC του domain, αντί να θεωρείτε ότι η ετικέτα του domain functional level καθορίζει από μόνη της αν είναι εφικτό το exploit.
- Απαιτείται λογαριασμός με delegated δικαιώματα τροποποίησης του attribute msDS-KeyCredentialLink του object-στόχου.

## Κατάχρηση

Η κατάχρηση του Key Trust για computer objects περιλαμβάνει βήματα πέρα από την απόκτηση ενός Ticket Granting Ticket (TGT) και του NTLM hash. Οι επιλογές περιλαμβάνουν:<sup>[[1]](#references)</sup>

1. Δημιουργία ενός **RC4 silver ticket** για να ενεργεί ο attacker ως privileged users στον προβλεπόμενο host.
2. Χρήση του TGT με **S4U2Self** για impersonation **privileged users**, κάτι που απαιτεί τροποποιήσεις στο Service Ticket ώστε να προστεθεί μια service class στο service name.

Ένα σημαντικό πλεονέκτημα της κατάχρησης του Key Trust είναι ότι περιορίζεται στο private key που δημιουργεί ο attacker, αποφεύγοντας την ανάθεση σε δυνητικά ευάλωτους λογαριασμούς και την ανάγκη δημιουργίας computer account, το οποίο μπορεί να είναι δύσκολο να αφαιρεθεί.<sup>[[1]](#references)</sup>

## Εργαλεία

### [**Whisker**](https://github.com/eladshamir/Whisker)

Το Whisker χρησιμοποιεί το DSInternals για να χειρίζεται το `msDS-KeyCredentialLink` από C#. Το Whisker και το Python counterpart του, **pyWhisker**, υποστηρίζουν την προσθήκη, την εμφάνιση, την αφαίρεση και την εκκαθάριση key credentials.<sup>[[2]](#references)[[4]](#references)</sup>

Οι λειτουργίες του **Whisker** περιλαμβάνουν:

- **Add**: Δημιουργεί ένα key pair και προσθέτει ένα key credential.
- **List**: Εμφανίζει όλες τις εγγραφές key credential.
- **Remove**: Διαγράφει ένα καθορισμένο key credential.
- **Clear**: Διαγράφει όλα τα key credentials, κάτι που ενδέχεται να διαταράξει τη νόμιμη χρήση του WHfB.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Το pyWhisker μεταφέρει τη ροή εργασίας σε **UNIX-like συστήματα** με τα Impacket και PyDSInternals, συμπεριλαμβανομένων των λειτουργιών list/add/remove και εισαγωγής/εξαγωγής JSON.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

Το ShadowSpray απαριθμεί αντικείμενα τομέα στα οποία ο operator έχει δικαιώματα όπως `GenericWrite`/`GenericAll`, επιχειρεί να προσθέσει μαζικά key credentials και περιλαμβάνει λειτουργίες cleanup/recursive. Το μαζικό spraying είναι διαταρακτικό και εμφανές· χρησιμοποιήστε συγκεκριμένους στόχους και διατηρήστε κάθε DeviceID που προστέθηκε, ώστε να μπορείτε να το αφαιρέσετε με ακρίβεια.<sup>[[3]](#references)</sup>

Το ADWS μπορεί να μεταφέρει την εγγραφή key credential όταν η απευθείας σύνδεση LDAP φιλτράρεται. Δείτε τη [ροή εργασίας SOAPy ADWS](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: Κατάχρηση του Key Trust Account Mapping για takeover λογαριασμού](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Εργαλείο για takeover λογαριασμών AD μέσω χειρισμού του msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Εργαλείο για spraying Shadow Credentials σε ολόκληρο το domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Έκδοση του εργαλείου Shadow Credentials σε Python](https://github.com/ShutdownRepo/pywhisker)
- [5] [Wiki του SOAPy – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
