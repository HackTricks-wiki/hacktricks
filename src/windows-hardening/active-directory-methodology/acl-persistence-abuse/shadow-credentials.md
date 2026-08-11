# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή <a href="#3f17" id="3f17"></a>

**Δείτε το αρχικό post για [όλες τις πληροφορίες σχετικά με αυτή την τεχνική](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Συνοπτικά, ο έλεγχος του **`msDS-KeyCredentialLink`** ενός χρήστη ή υπολογιστή μπορεί να επιτρέψει σε έναν attacker να προσθέσει ένα key credential, να πραγματοποιήσει authentication ως το συγκεκριμένο object με PKINIT και —όταν ο KDC και το account υποστηρίζουν τα απαραίτητα flows— να χρησιμοποιήσει το ticket που προκύπτει με `S4U2Self`/user-to-user για να ανακτήσει το NT hash του object.<sup>[[1]](#references)</sup>

Στο post περιγράφεται μια μέθοδος για τη ρύθμιση **public-private key authentication credentials**, με σκοπό την απόκτηση ενός μοναδικού **Service Ticket** που περιλαμβάνει το NTLM hash του target. Η διαδικασία αυτή περιλαμβάνει το κρυπτογραφημένο NTLM_SUPPLEMENTAL_CREDENTIAL μέσα στο Privilege Attribute Certificate (PAC), το οποίο μπορεί να αποκρυπτογραφηθεί.<sup>[[1]](#references)</sup>

### Απαιτήσεις

Για την εφαρμογή αυτής της τεχνικής, πρέπει να πληρούνται ορισμένες προϋποθέσεις:<sup>[[1]](#references)</sup>

- Απαιτείται τουλάχιστον ένας Windows Server 2016 Domain Controller.
- Ο Domain Controller πρέπει να διαθέτει εγκατεστημένο digital certificate για server authentication.
- Το directory schema πρέπει να περιλαμβάνει το `msDS-KeyCredentialLink`· ένας Windows Server 2016 ή νεότερος DC και ένα PKINIT-capable certificate στον KDC αποτελούν τις πρακτικές απαιτήσεις πλατφόρμας που περιγράφονται από την έρευνα. Επαληθεύστε το schema και το μείγμα DC του domain αντί να θεωρείτε ότι μόνο το domain functional-level label καθορίζει το αν είναι δυνατή η εκμετάλλευση.
- Απαιτείται ένα account με delegated rights για την τροποποίηση του attribute `msDS-KeyCredentialLink` του target object.

## Κατάχρηση

Η κατάχρηση του Key Trust για computer objects περιλαμβάνει βήματα πέρα από την απόκτηση ενός Ticket Granting Ticket (TGT) και του NTLM hash. Οι επιλογές περιλαμβάνουν:<sup>[[1]](#references)</sup>

1. Δημιουργία ενός **RC4 silver ticket** για την εκτέλεση ενεργειών ως privileged users στο intended host.
2. Χρήση του TGT με **S4U2Self** για impersonation **privileged users**, με απαραίτητες τροποποιήσεις στο Service Ticket ώστε να προστεθεί ένα service class στο service name.

Ένα σημαντικό πλεονέκτημα της κατάχρησης του Key Trust είναι ότι περιορίζεται στο private key που δημιουργείται από τον attacker, αποφεύγοντας delegation σε δυνητικά ευάλωτα accounts και χωρίς να απαιτείται η δημιουργία computer account, το οποίο μπορεί να είναι δύσκολο να αφαιρεθεί.<sup>[[1]](#references)</sup>

## Εργαλεία

### [**Whisker**](https://github.com/eladshamir/Whisker)

Το Whisker χρησιμοποιεί το DSInternals για να χειρίζεται το `msDS-KeyCredentialLink` από C#. Το Whisker και το αντίστοιχο Python εργαλείο **pyWhisker** υποστηρίζουν την προσθήκη, την καταχώριση, την αφαίρεση και την εκκαθάριση key credentials.<sup>[[2]](#references)[[4]](#references)</sup>

Οι λειτουργίες του **Whisker** περιλαμβάνουν:

- **Add**: Δημιουργεί ένα key pair και προσθέτει ένα key credential.
- **List**: Εμφανίζει όλες τις καταχωρίσεις key credential.
- **Remove**: Διαγράφει ένα καθορισμένο key credential.
- **Clear**: Διαγράφει όλα τα key credentials, προκαλώντας ενδεχομένως διακοπή της νόμιμης χρήσης του WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Το pyWhisker μεταφέρει τη ροή εργασίας σε **UNIX-like systems** με τα Impacket και PyDSInternals, συμπεριλαμβανομένων των λειτουργιών list/add/remove και JSON import/export.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

Το ShadowSpray απαριθμεί αντικείμενα του domain στα οποία ο operator έχει δικαιώματα όπως `GenericWrite`/`GenericAll`, προσπαθεί να προσθέσει key credentials σε ευρεία κλίμακα και περιλαμβάνει λειτουργίες cleanup/recursive. Το ευρύ spraying είναι παρεμβατικό και conspicuous· χρησιμοποιήστε explicit targets και διατηρήστε κάθε DeviceID που προστέθηκε για ακριβή αφαίρεση.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Κατάχρηση του Key Trust Account Mapping για Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Εργαλείο για takeover AD accounts μέσω τροποποίησης του msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Εργαλείο για spraying Shadow Credentials σε ολόκληρο το domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python version του Shadow Credentials tool](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
