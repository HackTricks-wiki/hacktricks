# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Η επίθεση **Overpass The Hash/Pass The Key (PTK)** έχει σχεδιαστεί για περιβάλλοντα όπου το παραδοσιακό πρωτόκολλο NTLM είναι περιορισμένο και η αυθεντικοποίηση Kerberos έχει προτεραιότητα. Αυτή η επίθεση εκμεταλλεύεται το NTLM hash ή τα κλειδιά AES ενός χρήστη για να ζητήσει εισιτήρια Kerberos, επιτρέποντας μη εξουσιοδοτημένη πρόσβαση σε πόρους εντός ενός δικτύου.

Για να εκτελεστεί αυτή η επίθεση, το αρχικό βήμα περιλαμβάνει την απόκτηση του NTLM hash ή του κωδικού πρόσβασης του λογαριασμού του στοχευμένου χρήστη. Αφού εξασφαλιστεί αυτή η πληροφορία, μπορεί να αποκτηθεί ένα Ticket Granting Ticket (TGT) για τον λογαριασμό, επιτρέποντας στον επιτιθέμενο να έχει πρόσβαση σε υπηρεσίες ή μηχανές στις οποίες ο χρήστης έχει άδειες.

Η διαδικασία μπορεί να ξεκινήσει με τις παρακάτω εντολές:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Για σενάρια που απαιτούν AES256, η επιλογή `-aesKey [AES key]` μπορεί να χρησιμοποιηθεί. Επιπλέον, το αποκτηθέν εισιτήριο μπορεί να χρησιμοποιηθεί με διάφορα εργαλεία, συμπεριλαμβανομένων των smbexec.py ή wmiexec.py, διευρύνοντας την έκταση της επίθεσης.

Τα προβλήματα που συναντώνται, όπως το _PyAsn1Error_ ή το _KDC cannot find the name_, συνήθως επιλύονται με την ενημέρωση της βιβλιοθήκης Impacket ή με τη χρήση του ονόματος υπολογιστή αντί της διεύθυνσης IP, διασφαλίζοντας τη συμβατότητα με το Kerberos KDC.

Μια εναλλακτική ακολουθία εντολών χρησιμοποιώντας το Rubeus.exe δείχνει μια άλλη πτυχή αυτής της τεχνικής:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Αυτή η μέθοδος αντικατοπτρίζει την προσέγγιση **Pass the Key**, με έμφαση στην κατάληψη και τη χρήση του εισιτηρίου απευθείας για σκοπούς αυθεντικοποίησης. Είναι κρίσιμο να σημειωθεί ότι η έναρξη ενός αιτήματος TGT ενεργοποιεί το γεγονός `4768: A Kerberos authentication ticket (TGT) was requested`, υποδηλώνοντας τη χρήση RC4-HMAC από προεπιλογή, αν και τα σύγχρονα συστήματα Windows προτιμούν το AES256.

Για να συμμορφωθεί με την επιχειρησιακή ασφάλεια και να χρησιμοποιήσει το AES256, μπορεί να εφαρμοστεί η ακόλουθη εντολή:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Stealthier version

> [!WARNING]
> Κάθε συνεδρία σύνδεσης μπορεί να έχει μόνο ένα ενεργό TGT τη φορά, οπότε να είστε προσεκτικοί.

1. Δημιουργήστε μια νέα συνεδρία σύνδεσης με **`make_token`** από το Cobalt Strike.
2. Στη συνέχεια, χρησιμοποιήστε το Rubeus για να δημιουργήσετε ένα TGT για τη νέα συνεδρία σύνδεσης χωρίς να επηρεάσετε την υπάρχουσα.

## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
