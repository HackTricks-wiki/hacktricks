# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς Λειτουργεί

**Smbexec** είναι ένα εργαλείο που χρησιμοποιείται για απομακρυσμένη εκτέλεση εντολών σε συστήματα Windows, παρόμοιο με το **Psexec**, αλλά αποφεύγει την τοποθέτηση κακόβουλων αρχείων στο σύστημα-στόχο.

### Κύρια Σημεία σχετικά με το **SMBExec**

- Λειτουργεί δημιουργώντας μια προσωρινή υπηρεσία (για παράδειγμα, "BTOBTO") στη μηχανή-στόχο για να εκτελεί εντολές μέσω του cmd.exe (%COMSPEC%), χωρίς να ρίχνει κανένα δυαδικό αρχείο.
- Παρά την κρυφή του προσέγγιση, δημιουργεί αρχεία καταγραφής γεγονότων για κάθε εντολή που εκτελείται, προσφέροντας μια μορφή μη διαδραστικού "shell".
- Η εντολή για σύνδεση χρησιμοποιώντας το **Smbexec** μοιάζει με αυτό:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Εκτέλεση Εντολών Χωρίς Δυαδικά

- **Smbexec** επιτρέπει την άμεση εκτέλεση εντολών μέσω των binPaths υπηρεσίας, εξαλείφοντας την ανάγκη για φυσικά δυαδικά στον στόχο.
- Αυτή η μέθοδος είναι χρήσιμη για την εκτέλεση εντολών μίας φοράς σε έναν στόχο Windows. Για παράδειγμα, η σύνδεση της με το module `web_delivery` του Metasploit επιτρέπει την εκτέλεση ενός PowerShell-στοχευμένου αντίστροφου payload Meterpreter.
- Δημιουργώντας μια απομακρυσμένη υπηρεσία στη μηχανή του επιτιθέμενου με το binPath ρυθμισμένο να εκτελεί την παρεχόμενη εντολή μέσω του cmd.exe, είναι δυνατό να εκτελεστεί το payload με επιτυχία, επιτυγχάνοντας callback και εκτέλεση payload με τον listener του Metasploit, ακόμη και αν προκύψουν σφάλματα απόκρισης υπηρεσίας.

### Παράδειγμα Εντολών

Η δημιουργία και εκκίνηση της υπηρεσίας μπορεί να επιτευχθεί με τις παρακάτω εντολές:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Για περισσότερες λεπτομέρειες ελέγξτε [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Αναφορές

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
