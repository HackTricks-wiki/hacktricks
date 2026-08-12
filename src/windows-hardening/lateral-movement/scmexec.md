# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργεί

Το Service Control Manager Remote Protocol (SCMR) είναι ένα πρωτόκολλο βασισμένο σε RPC για τη διαμόρφωση και τον έλεγχο Windows services σε έναν απομακρυσμένο υπολογιστή. Με επαρκή δικαιώματα, ένας operator μπορεί να δημιουργήσει ή να επαναδιαμορφώσει ένα service, του οποίου το binary path περιέχει μια εντολή, και στη συνέχεια να εκκινήσει αυτό το service για να εκτελέσει την εντολή απομακρυσμένα.<sup>[[1]](#references)</sup>

Αν δεν καθοριστεί service account, το `CreateService` χρησιμοποιεί το `LocalSystem`, το οποίο διαθέτει εκτεταμένα τοπικά δικαιώματα. Αυτό εξηγεί τον υψηλό αντίκτυπο μιας επιτυχούς SCM execution. Δεν απενεργοποιεί εγγενώς το UAC ή το Microsoft Defender: ο caller εξακολουθεί να χρειάζεται δικαιώματα απομακρυσμένου SCM, ενώ τα endpoint controls μπορούν να επιθεωρήσουν ή να αποκλείσουν το service ή το payload.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Εργαλεία

Το **SharpMove** υποστηρίζει authenticated remote execution μέσω SCM και αρκετών άλλων Windows mechanisms. Το ακόλουθο παράδειγμα επιλέγει το SCM action, δημιουργεί ένα service με όνομα `WindowsDebug` και το αντιστοιχίζει σε ένα payload που υπάρχει ήδη στον απομακρυσμένο host.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - επισκόπηση του Remote Protocol του Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - λογαριασμός LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - συνάρτηση `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
