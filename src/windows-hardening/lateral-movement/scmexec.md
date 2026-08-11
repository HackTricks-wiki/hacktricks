# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργεί

Το Service Control Manager Remote Protocol (SCMR) είναι ένα πρωτόκολλο βασισμένο σε RPC για τη διαμόρφωση και τον έλεγχο υπηρεσιών Windows σε έναν απομακρυσμένο υπολογιστή. Με επαρκή δικαιώματα, ένας operator μπορεί να δημιουργήσει ή να επαναδιαμορφώσει μια υπηρεσία, της οποίας η binary path περιέχει μια εντολή, και στη συνέχεια να εκκινήσει την υπηρεσία για να εκτελέσει την εντολή απομακρυσμένα.<sup>[[1]](#references)</sup>

## Εργαλεία

Το **SharpMove** υποστηρίζει authenticated remote execution μέσω SCM και αρκετών άλλων μηχανισμών των Windows. Το ακόλουθο παράδειγμα επιλέγει την ενέργεια SCM, δημιουργεί μια υπηρεσία με όνομα `WindowsDebug` και την κατευθύνει σε ένα payload που υπάρχει ήδη στον απομακρυσμένο host.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Επισκόπηση του Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}
