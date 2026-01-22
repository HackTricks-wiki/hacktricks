# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Όταν η υπηρεσία Windows Telephony (TapiSrv, `tapisrv.dll`) είναι ρυθμισμένη ως **TAPI server**, εκθέτει το **`tapsrv` MSRPC interface πάνω από το `\pipe\tapsrv` named pipe** σε αυθεντικοποιημένους SMB clients. Ένα σχεδιαστικό σφάλμα στην ασύγχρονη παράδοση συμβάντων για απομακρυσμένους clients επιτρέπει σε έναν επιτιθέμενο να μετατρέψει ένα mailslot handle σε έναν **ελεγχόμενο 4-byte write σε οποιοδήποτε προϋπάρχον αρχείο που είναι εγγράψιμο από το `NETWORK SERVICE`**. Αυτό το primitive μπορεί να αλυσιδωθεί για να αντικαταστήσει τη λίστα admin του Telephony και να εκμεταλλευτεί ένα **admin-only arbitrary DLL load** για να εκτελέσει κώδικα ως `NETWORK SERVICE`.

## Attack Surface
- **Remote exposure only when enabled**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` πρέπει να επιτρέψει το sharing (ή να έχει ρυθμιστεί μέσω `TapiMgmt.msc` / `tcmsetup /c <server>`). Εξ ορισμού, το `tapsrv` είναι μόνο τοπικό.
- Interface: MS-TRP (`tapsrv`) πάνω από **SMB named pipe**, οπότε ο επιτιθέμενος χρειάζεται έγκυρη SMB αυθεντικοποίηση.
- Service account: `NETWORK SERVICE` (manual start, on-demand).

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` αρχικοποιεί την ασύγχρονη παράδοση συμβάντων. Σε pull mode, η υπηρεσία κάνει:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
χωρίς να ελέγχει ότι το `pszDomainUser` είναι mailslot path (`\\*\MAILSLOT\...`). Οποιοδήποτε **υφιστάμενο filesystem path** εγγράψιμο από το `NETWORK SERVICE` γίνεται αποδεκτό.
- Κάθε ασύγχρονη εγγραφή συμβάντος αποθηκεύει ένα μόνο **`DWORD` = `InitContext`** (ελεγχόμενο από τον επιτιθέμενο στο επόμενο `Initialize` request) στο ανοιχτό handle, παράγοντας **write-what/write-where (4 bytes)**.

## Forcing Deterministic Writes
1. **Open target file**: `ClientAttach` με `pszDomainUser = <existing writable path>` (π.χ., `C:\Windows\TAPI\tsec.ini`).
2. Για κάθε `DWORD` που θέλεις να γράψεις, εκτέλεσε την παρακάτω ακολουθία RPC ενάντια σε `ClientRequest`:
- `Initialize` (`Req_Func 47`): θέσε `InitContext = <4-byte value>` και `pszModuleName = DIALER.EXE` (ή κάποιο άλλο top entry στη per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (εγγράφει το line app, επαναϋπολογίζει τον recipient με την υψηλότερη προτεραιότητα).
- `TRequestMakeCall` (`Req_Func 121`): αναγκάζει `NotifyHighestPriorityRequestRecipient`, δημιουργώντας το ασύγχρονο συμβάν.
- `GetAsyncEvents` (`Req_Func 0`): αποθέτει/ολοκληρώνει τη write.
- `LRegisterRequestRecipient` ξανά με `bEnable = 0` (απεγγραφή).
- `Shutdown` (`Req_Func 86`) για teardown του line app.
- Έλεγχος προτεραιότητας: ο “highest priority” recipient επιλέγεται συγκρίνοντας το `pszModuleName` με το `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (διαβάζεται ενώ γίνεται impersonating του client). Εάν χρειαστεί, εισάγεις το module name μέσω `LSetAppPriority` (`Req_Func 69`).
- Το αρχείο **πρέπει να υπάρχει ήδη** επειδή χρησιμοποιείται `OPEN_EXISTING`. Συνηθισμένοι υποψήφιοι που είναι εγγράψιμοι από `NETWORK SERVICE`: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## From DWORD Write to RCE inside TapiSrv
1. **Grant yourself Telephony “admin”**: στόχευσε `C:\Windows\TAPI\tsec.ini` και πρόσθεσε `[TapiAdministrators]\r\n<DOMAIN\\user>=1` χρησιμοποιώντας τις 4-byte εγγραφές παραπάνω. Ξεκίνησε μια **νέα** συνεδρία (`ClientAttach`) ώστε η υπηρεσία να ξαναδιαβάσει το INI και να θέσει `ptClient->dwFlags |= 9` για τον λογαριασμό σου.
2. **Admin-only DLL load**: στείλε `GetUIDllName` με `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` και δώσε ένα path μέσω `dwProviderFilenameOffset`. Για admins, η υπηρεσία κάνει `LoadLibrary(path)` και καλεί το export `TSPI_providerUIIdentify`:
- Λειτουργεί με UNC paths προς ένα πραγματικό Windows SMB share; κάποιοι επιτιθέμενοι SMB servers αποτυγχάνουν με `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Εναλλακτικά: αργά τοποθέτησε ένα τοπικό DLL χρησιμοποιώντας το ίδιο primitive των 4-byte εγγραφών, και μετά το φόρτωσε.
3. **Payload**: το export εκτελείται υπό `NETWORK SERVICE`. Ένα ελάχιστο DLL μπορεί να τρέξει `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` και να επιστρέψει μια μη-μηδενική τιμή (π.χ., `0x1337`) ώστε η υπηρεσία να αποφορτώσει το DLL, επιβεβαιώνοντας την εκτέλεση.

## Hardening / Detection Notes
- Απενεργοποίησε το TAPI server mode εκτός αν απαιτείται; μπλόκαρε την απομακρυσμένη πρόσβαση στο `\pipe\tapsrv`.
- Εφάρμοσε validation του mailslot namespace (`\\*\MAILSLOT\`) πριν το άνοιγμα των paths που παρέχονται από clients.
- Στεγάνωσε τα ACLs του `C:\Windows\TAPI\tsec.ini` και παρακολουθούσε αλλαγές; ενεργοποίησε alert για κλήσεις `GetUIDllName` που φορτώνουν μη-προεπιλεγμένα paths.

## References
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
