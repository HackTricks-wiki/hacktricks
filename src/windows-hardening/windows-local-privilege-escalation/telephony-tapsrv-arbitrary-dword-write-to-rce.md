# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Όταν η υπηρεσία Windows Telephony (TapiSrv, `tapisrv.dll`) έχει ρυθμιστεί ως **TAPI server**, εκθέτει το **`tapsrv` MSRPC interface μέσω του named pipe `\pipe\tapsrv`** σε authenticated SMB clients. Το CVE-2026-20931 στην asynchronous event delivery επιτρέπει σε έναν attacker να μετατρέψει ένα υποτιθέμενο mailslot handle σε **controlled εγγραφή 4 byte σε ένα προϋπάρχον αρχείο, στο οποίο έχει δικαίωμα εγγραφής το `NETWORK SERVICE`**. Η δημοσιευμένη αλυσίδα τροποποιεί τη λίστα Telephony administrators και στη συνέχεια φτάνει σε administrator-only DLL load, εκτελώντας κώδικα ως `NETWORK SERVICE`.<sup>[[1]](#references)[[2]](#references)</sup>

## Attack Surface

- **Remote exposure only when enabled**: Το `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` πρέπει να επιτρέπει το sharing (ή να έχει ρυθμιστεί μέσω `TapiMgmt.msc` / `tcmsetup /c <server>`). Από προεπιλογή, το `tapsrv` είναι local-only.
- Interface: MS-TRP (`tapsrv`) μέσω **SMB named pipe**, επομένως ο attacker χρειάζεται valid SMB auth.
- Service account: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- Η `ClientAttach(pszDomainUser, pszMachine, ...)` αρχικοποιεί το async event delivery. Σε pull mode, η υπηρεσία εκτελεί:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
χωρίς να επικυρώνει ότι το `pszDomainUser` είναι mailslot path (`\\*\MAILSLOT\...`). Οποιοδήποτε **υπάρχον filesystem path** στο οποίο έχει δικαίωμα εγγραφής το `NETWORK SERVICE` γίνεται αποδεκτό.
- Κάθε async event write αποθηκεύει ένα μόνο **`DWORD` = `InitContext`** (ελεγχόμενο από τον attacker στο επόμενο `Initialize` request) στο ανοιγμένο handle, παρέχοντας **write-what/write-where (4 bytes)**.<sup>[[1]](#references)</sup>

## Forcing Deterministic Writes
1. **Open target file**: `ClientAttach` με `pszDomainUser = <existing writable path>` (π.χ. `C:\Windows\TAPI\tsec.ini`).
2. Για κάθε `DWORD` που θέλετε να γράψετε, εκτελέστε την ακόλουθη RPC sequence εναντίον του `ClientRequest`:
- `Initialize` (`Req_Func 47`): ορίστε `InitContext = <4-byte value>` και `pszModuleName = DIALER.EXE` (ή άλλο module από τις πρώτες θέσεις της per-user priority list).
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (κάνει register το line app και υπολογίζει ξανά τον recipient με την υψηλότερη προτεραιότητα).
- `TRequestMakeCall` (`Req_Func 121`): προκαλεί `NotifyHighestPriorityRequestRecipient`, δημιουργώντας το async event.
- `GetAsyncEvents` (`Req_Func 0`): κάνει dequeue/complete το write.
- `LRegisterRequestRecipient` ξανά με `bEnable = 0` (unregister).
- `Shutdown` (`Req_Func 86`) για να τερματιστεί το line app.
- Priority control: ο recipient με την “highest priority” επιλέγεται μέσω σύγκρισης του `pszModuleName` με το `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (το οποίο διαβάζεται ενώ γίνεται impersonation του client). Αν χρειάζεται, εισαγάγετε το module name σας μέσω `LSetAppPriority` (`Req_Func 69`).
- Το αρχείο **πρέπει να υπάρχει ήδη**, επειδή χρησιμοποιείται το `OPEN_EXISTING`. Συνηθισμένοι writable από το `NETWORK SERVICE` υποψήφιοι: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## From DWORD Write to RCE inside TapiSrv
1. **Grant yourself Telephony “admin”**: στοχεύστε το `C:\Windows\TAPI\tsec.ini` και προσθέστε στο τέλος `[TapiAdministrators]\r\n<DOMAIN\\user>=1` χρησιμοποιώντας τα παραπάνω 4-byte writes. Ξεκινήστε ένα **νέο** session (`ClientAttach`), ώστε η υπηρεσία να διαβάσει ξανά το INI και να ορίσει `ptClient->dwFlags |= 9` για τον λογαριασμό σας.
2. **Admin-only DLL load**: στείλτε `GetUIDllName` με `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` και δώστε ένα path μέσω του `dwProviderFilenameOffset`. Για admins, η υπηρεσία εκτελεί `LoadLibrary(path)` και στη συνέχεια καλεί το export `TSPI_providerUIIdentify`:
- Λειτουργεί με UNC paths προς ένα πραγματικό Windows SMB share· ορισμένοι attacker SMB servers αποτυγχάνουν με `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternative: γράψτε αργά ένα local DLL χρησιμοποιώντας το ίδιο 4-byte write primitive και στη συνέχεια φορτώστε το.
3. **Payload**: το export εκτελείται υπό το `NETWORK SERVICE`. Ένα minimal DLL μπορεί να εκτελέσει `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` και να επιστρέψει non-zero value (π.χ. `0x1337`), ώστε η υπηρεσία να κάνει unload το DLL, επιβεβαιώνοντας την εκτέλεση.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- Εγκαταστήστε το Microsoft security update για το CVE-2026-20931. Ανεξάρτητα από αυτό, απενεργοποιήστε το TAPI server mode εκτός αν απαιτείται και αποκλείστε την remote access στο `\pipe\tapsrv`.
- Επιβάλετε mailslot namespace validation (`\\*\MAILSLOT\`) πριν από το άνοιγμα paths που παρέχονται από clients.
- Περιορίστε τα ACLs του `C:\Windows\TAPI\tsec.ini` και παρακολουθείτε τις αλλαγές· δημιουργήστε alert για κλήσεις `GetUIDllName` που φορτώνουν non-default paths.<sup>[[1]](#references)</sup>

## References

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
