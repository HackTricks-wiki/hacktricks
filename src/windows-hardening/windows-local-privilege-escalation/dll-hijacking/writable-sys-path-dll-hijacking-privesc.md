# Yazılabilir System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

**System-wide `PATH`** içinde (yalnızca kullanıcı `PATH`'inizde değil) bir dizine **yazabiliyorsanız**, sistemde **privilege escalation** gerçekleştirebilirsiniz.

Daha yüksek ayrıcalıklara sahip bir service veya process, önceki arama konumlarında bulunmayan bir DLL'yi yüklemeye çalıştığında ve sonunda yazılabilir system `PATH` dizininde arama yaptığında, bu durum **DLL hijacking** yoluyla kötüye kullanılabilir.

Yazılabilir bir Machine `PATH` girdisi yalnızca bir **primitive**'dir; code execution kanıtı değildir. Standard search order kullanan paketlenmemiş bir application için `PATH`; redirection, API sets, SxS, loaded-module list, KnownDLLs, application ve Windows dizinleri ile current directory'den sonra kontrol edilir. Tam bir path veya `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` policy, `PATH`'i tamamen devre dışı bırakabilir.<sup>[[4]](#references)</sup>

**DLL hijacking** hakkında daha fazla bilgi için:

{{#ref}}
./
{{#endref}}

## DLL Hijacking ile Privesc

### Eksik bir DLL Bulma

İlk olarak, **daha yüksek ayrıcalıklarla** çalışan ve **yazılabilir bir system `PATH` dizininden DLL yüklemeye** çalışan bir process **belirleyin**.

Bu tekniğin yalnızca **User PATH**'inize değil, bir **Machine/System PATH** girdisine bağlı olduğunu unutmayın. Bu nedenle Procmon üzerinde zaman harcamadan önce **Machine PATH** girdilerini enumerate etmek ve hangilerinin yazılabilir olduğunu kontrol etmek faydalıdır:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
ACL metni yanıltıcı olabilir; çünkü grup üyeliği, deny ACE'leri ve miras alınan izinler sonucu etkiler. Yetkili bir testte, create/delete probe mevcut token'ın **effective access** durumunu kontrol eder (intrusive bir işlemdir ve alert oluşturabilir):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Hedefin etkin `PATH` değerini doğrulama

Kayıt defterinden okunan Machine `PATH` yapılandırma verisidir; loader, **hedef process**'in environment block'unu kullanır. Her process bir environment block'a sahiptir ve bir child normalde parent'ının environment'ının bir kopyasını devralır. Sonuç olarak, uzun süre çalışan bir service daha eski bir değeri koruyabilir ve özel bir environment ile başlatılan bir service, shell'inizde görülen değerden farklı olabilir. Hedef PID tarafından tam dizine yapılan gözlemlenmiş bir Procmon probe'unu gerçek referans olarak kabul edin; bir lab ortamında `PATH` değerini değiştirdikten sonra lookup'ın gerçekleşmediği sonucuna varmadan önce ilgili process tree'yi yeniden başlatın veya reboot edin.<sup>[[5]](#references)</sup>

Bu durumlarda sorun, söz konusu process'lerin muhtemelen zaten çalışıyor olmasıdır. Service'lerin yüklemeyi deneyip başarısız olduğu DLL'leri belirlemek için Procmon'u mümkün olduğunca erken (process'ler başlamadan önce) başlatın, ardından:

> [!WARNING]
> User-writable bir dizini Machine `PATH` değerine eklemek **vulnerable condition oluşturur**. Bunu yalnızca hangi privileged process'lerin `PATH`'e eriştiğini ortaya çıkarmak için izole bir research VM'de yapın; değerlendirilen bir host'ta system configuration'ı değiştirmeden mevcut writable entry'yi izleyin.<sup>[[1]](#references)</sup>

- `C:\privesc_hijacking` klasörünü **oluşturun** ve `C:\privesc_hijacking` path'ini **System Path env variable**'a ekleyin. Bunu **manuel olarak** veya **PS** ile yapabilirsiniz:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- **`procmon`**'u başlatın ve **`Options`** --> **`Enable boot logging`** bölümüne gidip istemde **`OK`** düğmesine basın.
- Ardından **reboot** yapın. Bilgisayar yeniden başlatıldığında **`procmon`**, olayları hemen **kaydetmeye** başlayacaktır.
- **Windows** **başlatıldıktan** sonra **`procmon`**'u tekrar çalıştırın. Size programın çalıştığını söyleyecek ve olayları bir dosyada **saklamak isteyip istemediğinizi soracaktır**. **Evet** deyin ve **olayları bir dosyada saklayın**.
- **Dosya** **oluşturulduktan** sonra açılan **`procmon`** penceresini **kapatın** ve **olaylar dosyasını açın**.
- Bir **process'in writable System Path klasöründen yüklemeye çalıştığı** tüm DLL'leri bulmak için şu **filtreleri** ekleyin:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging**, yalnızca aksi durumda gözlemlemek için **çok erken başlayan** servisler için gereklidir. Hedef service/programı **isteğe bağlı olarak tetikleyebiliyorsanız** (örneğin COM interface'iyle etkileşime girerek, service'i yeniden başlatarak veya scheduled task'ı yeniden çalıştırarak), genellikle **`Path contains .dll`**, **`Result is NAME NOT FOUND`** ve **`Path begins with <writable_machine_path>`** gibi filtrelerle normal bir Procmon kaydı almak daha hızlıdır.

### Kaçırılan DLL'ler

Bunu ücretsiz bir **sanal (vmware) Windows 11 makinesinde** çalıştırdığımda şu sonuçları elde ettim:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Bu durumda `.exe` sonuçlarını göz ardı edin. Eksik DLL aramaları şunlardan geldi:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Aşağıdaki örnekte, bu makalede açıklanan [**privilege escalation için `WptsExtensions.dll`'i abuse etme**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) tekniği kullanılmıştır.<sup>[[3]](#references)</sup>

### Triaging için değerlendirilmeye değer diğer adaylar

`WptsExtensions.dll` iyi bir örnektir, ancak privileged service'lerde tekrar tekrar görülen tek **phantom DLL** bu değildir. Modern hunting kuralları ve public hijack catalog'ları hâlâ şu adları takip etmektedir:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client sistemlerinde klasik bir **SYSTEM** adayıdır. Writable directory, **Machine PATH** içinde olduğunda ve service başlangıç sırasında DLL'i aradığında iyi bir seçenektir. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Service **SYSTEM** olarak çalıştığı ve bazı build'lerde **normal bir kullanıcı tarafından isteğe bağlı olarak tetiklenebildiği** için **server editions** üzerinde ilgi çekicidir; bu durum onu yalnızca reboot gerektiren vakalardan daha iyi hâle getirir. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Genellikle ilk olarak **`NT AUTHORITY\LOCAL SERVICE`** elde edilir. Bu çoğu zaman yine de yeterlidir, çünkü token'da **`SeImpersonatePrivilege`** bulunur; böylece bunu [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) ile chain edebilirsiniz. |

Bu adları kesin sonuçlar olarak değil, **triage ipuçları** olarak değerlendirin: sonuçlar **SKU/build'e bağlıdır** ve Microsoft sürümler arasında davranışı değiştirebilir. Önemli nokta, özellikle service **reboot olmadan yeniden tetiklenebiliyorsa**, **Machine PATH'i dolaşan privileged service'lerde eksik DLL'leri** aramaktır.

### Weaponize etmeden önce bir adayı doğrulama

Tek başına bir `NAME NOT FOUND` olayı yeterli değildir. Bir payload yerleştirmeden önce zincirin tamamını doğrulayın:<sup>[[1]](#references)[[4]](#references)</sup>

1. Olayın beklenen **PID, command line, service account ve integrity level**'a ait olduğunu ve eksik path'in tam olarak writable Machine `PATH` directory'si olduğunu doğrulayın.
2. Aynı DLL basename'i için daha önceki hiçbir directory'nin `SUCCESS` döndürmediğini ve module'ün loaded-module list, KnownDLLs, redirection veya SxS manifest tarafından karşılanmadığını doğrulayın.
3. Düşük ayrıcalıklı bir kullanıcı hedeflenen trigger'ı çalıştırdığında aramanın tekrarlandığını doğrulayın. Yalnızca boot sırasında yapılan bir arama kullanılabilir, ancak isteğe bağlı bir aramaya göre operasyonel olarak çok daha kötüdür.
4. Payload architecture'ın process ile eşleştiğini doğrulayın. Application daha sonra export'ları çözümlüyorsa legitimate DLL'i proxy'leyin veya beklenen symbol'leri export edin; bkz. [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Önce PID, identity ve timestamp kaydeden zararsız bir canary DLL kullanın. Procmon'da, önceki bir file probe'un execution'a neden olduğunu varsaymak yerine, yerleştirilen path'ten başarılı bir **`Load Image`** gerektiğini doğrulayın.

### Exploitation

**Privileges escalate** etmek için **`WptsExtensions.dll`**'i hijack edin. **Path** ve **name** bilindikten sonra malicious DLL'i oluşturun.

[**Bu örneklerden herhangi birini kullanmayı deneyebilirsiniz**](README.md#creating-and-compiling-dlls). Şu payload'ları çalıştırabilirsiniz: rev shell almak, user eklemek, beacon execute etmek...

> [!WARNING]
> Tüm service'lerin **`NT AUTHORITY\SYSTEM`** olarak çalışmadığını unutmayın. Bazıları **`NT AUTHORITY\LOCAL SERVICE`** olarak çalışır; bu account'ın **daha az privilege'ı** vardır, dolayısıyla bu service'lerden birini abuse etmek yeni bir user oluşturmanıza izin vermeyebilir.\
> Ancak bu account'ta **`SeImpersonatePrivilege`** user right'ı bulunur; bu nedenle [**privilege escalation için Potato suite'i kullanabilirsiniz**](../roguepotato-and-printspoofer.md). Bu durumda reverse shell, user oluşturmaya çalışmaktan daha iyi bir seçenektir.

**Task Scheduler** service'i normalde **`NT AUTHORITY\SYSTEM`** olarak çalışır, ancak gerçek deployment'ı doğrulayın ve execution identity'sini yalnızca service name'inden çıkarmayın:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
**malicious Dll**'i oluşturduktan sonra (_benim durumumda x64 rev shell kullandım ve geri bir shell aldım ancak msfvenom'dan geldiği için defender bunu sonlandırdı_), onu writable System Path'e **WptsExtensions.dll** adıyla kaydedin ve bilgisayarı **restart** edin (veya servisi yeniden başlatın ya da etkilenen service/program'ın yeniden çalışmasını sağlamak için gereken işlemi yapın).

Service yeniden başlatıldığında, **DLL yüklenmeli ve çalıştırılmalıdır** (**library'nin beklendiği gibi yüklenip yüklenmediğini** kontrol etmek için **Procmon** yöntemini yeniden kullanabilirsiniz).

> [!NOTE]
> Tetiklemeden önce cleanup işlemini planlayın. Bir service, durana kadar DLL'yi mapped durumda tutabilir ve dosyayı kilitleyebilir; `WptsExtensions.dll` için Task Scheduler'ı durdurmak elevated rights gerektirir. İstenen context'i elde ettikten sonra hedefi güvenli bir şekilde durdurun, payload'ı kaldırın ve yalnızca lab için yapılan `PATH` değişikliğini geri alın.<sup>[[1]](#references)</sup>

### Düzeltme / tespit

Her Machine `PATH` directory'sinden zayıf write izinlerini kaldırın ve stale entry'leri silin. Developers, trusted library'leri full path kullanarak yüklemeli veya `SetDefaultDllDirectories` / `LoadLibraryEx` search flag'leriyle resolution'ı sınırlandırmalıdır. Defenders, Machine `PATH` üzerindeki değişiklikleri, privileged process'lerin non-system ve user-writable directory'lerden DLL yüklemesiyle ilişkilendirebilir.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking (Umarım) Açıklığa Kavuşturuldu](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Persistence veya Privilege Escalation için Şüpheli DLL Yüklendi](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Environment Variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
