# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Bir **System Path klasörüne yazabildiğinizi** tespit ettiyseniz (bunun bir User Path klasörüne yazabildiğiniz durumda çalışmayacağını unutmayın), sistemde **yetki yükseltmeniz** mümkün olabilir.

Bunu gerçekleştirmek için, sizden **daha fazla yetkiye** sahip bir service veya process tarafından yüklenen bir library'yi **hijack** edeceğiniz bir **Dll Hijacking** yöntemini kötüye kullanabilirsiniz. Bu service, muhtemelen sistemin hiçbir yerinde bulunmayan bir Dll'yi yüklemeye çalıştığı için, yazabildiğiniz System Path içinden yüklemeyi deneyecektir.

**Dll Hijacking'in ne olduğu** hakkında daha fazla bilgi için:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

İhtiyacınız olan ilk şey, sizden **daha fazla yetkiyle** çalışan ve yazabildiğiniz System Path içinden bir Dll **yüklemeye çalışan bir process** tespit etmektir.

Bu tekniğin yalnızca **User PATH**'inize değil, bir **Machine/System PATH** girdisine bağlı olduğunu unutmayın. Bu nedenle Procmon üzerinde zaman harcamadan önce **Machine PATH** girdilerini listelemeye ve hangilerinin yazılabilir olduğunu kontrol etmeye değer:<sup>[[1]](#references)</sup>
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
Bu durumlardaki sorun, muhtemelen söz konusu process'lerin zaten çalışıyor olmasıdır. Hangi DLL'lerin eksik olduğunu bulmak için procmon'ı mümkün olduğunca hızlı bir şekilde (process'ler yüklenmeden önce) başlatmanız gerekir. Eksik .dll'leri bulmak için:

- **`C:\privesc_hijacking`** klasörünü oluşturun ve **System Path env variable**'a **`C:\privesc_hijacking`** yolunu ekleyin. Bunu **manuel olarak** veya **PS** ile yapabilirsiniz:
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
- **`procmon`**'u başlatın ve **`Options`** --> **`Enable boot logging`** seçeneğine gidip istemde **`OK`** düğmesine basın.
- Ardından **yeniden başlatın**. Bilgisayar yeniden başlatıldığında **`procmon`**, mümkün olan en kısa sürede olayları **kaydetmeye** başlayacaktır.
- **Windows** **başlatıldıktan sonra `procmon`'u** tekrar çalıştırın. Size programın çalıştığını söyleyecek ve olayları bir dosyada **saklamak isteyip istemediğinizi soracaktır**. **Evet** deyin ve **olayları bir dosyaya kaydedin**.
- **Dosya** **oluşturulduktan sonra**, açık olan **`procmon`** penceresini kapatın ve **olaylar dosyasını açın**.
- Bu **filtreleri** eklediğinizde, bazı **process'lerin writable System Path klasöründen yüklemeye çalıştığı** tüm DLL'leri bulabilirsiniz:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging**, yalnızca gözlemlemek için **çok erken başlayan** service'ler için gereklidir. **Hedef service/programı isteğe bağlı olarak tetikleyebiliyorsanız** (örneğin COM interface'iyle etkileşime girerek, service'i yeniden başlatarak veya scheduled task'ı yeniden çalıştırarak), genellikle **`Path contains .dll`**, **`Result is NAME NOT FOUND`** ve **`Path begins with <writable_machine_path>`** gibi filtrelerle normal bir Procmon kaydı almak daha hızlıdır.

### Kaçırılan DLL'ler

Bunu boş bir **virtual (vmware) Windows 11 makinesinde** çalıştırdığımda şu sonuçları elde ettim:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Bu durumda .exe dosyaları işe yaramıyor, bu yüzden onları yok sayın; kaçırılan DLL'ler şunlardandı:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Bunu bulduktan sonra, [**privesc için WptsExtensions.dll'in nasıl abuse edileceğini açıklayan**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) bu ilginç blog yazısına rastladım. Şimdi **yapacağımız şey de bu**.<sup>[[3]](#references)</sup>

### İncelenmeye değer diğer adaylar

`WptsExtensions.dll` iyi bir örnektir, ancak ayrıcalıklı service'lerde görülen tek tekrarlayan **phantom DLL** değildir. Modern hunting kuralları ve public hijack catalog'ları hâlâ şu isimleri takip etmektedir:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | İstemci sistemlerinde klasik bir **SYSTEM** adayıdır. Writable dizin **Machine PATH** içinde olduğunda ve service başlangıç sırasında DLL'i aradığında kullanışlıdır. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | **Server edition'larında** ilgi çekicidir; çünkü service **SYSTEM** olarak çalışır ve bazı build'lerde **normal bir user tarafından isteğe bağlı olarak tetiklenebilir**. Bu da onu yalnızca reboot gerektiren durumlardan daha iyi hâle getirir. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Genellikle önce **`NT AUTHORITY\LOCAL SERVICE`** elde edilir. Bu çoğu zaman yine de yeterlidir; çünkü token'da **`SeImpersonatePrivilege`** bulunur ve bunu [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) ile chain edebilirsiniz. |

Bu isimleri kesin başarı garantisi olarak değil, **triage ipuçları** olarak değerlendirin: Sonuçlar **SKU/build'e bağlıdır** ve Microsoft sürümler arasında davranışı değiştirebilir. Önemli nokta, özellikle **reboot yapmadan yeniden tetiklenebilen** service'lerde **Machine PATH'i dolaşan ayrıcalıklı service'lerde eksik DLL'leri** aramaktır.

### Exploitation

Dolayısıyla **privilege escalation** gerçekleştirmek için **WptsExtensions.dll** library'sini hijack edeceğiz. **Path** ve **name** elimizde olduğuna göre yalnızca **malicious DLL'i oluşturmamız** gerekiyor.

[**Bu örneklerden herhangi birini kullanmayı deneyebilirsiniz**](#creating-and-compiling-dlls). Şu payload'ları çalıştırabilirsiniz: rev shell almak, user eklemek, beacon çalıştırmak...

> [!WARNING]
> **Tüm service'lerin** **`NT AUTHORITY\SYSTEM`** ile çalışmadığını unutmayın; bazıları daha **az ayrıcalığa** sahip olan **`NT AUTHORITY\LOCAL SERVICE`** ile de çalışır ve **yeni bir user oluşturamazsınız** veya bu user'ın izinlerini abuse edemezsiniz.\
> Ancak bu user'da **`seImpersonate`** privilege'ı vardır; bu nedenle [ **privilege escalation için potato suite'i kullanabilirsiniz**](../roguepotato-and-printspoofer.md). Bu durumda rev shell, user oluşturmaya çalışmaktan daha iyi bir seçenektir.

Yazının yazıldığı sırada **Task Scheduler** service'i **Nt AUTHORITY\SYSTEM** ile çalışmaktadır.

**Malicious DLL'i oluşturduktan** sonra (_ben x64 rev shell kullandım ve geri shell aldım, ancak msfvenom'dan geldiği için defender onu sonlandırdı_), bunu writable System Path içine **WptsExtensions.dll** adıyla kaydedin ve bilgisayarı **yeniden başlatın** (veya service'i yeniden başlatın ya da etkilenen service/programı tekrar çalıştırmak için gereken işlemi yapın).

Service yeniden başlatıldığında **DLL yüklenmeli ve çalıştırılmalıdır** (**library'nin beklendiği gibi yüklenip yüklenmediğini** kontrol etmek için **procmon** tekniğini yeniden kullanabilirsiniz).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
