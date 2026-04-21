# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Eğer bir **System Path** klasörüne **yazabildiğinizi** fark ettiyseniz (not: **User Path** klasörüne yazabiliyor olmanız bu durumda işe yaramaz), sistemde **privileges** yükseltmeniz mümkün olabilir.

Bunu yapmak için, sizden **daha yüksek privileges** ile çalışan bir servis veya process tarafından **yüklenen bir kütüphaneyi ele geçirdiğiniz** bir **Dll Hijacking** tekniğini kötüye kullanabilirsiniz; çünkü bu servis, muhtemelen sistemin tamamında bile olmayan bir Dll yüklemeye çalıştığında, onu yazabildiğiniz System Path içinden yüklemeyi deneyecektir.

**Dll Hijackig** nedir hakkında daha fazla bilgi için şuna bakın:


{{#ref}}
./
{{#endref}}

## Dll Hijacking ile Privesc

### Eksik bir Dll bulma

İlk ihtiyacınız olan şey, sizden **daha yüksek privileges** ile çalışan ve yazabildiğiniz **System Path** içinden bir **Dll yüklemeye çalışan** bir **process** belirlemektir.

Bu tekniğin yalnızca **Machine/System PATH** girdisine bağlı olduğunu, sadece **User PATH** üzerinde çalışmadığını unutmayın. Bu yüzden Procmon üzerinde zaman harcamadan önce, **Machine PATH** girdilerini enumerate edip hangilerinin writable olduğunu kontrol etmekte fayda var:
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
Bu durumlarda sorun, muhtemelen bu süreçlerin zaten çalışıyor olmasıdır. Hangi Dlls’in eksik olduğunu bulmak için procmon’u mümkün olan en kısa sürede başlatmanız gerekir (processes yüklenmeden önce). Bu nedenle, eksik .dlls’leri bulmak için şunu yapın:

- **Create** `C:\privesc_hijacking` klasörünü oluşturun ve `C:\privesc_hijacking` yolunu **System Path env variable** içine ekleyin. Bunu **manuel** olarak veya **PS** ile yapabilirsiniz:
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
- **`procmon`** uygulamasını başlatın ve **`Options`** --> **`Enable boot logging`** seçeneğine gidin ve istemde **`OK`** tuşuna basın.
- Ardından, **yeniden başlatın**. Bilgisayar yeniden başladığında **`procmon`** olayları mümkün olan en kısa sürede **kaydetmeye** başlayacaktır.
- **Windows** açıldıktan sonra **`procmon`** uygulamasını tekrar çalıştırın; program, bir süredir çalıştığını söyleyecek ve olayları bir dosyada **saklamak isteyip istemediğinizi** soracaktır. **Evet** deyin ve olayları bir dosyaya **kaydedin**.
- **Dosya** oluşturulduktan **sonra**, açık **`procmon`** penceresini **kapatın** ve **olaylar dosyasını açın**.
- Bu **filtreleri** ekleyin; böylece writable System Path klasöründen yüklemeye çalışan tüm Dlls'leri bulacaksınız:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** yalnızca başka şekilde gözlemleyemeyeceğiniz kadar erken başlayan servisler için gereklidir. Hedef service/program'ı **istek üzerine tetikleyebiliyorsanız** (örneğin COM interface'i ile etkileşime girerek, servisi yeniden başlatarak veya bir scheduled task'i tekrar çalıştırarak), genellikle **`Path contains .dll`**, **`Result is NAME NOT FOUND`** ve **`Path begins with <writable_machine_path>`** gibi filtrelerle normal bir Procmon capture almak daha hızlıdır.

### Kaçırılan Dlls

Bunu ücretsiz bir **virtual (vmware) Windows 11 machine** üzerinde çalıştırdığımda şu sonuçları aldım:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Bu durumda .exe dosyaları işe yaramaz, bu yüzden onları yok sayın; kaçırılan DLLs şuradan geliyordu:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Bunu bulduktan sonra, [**privesc için WptsExtensions.dll nasıl abuse edilir**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) konusunu da açıklayan bu ilginç blog yazısını buldum. Şimdi **yapacağımız şey de bu**.

### Triyaj yapmaya değer diğer adaylar

`WptsExtensions.dll` iyi bir örnektir, ancak privileged services içinde görünen tek tekrar eden **phantom DLL** bu değildir. Modern hunting kuralları ve public hijack katalogları hâlâ aşağıdaki isimleri takip eder:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client sistemlerde klasik bir **SYSTEM** adayı. Writable dizin **Machine PATH** içindeyse ve service başlangıçta DLL'i kontrol ediyorsa iyidir. |
| Windows Server üzerinde NetMan | `wlanhlp.dll` / `wlanapi.dll` | **Server editions** üzerinde ilginçtir; çünkü service **SYSTEM** olarak çalışır ve bazı build'lerde **normal bir user tarafından isteğe bağlı olarak tetiklenebilir**, bu da onu yalnızca reboot gerektiren durumlardan daha iyi yapar. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Genellikle önce **`NT AUTHORITY\LOCAL SERVICE`** verir. Bu çoğu zaman yine de yeterlidir; çünkü token **`SeImpersonatePrivilege`** içerir, bu yüzden bunu [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) ile zincirleyebilirsiniz. |

Bu isimleri **garantili başarı** olarak değil, **triyaj ipuçları** olarak değerlendirin: bunlar **SKU/build dependent**'tır ve Microsoft sürümler arasında davranışı değiştirebilir. Asıl önemli çıkarım, **Machine PATH** boyunca arama yapan privileged services içinde **eksik DLLs** aramaktır; özellikle de service **yeniden başlatmadan tekrar tetiklenebiliyorsa**.

### Exploitation

Bu yüzden, **privileges** yükseltmek için **WptsExtensions.dll** kütüphanesini hijack edeceğiz. **Path** ve **name** elimizde olduğuna göre tek yapmamız gereken **malicious dll** oluşturmak.

Bu örneklerden herhangi birini [**kullanmaya çalışabilirsiniz**](#creating-and-compiling-dlls). Şunlar gibi payloads çalıştırabilirsiniz: rev shell almak, user eklemek, beacon çalıştırmak...

> [!WARNING]
> Tüm service'lerin **`NT AUTHORITY\SYSTEM`** ile çalışmadığını unutmayın; bazıları **`NT AUTHORITY\LOCAL SERVICE`** ile de çalışır, bu daha az privileges verir ve yeni bir user oluşturup yetkilerini abuse edemezsiniz.\
> Ancak bu user'ın **`seImpersonate`** privilege'ı vardır, bu yüzden privileges yükseltmek için [**potato suite**](../roguepotato-and-printspoofer.md) kullanabilirsiniz. Dolayısıyla bu durumda, user oluşturmaya çalışmak yerine rev shell daha iyi bir seçenektir.

Bu yazının yazıldığı anda **Task Scheduler** service'i **Nt AUTHORITY\SYSTEM** ile çalışıyordu.

**Malicious Dll** oluşturduktan sonra (_benim durumumda x64 rev shell kullandım ve shell geri aldım, ancak Defender bunu msfvenom'dan geldiği için öldürdü_), bunu writable System Path içine **WptsExtensions.dll** adıyla kaydedin ve bilgisayarı **yeniden başlatın** (veya service'i yeniden başlatın ya da etkilenen service/program'ı tekrar çalıştırmak için ne gerekiyorsa yapın).

Service yeniden başlatıldığında, **dll yüklenmeli ve çalıştırılmalıdır** (library'nin beklendiği gibi yüklendiğini kontrol etmek için **procmon** hilesini **yeniden kullanabilirsiniz**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
