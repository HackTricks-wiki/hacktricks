# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

**system-wide `PATH`** içindeki bir dizine **yazabiliyorsanız** (yalnızca kullanıcı `PATH`'inize değil), sistemde **privileges escalate** edebilirsiniz.

Daha yüksek yetkilere sahip bir service veya process, önceki arama konumlarında bulunmayan bir DLL'i yüklemeye çalıştığında ve sonunda writable system `PATH` dizinini aradığında, bu durum **DLL hijacking** üzerinden kötüye kullanılabilir.

**DLL hijacking** hakkında daha fazla bilgi için bkz.:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a Missing DLL

İlk olarak, **writable system `PATH` directory** içinden bir **DLL load** etmeye çalışan ve **daha yüksek privileges** ile çalışan bir **process** belirleyin.

Bu tekniğin yalnızca **User PATH**'inize değil, bir **Machine/System PATH** girdisine dayandığını unutmayın. Bu nedenle Procmon üzerinde zaman harcamadan önce **Machine PATH** girdilerini enumerate etmek ve hangilerinin writable olduğunu kontrol etmek faydalıdır:<sup>[[1]](#references)</sup>
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
Bu durumlarda sorun, söz konusu işlemlerin muhtemelen zaten çalışıyor olmasıdır. Hizmetlerin yüklemeye çalıştığı ancak yükleyemediği DLL'leri belirlemek için Procmon'u mümkün olduğunca erken (işlemler başlamadan önce) başlatın, ardından:

- **`C:\privesc_hijacking`** klasörünü oluşturun ve **System Path env variable**'a `C:\privesc_hijacking` yolunu ekleyin. Bunu **manuel olarak** veya **PS** kullanarak yapabilirsiniz:
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
- **`procmon`**'ı başlatın ve **`Options`** --> **`Enable boot logging`** seçeneğine gidip istemde **`OK`** düğmesine basın.
- Ardından **reboot** yapın. Bilgisayar yeniden başlatıldığında **`procmon`**, olayları en kısa sürede **recording** etmeye başlayacaktır.
- **Windows** **started** olduktan sonra **`procmon`**'ı tekrar çalıştırın. Çalışmakta olduğunu söyleyecek ve olayları bir dosyada **store** etmek isteyip istemediğinizi soracaktır. **yes** deyin ve **store the events in a file** seçeneğini kullanın.
- **file** **generated** olduktan sonra açılmış olan **`procmon`** penceresini **close** edin ve olay dosyasını **open** edin.
- Bir **process**'in writable System Path klasöründen **load** etmeye çalıştığı tüm DLL'leri bulmak için şu **filters**'ları ekleyin:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging**, yalnızca aksi takdirde gözlemlemek için çok erken **start** olan service'ler için gereklidir. Hedef service/program'ı **on demand trigger** edebiliyorsanız (örneğin COM interface'iyle etkileşime girerek, service'i yeniden başlatarak veya scheduled task'ı yeniden başlatarak), genellikle **`Path contains .dll`**, **`Result is NAME NOT FOUND`** ve **`Path begins with <writable_machine_path>`** gibi filters'larla normal bir Procmon capture'ı tutmak daha hızlıdır.

### Kaçırılan Dll'ler

Bunu ücretsiz bir **virtual (vmware) Windows 11 machine** üzerinde çalıştırdığımda şu sonuçları aldım:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Bu durumda `.exe` sonuçlarını göz ardı edin. Eksik-DLL probe'ları şunlardan geldi:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Aşağıdaki örnek, bu makalede açıklanan [**privilege escalation için `WptsExtensions.dll` abuse etme**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) tekniğini kullanır.<sup>[[3]](#references)</sup>

### Triage edilmeye değer diğer adaylar

`WptsExtensions.dll` iyi bir örnektir, ancak privileged service'lerde görülen tek tekrarlanan **phantom DLL** bu değildir. Modern hunting rule'ları ve public hijack catalog'ları hâlâ şu isimleri takip etmektedir:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Client system'lerde klasik bir **SYSTEM** adayıdır. Writable directory **Machine PATH** içinde olduğunda ve service startup sırasında DLL'i probe ettiğinde iyi bir seçenektir. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | **Server editions** üzerinde ilgi çekicidir; service **SYSTEM** olarak çalışır ve bazı build'lerde normal bir user tarafından **on demand trigger** edilebilir. Bu da onu yalnızca reboot gerektiren durumlardan daha iyi hâle getirir. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Genellikle ilk olarak **`NT AUTHORITY\LOCAL SERVICE`** elde edilir. Bu çoğu zaman yine de yeterlidir; çünkü token'da **`SeImpersonatePrivilege`** bulunur ve bunu [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) ile chain edebilirsiniz. |

Bu isimleri garanti edilen sonuçlar olarak değil, **triage ipuçları** olarak değerlendirin: Bunlar **SKU/build dependent** özelliklerdir ve Microsoft sürümler arasında davranışı değiştirebilir. Önemli nokta, özellikle service **reboot yapmadan yeniden trigger edilebiliyorsa**, **Machine PATH** üzerinden ilerleyen privileged service'lerdeki **missing DLL**'leri aramaktır.

### Exploitation

**Privileges**'ı **escalate** etmek için **`WptsExtensions.dll`**'i hijack edin. **Path** ve **name** bilindiğinde malicious DLL'i generate edin.

[**Bu örneklerden herhangi birini kullanmayı deneyebilirsiniz**](#creating-and-compiling-dlls). Şu payload'ları çalıştırabilirsiniz: rev shell almak, user eklemek, beacon execute etmek...

> [!WARNING]
> Tüm service'lerin **`NT AUTHORITY\SYSTEM`** olarak çalışmadığını unutmayın. Bazıları daha **az privilege**'a sahip olan **`NT AUTHORITY\LOCAL SERVICE`** olarak çalışır; bu nedenle bu service'lerden birini abuse etmek yeni bir user oluşturmanıza izin vermeyebilir.\
> Ancak bu account'ta **`SeImpersonatePrivilege`** user right'ı bulunur; bu nedenle [**privileges escalate etmek için Potato suite'i**](../roguepotato-and-printspoofer.md) kullanabilirsiniz. Bu durumda reverse shell, user oluşturmaya çalışmaktan daha iyi bir seçenektir.

Yazım sırasında **Task Scheduler** service'i **Nt AUTHORITY\SYSTEM** ile çalışmaktadır.

Malicious Dll'i **generated** ettikten sonra (_benim durumumda x64 rev shell kullandım ve shell geri aldım, ancak msfvenom'dan geldiği için defender onu öldürdü_), bunu writable System Path içine **WptsExtensions.dll** adıyla kaydedin ve bilgisayarı **restart** edin (veya service'i yeniden başlatın ya da etkilenen service/program'ı yeniden çalıştırmak için gereken işlemi yapın).

Service yeniden başlatıldığında **dll load edilip execute edilmelidir** (**library**'nin beklendiği gibi **loaded** olup olmadığını kontrol etmek için **procmon** trick'ini yeniden kullanabilirsiniz).

## References

- [1] [Windows DLL Hijacking (Umarım) Açıklığa Kavuşturuldu](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Persistence veya Privilege Escalation için Yüklenen Şüpheli DLL](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
