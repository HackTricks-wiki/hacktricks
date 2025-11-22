# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Eğer bir System Path klasörüne **yazabildiğinizi** tespit ettiyseniz (bu, bir User Path klasörüne yazabiliyorsanız çalışmaz) sistemde **ayrıcalıkları yükseltmeniz** mümkün olabilir.

Bunu yapmak için, sizden **daha fazla ayrıcalığa** sahip bir servis veya süreç tarafından yüklenen bir kütüphaneyi **Dll Hijacking** ile ele geçirebilirsiniz; servis muhtemelen tüm sistemde hiç bulunmayan bir Dll'i yüklemeye çalıştığı için, yazabildiğiniz System Path'ten yüklemeye çalışacaktır.

Dll Hijacking hakkında daha fazla bilgi için bakın:

{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Eksik Dll'i Bulma

İhtiyacınız olan ilk şey, sizden **daha fazla ayrıcalıkla** çalışan ve yazabildiğiniz **System Path**'ten bir **Dll** yüklemeye çalışan bir süreci **tanımlamaktır**.

Bu durumda sorun, muhtemelen bu süreçlerin zaten çalışıyor olmasıdır. Hangi servislerin hangi Dll'lerden yoksun olduğunu bulmak için süreçler yüklenmeden önce mümkün olan en kısa sürede procmon'u başlatmanız gerekir. Eksik .dll'leri bulmak için şunları yapın:

- **Oluşturun** `C:\privesc_hijacking` klasörünü oluşturun ve `C:\privesc_hijacking` yolunu **System Path env variable**'a ekleyin. Bunu **manuel** olarak veya **PS** ile yapabilirsiniz:
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
- **`procmon`**'i başlatın ve **`Options`** --> **`Enable boot logging`** kısmına gidin ve istemde **`OK`**'ye basın.
- Ardından, **yeniden başlatın**. Bilgisayar yeniden başlatıldığında **`procmon`** mümkün olan en kısa sürede olayları **kaydetmeye** başlayacaktır.
- Windows başladıktan sonra **`procmon`**'i tekrar çalıştırın; size zaten çalıştığını söyleyecek ve olayları bir dosyaya kaydetmek isteyip istemediğinizi **soracaktır**. **yes** deyin ve **olayları bir dosyaya kaydedin**.
- **Dosya** oluşturulduktan sonra açılmış **`procmon`** penceresini **kapatın** ve **olay dosyasını açın**.
- Bu **filtreleri** ekleyin ve yazılabilir System Path klasöründen bazı işlemlerin **yüklemeye çalıştığı** tüm DLL'leri bulacaksınız:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Kaçırılan DLL'ler

Bunu ücretsiz bir **virtual (vmware) Windows 11 machine** üzerinde çalıştırdığımda şu sonuçları aldım:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Bu durumda .exe'ler işe yaramıyor, bunları göz ardı edin; kaçırılan DLL'ler şu kaynaklardan geliyordu:

| Servis                          | Dll                | CMD satırı                                                           |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Bunu bulduktan sonra, [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) konusunu da açıklayan ilginç bir blog yazısı buldum. Bu, şimdi **yapacağımız** şey.

### İstismar

Yani, ayrıcalıkları **escalate privileges** etmek için kütüphane **WptsExtensions.dll**'i hijack edeceğiz. **Path** ve **name** elimizde olduğuna göre sadece kötü amaçlı DLL'i **generate** etmemiz gerekiyor.

You can [**try to use any of these examples**](#creating-and-compiling-dlls). Aşağıdaki gibi payload'lar çalıştırabilirsiniz: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Not that **not all the service are run** with **`NT AUTHORITY\SYSTEM`**; bazıları **`NT AUTHORITY\LOCAL SERVICE`** ile de çalışır ve bu daha **az ayrıcalığa** sahiptir, bu yüzden onun izinlerini kötüye kullanarak **yeni bir kullanıcı oluşturamayabilirsiniz**.\
> Ancak o kullanıcıda **`seImpersonate`** ayrıcalığı vardır, bu yüzden [ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md) kullanabilirsiniz. Bu durumda rev shell almak, kullanıcı oluşturmaya çalışmaktan daha iyi bir seçenektir.

Yazının yazıldığı sırada **Task Scheduler** servisi **NT AUTHORITY\SYSTEM** ile çalışıyordu.

Kötü amaçlı DLL'i oluşturduktan sonra (_benim durumda x64 rev shell kullandım ve shell aldım ancak defender msfvenom kaynaklı olduğu için öldürdü_), onu yazılabilir System Path'e **WptsExtensions.dll** adıyla kaydedin ve bilgisayarı **restart** edin (veya servisi yeniden başlatın ya da etkilenen servis/programı yeniden çalıştırmak için gerekeni yapın).

Servis yeniden başlatıldığında, **DLL yüklenmeli ve çalıştırılmalıdır** (kütüphanenin beklenildiği gibi yüklenip yüklenmediğini kontrol etmek için **`procmon`** hilesini **tekrar kullanabilirsiniz**).

{{#include ../../../banners/hacktricks-training.md}}
