# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Eğer bir **Sistem Yolu klasöründe yazma** yeteneğiniz olduğunu bulduysanız (bu, bir Kullanıcı Yolu klasöründe yazma yeteneğiniz varsa çalışmayacaktır), sistemde **yetki yükseltmesi** yapmanız mümkün olabilir.

Bunu yapmak için, **sizinle daha fazla yetkiye sahip** bir hizmet veya işlem tarafından **yüklenen bir kütüphaneyi ele geçireceğiniz** bir **Dll Hijacking** durumunu kötüye kullanabilirsiniz ve bu hizmet, muhtemelen sistemde hiç var olmayan bir Dll'yi yüklemeye çalıştığı için, yazabileceğiniz Sistem Yolundan yüklemeye çalışacaktır.

**Dll Hijacking nedir** hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

İhtiyacınız olan ilk şey, **yazma yetkinizden daha fazla yetkiye sahip** bir işlemi **Sistem Yolundan Dll yüklemeye** çalışan bir işlemi **belirlemektir**.

Bu durumlarda sorun, muhtemelen bu işlemlerin zaten çalışıyor olmasıdır. Hangi Dll'lerin hizmetlerden eksik olduğunu bulmak için, mümkün olan en kısa sürede (işlemler yüklenmeden önce) procmon'u başlatmalısınız. Eksik .dll'leri bulmak için:

- **C:\privesc_hijacking** klasörünü **oluşturun** ve `C:\privesc_hijacking` yolunu **Sistem Yolü ortam değişkenine** ekleyin. Bunu **manuel olarak** veya **PS** ile yapabilirsiniz:
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
- **`procmon`**'u başlatın ve **`Options`** --> **`Enable boot logging`**'e gidin ve istemde **`OK`**'ye basın.
- Sonra, **yeniden başlatın**. Bilgisayar yeniden başladığında **`procmon`** olayları mümkün olan en kısa sürede **kaydetmeye** başlayacaktır.
- **Windows** **başladıktan sonra `procmon`'u** tekrar çalıştırın, çalıştığını söyleyecek ve olayları bir dosyada saklamak isteyip istemediğinizi **soracaktır**. **Evet** deyin ve olayları bir dosyada **saklayın**.
- **Dosya** **oluşturulduktan sonra**, açılan **`procmon`** penceresini **kapayın** ve **olay dosyasını** **açın**.
- Bu **filtreleri** ekleyin ve yazılabilir Sistem Yolu klasöründen bazı **proseslerin yüklemeye çalıştığı** tüm DLL'leri bulacaksınız:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Kaçırılan DLL'ler

Ücretsiz bir **sanallaştırma (vmware) Windows 11 makinesinde** bunu çalıştırdığımda bu sonuçları aldım:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Bu durumda .exe'ler işe yaramaz, bu yüzden onları göz ardı edin, kaçırılan DLL'ler şunlardı:

| Servis                          | DLL                | CMD satırı                                                          |
| ------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Görev Zamanlayıcı (Schedule)   | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`       |
| Tanılayıcı Politika Servisi (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`             |

Bunu bulduktan sonra, **privesc için WptsExtensions.dll'yi nasıl kötüye kullanacağınızı** açıklayan ilginç bir blog yazısı buldum. Şimdi **yapacağımız şey** bu.

### Sömürü

Yani, **yetkileri artırmak** için **WptsExtensions.dll** kütüphanesini ele geçireceğiz. **Yolu** ve **adı** bildiğimiz için sadece **kötü niyetli dll'yi** **oluşturmamız** gerekiyor.

[**Bu örneklerden herhangi birini kullanmayı deneyebilirsiniz**](#creating-and-compiling-dlls). Rev shell almak, bir kullanıcı eklemek, bir beacon çalıştırmak gibi yükleri çalıştırabilirsiniz...

> [!WARNING]
> Tüm hizmetlerin **`NT AUTHORITY\SYSTEM`** ile çalışmadığını unutmayın, bazıları **`NT AUTHORITY\LOCAL SERVICE`** ile de çalışır ki bu da **daha az yetkiye** sahiptir ve **yeni bir kullanıcı oluşturamazsınız** ve izinlerini kötüye kullanamazsınız.\
> Ancak, o kullanıcının **`seImpersonate`** yetkisi vardır, bu yüzden **yetkileri artırmak için potato suite**'i kullanabilirsiniz. Bu durumda, bir rev shell, bir kullanıcı oluşturmaya çalışmaktan daha iyi bir seçenektir.

Yazma anında **Görev Zamanlayıcı** hizmeti **Nt AUTHORITY\SYSTEM** ile çalışmaktadır.

**Kötü niyetli DLL'yi** (_benim durumumda x64 rev shell kullandım ve bir shell aldım ama defender bunu msfvenom'dan olduğu için öldürdü_) yazılabilir Sistem Yolu'na **WptsExtensions.dll** adıyla kaydedin ve bilgisayarı **yeniden başlatın** (veya hizmeti yeniden başlatın ya da etkilenen hizmet/programı yeniden çalıştırmak için ne gerekiyorsa yapın).

Hizmet yeniden başlatıldığında, **dll yüklenmeli ve çalıştırılmalıdır** (kütüphanenin **beklendiği gibi yüklendiğini kontrol etmek için **procmon** numarasını **kullanabilirsiniz**).

{{#include ../../../banners/hacktricks-training.md}}
