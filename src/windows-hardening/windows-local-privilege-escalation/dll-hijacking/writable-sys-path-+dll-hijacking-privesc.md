# Yazılabilir Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

Eğer bir **Sistem Yolu klasöründe yazma** yeteneğiniz olduğunu bulduysanız (bu, bir Kullanıcı Yolu klasöründe yazma yeteneğiniz varsa çalışmayacaktır), sistemde **yetki yükseltme** yapmanız mümkün olabilir.

Bunu yapmak için, **daha yüksek yetkilere** sahip bir hizmet veya işlem tarafından **yüklenen bir kütüphaneyi ele geçireceğiniz** bir **Dll Hijacking** durumunu kötüye kullanabilirsiniz ve bu hizmet, muhtemelen sistemde hiç var olmayan bir Dll'yi yüklemeye çalıştığı için, yazabileceğiniz Sistem Yolu'ndan yüklemeye çalışacaktır.

**Dll Hijacking nedir** hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
./
{{#endref}}

## Dll Hijacking ile Privesc

### Eksik bir Dll bulma

İhtiyacınız olan ilk şey, **yazdığınız Sistem Yolu'ndan bir Dll yüklemeye çalışan** ve **sizinle daha yüksek yetkilere** sahip bir **işlemi tanımlamak**.

Bu durumlarda sorun, muhtemelen bu işlemlerin zaten çalışıyor olmasıdır. Hangi Dll'lerin hizmetlerden eksik olduğunu bulmak için, işlemler yüklenmeden önce mümkün olan en kısa sürede procmon'u başlatmalısınız. Eksik .dll'leri bulmak için:

- `C:\privesc_hijacking` klasörünü **oluşturun** ve `C:\privesc_hijacking` yolunu **Sistem Yolu ortam değişkenine** ekleyin. Bunu **manuel olarak** veya **PS** ile yapabilirsiniz:
```powershell
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
- Sonra, **yeniden başlatın**. Bilgisayar yeniden başlatıldığında **`procmon`** olayları mümkün olan en kısa sürede **kaydetmeye** başlayacaktır.
- **Windows** başlatıldıktan sonra **`procmon`**'u tekrar çalıştırın, çalıştığını söyleyecek ve olayları bir dosyada **saklamak** isteyip istemediğinizi **soracaktır**. **Evet** deyin ve olayları bir dosyada **saklayın**.
- **Dosya** **oluşturulduktan sonra**, açılan **`procmon`** penceresini **kapatın** ve **olay dosyasını** **açın**.
- Bu **filtreleri** ekleyin ve yazılabilir Sistem Yolu klasöründen bazı **proseslerin yüklemeye çalıştığı** tüm DLL'leri bulacaksınız:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Kaçırılan DLL'ler

Ücretsiz bir **sanallaştırma (vmware) Windows 11 makinesinde** bunu çalıştırdığımda bu sonuçları aldım:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Bu durumda .exe'ler işe yaramaz, bu yüzden onları göz ardı edin, kaçırılan DLL'ler şunlardı:

| Servis                          | DLL                | CMD satırı                                                          |
| ------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Görev Zamanlayıcı (Schedule)   | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`       |
| Tanılama Politika Servisi (DPS)| Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`             |

Bunu bulduktan sonra, **privesc** için WptsExtensions.dll'yi nasıl [**istismar edeceğinizi**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) açıklayan ilginç bir blog yazısı buldum. Şimdi **bunu yapacağız**.

### İstismar

Yani, **yetkileri artırmak** için **WptsExtensions.dll** kütüphanesini ele geçireceğiz. **Yolu** ve **adı** bildiğimiz için sadece **kötü niyetli dll**'yi **oluşturmamız** gerekiyor.

[**Bu örneklerden herhangi birini kullanmayı deneyebilirsiniz**](./#creating-and-compiling-dlls). Rev shell almak, bir kullanıcı eklemek, bir beacon çalıştırmak gibi yükleri çalıştırabilirsiniz...

> [!WARNING]
> Tüm servislerin **`NT AUTHORITY\SYSTEM`** ile çalışmadığını unutmayın, bazıları **`NT AUTHORITY\LOCAL SERVICE`** ile de çalışır ki bu **daha az yetkiye** sahiptir ve **yeni bir kullanıcı oluşturamazsınız** izinlerini istismar edemezsiniz.\
> Ancak, o kullanıcının **`seImpersonate`** yetkisi vardır, bu yüzden [**yetkileri artırmak için potato suite'i**](../roguepotato-and-printspoofer.md) kullanabilirsiniz. Bu durumda bir rev shell, bir kullanıcı oluşturmaya çalışmaktan daha iyi bir seçenektir.

Yazma anında **Görev Zamanlayıcı** servisi **Nt AUTHORITY\SYSTEM** ile çalışmaktadır.

**Kötü niyetli DLL'yi** (_benim durumumda x64 rev shell kullandım ve bir shell aldım ama defender bunu msfvenom'dan olduğu için öldürdü_) yazılabilir Sistem Yolu'na **WptsExtensions.dll** adıyla kaydedin ve bilgisayarı **yeniden başlatın** (veya servisi yeniden başlatın ya da etkilenen servis/programı yeniden çalıştırmak için ne gerekiyorsa yapın).

Servis yeniden başlatıldığında, **dll yüklenmeli ve çalıştırılmalıdır** (kütüphanenin **beklendiği gibi yüklendiğini kontrol etmek için **procmon** numarasını **kullanabilirsiniz**).

{{#include ../../../banners/hacktricks-training.md}}
