{{#include ../../banners/hacktricks-training.md}}

**Orijinal gönderi** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Özet

Mevcut kullanıcı tarafından yazılabilir iki kayıt defteri anahtarı bulundu:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

**RpcEptMapper** hizmetinin izinlerini **regedit GUI** kullanarak kontrol etmenin önerildiği belirtildi, özellikle **Gelişmiş Güvenlik Ayarları** penceresinin **Geçerli İzinler** sekmesi. Bu yaklaşım, her Erişim Kontrol Girişi'ni (ACE) ayrı ayrı incelemeden belirli kullanıcılar veya gruplara verilen izinlerin değerlendirilmesini sağlar.

Düşük ayrıcalıklı bir kullanıcıya atanan izinleri gösteren bir ekran görüntüsü, **Create Subkey** izninin dikkat çekici olduğunu ortaya koydu. Bu izin, **AppendData/AddSubdirectory** olarak da adlandırılmakta olup, scriptin bulgularıyla örtüşmektedir.

Belirli değerleri doğrudan değiştirme yeteneğinin olmaması, ancak yeni alt anahtarlar oluşturma yeteneğinin bulunması kaydedildi. Öne çıkan bir örnek, **ImagePath** değerini değiştirme girişimiydi ve bu, erişim reddedildi mesajıyla sonuçlandı.

Bu sınırlamalara rağmen, **RpcEptMapper** hizmetinin kayıt defteri yapısında varsayılan olarak mevcut olmayan **Performance** alt anahtarını kullanma olasılığı ile ayrıcalık yükseltme potansiyeli belirlendi. Bu, DLL kaydı ve performans izleme imkanı sağlayabilir.

**Performance** alt anahtarı ve performans izleme için kullanımı hakkında belgeler incelendi ve bir kanıt konsepti DLL'si geliştirildi. **OpenPerfData**, **CollectPerfData** ve **ClosePerfData** fonksiyonlarının uygulanmasını gösteren bu DLL, **rundll32** aracılığıyla test edildi ve başarılı bir şekilde çalıştığı doğrulandı.

Amaç, **RPC Endpoint Mapper hizmetini** oluşturulan Performans DLL'sini yüklemeye zorlamaktı. Gözlemler, PowerShell aracılığıyla Performans Verileri ile ilgili WMI sınıf sorgularının yürütülmesinin bir günlük dosyası oluşturduğunu ve böylece **LOCAL SYSTEM** bağlamında keyfi kod yürütülmesine olanak tanıdığını ortaya koydu, bu da yükseltilmiş ayrıcalıklar sağladı.

Bu güvenlik açığının kalıcılığı ve potansiyel etkileri vurgulandı, post-exploitation stratejileri, yan hareket ve antivirüs/EDR sistemlerinden kaçınma ile ilgili önemine dikkat çekildi.

Güvenlik açığının başlangıçta script aracılığıyla istemeden ifşa edildiği belirtilse de, istismarının eski Windows sürümleriyle (örneğin, **Windows 7 / Server 2008 R2**) sınırlı olduğu ve yerel erişim gerektirdiği vurgulandı.

{{#include ../../banners/hacktricks-training.md}}
