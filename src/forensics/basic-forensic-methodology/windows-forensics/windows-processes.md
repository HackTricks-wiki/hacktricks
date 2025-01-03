{{#include ../../../banners/hacktricks-training.md}}

## smss.exe

**Oturum Yöneticisi**.\
Oturum 0, **csrss.exe** ve **wininit.exe** (**OS** **hizmetleri**) başlatırken, Oturum 1 **csrss.exe** ve **winlogon.exe** (**Kullanıcı** **oturumu**) başlatır. Ancak, süreçler ağacında **çocukları olmayan** bu **ikili** dosyadan **yalnızca bir süreç** görmelisiniz.

Ayrıca, 0 ve 1 dışındaki oturumlar RDP oturumlarının gerçekleştiğini gösterebilir.

## csrss.exe

**İstemci/Sunucu Çalışma Alt Sistemi Süreci**.\
**Süreçleri** ve **iş parçacıklarını** yönetir, diğer süreçler için **Windows** **API**'sini kullanılabilir hale getirir ve ayrıca **sürücü harflerini** eşler, **geçici dosyalar** oluşturur ve **kapatma** **sürecini** yönetir.

Oturum 0'da bir tane ve Oturum 1'de bir tane **çalışıyor** (yani süreçler ağacında **2 süreç**). Her yeni oturum için bir tane daha oluşturulur.

## winlogon.exe

**Windows Oturum Açma Süreci**.\
Kullanıcı **oturum açma**/**oturum kapama** işlemlerinden sorumludur. Kullanıcı adı ve şifre sormak için **logonui.exe**'yi başlatır ve ardından bunları doğrulamak için **lsass.exe**'yi çağırır.

Sonra, **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`**'da **Userinit** anahtarı ile belirtilen **userinit.exe**'yi başlatır.

Ayrıca, önceki kayıt defterinde **explorer.exe** **Shell anahtarı** içinde olmalıdır veya **kötü amaçlı yazılım kalıcılık yöntemi** olarak kötüye kullanılabilir.

## wininit.exe

**Windows Başlatma Süreci**. \
Oturum 0'da **services.exe**, **lsass.exe** ve **lsm.exe**'yi başlatır. Yalnızca 1 süreç olmalıdır.

## userinit.exe

**Userinit Oturum Açma Uygulaması**.\
**HKCU**'da **ntduser.dat**'ı yükler ve **kullanıcı** **ortamını** başlatır, **oturum açma** **betiklerini** ve **GPO**'yu çalıştırır.

**explorer.exe**'yi başlatır.

## lsm.exe

**Yerel Oturum Yöneticisi**.\
Kullanıcı oturumlarını manipüle etmek için smss.exe ile çalışır: Oturum açma/kapama, kabuk başlatma, masaüstünü kilitleme/açma vb.

W7'den sonra lsm.exe bir hizmete (lsm.dll) dönüştürüldü.

W7'de yalnızca 1 süreç olmalıdır ve bunlardan bir hizmet DLL'yi çalıştırmalıdır.

## services.exe

**Hizmet Kontrol Yöneticisi**.\
**Otomatik başlat** olarak yapılandırılan **hizmetleri** ve **sürücüleri** **yükler**.

**svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** ve daha birçok sürecin ebeveynidir.

Hizmetler `HKLM\SYSTEM\CurrentControlSet\Services`'de tanımlanır ve bu süreç, sc.exe tarafından sorgulanabilen hizmet bilgilerini bellekte tutan bir veritabanı yönetir.

**Bazı** **hizmetlerin** **kendi süreçlerinde** çalışacağını ve diğerlerinin **bir svchost.exe sürecini paylaşacağını** not edin.

Yalnızca 1 süreç olmalıdır.

## lsass.exe

**Yerel Güvenlik Otoritesi Alt Sistemi**.\
Kullanıcı **kimlik doğrulaması** için sorumludur ve **güvenlik** **jetonları** oluşturur. `HKLM\System\CurrentControlSet\Control\Lsa`'da bulunan kimlik doğrulama paketlerini kullanır.

**Güvenlik** **olay** **günlüğüne** yazar ve yalnızca 1 süreç olmalıdır.

Bu sürecin şifreleri dökmek için yüksek oranda saldırıya uğradığını unutmayın.

## svchost.exe

**Genel Hizmet Ana Bilgisayar Süreci**.\
Birden fazla DLL hizmetini tek bir paylaşılan süreçte barındırır.

Genellikle, **svchost.exe** `-k` bayrağı ile başlatılır. Bu, kayıt defterine **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** bir sorgu başlatır; burada -k'da belirtilen argümanla bir anahtar bulunur ve bu anahtar aynı süreçte başlatılacak hizmetleri içerir.

Örneğin: `-k UnistackSvcGroup` şunları başlatır: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Eğer **`-s` bayrağı** da bir argüman ile kullanılıyorsa, o zaman svchost'tan **yalnızca belirtilen hizmeti** bu argümanda başlatması istenir.

Birçok `svchost.exe` süreci olacaktır. Eğer bunlardan herhangi biri **`-k` bayrağını** kullanmıyorsa, bu çok şüphelidir. Eğer **services.exe ebeveyn değilse**, bu da çok şüphelidir.

## taskhost.exe

Bu süreç, DLL'lerden çalışan süreçler için bir ana bilgisayar görevi görür. Ayrıca DLL'lerden çalışan hizmetleri yükler.

W8'de bu taskhostex.exe olarak adlandırılır ve W10'da taskhostw.exe olarak adlandırılır.

## explorer.exe

Bu, **kullanıcının masaüstünden** ve dosyaları dosya uzantıları aracılığıyla başlatmaktan sorumlu olan süreçtir.

**Her oturum açan kullanıcı için yalnızca 1** süreç oluşturulmalıdır.

Bu, **userinit.exe**'den çalıştırılır ve sonlandırılmalıdır, böylece bu süreç için **ebeveyn** görünmemelidir.

# Kötü Amaçlı Süreçleri Yakalamak

- Beklenen yoldan mı çalışıyor? (Windows ikili dosyaları geçici konumdan çalışmaz)
- Garip IP'lerle mi iletişim kuruyor?
- Dijital imzaları kontrol edin (Microsoft belgeleri imzalanmış olmalıdır)
- Doğru yazılmış mı?
- Beklenen SID altında mı çalışıyor?
- Ebeveyn süreç beklenen mi (varsa)?
- Çocuk süreçler beklenenler mi? (cmd.exe, wscript.exe, powershell.exe..?)

{{#include ../../../banners/hacktricks-training.md}}
