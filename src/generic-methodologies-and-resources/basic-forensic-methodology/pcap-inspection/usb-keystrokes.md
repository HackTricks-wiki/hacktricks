# Πληκτρολογήσεις USB

{{#include ../../../banners/hacktricks-training.md}}

Αν έχετε ένα pcap που περιέχει την επικοινωνία μέσω USB ενός πληκτρολογίου, όπως το παρακάτω:

![Πληκτρολογήσεις USB: Αν έχετε ένα pcap που περιέχει την επικοινωνία μέσω USB ενός πληκτρολογίου, όπως το παρακάτω](<../../../images/image (962).png>)

Για ένα πληκτρολόγιο που χρησιμοποιεί το HID **boot protocol**, κάθε Interrupt IN report έχει σταθερή διάταξη 8 byte: ένα byte τροποποιητών, ένα δεσμευμένο byte και έξι byte κωδικών πλήκτρων. Ο host συγκρίνει διαδοχικά reports και αντιστοιχίζει τους κωδικούς πλήκτρων σε HID usages, ώστε να ανασυνθέσει τα συμβάντα πλήκτρων.<sup>[[8]](#references)</sup>

Για γενική αρχική ανάλυση ενός capture, δείτε το [Pcap Inspection](./).

## Βασικά στοιχεία για τα USB HID reports

Το τυπικό input report πληκτρολογίου σε boot mode έχει την εξής δομή.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Σημασία |
| --- | --- |
| 0 | Bitmap τροποποιητών (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt κ.λπ.). Μπορούν να οριστούν ταυτόχρονα πολλά bit. |
| 1 | Δεσμευμένο byte· τα αχρησιμοποίητα reports κανονικά πρέπει να το ορίζουν σε μηδέν. Η χρήση από OEM ή ειδικά για το σύστημα δεν είναι φορητή. |
| 2-7 | Έως έξι ταυτόχρονοι κωδικοί πλήκτρων σε μορφή USB usage ID (`0x04 = a`, `0x1E = 1`). Το `0x00` σημαίνει «κανένα πλήκτρο». | 

Στη διάταξη boot, το usage ID `0x01` (`Keyboard ErrorRollOver`) αναφέρεται σε όλες τις θέσεις πλήκτρων όταν πατηθούν περισσότερα από έξι πλήκτρα που δεν είναι τροποποιητές· μπορεί επίσης να υποδεικνύει μη αναγνωρίσιμο συνδυασμό.<sup>[[8]](#references)[[9]](#references)</sup> Η κατανόηση αυτής της διάταξης είναι χρήσιμη όταν έχετε μόνο τα ακατέργαστα byte `usb.capdata`.

## Εξαγωγή δεδομένων HID από PCAP

### Εντοπίστε πρώτα το interface του πληκτρολογίου

Σε captures με πολλή κίνηση, εντοπίστε το πληκτρολόγιο HID πριν εξαγάγετε τα reports. Ένα αξιόπιστο σημείο εκκίνησης είναι η απόκριση του interface descriptor:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

Η κλάση HID ορίζει τις ακόλουθες τιμές interface:<sup>[[8]](#references)</sup>

- `subclass == 1` είναι το Boot Interface Subclass· με `protocol == 1` προσδιορίζει ένα boot keyboard
- `protocol == 2` προσδιορίζει ένα boot mouse
- `protocol == 0` σημαίνει ότι δεν χρησιμοποιείται boot protocol· ελέγξτε τον HID report descriptor αντί να υποθέσετε διάταξη 8 byte

Ένα interface με δυνατότητα boot **δεν αποδεικνύει ότι είναι ενεργό το boot protocol**. Οι συσκευές HID αρχικοποιούνται σε report protocol. Ο host επιλέγει boot mode με το `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`)· το `wValue = 1` επιλέγει report protocol. Αν η καταγραφή περιλαμβάνει την απαρίθμηση, ελέγξτε το request για το interface του πληκτρολογίου (`wIndex`) πριν χρησιμοποιήσετε boot decoder οκτώ byte. Αν απουσιάζει, επαληθεύστε τη διάταξη report που παρατηρείται αντί να συμπεράνετε το mode από το interface descriptor.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Μόλις γνωρίζετε το interface, ορίστε τα φίλτρα σας με βάση τα `usb.bus_id`, `usb.device_address` και, αν είναι δυνατόν, το `usb.bInterfaceNumber` πριν κάνετε οποιαδήποτε εξαγωγή.

### Ροή εργασίας στο Wireshark

1. **Απομονώστε τη συσκευή**: φιλτράρετε την κίνηση interrupt IN από το keyboard, π.χ. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Προσθέστε χρήσιμες στήλες**: κάντε δεξί κλικ στο πεδίο `Leftover Capture Data` (`usb.capdata`) και στα πεδία `usbhid.*` που προτιμάτε (π.χ. `usbhid.boot_report.keyboard.keycode_1`), για να παρακολουθείτε τα keystrokes χωρίς να ανοίγετε κάθε frame.<sup>[[11]](#references)</sup>
3. **Αποκρύψτε τις κενές αναφορές**: εφαρμόστε το `!(usb.capdata == 00:00:00:00:00:00:00:00)` για να αφαιρέσετε τα idle frames.
4. **Κάντε εξαγωγή για μεταγενέστερη επεξεργασία**: `File -> Export Packet Dissections -> As CSV`, συμπεριλάβετε τα `frame.number`, `usb.src`, `usb.capdata` και αποκωδικοποιημένα πεδία modifier, όπως τα `usbhid.boot_report.keyboard.modifier.left_shift` και `usbhid.boot_report.keyboard.modifier.right_alt`, ώστε να αυτοματοποιήσετε αργότερα την ανακατασκευή.<sup>[[10]](#references)[[11]](#references)</sup>

### Ροή εργασίας γραμμής εντολών

Το κλασικό μοτίβο εξαγωγής — εξαγωγή του `usb.capdata`, αφαίρεση των idle reports και αντιστοίχιση των usage IDs — εμφανίζεται στην αρχική ανάλυση του 2017 και στον οδηγό της.<sup>[[1]](#references)[[2]](#references)</sup>

Το repository `ctf-usb-keyboard-parser` αυτοματοποιεί την κλασική ροή εργασίας `tshark` + `sed`:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

Σε νεότερες καταγραφές, προτιμήστε το αποκωδικοποιημένο πεδίο `usbhid.data` του Wireshark και χρησιμοποιήστε το `usb.capdata` ως εναλλακτική· γράψτε ένα payload ανά report σε αρχείο ανά συσκευή:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Αυτά τα αρχεία ανά συσκευή μπορούν να δοθούν σε έναν αποκωδικοποιητή αφού κανονικοποιηθεί η μορφή hex που αναμένει. Αν η καταγραφή προήλθε από πληκτρολόγια BLE που μεταφέρουν δεδομένα μέσω GATT, φιλτράρετε με `btatt.value && frame.len == 20` και εξαγάγετε τα payload σε hex πριν από την αποκωδικοποίηση.<sup>[[7]](#references)</sup>

### Όταν η αναφορά δεν είναι η κλασική αναφορά boot των 8 byte

Μια διεπαφή που δεν είναι boot ή ένα αναγνωριστικό αναφοράς μπορεί να αλλάξει τη διάταξη του payload, επομένως μην υποθέτετε ότι κάθε αναφορά πληκτρολογίου ακολουθεί τη μορφή `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Προτιμήστε το `usbhid.data` αντί για το `usb.capdata` όταν το Wireshark έχει ήδη αναλύσει το επίπεδο HID.
- Αν κάθε γραμμή αρχίζει με ένα σταθερό πρόθεμα ή αναγνωριστικό αναφοράς, αφαιρέστε το με αποκωδικοποιητή που λαμβάνει υπόψη το offset, αντί να υποθέσετε ότι το byte 0 είναι πάντα ο modifier.<sup>[[7]](#references)</sup>
- Ορισμένες εξαγωγές USBPcap παραλείπουν το byte reserved, επομένως οι αποκωδικοποιητές που υποστηρίζουν `--no-reserved` ή ένα προσαρμοσμένο offset εξοικονομούν χρόνο.<sup>[[7]](#references)</sup>
- Αν στην καταγραφή υπάρχει ο descriptor αναφοράς HID ή το report map BLE HOGP, χρησιμοποιήστε τον για να ανακτήσετε την πραγματική διάταξη των πεδίων πριν γράψετε parser.

### Αποκωδικοποίηση bitmap πλήκτρων πρωτοκόλλου αναφοράς

Για ένα πληκτρολόγιο του οποίου η αναφορά εισόδου είναι bitmap αντί για έξι θέσεις πλήκτρων boot, εντοπίστε τον **descriptor αναφοράς HID** στην κίνηση απαρίθμησης συσκευών. Αυτό το φίλτρο εντοπίζει πλαίσια στα οποία το Wireshark αποκωδικοποίησε ένα στοιχείο Report Size· ανοίξτε ένα και εξετάστε ολόκληρο τον descriptor. Ξεκινήστε νέα καταγραφή πριν συνδέσετε το πληκτρολόγιο, αν λείπει ο descriptor.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Για κάθε αναφορά εισόδου του πληκτρολογίου, σημειώστε το `Report ID` (αν υπάρχει), το `Usage Page` (`0x07` για τα πλήκτρα του πληκτρολογίου), τα `Usage Minimum/Maximum`, τα `Report Size`, `Report Count` και αν κάθε στοιχείο `Input` είναι **Variable** ή **Array**. Μετρήστε όλα τα προηγούμενα πεδία `Input` και τα πεδία συμπλήρωσης σταθερής τιμής για να βρείτε το offset bit του πεδίου πλήκτρων· τα πεδία αναφοράς δεν χρειάζεται να είναι ευθυγραμμισμένα σε byte. Ένα πεδίο Variable ενός bit με διαδοχικά keyboard usages είναι bitmap κατάστασης πλήκτρων: το bit 0 αυτού του πεδίου αντιστοιχεί στο πρώτο δηλωμένο usage, το bit 1 στο επόμενο και ούτω καθεξής. Ένα Array, αντίθετα, περιέχει τιμές που αντιστοιχίζονται βάσει του εύρους usage του descriptor και όχι ένα πλήκτρο πατημένο ανά bit. Αν έχει δηλωθεί `Report ID`, επιλέξτε πρώτα τις αναφορές με αυτό το πρόθεμα και παραλείψτε το byte του κατά τον υπολογισμό των offset των πεδίων. Συγκρίνετε τα σύνολα των ενεργών usages μεταξύ διαδοχικών αναφορών του **ίδιου interface και Report ID**, ώστε να καταγράφετε μόνο τα νέα πατήματα.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Αυτοματοποίηση της αποκωδικοποίησης

- Το **ctf-usb-keyboard-parser** παραμένει χρήσιμο για γρήγορα CTF challenges και περιλαμβάνεται ήδη στο repository.<sup>[[5]](#references)</sup>
- Το **CTF-Usb_Keyboard_Parser** (`main.py`) αναλύει εγγενώς αρχεία `pcap` και `pcapng`, υποστηρίζει τα `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` και δεν απαιτεί το tshark ή άλλη εξωτερική εξάρτηση, οπότε είναι κατάλληλο για απομονωμένα sandbox.<sup>[[6]](#references)</sup>
- Το **USB-HID-decoders** προσθέτει οπτικοποιητές για πληκτρολόγια, ποντίκια και tablets. Μπορείτε είτε να εκτελέσετε το βοηθητικό πρόγραμμα `extract_hid_data.sh` (backend tshark) είτε το `extract_hid_data.py` (backend scapy) και έπειτα να δώσετε το αρχείο κειμένου που προκύπτει στον decoder ή στις μονάδες replay για να παρακολουθήσετε την εξέλιξη των keystrokes.<sup>[[7]](#references)</sup>

### Η αποκωδικοποίηση με κατάσταση έχει σημασία

Τα USB boot keyboards στέλνουν αναφορές με τον ρυθμό αδράνειας ακόμη κι όταν δεν υπάρχει νέο συμβάν πλήκτρου, οπότε τα captures μπορεί να περιέχουν επαναλαμβανόμενες αναφορές πριν από το συμβάν απελευθέρωσης. Ένας πρακτικός decoder θα πρέπει να:<sup>[[3]](#references)[[8]](#references)</sup>

- καταγράφει μόνο τους νέους κωδικούς πλήκτρων σε σχέση με την προηγούμενη αναφορά
- διατηρεί την κατάσταση των modifiers (`Shift`, `Ctrl`, `AltGr`) από το byte 0 ή από αναλυμένα πεδία, όπως τα `usbhid.boot_report.keyboard.modifier.left_shift` και `usbhid.boot_report.keyboard.modifier.right_alt`
- παρακολουθεί πλήκτρα εναλλαγής κατάστασης, όπως το `Caps Lock`, επειδή η παραγωγή κεφαλαίων δεν ελέγχεται μόνο από το Shift
- θυμάται ότι τα HID usage IDs δεν εξαρτώνται από τη διάταξη: το `0x1d` είναι η φυσική θέση πλήκτρου `z`/`y`, ανάλογα με τη διάταξη πληκτρολογίου του host.<sup>[[9]](#references)</sup>

## Γρήγορος Python decoder

```python
#!/usr/bin/env python3
import sys
NORMAL = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n',0x2d:'-',0x2e:'=',0x2f:'[',0x30:']',0x33:';',0x34:"'",0x36:',',0x37:'.'}
SHIFTED = {0x2d:'_',0x2e:'+',0x2f:'{',0x30:'}',0x33:':',0x34:'"',0x36:'<',0x37:'>'}
prev = set()
caps = False
for raw in sys.stdin:
    raw = raw.strip().replace(':', '')
    if len(raw) != 16:
        continue
    modifier = int(raw[0:2], 16)
    keycodes = [int(raw[i:i+2], 16) for i in range(4, 16, 2)]
    current = {k for k in keycodes if k}
    newly_pressed = [k for k in keycodes if k and k not in prev]
    shift = bool(modifier & 0x22)
    for keycode in newly_pressed:
        if keycode == 0x39:
            caps = not caps
            continue
        char = SHIFTED.get(keycode) if shift else None
        if char is None:
            char = NORMAL.get(keycode, '?')
            if char.isalpha() and (shift ^ caps):
                char = char.upper()
        sys.stdout.write(char)
    prev = current
```

Δώστε του τις απλές γραμμές hex που αποτυπώθηκαν νωρίτερα, για να λάβετε αμέσως μια πρόχειρη ανακατασκευή χωρίς να χρειαστεί να προσθέσετε έναν πλήρη parser στο περιβάλλον. Για διατάξεις πληκτρολογίου εκτός ΗΠΑ, αυτό εξακολουθεί να ανακατασκευάζει τη φυσική θέση του πλήκτρου, όχι απαραίτητα τον τελικό χαρακτήρα που εμφανίζεται στον host του θύματος.

## Συμβουλές αντιμετώπισης προβλημάτων

- Αν το Wireshark δεν συμπληρώνει πεδία `usbhid.*`, πιθανότατα δεν καταγράφηκε ο HID report descriptor. Αποσυνδέστε και συνδέστε ξανά το πληκτρολόγιο κατά τη λήψη ή χρησιμοποιήστε το ακατέργαστο `usb.capdata`.
- Σε λήψεις λογισμικού Linux, η συνήθης πηγή είναι το `usbmon`· στα Windows, το Wireshark χρειάζεται το extcap **USBPcap** για να δει ακατέργαστα USB URBs.<sup>[[4]](#references)</sup>
- Αν το πληκτρολόγιο ήταν συνδεδεμένο μέσω hub ή dock, ελέγξτε πρώτα το interface descriptor και, στη συνέχεια, αποκωδικοποιήστε μόνο το ζεύγος συσκευής/interface. Οι σύνθετες καταγραφές HID συχνά αναμειγνύουν αναφορές πληκτρολογίου και ποντικιού.
- Οι λήψεις στα Windows απαιτούν το interface extcap **USBPcap**· βεβαιωθείτε ότι διατηρήθηκε μετά τις αναβαθμίσεις του Wireshark, καθώς τα extcap που λείπουν αφήνουν κενές τις λίστες συσκευών.<sup>[[4]](#references)</sup>
- Να συσχετίζετε πάντα την τριάδα διαύλου, συσκευής και interface (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`· π.χ. `1.9.1`) πριν από οποιαδήποτε αποκωδικοποίηση — η ανάμειξη πολλών πληκτρολογίων ή συσκευών αποθήκευσης οδηγεί σε ασυνάρτητα keystrokes.<sup>[[10]](#references)</sup>



## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Ανάλυση καταγραφής πακέτων πληκτρολογίου USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - write-up για τα pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Ρύθμιση καταγραφής USB στο Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [Αποκωδικοποιητές USB-HID](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Ορισμός κλάσης συσκευών για συσκευές ανθρώπινης διεπαφής (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Πίνακες χρήσης HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Αναφορά φίλτρων εμφάνισης του Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Αναφορά φίλτρων εμφάνισης του Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Πυρήνας Linux: Εισαγωγή στους HID report descriptors](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: write-up για το ordinary-keyboard](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
