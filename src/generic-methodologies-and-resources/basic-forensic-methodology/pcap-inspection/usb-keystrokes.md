# Πληκτρολόγηση μέσω USB

{{#include ../../../banners/hacktricks-training.md}}

Αν έχετε ένα pcap που περιέχει την επικοινωνία μέσω USB ενός πληκτρολογίου, όπως το παρακάτω:

![Πληκτρολόγηση μέσω USB: Αν έχετε ένα pcap που περιέχει την επικοινωνία μέσω USB ενός πληκτρολογίου, όπως το παρακάτω](<../../../images/image (962).png>)

Για ένα πληκτρολόγιο που χρησιμοποιεί το HID **boot protocol**, κάθε Interrupt IN report έχει σταθερή διάταξη 8 byte: ένα byte modifier, ένα reserved byte και έξι byte keycode. Το host συγκρίνει διαδοχικά reports και αντιστοιχίζει τα keycodes σε HID usages για να ανακατασκευάσει τα key events.<sup>[[8]](#references)</sup>

## Βασικά στοιχεία των USB HID reports

Το τυπικό boot keyboard input report έχει την ακόλουθη δομή.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Σημασία |
| --- | --- |
| 0 | Bitmap modifier (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt κ.λπ.). Μπορούν να είναι ενεργοποιημένα ταυτόχρονα πολλά bits. |
| 1 | Reserved byte· τα reports που δεν χρησιμοποιούνται κανονικά πρέπει να το ορίζουν σε μηδέν. Η χρήση από OEM ή συστήματα συγκεκριμένου κατασκευαστή δεν είναι portable. |
| 2-7 | Έως έξι ταυτόχρονα keycodes σε μορφή USB usage ID (`0x04` = a, `0x1E` = 1). Το `0x00` σημαίνει "κανένα πλήκτρο". |

Στη boot διάταξη, το usage ID `0x01` (`Keyboard ErrorRollOver`) αναφέρεται σε όλα τα key slots όταν πατηθούν περισσότερα από έξι πλήκτρα που δεν είναι modifiers· μπορεί επίσης να υποδεικνύει έναν μη αναγνωρίσιμο συνδυασμό.<sup>[[8]](#references)[[9]](#references)</sup> Η κατανόηση αυτής της διάταξης είναι χρήσιμη όταν διαθέτετε μόνο τα ακατέργαστα bytes `usb.capdata`.

## Εξαγωγή HID data από ένα PCAP

### Εντοπίστε πρώτα το interface του πληκτρολογίου

Σε captures με πολλή κίνηση, εντοπίστε το HID keyboard πριν κάνετε dump των reports. Ένα αξιόπιστο σημείο εκκίνησης είναι η απόκριση του interface descriptor:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Η κλάση HID ορίζει αυτές τις τιμές interface:<sup>[[8]](#references)</sup>

- `subclass == 1` είναι το Boot Interface Subclass· μαζί με `protocol == 1` προσδιορίζει ένα boot keyboard
- `protocol == 2` προσδιορίζει ένα boot mouse
- `protocol == 0` σημαίνει ότι δεν χρησιμοποιείται boot protocol· εξετάστε τον HID report descriptor αντί να υποθέσετε διάταξη 8 byte

Μόλις προσδιοριστεί το interface, περιορίστε τα φίλτρα σας στα `usb.bus_id`, `usb.device_address` και, αν είναι δυνατόν, στο `usb.bInterfaceNumber` πριν κάνετε οποιαδήποτε εξαγωγή.

### Ροή εργασίας στο Wireshark

1. **Απομονώστε τη συσκευή**: εφαρμόστε φίλτρο στην interrupt IN traffic από το keyboard, π.χ. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Προσθέστε χρήσιμες στήλες**: κάντε δεξί κλικ στο πεδίο `Leftover Capture Data` (`usb.capdata`) και στα πεδία `usbhid.*` της επιλογής σας (π.χ. `usbhid.boot_report.keyboard.keycode_1`) για να παρακολουθείτε τα keystrokes χωρίς να ανοίγετε κάθε frame.<sup>[[11]](#references)</sup>
3. **Αποκρύψτε τα κενά reports**: εφαρμόστε το `!(usb.capdata == 00:00:00:00:00:00:00:00)` για να απορρίψετε τα idle frames.
4. **Κάντε export για post-processing**: `File -> Export Packet Dissections -> As CSV`, συμπεριλάβετε τα `frame.number`, `usb.src`, `usb.capdata` και τα decoded modifier fields, όπως `usbhid.boot_report.keyboard.modifier.left_shift` και `usbhid.boot_report.keyboard.modifier.right_alt`, ώστε να κάνετε αργότερα το reconstruction με script.<sup>[[10]](#references)[[11]](#references)</sup>

### Ροή εργασίας από τη γραμμή εντολών

Το κλασικό pattern εξαγωγής — dump του `usb.capdata`, απόρριψη των idle reports και αντιστοίχιση των usage IDs — εμφανίζεται στην αρχική ανάλυση του 2017 και στο walkthrough της.<sup>[[1]](#references)[[2]](#references)</sup>

Το repository `ctf-usb-keyboard-parser` αυτοματοποιεί το κλασικό pipeline `tshark + sed`:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Σε νεότερα captures, προτιμήστε το decoded πεδίο `usbhid.data` του Wireshark και χρησιμοποιήστε ως εναλλακτική το `usb.capdata`· γράψτε ένα payload ανά report σε αρχείο ανά συσκευή:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Αυτά τα αρχεία ανά συσκευή μπορούν να δοθούν σε έναν decoder αφού πρώτα κανονικοποιηθεί η μορφή hex που αναμένει. Αν η καταγραφή προήλθε από BLE keyboards που μεταφέρονται μέσω GATT, εφαρμόστε φίλτρο σε `btatt.value && frame.len == 20` και εξαγάγετε τα payloads hex πριν από το decoding.<sup>[[7]](#references)</sup>

### Όταν το report δεν είναι το κλασικό boot report των 8 byte

Ένα non-boot interface ή ένα report ID μπορεί να αλλάξει τη διάταξη του payload, επομένως μην υποθέτετε ότι κάθε keyboard report ακολουθεί τη μορφή `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Προτιμήστε το `usbhid.data` αντί για το `usb.capdata` όταν το Wireshark έχει ήδη κάνει parse το HID layer.
- Αν κάθε γραμμή ξεκινά με ένα σταθερό prefix ή report ID, αφαιρέστε το με έναν decoder που λαμβάνει υπόψη το offset, αντί να θεωρείτε ότι το byte 0 είναι πάντα το modifier.<sup>[[7]](#references)</sup>
- Ορισμένα USBPcap exports παραλείπουν το reserved byte, επομένως οι decoders που υποστηρίζουν `--no-reserved` ή ένα custom offset εξοικονομούν χρόνο.<sup>[[7]](#references)</sup>
- Αν το HID report descriptor ή το BLE HOGP report map υπάρχει στην καταγραφή, χρησιμοποιήστε το για να ανακτήσετε την πραγματική διάταξη των πεδίων πριν γράψετε parser.

## Αυτοματοποίηση του decoding

- Το **ctf-usb-keyboard-parser** παραμένει χρήσιμο για γρήγορα CTF challenges και περιλαμβάνεται ήδη στο repository.<sup>[[5]](#references)</sup>
- Το **CTF-Usb_Keyboard_Parser** (`main.py`) κάνει parse εγγενώς αρχεία `pcap` και `pcapng`, κατανοεί τα `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` και δεν απαιτεί το tshark ή άλλη εξωτερική dependency, επομένως είναι κατάλληλο για isolated sandboxes.<sup>[[6]](#references)</sup>
- Το **USB-HID-decoders** προσθέτει visualizers για keyboard, mouse και tablet. Μπορείτε είτε να εκτελέσετε το helper `extract_hid_data.sh` (tshark backend) είτε το `extract_hid_data.py` (scapy backend) και στη συνέχεια να δώσετε το resulting text file στον decoder ή στα replay modules, ώστε να παρακολουθήσετε τα keystrokes να εμφανίζονται.<sup>[[7]](#references)</sup>

### Το stateful decoding έχει σημασία

Τα USB boot keyboards στέλνουν reports με βάση το idle rate ακόμη και όταν δεν υπάρχει νέο key event, επομένως οι καταγραφές μπορεί να περιέχουν επαναλαμβανόμενα reports πριν από το release event. Ένας πρακτικός decoder θα πρέπει:<sup>[[3]](#references)[[8]](#references)</sup>

- να εκπέμπει μόνο τα keycodes που πατήθηκαν πρόσφατα σε σύγκριση με το προηγούμενο report
- να διατηρεί την κατάσταση των modifiers (`Shift`, `Ctrl`, `AltGr`) από το byte 0 ή από parsed fields όπως τα `usbhid.boot_report.keyboard.modifier.left_shift` και `usbhid.boot_report.keyboard.modifier.right_alt`
- να παρακολουθεί toggle keys όπως το `Caps Lock`, επειδή η έξοδος κεφαλαίων δεν ελέγχεται μόνο από το Shift
- να θυμάται ότι τα HID usage IDs είναι ανεξάρτητα από το layout: το `0x1d` είναι η φυσική θέση του πλήκτρου `z`/`y`, ανάλογα με το keyboard layout του host.<sup>[[9]](#references)</sup>

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
Τροφοδοτήστε το με τις απλές γραμμές hex που αποτυπώθηκαν νωρίτερα, για να λάβετε άμεσα μια πρόχειρη ανακατασκευή χωρίς να φορτώσετε έναν πλήρη parser στο περιβάλλον. Για διατάξεις πληκτρολογίου εκτός ΗΠΑ, αυτό εξακολουθεί να ανακατασκευάζει τη φυσική θέση του πλήκτρου και όχι απαραίτητα το τελικό glyph που εμφανίζεται στο host του θύματος.

## Συμβουλές αντιμετώπισης προβλημάτων

- Αν το Wireshark δεν συμπληρώνει πεδία `usbhid.*`, πιθανότατα δεν καταγράφηκε ο HID report descriptor. Αποσυνδέστε και επανασυνδέστε το πληκτρολόγιο κατά την καταγραφή ή χρησιμοποιήστε ως εναλλακτική το raw `usb.capdata`.
- Σε captures λογισμικού Linux, το `usbmon` είναι η συνήθης πηγή· στα Windows, το Wireshark εξαρτάται από το **USBPcap** extcap για να δει raw USB URBs.<sup>[[4]](#references)</sup>
- Αν το πληκτρολόγιο ήταν συνδεδεμένο μέσω hub ή dock, επιβεβαιώστε πρώτα το interface descriptor και, στη συνέχεια, κάντε decode μόνο για το συγκεκριμένο ζεύγος device/interface. Τα σύνθετα HID captures συχνά αναμειγνύουν reports πληκτρολογίου και ποντικιού.
- Τα Windows captures απαιτούν το **USBPcap** extcap interface· βεβαιωθείτε ότι παρέμεινε διαθέσιμο μετά τις αναβαθμίσεις του Wireshark, καθώς τα extcaps που λείπουν αφήνουν κενές λίστες συσκευών.<sup>[[4]](#references)</sup>
- Να συσχετίζετε πάντα το tuple bus, device και interface (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`· π.χ. `1.9.1`) πριν κάνετε decode οτιδήποτε — η ανάμειξη πολλών πληκτρολογίων ή συσκευών αποθήκευσης οδηγεί σε ασυνάρτητες keystrokes.<sup>[[10]](#references)</sup>

## References

- [1] [Writeup του HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Ανάλυση packet capture πληκτρολογίου USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - write-up των pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Ρύθμιση USB capture στο Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Ορισμός κλάσης συσκευής για Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Πίνακες χρήσης HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Αναφορά Display Filter του Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Αναφορά Display Filter του Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
