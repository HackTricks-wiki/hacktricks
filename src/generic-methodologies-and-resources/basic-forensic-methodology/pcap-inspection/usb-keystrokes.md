# Πλήκτρα USB

{{#include ../../../banners/hacktricks-training.md}}

Αν έχετε ένα pcap που περιέχει την επικοινωνία μέσω USB ενός πληκτρολογίου, όπως το παρακάτω:

![Πλήκτρα USB: Αν έχετε ένα pcap που περιέχει την επικοινωνία μέσω USB ενός πληκτρολογίου, όπως το παρακάτω](<../../../images/image (962).png>)

Τα πληκτρολόγια USB συνήθως χρησιμοποιούν το HID **boot protocol**, επομένως κάθε interrupt transfer προς το host έχει μήκος μόνο 8 bytes: ένα byte με τα modifier bits (Ctrl/Shift/Alt/Super), ένα δεσμευμένο byte και έως έξι keycodes ανά report. Η αποκωδικοποίηση αυτών των bytes αρκεί για την ανακατασκευή όλων όσων πληκτρολογήθηκαν.

## Βασικά στοιχεία των USB HID reports

Το τυπικό IN report έχει τη μορφή:

| Byte | Σημασία |
| --- | --- |
| 0 | Bitmap modifiers (`0x02` = Left Shift, `0x20` = Right Alt κ.λπ.). Μπορούν να οριστούν πολλά bits ταυτόχρονα. |
| 1 | Reserved/padding, αλλά συχνά επαναχρησιμοποιείται από gaming keyboards για vendor data. |
| 2-7 | Έως έξι ταυτόχρονα keycodes σε USB usage ID format (`0x04 = a`, `0x1E = 1`). Το `0x00` σημαίνει "no key". |

Τα πληκτρολόγια χωρίς NKRO συνήθως στέλνουν `0x01` στο byte 2 όταν πατηθούν περισσότερα από έξι πλήκτρα, για να σηματοδοτήσουν "rollover". Η κατανόηση αυτής της διάταξης βοηθά όταν διαθέτετε μόνο τα raw bytes του `usb.capdata`.

## Εξαγωγή HID data από ένα PCAP

### Εντοπίστε πρώτα το interface του πληκτρολογίου

Σε captures με πολλή κίνηση, εντοπίστε το HID keyboard πριν κάνετε dump των reports. Ένα αξιόπιστο σημείο εκκίνησης είναι η απόκριση του interface descriptor:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Εξετάστε τα `usb.bInterfaceSubClass` και `usb.bInterfaceProtocol`:

- `subclass == 1` και `protocol == 1` συνήθως σημαίνουν boot keyboard
- `protocol == 2` συνήθως σημαίνει mouse
- `protocol == 0` συχνά σημαίνει vendor-defined ή NKRO-style HID interface που εξακολουθεί να μεταφέρει δεδομένα πληκτρολογίου, αλλά όχι στη simple 8-byte boot layout

Μόλις αναγνωρίσετε το interface, περιορίστε τα φίλτρα σας στα `usb.bus_id`, `usb.device_address` και, αν είναι δυνατόν, στο `usb.interface_number` πριν κάνετε οποιαδήποτε εξαγωγή.

### Ροή εργασίας στο Wireshark

1. **Απομονώστε τη συσκευή**: εφαρμόστε φίλτρο στην interrupt IN traffic από το πληκτρολόγιο, π.χ. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Προσθέστε χρήσιμες στήλες**: κάντε δεξί κλικ στο πεδίο `Leftover Capture Data` (`usb.capdata`) και στα προτιμώμενα πεδία `usbhid.*` (π.χ. `usbhid.boot_report.keyboard.keycode_1`) για να παρακολουθείτε τα keystrokes χωρίς να ανοίγετε κάθε frame.
3. **Αποκρύψτε τα κενά reports**: εφαρμόστε το `!(usb.capdata == 00:00:00:00:00:00:00:00)` για να απορρίψετε τα idle frames.
4. **Κάντε export για post-processing**: `File -> Export Packet Dissections -> As CSV`, συμπεριλάβετε τα `frame.number`, `usb.src`, `usb.capdata` και `usbhid.modifiers`, ώστε να κάνετε script το reconstruction αργότερα.

### Ροή εργασίας γραμμής εντολών

Το `ctf-usb-keyboard-parser` αυτοματοποιεί ήδη το κλασικό tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Σε νεότερες καταγραφές, μπορείτε να διατηρήσετε τόσο το `usb.capdata` όσο και το πιο πλούσιο πεδίο `usbhid.data`, ομαδοποιώντας ανά συσκευή:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Αυτά τα αρχεία ανά συσκευή εισάγονται απευθείας σε οποιονδήποτε decoder. Αν το capture προήλθε από BLE keyboards που διοχετεύονται μέσω GATT, εφαρμόστε φίλτρο `btatt.value && frame.len == 20` και εξαγάγετε τα hex payloads πριν από το decoding.

### Όταν το report δεν είναι το κλασικό boot report των 8 byte

Τα σύγχρονα gaming keyboards, τα split keyboards και οι composite HID συσκευές συχνά εκθέτουν ένα non-boot keyboard interface, όπου το payload δεν αντιστοιχεί πλέον στο `modifier,reserved,key1..key6`.

- Προτιμήστε το `usbhid.data` αντί για το `usb.capdata` όταν το Wireshark έχει ήδη κάνει parsing στο HID layer.
- Αν κάθε γραμμή ξεκινά με ένα σταθερό prefix ή report ID, αφαιρέστε το με έναν offset-aware decoder αντί να υποθέσετε ότι το byte 0 είναι πάντα το modifier.
- Ορισμένα USBPcap exports παραλείπουν το reserved byte, επομένως οι decoders που υποστηρίζουν `--no-reserved` ή ένα custom offset εξοικονομούν χρόνο.
- Αν το HID report descriptor ή το BLE HOGP report map υπάρχει στο capture, χρησιμοποιήστε το για να ανακτήσετε την πραγματική διάταξη των πεδίων πριν γράψετε parser.

## Αυτοματοποίηση του decoding

- Το **ctf-usb-keyboard-parser** παραμένει χρήσιμο για γρήγορα CTF challenges και περιλαμβάνεται ήδη στο repository.<sup>[[3]](#references)</sup>
- Το **CTF-Usb_Keyboard_Parser** (`main.py`) κάνει parsing σε αρχεία `pcap` και `pcapng` natively, κατανοεί τα `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` και δεν απαιτεί tshark, επομένως λειτουργεί άψογα μέσα σε isolated sandboxes.<sup>[[4]](#references)</sup>
- Το **USB-HID-decoders** προσθέτει visualizers για keyboard, mouse και tablet. Μπορείτε είτε να εκτελέσετε το helper `extract_hid_data.sh` (tshark backend) είτε το `extract_hid_data.py` (scapy backend) και στη συνέχεια να τροφοδοτήσετε το resulting text file στον decoder ή στα replay modules, ώστε να παρακολουθήσετε τα keystrokes να εμφανίζονται.<sup>[[5]](#references)</sup>

### Το stateful decoding έχει σημασία

Τα USB interrupt captures συνήθως περιέχουν τόσο το key press όσο και ένα ή περισσότερα repeated αντίγραφα του ίδιου report, πριν φτάσει το release event. Ένας πρακτικός decoder πρέπει να:<sup>[[2]](#references)</sup>

- εκπέμπει μόνο τα keycodes που πατήθηκαν πρόσφατα σε σύγκριση με το προηγούμενο report
- διατηρεί την κατάσταση των modifiers (`Shift`, `Ctrl`, `AltGr`) από το byte 0 ή από το parsed πεδίο `usbhid.boot_report.keyboard.modifier`
- παρακολουθεί toggle keys όπως το `Caps Lock`, επειδή η έξοδος με κεφαλαία δεν ελέγχεται μόνο από το Shift
- θυμάται ότι τα HID usage IDs είναι ανεξάρτητα από το layout: το `0x1d` είναι η φυσική θέση του πλήκτρου `z`/`y`, ανάλογα με το keyboard layout του host

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
Τροφοδοτήστε το με τις απλές γραμμές hex που απορρίφθηκαν νωρίτερα, για να αποκτήσετε άμεσα μια πρόχειρη ανακατασκευή χωρίς να φορτώσετε έναν πλήρη parser στο περιβάλλον. Για διατάξεις εκτός ΗΠΑ, αυτό εξακολουθεί να ανακατασκευάζει τη φυσική θέση του πλήκτρου και όχι απαραίτητα το τελικό glyph που εμφανίζεται στο host του θύματος.

## Συμβουλές αντιμετώπισης προβλημάτων

- Αν το Wireshark δεν συμπληρώνει πεδία `usbhid.*`, πιθανότατα δεν καταγράφηκε ο HID report descriptor. Αποσυνδέστε και επανασυνδέστε το πληκτρολόγιο κατά την καταγραφή ή χρησιμοποιήστε το raw `usb.capdata`.
- Σε software captures στο Linux, το `usbmon` είναι η κανονική πηγή· στα Windows, το Wireshark εξαρτάται από το **USBPcap** extcap για να δει raw USB URBs.<sup>[[1]](#references)</sup>
- Αν το πληκτρολόγιο ήταν συνδεδεμένο μέσω hub ή dock, επιβεβαιώστε πρώτα το interface descriptor και, στη συνέχεια, κάντε decode μόνο για το συγκεκριμένο ζεύγος device/interface. Τα σύνθετα HID captures συχνά αναμειγνύουν reports πληκτρολογίου και ποντικιού.
- Οι καταγραφές των Windows απαιτούν το **USBPcap** extcap interface· βεβαιωθείτε ότι παρέμεινε μετά από upgrades του Wireshark, καθώς τα extcaps που λείπουν αφήνουν κενές λίστες συσκευών.<sup>[[1]](#references)</sup>
- Να συσχετίζετε πάντα το `usb.bus_id:device:interface` (π.χ. `1.9.1`) πριν κάνετε decode οτιδήποτε — η ανάμειξη πολλών πληκτρολογίων ή storage devices οδηγεί σε ασυνάρτητα keystrokes.

## References

- [1] [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
