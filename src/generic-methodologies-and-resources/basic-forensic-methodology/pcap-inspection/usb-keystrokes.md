# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Αν έχεις ένα pcap που περιέχει την επικοινωνία μέσω USB ενός keyboard όπως το παρακάτω:

![](<../../../images/image (962).png>)

Τα USB keyboards συνήθως μιλούν το HID **boot protocol**, οπότε κάθε interrupt transfer προς το host είναι μόνο 8 bytes: ένα byte από modifier bits (Ctrl/Shift/Alt/Super), ένα reserved byte, και έως έξι keycodes ανά report. Η αποκωδικοποίηση αυτών των bytes αρκεί για να ανακατασκευάσεις ό,τι πληκτρολογήθηκε.

## USB HID report basics

Το τυπικό IN report μοιάζει έτσι:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, κ.λπ.). Πολλά bits μπορούν να οριστούν ταυτόχρονα. |
| 1 | Reserved/padding αλλά συχνά επαναχρησιμοποιείται από gaming keyboards για vendor data. |
| 2-7 | Έως έξι ταυτόχρονα keycodes σε USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` σημαίνει "no key". |

Keyboards χωρίς NKRO συνήθως στέλνουν `0x01` στο byte 2 όταν πατιούνται περισσότερα από έξι keys για να σηματοδοτήσουν "rollover". Η κατανόηση αυτής της διάταξης βοηθά όταν έχεις μόνο τα raw `usb.capdata` bytes.

## Extracting HID data from a PCAP

### Identify the keyboard interface first

Σε captures με πολλή κίνηση, identify το HID keyboard πριν κάνεις dump οποιωνδήποτε reports. Ένα αξιόπιστο σημείο εκκίνησης είναι το interface descriptor response:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Δες τα `usb.bInterfaceSubClass` και `usb.bInterfaceProtocol`:

- `subclass == 1` και `protocol == 1` συνήθως σημαίνει boot keyboard
- `protocol == 2` είναι συνήθως mouse
- `protocol == 0` συχνά σημαίνει vendor-defined ή NKRO-style HID interface που εξακολουθεί να μεταφέρει keyboard data, αλλά όχι στη simple 8-byte boot layout

Μόλις η interface γίνει γνωστή, όρισε τα filters σου στα `usb.bus_id`, `usb.device_address` και, αν είναι δυνατόν, `usb.interface_number` πριν κάνεις export οτιδήποτε.

### Wireshark workflow

1. **Απομόνωσε τη συσκευή**: βάλε φίλτρο στο interrupt IN traffic από το keyboard, π.χ. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Πρόσθεσε χρήσιμες στήλες**: κάνε right-click στο πεδίο `Leftover Capture Data` (`usb.capdata`) και στα προτιμώμενα `usbhid.*` fields σου (π.χ. `usbhid.boot_report.keyboard.keycode_1`) για να παρακολουθείς keystrokes χωρίς να ανοίγεις κάθε frame.
3. **Κρύψε τα empty reports**: εφάρμοσε `!(usb.capdata == 00:00:00:00:00:00:00:00)` για να αφαιρέσεις idle frames.
4. **Κάνε export για post-processing**: `File -> Export Packet Dissections -> As CSV`, συμπερίλαβε τα `frame.number`, `usb.src`, `usb.capdata`, και `usbhid.modifiers` για να κάνεις αργότερα script τη reconstruction.

### Command-line workflow

`ctf-usb-keyboard-parser` ήδη αυτοματοποιεί το κλασικό tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Σε νεότερα captures μπορείς να διατηρείς και τα δύο `usb.capdata` και το πιο πλούσιο πεδίο `usbhid.data` ομαδοποιώντας ανά συσκευή:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Αυτά τα per-device αρχεία μπαίνουν κατευθείαν σε οποιονδήποτε decoder. Αν το capture προήλθε από BLE keyboards tunneled over GATT, φιλτράρισε με `btatt.value && frame.len == 20` και κάνε dump τα hex payloads πριν το decoding.

### Όταν η αναφορά δεν είναι το κλασικό 8-byte boot report

Recent gaming keyboards, split keyboards, και composite HID devices συχνά εκθέτουν ένα non-boot keyboard interface όπου το payload δεν ταιριάζει πλέον με `modifier,reserved,key1..key6`.

- Προτίμησε `usbhid.data` αντί για `usb.capdata` όταν το Wireshark έχει ήδη κάνει parse το HID layer.
- Αν κάθε γραμμή ξεκινά με ένα σταθερό prefix ή report ID, αφαίρεσέ το με έναν offset-aware decoder αντί να υποθέτεις ότι το byte 0 είναι πάντα το modifier.
- Κάποια USBPcap exports παραλείπουν το reserved byte, οπότε decoders που υποστηρίζουν `--no-reserved` ή ένα custom offset γλιτώνουν χρόνο.
- Αν το HID report descriptor ή το BLE HOGP report map υπάρχει στο capture, χρησιμοποίησέ το για να ανακτήσεις το πραγματικό field layout πριν γράψεις parser.

## Αυτοματοποίηση του decoding

- **ctf-usb-keyboard-parser** παραμένει χρήσιμο για γρήγορα CTF challenges και ήδη περιλαμβάνεται στο repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) κάνει parse και `pcap` και `pcapng` files natively, καταλαβαίνει `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, και δεν απαιτεί tshark, οπότε δουλεύει καλά μέσα σε isolated sandboxes.
- **USB-HID-decoders** προσθέτει keyboard, mouse, και tablet visualizers. Μπορείς είτε να τρέξεις το helper `extract_hid_data.sh` (tshark backend) είτε το `extract_hid_data.py` (scapy backend) και μετά να δώσεις το resulting text file στον decoder ή στα replay modules για να δεις τα keystrokes να ξεδιπλώνονται.

### Το stateful decoding έχει σημασία

Τα USB interrupt captures συνήθως περιέχουν τόσο το key press όσο και ένα ή περισσότερα repeated copies του ίδιου report πριν φτάσει το release event. Ένας πρακτικός decoder θα πρέπει να:

- εκπέμπει μόνο τα newly pressed keycodes σε σύγκριση με το προηγούμενο report
- κρατάει το modifier state (`Shift`, `Ctrl`, `AltGr`) από το byte 0 ή από το parsed `usbhid.boot_report.keyboard.modifier` field
- παρακολουθεί toggle keys όπως `Caps Lock`, επειδή το uppercase output δεν ελέγχεται μόνο από το Shift
- θυμάται ότι τα HID usage IDs είναι layout-agnostic: το `0x1d` είναι η φυσική θέση του `z`/`y` key ανάλογα με το host keyboard layout

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
Τροφοδότησέ το με τις απλές hex γραμμές που dumpαρίστηκαν νωρίτερα για να πάρεις άμεσα μια πρόχειρη ανακατασκευή, χωρίς να φέρεις έναν πλήρη parser στο περιβάλλον. Για non-US layouts αυτό ανακατασκευάζει τη φυσική θέση του πλήκτρου, όχι απαραίτητα το τελικό glyph που εμφανίζεται στον host του θύματος.

## Συμβουλές αντιμετώπισης προβλημάτων

- Αν το Wireshark δεν συμπληρώνει πεδία `usbhid.*`, το HID report descriptor πιθανότατα δεν καταγράφηκε. Ξανασύνδεσε το keyboard ενώ γίνεται capture ή γύρνα σε raw `usb.capdata`.
- Σε Linux software captures, το `usbmon` είναι η κανονική πηγή· σε Windows, το Wireshark εξαρτάται από το **USBPcap** extcap για να δει καθόλου raw USB URBs.
- Αν το keyboard ήταν συνδεδεμένο μέσω hub ή dock, επιβεβαίωσε πρώτα το interface descriptor και μετά κάνε decode μόνο για εκείνο το device/interface pair. Τα composite HID captures συχνά ανακατεύουν reports από keyboard και mouse.
- Τα Windows captures απαιτούν το **USBPcap** extcap interface· βεβαιώσου ότι επέζησε από τα Wireshark upgrades, γιατί τα missing extcaps σε αφήνουν με άδειες device lists.
- Πάντα να συσχετίζεις `usb.bus_id:device:interface` (π.χ. `1.9.1`) πριν αποκωδικοποιήσεις οτιδήποτε — η ανάμειξη πολλών keyboards ή storage devices οδηγεί σε αλαζονικά keystrokes.

## Αναφορές

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
