# Πιέσεις πλήκτρων USB

{{#include ../../../banners/hacktricks-training.md}}

Αν έχετε ένα pcap που περιέχει την επικοινωνία μέσω USB ενός πληκτρολογίου όπως το παρακάτω:

![](<../../../images/image (962).png>)

Τα USB keyboards συνήθως χρησιμοποιούν το HID **boot protocol**, οπότε κάθε interrupt transfer προς τον host είναι μόνο 8 bytes: ένα byte με bitmap των modifier bits (Ctrl/Shift/Alt/Super), ένα κρατημένο byte, και έως έξι keycodes ανά report. Η αποκωδικοποίηση αυτών των bytes είναι αρκετή για να ανακατασκευάσει ό,τι πληκτρολογήθηκε.

## Βασικά των USB HID reports

Το τυπικό IN report έχει την εξής μορφή:

| Byte | Σημασία |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Multiple bits can be set simultaneously. |
| 1 | Reserved/padding but often reused by gaming keyboards for vendor data. |
| 2-7 | Up to six concurrent keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` means "no key". |

Τα πληκτρολόγια χωρίς NKRO συνήθως στέλνουν `0x01` στο byte 2 όταν πατηθούν περισσότερα από έξι πλήκτρα για να σηματοδοτήσουν "rollover". Η κατανόηση αυτής της διάταξης βοηθά όταν έχετε μόνο τα ακατέργαστα bytes `usb.capdata`.

## Εξαγωγή δεδομένων HID από ένα PCAP

### Διαδικασία με Wireshark

1. **Απομονώστε τη συσκευή**: φιλτράρετε την interrupt IN κίνηση από το πληκτρολόγιο, π.χ. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Προσθέστε χρήσιμες στήλες**: δεξί κλικ στο πεδίο `Leftover Capture Data` (`usb.capdata`) και στα προτιμώμενα πεδία `usbhid.*` (π.χ. `usbhid.boot_report.keyboard.keycode_1`) για να ακολουθείτε τις πιέσεις χωρίς να ανοίγετε κάθε frame.
3. **Απόκρυψη κενών reports**: εφαρμόστε `!(usb.capdata == 00:00:00:00:00:00:00:00)` για να αποκλείσετε frames αδράνειας.
4. **Εξαγωγή για μετα-επεξεργασία**: `File -> Export Packet Dissections -> As CSV`, συμπεριλάβετε `frame.number`, `usb.src`, `usb.capdata`, και `usbhid.modifiers` για να αυτοματοποιήσετε την ανακατασκευή αργότερα.

### Διαδικασία γραμμής εντολών

`ctf-usb-keyboard-parser` already automates the classic tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Σε νεότερα captures μπορείτε να κρατήσετε και τα δύο `usb.capdata` και το πλουσιότερο πεδίο `usbhid.data` κάνοντας batching ανά συσκευή:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Τα αρχεία ανά συσκευή φορτώνονται απευθείας σε οποιονδήποτε αποκωδικοποιητή. Εάν η καταγραφή προήλθε από BLE keyboards tunneled over GATT, φιλτράρετε με `btatt.value && frame.len == 20` και εξάγετε τα hex payloads πριν από την αποκωδικοποίηση.

## Αυτοματοποίηση της αποκωδικοποίησης

- **ctf-usb-keyboard-parser** παραμένει χρήσιμο για γρήγορους CTF challenges και ήδη περιλαμβάνεται στο αποθετήριο.
- **CTF-Usb_Keyboard_Parser** (`main.py`) αναλύει τόσο αρχεία `pcap` όσο και `pcapng` εγγενώς, κατανοεί `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` και δεν χρειάζεται το tshark, οπότε λειτουργεί καλά μέσα σε απομονωμένα sandboxes.
- **USB-HID-decoders** προσθέτει οπτικοποιητές για πληκτρολόγιο, ποντίκι και ταμπλέτα. Μπορείτε είτε να τρέξετε το βοηθητικό `extract_hid_data.sh` (tshark backend) είτε το `extract_hid_data.py` (scapy backend) και στη συνέχεια να δώσετε το προκύπτον αρχείο κειμένου στον αποκωδικοποιητή ή στα replay modules για να δείτε τα keystrokes να ξεδιπλώνονται.

## Γρήγορος Python αποκωδικοποιητής
```python
#!/usr/bin/env python3
import sys
HID = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n'}
for raw in sys.stdin:
raw = raw.strip().replace(':', '')
if len(raw) != 16:
continue
keycode = int(raw[4:6], 16)
modifier = int(raw[0:2], 16)
if keycode:
char = HID.get(keycode, '?')
if modifier & 0x02:
char = char.upper()
sys.stdout.write(char)
```
Δώστε του τις απλές γραμμές hex που εξήχθησαν προηγουμένως για να έχετε μια άμεση, πρόχειρη ανακατασκευή χωρίς να χρειαστεί να φορτώσετε έναν πλήρη parser στο περιβάλλον.

## Συμβουλές αντιμετώπισης προβλημάτων

- Εάν το Wireshark δεν συμπληρώνει τα πεδία `usbhid.*`, πιθανότατα δεν καταγράφηκε ο HID report descriptor. Αποσυνδέστε και επανασυνδέστε το πληκτρολόγιο ενώ γίνεται καταγραφή ή επιστρέψτε στα ακατέργαστα `usb.capdata`.
- Οι καταγραφές σε Windows απαιτούν τη διεπαφή **USBPcap** extcap· βεβαιωθείτε ότι παρέμεινε μετά τις αναβαθμίσεις του Wireshark, καθώς οι λείπoν extcaps αφήνουν κενές λίστες συσκευών.
- Συνδέετε πάντα τα `usb.bus_id:device:interface` (π.χ. `1.9.1`) πριν αποκωδικοποιήσετε οτιδήποτε — η ανάμειξη πολλαπλών πληκτρολογίων ή αποθηκευτικών συσκευών οδηγεί σε μη-νοηματικές ακολουθίες πλήκτρων.

## Αναφορές

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
