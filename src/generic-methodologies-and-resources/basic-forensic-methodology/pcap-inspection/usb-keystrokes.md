# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

If you have a pcap containing the communication via USB of a keyboard like the following one:

![](<../../../images/image (962).png>)

USB keyboards usually speak the HID **boot protocol**, so every interrupt transfer towards the host is only 8 bytes long: one byte of modifier bits (Ctrl/Shift/Alt/Super), one reserved byte, and up to six keycodes per report. Decoding those bytes is enough to rebuild everything that was typed.

## USB HID report basics

The typical IN report looks like:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Multiple bits can be set simultaneously. |
| 1 | Reserved/padding but often reused by gaming keyboards for vendor data. |
| 2-7 | Up to six concurrent keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` means "no key". | 

Keyboards without NKRO usually send `0x01` in byte 2 when more than six keys are pressed to signal "rollover". Understanding this layout helps when you only have the raw `usb.capdata` bytes.

## Extracting HID data from a PCAP

### Wireshark workflow

1. **Isolate the device**: filter on interrupt IN traffic from the keyboard, e.g. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Add useful columns**: right-click the `Leftover Capture Data` field (`usb.capdata`) and your preferred `usbhid.*` fields (e.g. `usbhid.boot_report.keyboard.keycode_1`) to follow keystrokes without opening every frame.
3. **Hide empty reports**: apply `!(usb.capdata == 00:00:00:00:00:00:00:00)` to drop idle frames.
4. **Export for post-processing**: `File -> Export Packet Dissections -> As CSV`, include `frame.number`, `usb.src`, `usb.capdata`, and `usbhid.modifiers` to script the reconstruction later.

### Command-line workflow

`ctf-usb-keyboard-parser` already automates the classic tshark + sed pipeline:

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

On newer captures you can keep both `usb.capdata` and the richer `usbhid.data` field by batching per device:

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
  sort -s -k1,1 | \
  awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
  awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```

Those per-device files drop straight into any decoder. If the capture came from BLE keyboards tunneled over GATT, filter on `btatt.value && frame.len == 20` and dump the hex payloads before decoding.

## Automating the decoding

- **ctf-usb-keyboard-parser** remains handy for quick CTF challenges and already ships in the repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) parses both `pcap` and `pcapng` files natively, understands `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, and does not require tshark, so it works nicely inside isolated sandboxes.
- **USB-HID-decoders** adds keyboard, mouse, and tablet visualizers. You can either run the `extract_hid_data.sh` helper (tshark backend) or `extract_hid_data.py` (scapy backend) and then feed the resulting text file to the decoder or replay modules to watch the keystrokes unfold.

## Quick Python decoder

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

Feed it with the plain hex lines dumped earlier to get an instant rough reconstruction without pulling a full parser into the environment.

## Troubleshooting tips

- If Wireshark does not populate `usbhid.*` fields, the HID report descriptor was probably not captured. Replug the keyboard while capturing or fall back to raw `usb.capdata`.
- Windows captures require the **USBPcap** extcap interface; make sure it survived Wireshark upgrades, as missing extcaps leave you with empty device lists.
- Always correlate `usb.bus_id:device:interface` (e.g. `1.9.1`) before decoding anything — mixing multiple keyboards or storage devices leads to nonsense keystrokes.

## References

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
