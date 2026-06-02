# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

If you have a pcap containing the communication via USB of a keyboard like the following one:

![USB Keystrokes: If you have a pcap containing the communication via USB of a keyboard like the following one](<../../../images/image (962).png>)

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

### Identify the keyboard interface first

On busy captures, identify the HID keyboard before dumping any reports. A reliable starting point is the interface descriptor response:

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

Look at `usb.bInterfaceSubClass` and `usb.bInterfaceProtocol`:

- `subclass == 1` and `protocol == 1` usually means a boot keyboard
- `protocol == 2` is typically a mouse
- `protocol == 0` often means a vendor-defined or NKRO-style HID interface that still carries keyboard data, but not in the simple 8-byte boot layout

Once the interface is known, pin your filters to `usb.bus_id`, `usb.device_address`, and if possible `usb.interface_number` before exporting anything.

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

### When the report is not the classic 8-byte boot report

Recent gaming keyboards, split keyboards, and composite HID devices often expose a non-boot keyboard interface where the payload no longer matches `modifier,reserved,key1..key6`.

- Prefer `usbhid.data` over `usb.capdata` when Wireshark has already parsed the HID layer.
- If every line starts with a constant prefix or report ID, strip it with an offset-aware decoder rather than assuming byte 0 is always the modifier.
- Some USBPcap exports omit the reserved byte, so decoders that support `--no-reserved` or a custom offset save time.
- If the HID report descriptor or BLE HOGP report map is present in the capture, use it to recover the actual field layout before writing a parser.

## Automating the decoding

- **ctf-usb-keyboard-parser** remains handy for quick CTF challenges and already ships in the repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) parses both `pcap` and `pcapng` files natively, understands `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, and does not require tshark, so it works nicely inside isolated sandboxes.
- **USB-HID-decoders** adds keyboard, mouse, and tablet visualizers. You can either run the `extract_hid_data.sh` helper (tshark backend) or `extract_hid_data.py` (scapy backend) and then feed the resulting text file to the decoder or replay modules to watch the keystrokes unfold.

### Stateful decoding matters

USB interrupt captures usually contain both the key press and one or more repeated copies of the same report before the release event arrives. A practical decoder should:

- emit only newly pressed keycodes compared to the previous report
- keep modifier state (`Shift`, `Ctrl`, `AltGr`) from byte 0 or the parsed `usbhid.boot_report.keyboard.modifier` field
- track toggle keys such as `Caps Lock`, because uppercase output is not controlled by Shift alone
- remember that HID usage IDs are layout-agnostic: `0x1d` is the physical `z`/`y` key position depending on the host keyboard layout

## Quick Python decoder

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

Feed it with the plain hex lines dumped earlier to get an instant rough reconstruction without pulling a full parser into the environment. For non-US layouts this still reconstructs the physical key position, not necessarily the final glyph shown on the victim host.

## Troubleshooting tips

- If Wireshark does not populate `usbhid.*` fields, the HID report descriptor was probably not captured. Replug the keyboard while capturing or fall back to raw `usb.capdata`.
- On Linux software captures, `usbmon` is the normal source; on Windows, Wireshark depends on the **USBPcap** extcap to see raw USB URBs at all.
- If the keyboard was attached through a hub or dock, confirm the interface descriptor first and then decode only that device/interface pair. Composite HID captures frequently mix keyboard and mouse reports.
- Windows captures require the **USBPcap** extcap interface; make sure it survived Wireshark upgrades, as missing extcaps leave you with empty device lists.
- Always correlate `usb.bus_id:device:interface` (e.g. `1.9.1`) before decoding anything — mixing multiple keyboards or storage devices leads to nonsense keystrokes.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
