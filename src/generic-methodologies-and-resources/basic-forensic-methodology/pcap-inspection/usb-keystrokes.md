# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

If you have a pcap containing the communication via USB of a keyboard like the following one:

![USB Keystrokes: If you have a pcap containing the communication via USB of a keyboard like the following one](<../../../images/image (962).png>)

For a keyboard using the HID **boot protocol**, each Interrupt IN report has a fixed 8-byte layout: one modifier byte, one reserved byte, and six keycode bytes. The host compares successive reports and maps keycodes to HID usages to reconstruct key events.<sup>[[8]](#references)</sup>

## USB HID report basics

The standard boot keyboard input report is structured as follows.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, etc.). Multiple bits can be set simultaneously. |
| 1 | Reserved byte; unused reports should normally set it to zero. OEM or system-specific use is not portable. |
| 2-7 | Up to six concurrent keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` means "no key". | 

In the boot layout, usage ID `0x01` (`Keyboard ErrorRollOver`) is reported in all key slots when more than six non-modifier keys are pressed; it can also signal an unrecognizable combination.<sup>[[8]](#references)[[9]](#references)</sup> Understanding this layout helps when you only have the raw `usb.capdata` bytes.

## Extracting HID data from a PCAP

### Identify the keyboard interface first

On busy captures, identify the HID keyboard before dumping any reports. A reliable starting point is the interface descriptor response:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

The HID class defines these interface values:<sup>[[8]](#references)</sup>

- `subclass == 1` is the Boot Interface Subclass; with `protocol == 1` it identifies a boot keyboard
- `protocol == 2` identifies a boot mouse
- `protocol == 0` means no boot protocol; inspect the HID report descriptor instead of assuming an 8-byte layout

Once the interface is known, pin your filters to `usb.bus_id`, `usb.device_address`, and if possible `usb.bInterfaceNumber` before exporting anything.

### Wireshark workflow

1. **Isolate the device**: filter on interrupt IN traffic from the keyboard, e.g. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Add useful columns**: right-click the `Leftover Capture Data` field (`usb.capdata`) and your preferred `usbhid.*` fields (e.g. `usbhid.boot_report.keyboard.keycode_1`) to follow keystrokes without opening every frame.<sup>[[11]](#references)</sup>
3. **Hide empty reports**: apply `!(usb.capdata == 00:00:00:00:00:00:00:00)` to drop idle frames.
4. **Export for post-processing**: `File -> Export Packet Dissections -> As CSV`, include `frame.number`, `usb.src`, `usb.capdata`, and decoded modifier fields such as `usbhid.boot_report.keyboard.modifier.left_shift` and `usbhid.boot_report.keyboard.modifier.right_alt` to script the reconstruction later.<sup>[[10]](#references)[[11]](#references)</sup>

### Command-line workflow

The classic extraction pattern—dump `usb.capdata`, drop idle reports, and map usage IDs—appears in the original 2017 analysis and its walkthrough.<sup>[[1]](#references)[[2]](#references)</sup>

The `ctf-usb-keyboard-parser` repository automates the classic tshark + sed pipeline:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

On newer captures, prefer Wireshark's decoded `usbhid.data` field and fall back to `usb.capdata`; write one payload per report to a per-device file:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Those per-device files can be fed to a decoder after normalizing the hex format it expects. If the capture came from BLE keyboards tunneled over GATT, filter on `btatt.value && frame.len == 20` and dump the hex payloads before decoding.<sup>[[7]](#references)</sup>

### When the report is not the classic 8-byte boot report

A non-boot interface or a report ID can change the payload layout, so do not assume every keyboard report matches `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Prefer `usbhid.data` over `usb.capdata` when Wireshark has already parsed the HID layer.
- If every line starts with a constant prefix or report ID, strip it with an offset-aware decoder rather than assuming byte 0 is always the modifier.<sup>[[7]](#references)</sup>
- Some USBPcap exports omit the reserved byte, so decoders that support `--no-reserved` or a custom offset save time.<sup>[[7]](#references)</sup>
- If the HID report descriptor or BLE HOGP report map is present in the capture, use it to recover the actual field layout before writing a parser.

## Automating the decoding

- **ctf-usb-keyboard-parser** remains handy for quick CTF challenges and already ships in the repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) parses both `pcap` and `pcapng` files natively, understands `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, and does not require tshark or another external dependency, so it is suitable for isolated sandboxes.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** adds keyboard, mouse, and tablet visualizers. You can either run the `extract_hid_data.sh` helper (tshark backend) or `extract_hid_data.py` (scapy backend) and then feed the resulting text file to the decoder or replay modules to watch the keystrokes unfold.<sup>[[7]](#references)</sup>

### Stateful decoding matters

USB boot keyboards send reports at the idle rate even when there is no new key event, so captures may contain repeated reports before the release event. A practical decoder should:<sup>[[3]](#references)[[8]](#references)</sup>

- emit only newly pressed keycodes compared to the previous report
- keep modifier state (`Shift`, `Ctrl`, `AltGr`) from byte 0 or parsed fields such as `usbhid.boot_report.keyboard.modifier.left_shift` and `usbhid.boot_report.keyboard.modifier.right_alt`
- track toggle keys such as `Caps Lock`, because uppercase output is not controlled by Shift alone
- remember that HID usage IDs are layout-agnostic: `0x1d` is the physical `z`/`y` key position depending on the host keyboard layout.<sup>[[9]](#references)</sup>

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
- On Linux software captures, `usbmon` is the normal source; on Windows, Wireshark depends on the **USBPcap** extcap to see raw USB URBs at all.<sup>[[4]](#references)</sup>
- If the keyboard was attached through a hub or dock, confirm the interface descriptor first and then decode only that device/interface pair. Composite HID captures frequently mix keyboard and mouse reports.
- Windows captures require the **USBPcap** extcap interface; make sure it survived Wireshark upgrades, as missing extcaps leave you with empty device lists.<sup>[[4]](#references)</sup>
- Always correlate the bus, device, and interface tuple (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; e.g. `1.9.1`) before decoding anything — mixing multiple keyboards or storage devices leads to nonsense keystrokes.<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [USB Keyboard packet capture analysis](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Device Class Definition for Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)

{{#include ../../../banners/hacktricks-training.md}}
