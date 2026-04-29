# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

以下のようなキーボードのUSB通信を含むpcapがある場合:

![](<../../../images/image (962).png>)

USBキーボードは通常 HID **boot protocol** を話すので、ホストへの各 interrupt transfer は常に 8 bytes です: 1 byte の modifier bits (Ctrl/Shift/Alt/Super)、1 byte の reserved、そして1 reportあたり最大6個の keycodes。これらの bytes をデコードすれば、入力された内容をすべて再構築できます。

## USB HID report basics

典型的な IN report は次のようになります:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). 複数の bit を同時に立てられます。 |
| 1 | Reserved/padding ですが、gaming keyboards では vendor data に再利用されることがよくあります。 |
| 2-7 | USB usage ID format の最大6個の同時 keycodes (`0x04 = a`, `0x1E = 1`)。`0x00` は "no key" を意味します。 |

NKRO のない keyboards は、6個を超えるキーが押されると byte 2 に `0x01` を送って "rollover" を示すことがあります。このレイアウトを理解しておくと、raw な `usb.capdata` bytes しかない場合でも役立ちます。

## Extracting HID data from a PCAP

### Identify the keyboard interface first

大きな capture では、どの report を dump する前でも、まず HID keyboard を特定してください。信頼できる出発点は interface descriptor response です:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
`usb.bInterfaceSubClass` と `usb.bInterfaceProtocol` を確認してください:

- `subclass == 1` かつ `protocol == 1` は通常 boot keyboard を意味します
- `protocol == 2` は通常 mouse です
- `protocol == 0` は、vendor-defined もしくは NKRO-style の HID interface を示すことが多く、keyboard データは含むものの、単純な 8-byte の boot layout ではありません

interface が分かったら、何かを export する前に `usb.bus_id`、`usb.device_address`、可能なら `usb.interface_number` に filter を絞ってください。

### Wireshark workflow

1. **Isolate the device**: keyboard からの interrupt IN traffic に filter をかけます。例: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Add useful columns**: `Leftover Capture Data` field (`usb.capdata`) と、好みの `usbhid.*` fields（例: `usbhid.boot_report.keyboard.keycode_1`）を右クリックして、各 frame を開かずに keystrokes を追跡します。
3. **Hide empty reports**: `!(usb.capdata == 00:00:00:00:00:00:00:00)` を適用して idle frames を除外します。
4. **Export for post-processing**: `File -> Export Packet Dissections -> As CSV` を使い、`frame.number`、`usb.src`、`usb.capdata`、`usbhid.modifiers` を含めて、後で reconstruction を script 化します。

### Command-line workflow

`ctf-usb-keyboard-parser` は、定番の tshark + sed pipeline をすでに自動化しています:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
新しいキャプチャでは、デバイスごとにまとめることで `usb.capdata` と、より詳細な `usbhid.data` フィールドの両方を保持できます:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Those per-device files drop straight into any decoder. If the capture came from BLE keyboards tunneled over GATT, filter on `btatt.value && frame.len == 20` and dump the hex payloads before decoding.

### When the report is not the classic 8-byte boot report

Recent gaming keyboards, split keyboards, and composite HID devices often expose a non-boot keyboard interface where the payload no longer matches `modifier,reserved,key1..key6`.

- `usbhid.data` を `usb.capdata` より優先してください。Wireshark がすでに HID レイヤを解析している場合はこちらが使えます。
- すべての行が固定プレフィックスまたは report ID で始まる場合は、byte 0 が常に modifier だと仮定せず、offset-aware decoder で取り除いてください。
- 一部の USBPcap export は reserved byte を省略するので、`--no-reserved` や custom offset をサポートする decoder を使うと時間を節約できます。
- capture 内に HID report descriptor や BLE HOGP report map がある場合は、parser を書く前にそれを使って実際の field layout を復元してください。

## Automating the decoding

- **ctf-usb-keyboard-parser** は、手早い CTF challenge で今でも便利で、repository にすでに入っています。
- **CTF-Usb_Keyboard_Parser** (`main.py`) は `pcap` と `pcapng` の両方をネイティブに解析し、`LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` を理解し、tshark を必要としないため、isolated sandbox 内でもうまく動作します。
- **USB-HID-decoders** は keyboard, mouse, tablet の visualizer を追加します。`extract_hid_data.sh` helper (tshark backend) または `extract_hid_data.py` (scapy backend) を実行してから、生成された text file を decoder か replay module に渡せば、keystrokes が展開される様子を確認できます。

### Stateful decoding matters

USB interrupt capture には通常、key press と、release event が来る前に同じ report が 1 回以上 repeated copy されたものの両方が含まれます。実用的な decoder は次を行うべきです:

- 前の report と比べて新しく押された keycode だけを出力する
- byte 0 または解析済みの `usbhid.boot_report.keyboard.modifier` field から modifier state (`Shift`, `Ctrl`, `AltGr`) を保持する
- `Caps Lock` のような toggle key を追跡する。大文字出力は Shift だけでは制御されないため
- HID usage ID は layout-agnostic であることを覚えておく: `0x1d` は host keyboard layout によって物理的な `z`/`y` key position を表す

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
平文の hex 行をそのまま与えれば、フル parser を環境に入れなくても、即座にざっくり再構成できます。US 以外のレイアウトでは、これは物理的なキー位置を再構成するだけで、victim host 上で最終的に表示された glyph とは限りません。

## Troubleshooting tips

- Wireshark が `usbhid.*` fields を埋めない場合、HID report descriptor が capture されていなかった可能性が高いです。capture 中に keyboard を再接続するか、raw `usb.capdata` に切り替えてください。
- Linux の software captures では、`usbmon` が通常の source です。Windows では、raw USB URBs を見るには Wireshark が **USBPcap** extcap に依存します。
- keyboard が hub や dock 経由で接続されていた場合は、まず interface descriptor を確認し、その device/interface pair だけを decode してください。Composite HID captures では、keyboard と mouse の reports が混在しがちです。
- Windows captures では **USBPcap** extcap interface が必要です。Wireshark の upgrade 後も残っていることを確認してください。extcap が見つからないと device list が空になります。
- 何かを decode する前に、必ず `usb.bus_id:device:interface`（例: `1.9.1`）を照合してください。複数の keyboard や storage devices を混ぜると、意味不明な keystrokes になります。

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
