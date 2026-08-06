# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

以下のように、keyboard の USB 経由の通信を含む pcap がある場合:

![USB Keystrokes: 以下のように、keyboard の USB 経由の通信を含む pcap がある場合](<../../../images/image (962).png>)

USB keyboard は通常 HID **boot protocol** を使用するため、host への各 interrupt transfer はわずか 8 バイトです。1 バイトの modifier bits（Ctrl/Shift/Alt/Super）、1 バイトの reserved byte、および report ごとに最大 6 個の keycode で構成されます。これらのバイトを decode するだけで、入力された内容をすべて再構築できます。

## USB HID report basics

典型的な IN report は次のようになります:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap（`0x02` = Left Shift、`0x20` = Right Alt など）。複数の bit を同時に設定できます。 |
| 1 | Reserved/padding ですが、gaming keyboard では vendor data 用に再利用されることがあります。 |
| 2-7 | USB usage ID format の最大 6 個の同時 keycode（`0x04` = `a`、`0x1E` = `1`）。`0x00` は「key なし」を意味します。 |

NKRO に対応していない keyboard は、6 個を超える key が押された場合、rollover を示すために通常 byte 2 に `0x01` を送信します。この layout を理解しておくと、raw の `usb.capdata` bytes しかない場合にも役立ちます。

## PCAP からの HID data の抽出

### まず keyboard interface を特定する

大量の通信を含む capture では、report を dump する前に HID keyboard を特定します。信頼できる開始点は interface descriptor response です:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
`usb.bInterfaceSubClass` と `usb.bInterfaceProtocol` を確認します。

- `subclass == 1` かつ `protocol == 1` は、通常 boot keyboard を意味します
- `protocol == 2` は、一般的に mouse です
- `protocol == 0` は、vendor-defined または NKRO-style の HID interface を意味することが多く、単純な 8-byte boot layout ではないものの、keyboard data を保持しています

interface が判明したら、何かを export する前に、フィルターを `usb.bus_id`、`usb.device_address`、可能であれば `usb.interface_number` に絞り込みます。

### Wireshark workflow

1. **デバイスを分離する**: keyboard からの interrupt IN traffic にフィルターを適用します。例: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`
2. **有用な列を追加する**: `Leftover Capture Data` field (`usb.capdata`) と、使用する `usbhid.*` fields（例: `usbhid.boot_report.keyboard.keycode_1`）を右クリックして、すべての frame を開かずに keystroke を追跡できるようにします。
3. **空の report を非表示にする**: `!(usb.capdata == 00:00:00:00:00:00:00:00)` を適用して idle frame を除外します。
4. **post-processing 用に export する**: `File -> Export Packet Dissections -> As CSV` を選択し、後で reconstruction を script 化できるように `frame.number`、`usb.src`、`usb.capdata`、`usbhid.modifiers` を含めます。

### Command-line workflow

`ctf-usb-keyboard-parser` は、従来の tshark + sed pipeline をすでに自動化しています:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
新しいキャプチャでは、デバイスごとにバッチ処理することで、`usb.capdata` と、より情報量の多い `usbhid.data` フィールドの両方を保持できます：
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
これらのデバイスごとのファイルは、そのまま任意の decoder に入力できます。キャプチャが GATT 経由でトンネリングされた BLE keyboards から取得された場合は、`btatt.value && frame.len == 20` でフィルタリングし、decoding の前に hex payloads をダンプしてください。

### レポートが従来の 8-byte boot report ではない場合

Recent gaming keyboards、split keyboards、composite HID devices では、payload が `modifier,reserved,key1..key6` と一致しない non-boot keyboard interface が公開されていることがよくあります。

- Wireshark がすでに HID layer を解析している場合は、`usb.capdata` よりも `usbhid.data` を優先します。
- すべての行が constant prefix または report ID で始まる場合は、byte 0 が常に modifier であると仮定せず、offset-aware decoder でそれを除去します。
- 一部の USBPcap exports では reserved byte が省略されるため、`--no-reserved` または custom offset をサポートする decoders を使うと時間を節約できます。
- HID report descriptor または BLE HOGP report map が capture に含まれている場合は、parser を作成する前にそれを使って実際の field layout を復元します。

## decoding の自動化

- **ctf-usb-keyboard-parser** は quick CTF challenges に引き続き便利で、すでに repository に含まれています。<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) は `pcap` と `pcapng` files の両方を native に parse し、`LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` を理解します。また tshark を必要としないため、isolated sandboxes 内で問題なく動作します。<sup>[[4]](#references)</sup>
- **USB-HID-decoders** は keyboard、mouse、tablet visualizers を追加します。`extract_hid_data.sh` helper（tshark backend）または `extract_hid_data.py`（scapy backend）を実行し、生成された text file を decoder または replay modules に渡して、keystrokes が展開される様子を確認できます。<sup>[[5]](#references)</sup>

### Stateful decoding が重要な理由

USB interrupt captures には通常、release event が到着するまで、key press と同じ report の repeated copies が 1 つ以上含まれています。実用的な decoder は次の処理を行う必要があります。<sup>[[2]](#references)</sup>

- previous report と比較して、新しく押された keycodes のみを emit する
- byte 0 または解析済みの `usbhid.boot_report.keyboard.modifier` field から modifier state（`Shift`、`Ctrl`、`AltGr`）を保持する
- `Caps Lock` などの toggle keys を追跡する。uppercase output は Shift だけでは制御されないためです
- HID usage IDs は layout-agnostic であることを覚えておく。`0x1d` は、host keyboard layout に応じて物理的な `z`/`y` key position を表します

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
先ほどダンプしたプレーンな hex 行を入力すると、環境に完全な parser を導入せずに、すぐに大まかな再構成を取得できます。US 配列以外のレイアウトでは、これは物理的なキー位置を再構成するものであり、victim host 上に表示される最終的な glyph とは必ずしも一致しません。

## Troubleshooting tips

- Wireshark に `usbhid.*` フィールドが表示されない場合、HID report descriptor がキャプチャされていない可能性があります。キャプチャ中にキーボードを再接続するか、raw `usb.capdata` にフォールバックしてください。
- Linux の software capture では `usbmon` が通常のソースです。Windows では、raw USB URB を確認するために Wireshark が **USBPcap** extcap に依存します。<sup>[[1]](#references)</sup>
- キーボードが hub または dock 経由で接続されている場合、まず interface descriptor を確認し、その後で対象の device/interface ペアのみを decode してください。Composite HID capture では、keyboard と mouse の report が頻繁に混在します。
- Windows の capture では **USBPcap** extcap interface が必要です。Wireshark の upgrade 後もそれが残っていることを確認してください。extcap がないと device list が空になります。<sup>[[1]](#references)</sup>
- decode を開始する前に、必ず `usb.bus_id:device:interface`（例: `1.9.1`）を照合してください。複数の keyboard や storage device を混在させると、意味のない keystroke になります。

## References

- [1] [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
