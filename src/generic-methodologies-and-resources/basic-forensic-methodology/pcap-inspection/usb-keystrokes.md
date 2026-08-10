# USB Keystrokes

以下のようなキーボードの USB 経由の通信を含む pcap がある場合:

![USB Keystrokes: 以下のようなキーボードの USB 経由の通信を含む pcap がある場合](<../../../images/image (962).png>)

**boot protocol** を使用するキーボードでは、各 Interrupt IN report は固定の 8 バイトレイアウトになっています。1 バイトの modifier、1 バイトの reserved、6 バイトの keycode です。host は連続する report を比較し、keycode を HID usage にマッピングして key event を再構成します。<sup>[[8]](#references)</sup>

## USB HID report の基本

標準の boot keyboard input report は以下のように構成されています。<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap（`0x02` = Left Shift、`0x20` = Right Shift、`0x40` = Right Alt など）。複数の bit を同時に設定できます。 |
| 1 | Reserved byte。未使用の report では通常、ゼロに設定します。OEM または system-specific な用途は portable ではありません。 |
| 2-7 | USB usage ID 形式の最大 6 個の同時 keycode（`0x04` = a、`0x1E` = 1）。`0x00` は「key なし」を意味します。 |

boot layout では、6 個を超える non-modifier key が押されている場合、usage ID `0x01`（`Keyboard ErrorRollOver`）がすべての key slot で report されます。また、認識できない組み合わせを示す場合もあります。<sup>[[8]](#references)[[9]](#references)</sup> この layout を理解しておくと、raw の `usb.capdata` bytes しかない場合に役立ちます。

## PCAP からの HID data の抽出

### 最初に keyboard interface を特定する

busy な capture では、report を dump する前に HID keyboard を特定します。信頼できる開始点は interface descriptor response です。<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
HID class は、以下の interface 値を定義します。<sup>[[8]](#references)</sup>

- `subclass == 1` は Boot Interface Subclass です。`protocol == 1` と組み合わせると、boot keyboard を識別します
- `protocol == 2` は boot mouse を識別します
- `protocol == 0` は boot protocol がないことを意味します。8 バイトのレイアウトを前提にせず、HID report descriptor を調べてください

interface が判明したら、何かを export する前に、フィルターを `usb.bus_id`、`usb.device_address`、可能であれば `usb.bInterfaceNumber` に固定してください。

### Wireshark workflow

1. **デバイスを分離する**: keyboard からの interrupt IN トラフィックに対して、例として `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3` でフィルターします。
2. **有用な列を追加する**: `Leftover Capture Data` フィールド（`usb.capdata`）と、任意の `usbhid.*` フィールド（例: `usbhid.boot_report.keyboard.keycode_1`）を右クリックして列に追加し、すべての frame を開かずに keystroke を追跡できるようにします。<sup>[[11]](#references)</sup>
3. **空の report を非表示にする**: `!(usb.capdata == 00:00:00:00:00:00:00:00)` を適用して、idle frame を除外します。
4. **post-processing 用に export する**: `File -> Export Packet Dissections -> As CSV` を選択し、`frame.number`、`usb.src`、`usb.capdata`、および `usbhid.boot_report.keyboard.modifier.left_shift` や `usbhid.boot_report.keyboard.modifier.right_alt` などの decoded modifier フィールドを含めます。後で script を使って再構築できます。<sup>[[10]](#references)[[11]](#references)</sup>

### Command-line workflow

`usb.capdata` を dump し、idle report を削除して usage ID をマッピングするという classic な extraction pattern は、2017 年の original analysis とその walkthrough に記載されています。<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser` repository は、classic な tshark + sed pipeline を自動化します。<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
新しいキャプチャでは、Wireshark のデコード済み `usbhid.data` フィールドを優先し、利用できない場合は `usb.capdata` にフォールバックします。レポートごとに 1 つの payload をデバイスごとのファイルに書き込みます。<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
これらのデバイスごとのファイルは、想定される hex format に正規化した後、decoder に渡せます。キャプチャが GATT 経由でトンネリングされた BLE keyboards から取得された場合は、`btatt.value && frame.len == 20` で filter し、decoding 前に hex payloads を dump します。<sup>[[7]](#references)</sup>

### レポートが classic 8-byte boot report ではない場合

non-boot interface や report ID によって payload layout が変わる可能性があるため、すべての keyboard report が `modifier,reserved,key1..key6` に一致すると仮定しないでください。<sup>[[8]](#references)[[11]](#references)</sup>

- Wireshark がすでに HID layer を parse している場合は、`usb.capdata` よりも `usbhid.data` を優先します。
- すべての行が constant prefix または report ID で始まる場合は、byte 0 が常に modifier だと仮定せず、offset-aware decoder で strip します。<sup>[[7]](#references)</sup>
- 一部の USBPcap exports では reserved byte が省略されるため、`--no-reserved` または custom offset に対応した decoders を使うと時間を節約できます。<sup>[[7]](#references)</sup>
- HID report descriptor または BLE HOGP report map が capture に含まれている場合は、parser を作成する前にそれを使って実際の field layout を復元します。

## decoding の自動化

- **ctf-usb-keyboard-parser** は、簡単な CTF challenges に引き続き便利で、すでに repository に含まれています。<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) は `pcap` と `pcapng` files の両方を native に parse し、`LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` を理解します。また、tshark やその他の external dependency を必要としないため、isolated sandboxes に適しています。<sup>[[6]](#references)</sup>
- **USB-HID-decoders** は keyboard、mouse、tablet の visualizers を追加します。`extract_hid_data.sh` helper（tshark backend）または `extract_hid_data.py`（scapy backend）を実行し、生成された text file を decoder または replay modules に渡して、keystrokes が展開される様子を確認できます。<sup>[[7]](#references)</sup>

### Stateful decoding が重要な理由

USB boot keyboards は、新しい key event がない場合でも idle rate で reports を送信するため、capture には release event の前に同じ reports が繰り返し含まれることがあります。実用的な decoder は次の処理を行う必要があります。<sup>[[3]](#references)[[8]](#references)</sup>

- 前回の report と比較し、新しく押された keycodes のみを出力する
- byte 0、または `usbhid.boot_report.keyboard.modifier.left_shift` や `usbhid.boot_report.keyboard.modifier.right_alt` などの parsed fields から modifier state（`Shift`、`Ctrl`、`AltGr`）を保持する
- `Caps Lock` などの toggle keys を追跡する。uppercase output は Shift だけでは制御されないためです
- HID usage IDs は layout-agnostic であることに注意する。`0x1d` は、host keyboard layout に応じて物理的な `z`/`y` key position を表します。<sup>[[9]](#references)</sup>

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
先ほどダンプしたプレーンな hex 行を入力すると、環境に完全な parser を取り込むことなく、すぐに大まかな再構成を取得できます。US 以外のレイアウトでは、これは被害者ホスト上で最終的に表示される glyph とは限らず、物理的なキー位置を再構成します。

## Troubleshooting tips

- Wireshark に `usbhid.*` フィールドが生成されない場合、HID report descriptor がキャプチャされていない可能性があります。キャプチャ中にキーボードを抜き差しするか、raw の `usb.capdata` にフォールバックしてください。
- Linux の software capture では `usbmon` が通常のソースです。Windows では、raw USB URB を確認するために Wireshark が **USBPcap** extcap に依存します。<sup>[[4]](#references)</sup>
- キーボードが hub または dock 経由で接続されていた場合は、まず interface descriptor を確認し、その後、その device/interface ペアだけを decode してください。Composite HID capture では、keyboard と mouse の report が混在することがよくあります。
- Windows の capture には **USBPcap** extcap interface が必要です。Wireshark の upgrade 後もそれが残っていることを確認してください。extcap がないと device list が空になります。<sup>[[4]](#references)</sup>
- 何かを decode する前に、必ず bus、device、interface の tuple（`usb.bus_id`、`usb.device_address`、`usb.bInterfaceNumber`、例：`1.9.1`）を照合してください — 複数の keyboard や storage device を混在させると、意味のない keystroke になります。<sup>[[10]](#references)</sup>

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
