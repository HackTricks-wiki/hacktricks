# USB キーストローク

{{#include ../../../banners/hacktricks-training.md}}

次のようなキーボードの USB 通信を含む pcap がある場合：

![](<../../../images/image (962).png>)

USB キーボードは通常 HID **boot protocol** を使用するため、ホストへの各割り込み転送は 8 バイトだけです：1 バイトの modifier ビット（Ctrl/Shift/Alt/Super）、1 バイトの予約領域、そして各レポートあたり最大 6 つの keycode。これらのバイトをデコードすれば、入力された内容をすべて復元できます。

## USB HID レポートの基本

典型的な IN レポートは次のようになります：

| Byte | 意味 |
| --- | --- |
| 0 | Modifier ビットマップ（`0x02` = Left Shift、`0x20` = Right Alt、など）。複数のビットが同時に設定されることがあります。 |
| 1 | 予約/パディング。ただしゲーミングキーボードではベンダーデータに再利用されることが多い。 |
| 2-7 | USB usage ID 形式の同時最大 6 つのキーコード（`0x04 = a`、`0x1E = 1`）。`0x00` は「キー無し」を意味します。 |

NKRO がないキーボードは、6 個以上のキーが押されたときに「rollover」を示すために通常 byte 2 に `0x01` を送ります。このレイアウトを理解しておくと、生の `usb.capdata` バイトしかない場合に役立ちます。

## PCAP から HID データを抽出する

### Wireshark ワークフロー

1. **デバイスを分離する**: キーボードからの interrupt IN トラフィックでフィルタリング、例: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`。
2. **有用な列を追加する**: `Leftover Capture Data` フィールド (`usb.capdata`) と好みの `usbhid.*` フィールド（例: `usbhid.boot_report.keyboard.keycode_1`）を右クリックして、毎フレームを開かずにキーストロークを追跡します。
3. **空のレポートを非表示にする**: アイドルフレームを除外するために `!(usb.capdata == 00:00:00:00:00:00:00:00)` を適用します。
4. **後処理のためにエクスポートする**: `File -> Export Packet Dissections -> As CSV`、`frame.number`、`usb.src`、`usb.capdata`、および `usbhid.modifiers` を含めて後で再構築をスクリプト化します。

### コマンドラインワークフロー

`ctf-usb-keyboard-parser` は古典的な tshark + sed パイプラインを既に自動化しています：
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
新しいキャプチャでは、デバイスごとにバッチ処理することで、`usb.capdata` とより詳細な `usbhid.data` フィールドの両方を保持できます:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
それらのデバイスごとのファイルはそのまま任意の decoder に投入できます。キャプチャが GATT 経由でトンネリングされた BLE キーボードからのものであれば、`btatt.value && frame.len == 20` でフィルタして、decoding の前に hex payloads をダンプしてください。

## デコードの自動化

- **ctf-usb-keyboard-parser** は短い CTF チャレンジに便利で、既にリポジトリに同梱されています。
- **CTF-Usb_Keyboard_Parser** (`main.py`) は `pcap` と `pcapng` ファイルをネイティブに解析し、`LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` を理解し、tshark を必要としないので、隔離されたサンドボックス内でもうまく動作します。
- **USB-HID-decoders** はキーボード、マウス、タブレットのビジュアライザを追加します。`extract_hid_data.sh` ヘルパー（tshark backend）または `extract_hid_data.py`（scapy backend）を実行して、生成されたテキストファイルを decoder または replay モジュールに渡すことで、キー入力の再生を確認できます。

## 簡易 Python デコーダ
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
以前ダンプしたプレーンな hex 行をこれに与えると、フルパーサーを環境に持ち込まずに即座に粗い再構築が得られます。

## トラブルシューティングのヒント

- If Wireshark does not populate `usbhid.*` fields, the HID report descriptor was probably not captured. Replug the keyboard while capturing or fall back to raw `usb.capdata`.
- Windows captures require the **USBPcap** extcap interface; make sure it survived Wireshark upgrades, as missing extcaps leave you with empty device lists.
- Always correlate `usb.bus_id:device:interface` (e.g. `1.9.1`) before decoding anything — mixing multiple keyboards or storage devices leads to nonsense keystrokes.

## References

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
