# USBキーストローク

{{#include ../../../banners/hacktricks-training.md}}

次のような、キーボードのUSB通信を含むpcapがある場合:

![USBキーストローク: 次のような、キーボードのUSB通信を含むpcapがある場合](<../../../images/image (962).png>)

HID **boot protocol**を使用するキーボードでは、各Interrupt INレポートは固定の8バイト構成です。1バイト目は修飾キー、2バイト目は予約済み、残りの6バイトはキーコードです。ホストは連続するレポートを比較し、キーコードをHID usageに対応付けてキーイベントを再構成します。<sup>[[8]](#references)</sup>

一般的なキャプチャの初期調査については、[Pcap Inspection](./)を参照してください。

## USB HIDレポートの基本

標準的なboot keyboard入力レポートは、次のような構成です。<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | 意味 |
| --- | --- |
| 0 | 修飾キーのビットマップ（`0x02` = 左Shift、`0x20` = 右Shift、`0x40` = 右Altなど）。複数のビットを同時に設定できます。 |
| 1 | 予約済みバイト。未使用のレポートでは通常、ゼロに設定します。OEMまたはシステム固有の用途には互換性がありません。 |
| 2-7 | USB usage ID形式のキーコードを最大6個まで格納します（`0x04 = a`、`0x1E = 1`）。`0x00`は「キーなし」を意味します。 | 

bootレイアウトでは、修飾キー以外のキーが6個を超えて押されると、すべてのキー用スロットにusage ID `0x01`（`Keyboard ErrorRollOver`）が報告されます。また、認識できない組み合わせを示す場合もあります。<sup>[[8]](#references)[[9]](#references)</sup> このレイアウトを理解しておくと、生の`usb.capdata`バイトしかない場合にも役立ちます。

## PCAPからのHIDデータの抽出

### 最初にキーボードインターフェースを特定する

通信量の多いキャプチャでは、レポートをダンプする前にHIDキーボードを特定してください。信頼できる出発点は、インターフェースディスクリプターの応答です。<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

HID class は次のインターフェース値を定義します:<sup>[[8]](#references)</sup>

- `subclass == 1` は Boot Interface Subclass です。`protocol == 1` の場合、ブートキーボードを示します
- `protocol == 2` はブートマウスを示します
- `protocol == 0` はブートプロトコルなしを意味します。8バイトのレイアウトだと決めつけず、HID report descriptor を調べてください

ブート対応インターフェースがあっても、**ブートプロトコルが有効である証拠にはなりません**。HID デバイスは report protocol で初期化されます。ホストは `SET_PROTOCOL` (`bRequest = 0x0b`、`wValue = 0`) でブートモードを選択します。`wValue = 1` は report protocol を選択します。キャプチャに列挙処理が含まれている場合、8バイトのブートデコーダーを使う前に、キーボードインターフェースのリクエスト（`wIndex`）を確認してください。含まれていない場合は、インターフェース記述子からモードを推測せず、観測されたレポートレイアウトを確認してください。<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

インターフェースが判明したら、何かをエクスポートする前に、`usb.bus_id`、`usb.device_address`、可能であれば`usb.bInterfaceNumber`でフィルターを絞り込みます。

### Wiresharkでのワークフロー

1. **デバイスを分離する**: キーボードからのinterrupt INトラフィックをフィルターします。例: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`。
2. **便利な列を追加する**: `Leftover Capture Data`フィールド（`usb.capdata`）や、好みの`usbhid.*`フィールド（例: `usbhid.boot_report.keyboard.keycode_1`）を右クリックして列に追加すると、すべてのフレームを開かずにキーストロークを追跡できます。<sup>[[11]](#references)</sup>
3. **空のレポートを非表示にする**: `!(usb.capdata == 00:00:00:00:00:00:00:00)`を適用し、アイドルフレームを除外します。
4. **後処理用にエクスポートする**: `File -> Export Packet Dissections -> As CSV`を選択し、`frame.number`、`usb.src`、`usb.capdata`、および`usbhid.boot_report.keyboard.modifier.left_shift`や`usbhid.boot_report.keyboard.modifier.right_alt`などのデコード済み修飾キーのフィールドを含めます。後でスクリプトを使って再構成できます。<sup>[[10]](#references)[[11]](#references)</sup>

### コマンドラインでのワークフロー

`usb.capdata`をダンプし、アイドルレポートを除外して、Usage IDをマッピングする古典的な抽出手法は、2017年の元の分析とそのウォークスルーで紹介されています。<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser`リポジトリは、古典的なtshark + sedのパイプラインを自動化します。<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

新しいキャプチャでは、Wiresharkでデコードされた `usbhid.data` フィールドを優先し、使用できない場合は `usb.capdata` を使います。レポートごとに1つのペイロードをデバイスごとのファイルに書き込みます:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

デバイスごとのファイルは、デコーダーが想定する形式に合わせて16進数形式を正規化した後、デコーダーに渡せます。キャプチャがGATT経由でトンネリングされたBLEキーボードからのものなら、`btatt.value && frame.len == 20`でフィルタリングし、デコード前に16進数のペイロードをダンプしてください。<sup>[[7]](#references)</sup>

### レポートが一般的な8バイトのboot reportではない場合

非bootインターフェースやReport IDによってペイロードのレイアウトが変わることがあるため、すべてのキーボードレポートが`modifier,reserved,key1..key6`に一致するとは限りません。<sup>[[8]](#references)[[11]](#references)</sup>

- WiresharkがすでにHIDレイヤーを解析している場合は、`usb.capdata`より`usbhid.data`を優先してください。
- 各行が一定のプレフィックスまたはReport IDで始まる場合は、常にバイト0がmodifierだと仮定せず、オフセットに対応したデコーダーで取り除いてください。<sup>[[7]](#references)</sup>
- USBPcapのエクスポートによってはreservedバイトが省略されているため、`--no-reserved`に対応したデコーダーやカスタムオフセットを使うと時間を節約できます。<sup>[[7]](#references)</sup>
- キャプチャにHID report descriptorまたはBLE HOGP report mapが含まれている場合は、パーサーを作成する前にそれを使って実際のフィールドレイアウトを特定してください。

### report-protocolのキーbitmapをデコードする

入力レポートが6つのbootキーslotではなくbitmapであるキーボードの場合、enumerationトラフィック内で**HID report descriptor**を見つけてください。このフィルターは、WiresharkがReport Sizeアイテムをデコードしたフレームを検出します。フレームを開き、descriptor全体を確認してください。descriptorが見つからない場合は、キーボードを接続する前に新しいキャプチャを開始してください。<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

各キーボード Input レポートについて、`Report ID`（存在する場合）、`Usage Page`（キーボードキーは `0x07`）、`Usage Minimum/Maximum`、`Report Size`、`Report Count`、および各 `Input` 項目が **Variable** か **Array** かを確認します。キー項目のビットオフセットを求めるには、それ以前のすべての Input フィールドと定数パディングを数えます。レポートフィールドはバイト境界に揃っているとは限りません。連続するキーボードの Usage を持つ1ビットの Variable フィールドは、キー状態ビットマップです。このフィールドのビット0は最初に宣言された Usage に、ビット1は次の Usage に対応します。一方、Array には、押されたキーごとに1つのビットが格納されるのではなく、ディスクリプターの Usage 範囲を使って解決する値が格納されます。Report ID が宣言されている場合は、まずそのプレフィックスを持つレポートを選び、フィールドオフセットを計算するときはそのバイトをスキップします。新しいキー押下だけを出力するには、同じインターフェースかつ同じ Report ID の連続するレポート間で、押下中の Usage の集合を比較します。<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## デコードの自動化

- **ctf-usb-keyboard-parser** は、手早く CTF に取り組む際に今も便利で、リポジトリに同梱されています。<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser**（`main.py`）は `pcap` と `pcapng` の両ファイルをネイティブに解析し、`LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` に対応しています。また、tshark などの外部依存関係が不要なため、隔離されたサンドボックスに適しています。<sup>[[6]](#references)</sup>
- **USB-HID-decoders** は、キーボード、マウス、タブレットのビジュアライザーを追加します。`extract_hid_data.sh` ヘルパー（tshark バックエンド）または `extract_hid_data.py`（scapy バックエンド）を実行し、生成されたテキストファイルをデコーダーまたはリプレイモジュールに渡して、キー入力を再現できます。<sup>[[7]](#references)</sup>

### 状態を考慮したデコードが重要

USB boot keyboard は、新しいキーイベントがない場合もアイドルレートでレポートを送信するため、キャプチャにはキーが離される前の同一レポートが複数含まれることがあります。実用的なデコーダーでは、次の処理が必要です。<sup>[[3]](#references)[[8]](#references)</sup>

- 前のレポートと比較し、新しく押されたキーコードだけを出力する
- バイト0、または `usbhid.boot_report.keyboard.modifier.left_shift` や `usbhid.boot_report.keyboard.modifier.right_alt` などの解析済みフィールドから、修飾キーの状態（`Shift`、`Ctrl`、`AltGr`）を保持する
- 大文字の出力は `Shift` だけで決まるわけではないため、`Caps Lock` などのトグルキーの状態を追跡する
- HID Usage ID はキーボードレイアウトに依存しないことに留意する。`0x1d` は、ホストのキーボードレイアウトによって物理的な `z`/`y` キーの位置を示します。<sup>[[9]](#references)</sup>

## 簡易 Python デコーダー

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

先ほどダンプしたプレーンな16進数の行を入力すれば、環境にフルパーサーを導入せずに、すぐに大まかな再構成結果を得られます。US以外のレイアウトでは、被害者ホスト上で最終的に表示される文字ではなく、物理キーの位置が再構成されます。

## トラブルシューティングのヒント

- Wiresharkに`usbhid.*`フィールドが表示されない場合、HID report descriptorがキャプチャされていない可能性があります。キャプチャ中にキーボードを再接続するか、`usb.capdata`の生データにフォールバックしてください。
- Linuxでソフトウェアキャプチャする場合は、通常`usbmon`を使用します。Windowsで生のUSB URBを確認するには、Wiresharkが**USBPcap** extcapに依存します。<sup>[[4]](#references)</sup>
- キーボードがハブまたはドック経由で接続されていた場合は、まずinterface descriptorを確認し、その後、そのデバイス/interfaceの組み合わせだけをデコードしてください。Composite HIDのキャプチャでは、キーボードとマウスのレポートが混在することがよくあります。
- Windowsでのキャプチャには**USBPcap** extcapインターフェースが必要です。Wiresharkのアップグレード後も利用できることを確認してください。extcapが欠けていると、デバイス一覧が空になります。<sup>[[4]](#references)</sup>
- デコードする前に、必ずバス、デバイス、interfaceの組み合わせ（`usb.bus_id`、`usb.device_address`、`usb.bInterfaceNumber`。例：`1.9.1`）を照合してください。複数のキーボードやストレージデバイスを混同すると、意味不明なキー入力になります。<sup>[[10]](#references)</sup>



## References

- [1] [HackIT CTF 2017 解説: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [USB Keyboardパケットキャプチャの解析](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1、2の解説](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [WiresharkのUSBキャプチャ設定](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [ヒューマンインターフェースデバイス（HID）のデバイスクラス定義 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Linux kernel: HID report descriptor入門](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: ordinary-keyboardの解説](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
