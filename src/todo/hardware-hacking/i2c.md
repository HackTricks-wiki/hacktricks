# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Bus Pirateを接続する前に、対象の電圧、ピン配置、プルアップの構成、共通グラウンドを確認してください。スニッフィングだけを目的に、対象機器の電源が入ったバスでBus Pirateの電源を有効にしないでください。2つの電源が競合してハードウェアを損傷する可能性があります。以下のトランスクリプトは、特定のデバイスであるBus Pirate v3とコミュニティファームウェアの例であり、汎用的な配線手順ではありません。<sup>[[1]](#references)[[2]](#references)</sup>

Bus Pirateが動作しているかテストするには、+5VをVPUに、3.3VをADCに接続し、Bus Pirateにアクセスして（たとえばTera Termを使用）、コマンド`~`を実行します。

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

前のコマンドラインに表示されているように、エラーは0件でした。購入後やファームウェアの書き込み後に正常に動作しているか確認するうえで、これは非常に役立ちます。

Bus Pirateに接続するには、ドキュメントに従ってください。

![コマンドを使用 - スペースキーを押す: Bus Pirateに接続するには、ドキュメントに従ってください](<../../images/image (484).png>)

この場合、対象は24C256ファミリーのI²C EEPROMです。対応する電源電圧は部品によって異なるため、正確な型番の末尾とデータシートを確認してください。<sup>[[3]](#references)</sup>

![コマンドを使用 - スペースキーを押す: 今回はEPROMに接続します: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Bus Pirateと通信するため、Tera TermをBus PirateのCOMポートに接続し、Setup --> Serial Port --> Speedを115200に設定しました。\
以下の通信例では、Bus PirateをI2Cで通信できるように準備し、メモリに書き込み、読み取る方法を確認できます（コメントは「#」を使って記載しています。通信例には含まれていないので注意してください）:

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Sniffer

このシナリオでは、arduino と先ほどの EPROM 間の I2C 通信をスニッフィングします。両方のデバイスを通信させてから、bus pirate を SCL、SDA、GND ピンに接続するだけです。

![事前に設定したアドレス 0x69 から 20B を読み取る - Sniffer: このシナリオでは、arduino と先ほどの EPROM 間の I2C 通信をスニッフィングします。両方のデバイスを通信させてから、bus pirate を SCL、SDA、GND ピンに接続するだけです。](<../../images/image (166).png>)

```bash
I2C>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## ブラックボックス I2C プロトコルの再構築

### 稼働中のピンからバスを特定する

ペリフェラルのピン配置やデータシートがない場合は、まず元のホストが動作している状態で、高インピーダンスのロジックアナライザーを使って受動的に観測します。共通のグラウンドと安全なロジックレベルを確認したら、常に一定のピンを電源、グラウンド、またはプルアップされた信号線の候補として分類し、動作中のラインを一般的なバスと比較します。UARTは非同期で、TX/RXの方向がそれぞれ独立しています。一般的なSPIには通常、クロック、チップセレクト、方向ごとに分かれたデータ線があります。I2Cには規則的なクロックと、双方向のデータ線が1本あります。I2Cデコードにより、7ビットのターゲットアドレス、読み書きの方向、ACK/NACK、繰り返し現れるペイロードが確認できるはずです。<sup>[[2]](#references)[[4]](#references)</sup>

正規の通信を複数回キャプチャし、デコードしたバイト列と生のタイミング情報の両方を保存します。繰り返されるフレームは、後でシリアライザーを検証するための既知の正解テストに役立ちます。また、リクエスト間の変化から、オペコード、インデックス、オフセット、長さ、シーケンス番号、チェックサムなどのフィールドを推定できる場合があります。<sup>[[4]](#references)</sup>

### ホストファームウェアからフレーミングを特定する

ペリフェラルのファームウェアにアクセスできない場合は、**ホスト**のファームウェアを抽出し、I2Cデバイスを開くコンポーネントを探します。ペリフェラル名、`/dev/i2c-`、コマンドビルダー、レスポンスパーサー、リセット／初期化ルーチン、チェックサム関数をキーワードに、文字列やシンボルを検索します。各ビルダーについて、関数名から形式を推測するのではなく、フィールドの正確なオフセット、定数、受け付ける引数サイズ、ペイロード長、チェックサムの対象範囲、チェックサムのバイト順、返されるフレーム長を記録します。<sup>[[4]](#references)</sup>

`crc16_ccitt`という名前のチェックサム関数だけでは、使用するプリセットを特定できません。シフト方向、テーブルインデックスに使うバイト、テーブルが表す多項式、初期レジスター値、入力／出力のビット反転、最終XOR／反転、そしてシリアライザーのワイヤ上のエンディアンを特定してください。たとえば、反転多項式`0x8408`を基にした右シフトの下位バイトテーブルを使い、`0xFFFF`で初期化して最後に補数を取る方式は、**CRC-16/X-25 (IBM-SDLC)**を示します。整合性検証を通過してコマンドパーサーまでテストケースを進めるには、正しいチェックサムが必要になることがよくあります。<sup>[[4]](#references)</sup>

形式を再構築したら、特徴的なシンボル名や定数を公開コードから検索します。MJA1のケースでは、別途見つかったSDKラッパーによって、コマンドID、引数の検証、レスポンス定義、同じ方式のCRC実装を確認できました。このようなソースは検証に使い、対象バイナリや実際に送受信されるバイト順を確認する作業の代わりにしないでください。<sup>[[4]](#references)[[5]](#references)</sup>

### root化されたLinuxホストからフレームを送信する

侵害された組み込みLinuxホストを使えば、別のバスコントローラーを追加せずにペリフェラルを操作できます。該当するアダプターを開き、`I2C_SLAVE`で7ビットアドレスを選択し、専用シリアライザーで生成したフレームを送信します。ミューテーションやファジングに使えるよう、生フレームモードも用意しておきます。<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

ターゲット CPU および libc と互換性のある toolchain でクロスコンパイルし、test client の analyzer trace を正規の通信と比較します。目に見えるバイト列が一致していても、トランザクションの境界、書き込みと読み取りの順序、遅延、周辺機器の状態が重要な場合があります。<sup>[[4]](#references)</sup>

### 応答を手がかりにした opcode 列挙

最短の有効なフレームと checksum が判明したら、opcode の全ビット幅を列挙し、プロトコルで明示された **unsupported-command** 応答を負のベースラインとして使います。無効な引数、無効な状態、未文書化のステータスなど、異なる結果が返る場合は、デコードが実装済み、または部分的に実装されたハンドラーに到達したことを示唆します。ただし、これは exploitability の証明にはなりません。候補を優先し、長さ、引数、状態、コマンドシーケンスを構造化して fuzzing してください。<sup>[[4]](#references)</sup>

テストによって周辺機器が応答しなくなった場合は、外部コントローラーから、起動ごとに分離したテストを1件ずつ自動実行します。SSH で接続してテストを実行し、生のリクエスト／レスポンスとタイミングを保存したうえで、再起動または電源を入れ直し、ヘルスチェックの回復を待ってから続行します。後でコンポーネントをマイクロコントローラー制御のテスト治具に移せば、決定論的なリセット、直接的な電源制御、より高速な fuzzing が可能になります。<sup>[[4]](#references)</sup>

## References

- [1] [Bus Pirate ドキュメント — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-bus 仕様およびユーザーマニュアル](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C シリアル EEPROM データシート](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — ブラックボックスプロービング：Xiaomi MJA1 セキュアチップのセキュリティ分析](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK MJA1 暗号化ラッパー](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
