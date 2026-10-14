# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Bus Pirateを接続する前に、ターゲットの電圧、ピン配列、プルアップの構成、共通グラウンドを確認してください。動作中でターゲットから給電されているバスをスニッフィングするためだけにBus Pirateの電源を有効にしないでください。2つの電源が競合し、ハードウェアを損傷するおそれがあります。以下のログは、特定のデバイスであるBus Pirate v3とコミュニティファームウェアを使った例であり、汎用的な配線手順ではありません。<sup>[[1]](#references)[[2]](#references)</sup>

Bus Pirateが動作しているかテストするには、+5VをVPUに、3.3VをADCに接続して、Bus Pirateにアクセスし（たとえばTera Termを使用）、コマンド`~`を入力します：

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

前のコマンドラインに表示されているとおり、エラーは0件でした。購入後やファームウェアを書き込んだ後に、正常に動作していることを確認するのにとても役立ちます。

Bus Pirateに接続するには、ドキュメントに従ってください。

![コマンドを使用 - スペースを押す: Bus Pirateに接続するには、ドキュメントに従ってください](<../../images/image (484).png>)

この場合、ターゲットは24C256ファミリーのI²C EEPROMです。対応する電源電圧は部品によって異なるため、正確な型番の末尾とデータシートを確認してください。<sup>[[3]](#references)</sup>

![コマンドを使用 - スペースを押す: この場合、EPROM（ATMEL901 24C256 PU27）に接続します](<../../images/image (964).png>)

Bus Pirateと通信するために、Tera Termを使い、Bus PirateのCOMポートに接続して、Setup --> Serial Port --> Speedを115200に設定しました。\
以下の通信例では、I2Cで通信するためのBus Pirateの準備方法と、メモリへの書き込みおよび読み取り方法を確認できます（コメントには「#」を使用しています。通信内容にこの部分が含まれるとは限りません）:

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

このシナリオでは、arduino と先ほどの EPROM 間の I2C 通信を Sniffer します。両方のデバイスを通信させ、bus pirate を SCL、SDA、GND ピンに接続するだけです。

![事前に設定したアドレス 0x69 から 20B を読み取る - Sniffer: このシナリオでは、arduino と先ほどの EPROM 間の I2C 通信を Sniffer します。両方のデバイスを通信させ、bus pirate を接続するだけです...](<../../images/image (166).png>)

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

周辺機器にピン配置図やデータシートがない場合は、元のホストが動作している間に、高インピーダンスのロジックアナライザーで受動的に調べることから始めます。共通のグラウンドと安全なロジックレベルを確認したら、一定の状態にあるピンを電源、グラウンド、またはプルアップされた信号の候補として分類し、アクティブなラインを一般的なバスと比較します。UART は非同期で送受信方向が独立しています。一般的な SPI では通常、クロック、チップセレクト、独立したデータ方向が確認できます。I2C には規則的なクロックと双方向データラインが 1 本あります。次に I2C デコードを行うと、7 ビットのターゲットアドレス、読み書き方向、ACK/NACK、繰り返されるペイロードが明らかになります。<sup>[[2]](#references)[[4]](#references)</sup>

正規のやり取りを複数回キャプチャし、デコードしたバイト列と生のタイミング情報の両方を保存します。繰り返されるフレームは、後でシリアライザーを検証するための既知解テストとして役立ちます。また、リクエスト間の変化から、オペコード、インデックス、オフセット、長さ、シーケンス、チェックサムと思われるフィールドを特定できる場合があります。<sup>[[4]](#references)</sup>

### ホストファームウェアからフレーミングを特定する

周辺機器のファームウェアにアクセスできない場合は、**ホスト**ファームウェアを抽出し、I2C デバイスを開くコンポーネントを探します。周辺機器の名前、`/dev/i2c-`、コマンドビルダー、レスポンスパーサー、リセット／初期化ルーチン、チェックサム関数を、文字列やシンボルから検索します。各ビルダーについて、関数名から形式を推測するのではなく、正確なフィールドオフセット、定数、受け付ける引数サイズ、ペイロード長、チェックサムの対象範囲、チェックサムのバイト順、返されるフレーム長を記録します。<sup>[[4]](#references)</sup>

`crc16_ccitt`という名前のチェックサム関数だけでは、使用するプリセットを決められません。シフト方向、テーブルのインデックスとなるバイト、テーブルで表される多項式、初期レジスター、入力／出力のビット反転、最終 XOR／反転、シリアライザーのワイヤー上のエンディアンを確認します。たとえば、反転多項式`0x8408`を基にした右シフトの下位バイトテーブルを使用し、`0xFFFF`で初期化して最後に反転する場合、**CRC-16/X-25 (IBM-SDLC)**だと特定できます。整合性検証を通過してコマンドパーサーに到達するテストケースを作るには、正しいチェックサムが必要になることがよくあります。<sup>[[4]](#references)</sup>

形式を再構築したら、特徴的なシンボル名や定数を公開コードから検索します。MJA1 のケースでは、別途見つかった SDK ラッパーにより、コマンド ID、引数の検証、レスポンス定義、ミラーされた CRC 実装が確認できました。このようなソースコードは検証に使い、対象バイナリーとワイヤー上のバイト順を実際に確認する作業の代わりにしないでください。<sup>[[4]](#references)[[5]](#references)</sup>

### root 化された Linux ホストからフレームを送信する

侵害された組み込み Linux ホストを使えば、別のバスコントローラーを追加せずに周辺機器を操作できます。対象のアダプターを開き、`I2C_SLAVE`で 7 ビットアドレスを選択し、専用シリアライザーで生成したフレームを送信します。変更やファジング用に、生フレームモードも保持します。<sup>[[4]](#references)</sup>

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

ターゲット CPU および libc と互換性のある toolchain を使ってクロスコンパイルし、test client の analyzer trace と正規の通信を比較します。可視バイト列が一致していても、トランザクション境界、書き込み／読み取りの順序、遅延、周辺機器の状態が重要な場合があります。<sup>[[4]](#references)</sup>

### 応答を手がかりにした opcode の列挙

最短の有効なフレームと checksum が判明したら、opcode の全幅を列挙し、プロトコルで明示されている **unsupported-command** 応答をネガティブベースラインとして使います。引数無効、状態無効、または文書化されていないステータスなど、異なる結果が返る場合は、デコード処理が実装済みまたは部分的に実装されたハンドラーに到達したことが示唆されます。これは exploitability を示すものではありません。候補を優先し、長さ、引数、状態、コマンドシーケンスを体系的に fuzzing してください。<sup>[[4]](#references)</sup>

テストによって周辺機器がハングする場合は、外部コントローラーから、起動ごとに独立したケースを1つだけ自動実行します。SSH で接続し、ケースを実行して、生のリクエスト／レスポンスとタイミングを保存し、再起動または電源を入れ直します。ヘルスチェックの回復を待ってから次に進みます。後でコンポーネントをマイクロコントローラー制御の治具に移せば、決定的なリセット、直接的な電源制御、より高速な fuzzing が可能になります。<sup>[[4]](#references)</sup>

## References

- [1] [Bus Pirate ドキュメント — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-bus 仕様およびユーザーマニュアル](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C シリアル EEPROM データシート](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — ブラックボックス・プロービング：Xiaomi MJA1 セキュアチップのセキュリティ分析](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK MJA1 暗号化ラッパー](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
