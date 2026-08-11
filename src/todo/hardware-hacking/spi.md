# SPI

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

SPI（Serial Peripheral Interface）は、集積回路間の短距離通信に一般的に使用される同期シリアルバスです。コントローラーはクロックを供給し、chip-select信号を使用してEEPROM、センサー、制御デバイスなどのペリフェラルを選択します。<sup>[[1]](#references)</sup>

複数のペリフェラルでクロック線とデータ線を共有でき、通常はペリフェラルごとに個別のchip-selectを使用します。コントローラーが転送を調整し、ペリフェラル同士がSPIバス上で直接通信することは通常ありません。chip-selectの極性とタイミングはデバイスごとに異なります。active-lowによる選択が一般的ですが、普遍的ではありません。SPIは、discovery、アドレス指定、コマンド、単一の最大転送長を定義していないため、必ず対象データシートを確認してください。<sup>[[1]](#references)</sup>

MOSI/COPIはコントローラーからペリフェラルへのデータを運び、MISO/CIPOはペリフェラルからコントローラーへのデータを運びます。両方向のシフトを同時に実行できます。コマンド、アドレス、dummy cycles、返されるデータの関係はSPIではなくペリフェラルによって定義され、clock polarityとphase（mode 0～3）に依存します。入力の終了からちょうど1クロック後に出力が始まるとは限りません。<sup>[[1]](#references)</sup>

## EEPROMからのFirmwareのダンプ

Firmwareをダンプすると、その解析や脆弱性の発見に役立ちます。正しいイメージがオンラインで入手できない場合や、モデル、hardware revision、versionによって異なる場合があるため、物理デバイスから直接抽出することで、正確な評価対象を取得できます。

シリアルコンソールは役立ちますが、そのファイルシステムがread-onlyである可能性があり、対象にテストトラフィックの送受信やバイナリの便利な抽出に必要なユーティリティなど、解析ツールが存在しない場合があります。offline imageを使用すれば、完全なflash layoutを保持でき、実行中の対象を変更せずにファイルシステムの抽出とreverse engineeringを実行できます。

承認済みの物理評価では、検証済みのダンプを制御された変更やreflashingテストにも利用できます。これには、ファイルの変更やtest payload/backdoorの注入によってfirmware-level persistenceを実証することが含まれます。書き込みを行う前に、一致する複数回の読み取り結果と元のイメージを保存してください。誤った電圧、chip selection、layout、またはイメージによってデバイスがbrickする可能性があります。

### CH341A EEPROM Programmer and Reader

この安価なUSBツールは、互換性のあるserial EEPROMおよびSPI flashデバイスのダンプとreflashに使用できます。PCのBIOS/UEFI firmwareを保存するSPI NOR flash chipで一般的に使用され、時間が限られた物理アクセス時に便利です。

![drawing](../../images/board_image_ch341a.jpg)

flash memoryをCH341Aに接続し、次にprogrammerをコンピューターへ接続します。programmer自体が検出されない場合は、対象chipのトラブルシューティングを行う前に、USBケーブル、OSの権限、適切なCH341A driverを確認してください。データシートまたはmeterを使用して、chipの電圧、pin 1、adapter wiring、programmerの出力を確認してください。「VCCをUSBコネクターの反対側に配置する」といったルールに**依存してはいけません**。向きを誤ったり、3.3/1.8 V用の部品に5 Vを印加したりすると、部品が破壊される可能性があります。in-circuit readも、ボード上の他の回路がバスに負荷をかけたり電力を供給したりするため、失敗する場合があります。<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

`flashrom`やG-Flashなどのソフトウェアを使用してchipを読み取ります。G-Flashはminimal GUIであり、互換性のあるデバイスをauto-detectできる場合があります。これは迅速な取得時に便利ですが、検出されたモデルと電圧は自分で確認してください。正確なprogrammerを指定し、必要に応じて正確なchip modelも指定してください。ダンプを信頼できるものとして扱う前に、少なくとも2回読み取り、それらのhashを比較してください。<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

firmwareをダンプした後は、バイナリファイルを解析できます。strings、hexdump、xxd、binwalkなどのツールを使用して、firmwareおよびファイルシステム全体から大量の情報を抽出できます。

初期triageでは、Binwalkを使用して既知のsignatureをスキャンし、対応しているembedded contentを抽出できます：
```
binwalk -e <filename>
```
出力ファイルには `.bin`、`.rom`、または別の拡張子が使用される場合がありますが、拡張子によって形式が決まるわけではありません。

> [!CAUTION]
> firmware の抽出は繊細な作業であり、多くの忍耐が必要です。取り扱いを誤ると、firmware が破損したり、完全に消去されたりして、デバイスが使用不能になる可能性があります。firmware の抽出を試みる前に、対象デバイスについて調査することを推奨します。

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

一部のデータシートでは、対象のピンに `DI` および `DO` というラベルが付けられています。従来の単一データ線 flash 接続では、controller の **MOSI/COPI は DI に接続**し、controller の **MISO/CIPO は DO に接続**します。dual/quad I/O 部品では別のモードで同じピンを再利用するため、対象のデータシートを確認してください。

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate の PINOUT に MOSI と MISO を SPI に接続するためのピンが示されていても、一部の SPI では...](<../../images/image (360).png>)

Windows または Linux では、[**`flashrom`**](https://www.flashrom.org/Flashrom) プログラムを使用して、次のようなコマンドを実行し、flash memory の内容を dump できます:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
最近の Bus Pirate documentation には、オプションの `serialspeed` および `spispeed` パラメータも記載されています。長い配線や回路内の負荷によって読み取りが不安定になる場合は、控えめな値から開始してください。<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — SPIインターフェースの紹介](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom manual — CH341A SPI programmer and read/write options](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate documentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
