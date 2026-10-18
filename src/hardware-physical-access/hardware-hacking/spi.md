# SPI

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

SPI（Serial Peripheral Interface）は、集積回路間の近距離通信によく使われる同期シリアルバスです。コントローラーがクロックを供給し、チップセレクト信号を使って EEPROM、センサー、制御デバイスなどのペリフェラルを選択します。<sup>[[1]](#references)</sup>

複数のペリフェラルでクロック線とデータ線を共有でき、通常はペリフェラルごとに個別のチップセレクト信号を使用します。転送はコントローラーが制御します。通常、ペリフェラル同士がSPIバス経由で直接通信することはありません。チップセレクトの極性とタイミングはデバイスによって異なります。アクティブLowが一般的ですが、必ずしもそうとは限りません。SPIでは、デバイスの検出、アドレス指定、コマンド、単一の最大転送長は定義されていないため、必ず対象デバイスのデータシートを確認してください。<sup>[[1]](#references)</sup>

MOSI/COPIはコントローラーからペリフェラルへのデータを伝送し、MISO/CIPOはペリフェラルからコントローラーへのデータを伝送します。両方向のデータは同時にシフトできます。コマンド、アドレス、ダミーサイクル、返されるデータの関係はSPIではなくペリフェラルによって定義され、クロックの極性と位相（モード0～3）によって異なります。入力の終了からちょうど1クロック後に出力が始まるとは限りません。<sup>[[1]](#references)</sup>

## EEPROMからのファームウェアのダンプ

ファームウェアをダンプすると、分析や脆弱性の発見に役立ちます。正確なイメージがオンラインで入手できない場合や、モデル、ハードウェアリビジョン、バージョンによって異なる場合があります。そのため、物理デバイスから直接抽出すれば、評価対象と完全に一致するイメージを取得できます。

シリアルコンソールが役立つ場合もありますが、ファイルシステムが読み取り専用だったり、テスト用の通信を送受信するユーティリティや、バイナリを手軽に抽出するツールなど、分析に必要なツールが対象デバイスにない場合があります。オフラインイメージならフラッシュ全体のレイアウトが保持され、稼働中の対象デバイスを変更せずに、ファイルシステムの抽出やリバースエンジニアリングができます。

許可を得た物理評価では、検証済みのダンプを使って、制御された変更や再フラッシュのテストも行えます。これには、ファイルの変更や、ファームウェアレベルの永続化を実証するためのテスト用ペイロード／バックドアの注入が含まれます。書き込みを行う前に、複数回読み取って内容が一致することを確認し、元のイメージを保存してください。電圧、チップの選択、レイアウト、イメージを間違えると、デバイスが起動不能になるおそれがあります。

### CH341A EEPROM Programmer and Reader

この安価なUSBツールは、対応するシリアルEEPROMやSPIフラッシュデバイスのダンプと再フラッシュに使用できます。PCのBIOS/UEFIファームウェアを格納するSPI NORフラッシュチップによく使われ、時間が限られた物理アクセス時に便利です。

![drawing](../../images/board_image_ch341a.jpg)

フラッシュメモリをCH341Aに接続し、次にプログラマーをコンピューターに接続します。プログラマー自体が検出されない場合は、対象チップのトラブルシューティングを始める前に、USBケーブル、OSの権限、適切なCH341Aドライバーを確認してください。チップの電圧、1番ピン、アダプターの配線、プログラマーの出力を、データシートやテスターで確認してください。VCCをUSBコネクターの反対側に配置するといったルールに**頼らないでください**。向きを間違えたり、3.3/1.8 Vの部品に5 Vを印加したりすると、破損するおそれがあります。回路上で読み取る場合、基板上の他の部品がバスに負荷をかけたり、電源を供給したりするため、読み取りに失敗することもあります。<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

`flashrom`やG-Flashなどのソフトウェアを使ってチップを読み取ります。G-Flashは最小限のGUIを備え、対応デバイスを自動検出することもあるため、短時間での取得に便利です。ただし、検出されたモデルと電圧は自分で確認してください。正確なプログラマーを指定し、必要に応じてチップの正確なモデルも指定します。ダンプを信頼できるものとして扱う前に、少なくとも2回読み取り、ハッシュを比較してください。<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

ファームウェアをダンプした後は、バイナリファイルを分析できます。strings、hexdump、xxd、binwalkなどのツールを使うと、ファームウェアやファイルシステム全体について多くの情報を抽出できます。

初期トリアージでは、Binwalkを使って既知のシグネチャをスキャンし、対応する埋め込みコンテンツを抽出できます。

```
binwalk -e <filename>
```

出力ファイルの拡張子は`.bin`、`.rom`、またはその他の場合があります。拡張子からファイル形式を判断することはできません。

> [!CAUTION]
> ファームウェアの抽出は繊細な作業であり、多くの忍耐が必要です。取り扱いを誤ると、ファームウェアが破損したり、完全に消去されてデバイスが使用不能になったりする可能性があります。ファームウェアの抽出を試みる前に、対象デバイスについて調べておくことをおすすめします。

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

一部のデータシートでは、対象ピンを`DI`および`DO`と表記しています。従来の単一データラインのフラッシュ接続では、コントローラーの**MOSI/COPIをDIに**、コントローラーの**MISO/CIPOをDOに**接続します。デュアル/クアッドI/O部品では、別のモードでピンを再利用するため、対象デバイスのデータシートで確認してください。

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus PirateのPINOUTではSPI接続用のMOSIピンとMISOピンが示されていますが、一部のSPIは...](<../../images/image (360).png>)

WindowsまたはLinuxでは、[**`flashrom`**](https://www.flashrom.org/Flashrom)を使って、次のようなコマンドでフラッシュメモリの内容をダンプできます。

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

最近の Bus Pirate ドキュメントには、オプションの `serialspeed` および `spispeed` パラメーターも記載されています。長い配線や回路上の負荷によって読み取りが不安定になる場合は、控えめな設定から始めてください。<sup>[[3]](#references)</sup>

### コントローラーがフラッシュバスを共有している場合の回路上での読み取り

SOICクリップによって、フラッシュの電源が PCB の他の部分にも供給されることがあります。その状態で MCU の電源が入り、同じチップにアクセスすると、その SPI 転送が外部プログラマーの転送と衝突する可能性があります。したがって、`No EEPROM/flash device found` という結果だけでは、フラッシュが存在しない、またはサポートされていないとは言えません。まずピン配置、電圧、接触状態を確認し、その後、基板上のコントローラーも動作しているかを確認してください。<sup>[[4]](#references)</sup>

リセット用テストパッドがある場合は、リセットをかける前に、テスターで極性と電圧を確認してください。MCU をリセット状態に保持すると、競合する SPI ホストを停止させながら、フラッシュにはアクセスできる場合があります。代替手段として、チップを取り外す方法や、MCU の読み取りを受動的に記録する方法があります。後者では未読領域へのアクセスやチップへの書き込みはできず、プローブ配線を追加すると高速バスを乱す可能性があります。発振器やブートモードへの介入は対象に依存するため、回路図や信号を確認する代わりにはなりません。<sup>[[4]](#references)</sup>

MCU を非アクティブ状態に保持した状態で、`spidev` インターフェースを有効にした Raspberry Pi を使い、flashrom の `linux_spi` プログラマー経由で読み取ることができます。別のアダプターを使う場合は `-p` を変更してください。読み取りを繰り返してハッシュを比較し、結果を信頼できるか確認してください。SFDP による自動検出や読み取りの成功だけでは、他の点で未サポートの部品に対して、消去、書き込み、書き込み保護の操作が機能するとは確認できません。<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### logic analyzerを使ったSPI flash読み出しの再構成

active readができない場合は、起動中または選択したUI操作中に、chip select、clock、controller-to-flash data、flash-to-controller dataをキャプチャします。PulseViewでは、まずアクティブなchip-select区間とclockを特定し、次にflashのピン配置に基づいてSPI decoderのデータチャンネルを設定します。その後、妥当なコマンドとアドレスに続いて返却バイトがあることを確認します。Binary Decoder Output Viewで**MISO/flash-output**のバイトをエクスポートし、各応答を対応するflashオフセットに配置できるよう、デコードされた読み出しアドレスを保持してください。メニュー操作による読み出しだけをキャプチャしても、取得できるのは要求された領域のみで、flashイメージ全体ではありません。アドレスを確認せずに、応答を連続したデータとして結合しないでください。<sup>[[4]](#references)</sup>

ダンプに実行可能コードではなくグラフィックが含まれているように見える場合は、[raw display-asset triage](../firmware-analysis/#raw-display-assets-in-external-flash)に進んでください。<sup>[[4]](#references)</sup>

#### ScapyとSPI/QSPIの混在キャプチャ

ラベルのないプローブでは、応答データの前にopcodeが出ているラインを確認してMOSIとMISOを区別し、flashのデータシートと照合してコマンドを検証します。クロック幅より短いパルスは、サンプリングされたビットではなくプローブのノイズかもしれません。また、クリップ配線を追加すると、高速キャプチャの信頼性が低下することがあります。<sup>[[5]](#references)</sup>

SaleaeのSPI CSVエクスポートでは、`enable`と`disable`でchip-select区間を囲み、MOSI/MISOのバイトは`result`行に記録されます。デコードする前に、区間ごとにバイトをまとめてください。すべてのMISOデータを結合すると、トランザクションのアドレス情報が失われます。<sup>[[5]](#references)</sup> Scapyの`Packet`では、MOSIヘッダーを`ByteEnumField`のopcodeと、条件付きのaddressフィールドおよびdummyフィールドでモデル化できます。24-bit NOR読み出しでは、`0x03`はopcodeと3バイトのアドレスで構成され、`0x0B`ではdummyバイトが追加されます。`len(req.self_build())`でモデル化されたヘッダーの長さを取得できます。single-lane readでは、`miso[header_length:]`がflashの応答です。一方、ヘッダー以降のMOSIデータは、controller側では無視されるデータです。<sup>[[5]](#references)</sup> 応答は`0xFF`で埋めたイメージ内のデコード済みアドレスに配置し、カバー済みのオフセットは別途記録してください。観測されていないバイトは、flashがその位置に`0xFF`を保持していた証拠にはなりません。<sup>[[5]](#references)[[6]](#references)</sup>

W25Q系の`0x6B`（1-1-4）読み出しでは、opcodeとアドレスに1レーンを使い、応答データにはIO0～IO3を使います。前の`/WP`ピンと`/HOLD`ピンでの動作は、clockが速くなったことだけよりも、quad modeへの切り替えを強く示す証拠です。single-lane analyzerでは、quad応答を誤ってデコードする可能性があります。<sup>[[5]](#references)</sup> コマンドのレーン幅とdummy cycleに合わせてQSPI analyzerを設定し、そのフェーズをエクスポートしてから、single-laneとquad-laneの読み出しをflashアドレスに基づいて統合してください。<sup>[[5]](#references)[[7]](#references)</sup> `spidump`は両方のエクスポート形式を自動検出し、誤ったレーン幅でデコードされた読み出しを破棄して、読み出し範囲を報告します。<sup>[[6]](#references)</sup> リポジトリから依存関係をインストールした後、次のコマンドでキャプチャを統合します。<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

結果は依然として疎な観測であり、チップ全体のダンプではありません。<sup>[[5]](#references)[[6]](#references)</sup> 書き込みを個別に調べるには、`0x06` write-enable、`0x05` status poll、erase opcode、`0x02` page-program commandを関連付けてください。page-programのデータはMOSI上でアドレスに続き、read-onlyの再構成には含まれません。<sup>[[5]](#references)</sup> 読み取り範囲の情報を保持しながら、得られたイメージを[ファームウェア解析](../firmware-analysis/)で分析してください。

## References

- [1] [Analog Devices — SPIインターフェース入門](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom manual — CH341A SPI programmer and read/write options](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate documentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — ハードウェアハッキングの復習 Part 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — ハードウェアリバースエンジニアリング向けScapyの拡張](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — SPI/QSPIトレースのキャプチャと再構成](https://github.com/wrongbaud/spidump)
- [7] [Saleae Logic/KingstVIS向けQSPI Analyzer](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
