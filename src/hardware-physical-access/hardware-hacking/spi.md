# SPI

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

SPI（Serial Peripheral Interface）は、集積回路間の短距離通信で一般的に使用される同期シリアルバスです。コントローラーがクロックを供給し、chip-select信号を使ってEEPROM、センサー、制御デバイスなどのペリフェラルを選択します。<sup>[[1]](#references)</sup>

複数のペリフェラルでクロック線とデータ線を共有できます。通常、ペリフェラルごとに個別のchip-selectがあります。転送はコントローラーが制御し、ペリフェラル同士がSPIバスを介して直接通信することは通常ありません。chip-selectの極性とタイミングはデバイスごとに異なります。Lowで選択する方式が一般的ですが、常にそうとは限りません。SPIでは、デバイスの検出、アドレス指定、コマンド、単一の最大転送長は定義されていないため、必ず対象デバイスのデータシートを確認してください。<sup>[[1]](#references)</sup>

MOSI/COPIはコントローラーからペリフェラルへのデータを伝送し、MISO/CIPOはペリフェラルからコントローラーへのデータを伝送します。両方向のデータを同時にシフトできます。コマンド、アドレス、ダミーサイクル、返されるデータの関係は、SPIではなくペリフェラルによって定義され、クロックの極性と位相（モード0～3）によって異なります。入力が終わってからちょうど1クロック後に出力が始まると想定しないでください。<sup>[[1]](#references)</sup>

## EEPROMからのファームウェアのダンプ

ファームウェアをダンプすると、解析や脆弱性の発見に役立ちます。オンラインで適切なイメージが見つからない場合や、モデル、ハードウェアリビジョン、バージョンによって異なる場合があるため、物理デバイスから直接抽出すれば、正確な評価対象を得られます。

シリアルコンソールは役立つことがありますが、ファイルシステムが読み取り専用であったり、テスト用トラフィックの送受信やバイナリの簡単な抽出に必要なユーティリティなど、解析ツールが対象に備わっていなかったりする場合があります。オフラインイメージがあれば、フラッシュ全体のレイアウトを保持でき、稼働中の対象を変更せずにファイルシステムの抽出やリバースエンジニアリングを行えます。

許可を得た物理的な評価では、検証済みのダンプを使って、制御された改変や再書き込みのテストを行うこともできます。これには、ファイルの変更やテスト用ペイロード／バックドアの注入によって、ファームウェアレベルの永続化を実証することが含まれます。書き込みを行う前に、内容が一致する複数回の読み取り結果と元のイメージを保存してください。電圧、チップの選択、レイアウト、イメージが不適切だと、デバイスが起動不能になることがあります。

### CH341A EEPROM Programmer and Reader

この安価なUSBツールは、対応するシリアルEEPROMおよびSPIフラッシュデバイスのダンプと再書き込みに使用できます。PCのBIOS/UEFIファームウェアを格納するSPI NORフラッシュチップでよく使われ、時間が限られた物理アクセス時に便利です。

![drawing](../../images/board_image_ch341a.jpg)

フラッシュメモリをCH341Aに接続し、次にプログラマーをコンピューターに接続します。プログラマー自体が検出されない場合は、対象チップのトラブルシューティングを行う前に、USBケーブル、OSの権限、適切なCH341Aドライバーを確認してください。データシートやテスターを使って、チップの電圧、1番ピン、アダプターの配線、プログラマーの出力を確認してください。VCCをUSBコネクターの反対側に配置するといったルールを**鵜呑みにしないでください**。向きを間違えたり、3.3/1.8 V部品に5 Vを印加したりすると、破損するおそれがあります。回路上で読み取る場合、基板上の他の部分がバスに負荷をかけたり、電力を供給したりするため、読み取りに失敗することもあります。<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

`flashrom`やG-Flashなどのソフトウェアを使ってチップを読み取ります。G-Flashは最小限のGUIを備え、対応デバイスを自動検出できる場合があるため、短時間での取得に便利ですが、検出されたモデルと電圧は自分で確認してください。正確なプログラマーを指定し、必要に応じて正確なチップモデルも指定します。ダンプを信頼できるものとして扱う前に、少なくとも2回読み取り、ハッシュを比較してください。<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

ファームウェアをダンプした後は、バイナリファイルを解析できます。strings、hexdump、xxd、binwalkなどのツールを使うと、ファームウェアやファイルシステム全体について多くの情報を抽出できます。

初期トリアージでは、Binwalkで既知のシグネチャをスキャンし、対応する埋め込みコンテンツを抽出できます：

```
binwalk -e <filename>
```

出力ファイルの拡張子は`.bin`、`.rom`、その他の場合がありますが、拡張子だけでは形式を特定できません。

> [!CAUTION]
> ファームウェアの抽出は繊細な作業であり、かなりの忍耐が必要です。取り扱いを誤ると、ファームウェアが破損したり、完全に消去されたりして、デバイスが使用不能になる可能性があります。ファームウェアの抽出を試みる前に、対象デバイスについて調べておくことを推奨します。

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

一部のデータシートでは、対象のピンに`DI`および`DO`というラベルが付いています。一般的な単一データラインのフラッシュ接続では、コントローラーの**MOSI/COPIはDIに接続し**、コントローラーの**MISO/CIPOはDOに接続します**。デュアル／クアッドI/Oパーツでは、別のモードでピンが再利用されるため、対象のデータシートを確認してください。

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Pirate BusのPINOUTではSPI接続用のMOSIピンとMISOピンが示されていますが、一部のSPIは...](<../../images/image (360).png>)

WindowsまたはLinuxでは、[**`flashrom`**](https://www.flashrom.org/Flashrom)を使って、次のようなコマンドでフラッシュメモリの内容をダンプできます。

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

最近の Bus Pirate ドキュメントには、オプションの `serialspeed` および `spispeed` パラメーターも記載されています。長い配線や回路上の負荷によって読み取りが不安定になる場合は、控えめな速度から始めてください。<sup>[[3]](#references)</sup>

### コントローラーがフラッシュバスを共有している場合の回路上での読み取り

SOIC クリップを接続すると、フラッシュへの電源が PCB の他の部分にも供給される場合があります。その状態で MCU に電源が入り、同じチップにアクセスすると、MCU の SPI 通信が外部プログラマーの通信と衝突する可能性があります。そのため、`No EEPROM/flash device found` という結果は、フラッシュが存在しない、またはサポートされていないことの証明にはなりません。まずピン配置、電圧、接触状態を確認し、次に基板上のコントローラーも動作しているかを調べてください。<sup>[[4]](#references)</sup>

リセット用のテストパッドがある場合は、リセットをかける前に、メーターで極性と電圧を確認してください。MCU をリセット状態に保つと、競合する SPI ホストを停止しながらフラッシュにアクセスできる場合があります。代替手段として、チップの取り外しや、MCU の読み取りを受動的に記録する方法があります。後者では未読領域にアクセスしたり、チップに書き込んだりできません。また、プローブ配線を追加すると高速バスに影響を与える可能性があります。発振器やブートモードへの介入は対象ごとに異なるため、回路図や信号の確認に代わるものではありません。<sup>[[4]](#references)</sup>

MCU を非アクティブ状態にしたうえで、`spidev` インターフェースを有効にした Raspberry Pi は、flashrom の `linux_spi` programmer を使って読み取りできます。別のアダプターを使う場合は `-p` を変更してください。読み取りを繰り返してハッシュを比較し、結果を信用できるか確認してください。SFDP による自動検出や読み取りの成功だけでは、その他の点で未対応のパーツに対して、消去、書き込み、書き込み保護の操作が機能することは確認できません。<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### ロジックアナライザーで SPI flash の読み出しを再構築する

アクティブな読み出しができない場合は、起動中または選択した UI 操作中に、チップセレクト、クロック、コントローラーから flash へのデータ、flash からコントローラーへのデータをキャプチャします。PulseView では、まずアクティブなチップセレクト区間とクロックを特定し、次に flash のピン配置に基づいて SPI デコーダーのデータチャンネルを設定し、妥当なコマンドとアドレスに続いてデータが返されることを確認します。Binary Decoder Output View で **MISO/flash-output** のバイト列をエクスポートし、デコードされた読み出しアドレスを保持して、各応答を対応する flash オフセットに配置できるようにします。メニュー操作による読み出しだけをキャプチャした場合、得られるのは要求された領域のみであり、flash 全体のイメージではありません。アドレスを確認せずに、応答を連続したデータであるかのように連結しないでください。<sup>[[4]](#references)</sup>

ダンプに実行可能コードではなくグラフィックが含まれているように見える場合は、[raw ディスプレイアセットのトリアージ](../firmware-analysis/#raw-display-assets-in-external-flash)に進んでください。<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — SPI インターフェース入門](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom manual — CH341A SPI プログラマーと読み書きオプション](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate documentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — ハードウェアハッキングの復習 パート 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
