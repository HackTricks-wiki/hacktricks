# SPI

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

SPI（Serial Peripheral Interface）は、集積回路間の短距離通信によく使われる同期シリアルバスです。コントローラーがクロックを供給し、チップセレクト信号を使ってEEPROM、センサー、制御デバイスなどの周辺機器を選択します。<sup>[[1]](#references)</sup>

複数の周辺機器でクロック線とデータ線を共有し、通常は周辺機器ごとに別のチップセレクトを使用します。転送はコントローラーが制御します。通常、周辺機器同士がSPIバス上で直接通信することはありません。チップセレクトの極性とタイミングはデバイスによって異なります。アクティブLowが一般的ですが、必ずしもそうとは限りません。SPIでは、デバイスの検出、アドレス指定、コマンド、最大転送長は定義されていないため、必ず対象デバイスのデータシートを確認してください。<sup>[[1]](#references)</sup>

MOSI/COPIはコントローラーから周辺機器へのデータを伝送し、MISO/CIPOは周辺機器からコントローラーへのデータを伝送します。両方向のデータは同時にシフトできます。コマンド、アドレス、ダミーサイクル、返されるデータの関係は周辺機器側で定義されており、SPI自体では定義されていません。また、クロックの極性と位相（モード0〜3）によって異なります。入力が終わってからちょうど1クロック後に出力が始まるとは限りません。<sup>[[1]](#references)</sup>

## EEPROMからのファームウェアのダンプ

ファームウェアのダンプは、分析や脆弱性の発見に役立ちます。適切なイメージがオンラインで入手できない場合や、モデル、ハードウェアリビジョン、バージョンによって異なる場合があります。そのため、物理デバイスから直接抽出すれば、評価対象そのものを正確に取得できます。

シリアルコンソールが役立つこともありますが、ファイルシステムが読み取り専用の場合や、テストトラフィックの送受信やバイナリの抽出に必要なユーティリティなど、対象に分析ツールがない場合があります。オフラインイメージなら、フラッシュ全体のレイアウトを保持でき、稼働中の対象を変更せずにファイルシステムの抽出やリバースエンジニアリングを行えます。

許可された物理アセスメントでは、検証済みのダンプを使って、制御された変更や再フラッシュのテストを行うこともできます。たとえば、ファイルを変更したり、テスト用のペイロード／バックドアを注入したりして、ファームウェアレベルの永続化を実証できます。書き込みを行う前に、複数回読み出した内容が一致することを確認し、元のイメージを保管してください。電圧、チップの選択、レイアウト、イメージを誤ると、デバイスが起動不能になるおそれがあります。

### CH341A EEPROMプログラマー／リーダー

この安価なUSBツールは、対応するシリアルEEPROMやSPIフラッシュデバイスのダンプと再フラッシュに使えます。PCのBIOS/UEFIファームウェアを格納するSPI NORフラッシュチップによく使われ、時間が限られた物理アクセス時にも便利です。

![drawing](../../images/board_image_ch341a.jpg)

フラッシュメモリをCH341Aに接続し、次にプログラマーをコンピューターに接続します。プログラマー自体が認識されない場合は、対象チップのトラブルシューティングに進む前に、USBケーブル、OSの権限、適切なCH341Aドライバーを確認してください。データシートやテスターを使って、チップの電圧、1番ピン、アダプターの配線、プログラマーの出力を確認してください。VCCをUSBコネクターの反対側に配置するといった規則に**頼らないでください**。向きを誤ったり、3.3/1.8 V部品に5 Vを印加したりすると、部品が破損するおそれがあります。基板に実装したまま読み出す場合、基板上のほかの部品がバスに負荷をかけたり、電源を供給したりするため、読み出しに失敗することもあります。<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

チップの読み出しには、`flashrom`やG-Flashなどのソフトウェアを使います。G-Flashは最小限のGUIを備えており、対応デバイスを自動検出できるため、迅速な取得に便利な場合があります。ただし、検出されたモデルと電圧は自分で確認してください。正確なプログラマーを指定し、必要に応じてチップの正確なモデルも指定します。ダンプを信頼できるものとして扱う前に、少なくとも2回読み出し、ハッシュを比較してください。<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

ファームウェアをダンプした後は、バイナリファイルを分析できます。strings、hexdump、xxd、binwalkなどのツールを使えば、ファームウェアやファイルシステム全体について、多くの情報を抽出できます。

初期トリアージでは、Binwalkを使って既知のシグネチャをスキャンし、対応する埋め込みコンテンツを抽出できます。

```
binwalk -e <filename>
```

出力ファイルには`.bin`、`.rom`、または別の拡張子が使われる場合がありますが、拡張子だけではフォーマットは特定できません。

> [!CAUTION]
> ファームウェアの抽出は繊細な作業であり、十分な忍耐が必要です。取り扱いを誤ると、ファームウェアが破損したり、完全に消去されたりして、デバイスが使用不能になるおそれがあります。ファームウェアの抽出を試みる前に、対象デバイスについて調べておくことをおすすめします。

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

データシートによっては、対象のピンが`DI`と`DO`と表記されています。一般的な単一データラインのフラッシュ接続では、コントローラーの**MOSI/COPIをDIに**、コントローラーの**MISO/CIPOをDOに**接続します。デュアル／クワッドI/O対応部品では、別のモードで同じピンを再利用するため、対象のデータシートを確認してください。

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Pirate Busのピン配置ではSPI接続用のMOSIピンとMISOピンが示されていますが、SPIによっては...](<../../images/image (360).png>)

WindowsまたはLinuxでは、[**`flashrom`**](https://www.flashrom.org/Flashrom)を使って、次のようなコマンドでフラッシュメモリの内容をダンプできます。

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Bus Pirateの最近のドキュメントには、オプションの`serialspeed`および`spispeed`パラメータも記載されています。長いワイヤや回路内の負荷によって読み取りが不安定になる場合は、低速から始めてください。<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — SPIインターフェースの概要](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom manual — CH341A SPIプログラマと読み書きオプション](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate documentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
