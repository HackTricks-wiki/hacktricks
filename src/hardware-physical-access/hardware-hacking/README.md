# ハードウェアハッキング

{{#include ../../banners/hacktricks-training.md}}

デバイスに物理的にアクセスできる場合は、基板や信号に露出しているインターフェースから始めましょう。[UART serial consoles](uart.md)、[JTAG/SWD debug access](jtag.md)、[I²C](i2c.md)、[SPI flash](spi.md) buses を確認します。[Side-channel analysis](side_channel_analysis.md) と [fault injection](fault_injection_attacks.md) は、異なる測定やグリッチングの作業に対応します。[radio signal analysis](radio.md) は、無線経由の侵入経路を扱います。対象固有の RFID/NFC、sub-GHz、赤外線、BLE、LoRaWAN、iButton の手順については、[Radio Hacking and Proximity Interfaces](../radio-hacking/README.md) を参照してください。ツールを接続する前に、対象の電圧レベルと関連する章に記載された制限を確認してください。

## JTAG

JTAG (IEEE 1149.1) は、デバイスの I/O ピン周辺に配置されたセルを通じて、boundary-scan testing をサポートします。多くのプロセッサは、同じ Test Access Port (TAP) を通じて、ベンダー固有のデバッグ機能も提供します。boundary scan と CPU debugging は、JTAG の関連する用途ですが、同義語ではありません。<sup>[[1]](#references)</sup>

JTAG 規格では、**boundary scan を実行するための特定のコマンド**が定義されています。たとえば、次のものがあります。

- **BYPASS** は、1ビットのバイパスレジスタを選択します。これにより、scan chain 内の他のデバイスに最小限のオーバーヘッドでアクセスできます。
- **SAMPLE/PRELOAD** は、通常動作中にピンの値を取得し、別の命令を実行する前に boundary-scan register に値をプリロードできます。
- **EXTEST** は、ピンの状態を設定および読み取りします。

次のような他のコマンドもサポートできます。

- デバイスを識別する **IDCODE**
- デバイス内部をテストする **INTEST**

JTAGulator などのツールを使うと、これらの命令に遭遇することがあります。

### Test Access Port

**Test Access Port (TAP)** は、コンポーネントの JTAG test logic へのアクセスを提供します。4つの信号が必要で、`TRST` は任意です。<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK は、TAP controller が1回の動作を行う頻度（言い換えると、state machine の次の状態へ遷移する頻度）を定める**クロック**です。
- Test mode select (**TMS**) input TMS は**有限状態機械**を制御します。クロックの各周期で、デバイスの JTAG TAP controller は TMS ピンの電圧を確認します。電圧が特定のしきい値を下回ると信号は low とみなされて 0 と解釈され、しきい値を上回ると high とみなされて 1 と解釈されます。
- Test data input (**TDI**) は、シリアル命令またはテストデータを選択した TAP register にシフト入力します。IEEE 1149.1 は TAP の転送動作を定義し、ベンダーはオプションの命令とデバッグレジスタを定義します。
- Test data output (**TDO**) は、**チップからデータを出力する**ピンです。
- Test reset (**TRST**) input 任意の TRST は、有限状態機械を**既知の正常な状態に**リセットします。あるいは、TMS を5クロック周期連続で 1 に保持してもリセットが実行されます。これは TRST ピンを使う場合と同じ動作であり、TRST が任意である理由です。

基板上でこれらのピンを示す表記が見つかることもあります。そうでなければ、**特定する**必要があります。

### JTAG ピンの特定

JTAG ポートを検出するための、すばやく使える専用ツールとして **JTAGulator** があります。ただし、比較的高価です。UART のピン配列も特定できます。<sup>[[2]](#references)</sup>

基板上のテストポイントに接続できる **24チャンネル**を備えています。**IDCODE** と **BYPASS** のスキャンを使ってピンの候補の組み合わせを列挙し、検出した JTAG 信号に対応するチャンネルを報告します。

JTAG のピン配列を特定する、より安価ですが大幅に時間のかかる方法として、Arduino 互換マイクロコントローラーに [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) を書き込む方法があります。

**JTAGenum** では、まず列挙に使うプロービング用マイクロコントローラーのピンを定義します。ピン配置を確認してから、それらのピンを対象基板上の候補となるテストポイントに接続してください。<sup>[[3]](#references)</sup>

JTAG ピンを特定する**3つ目の方法**は、**基板を調べて**既知のフットプリントを探すことです。Tag-Connect フットプリントを備えた基板もあります。ただし、Tag-Connect は JTAG、SWD、UART、その他のインターフェースを通せるコネクターシステムであり、それだけでピンが JTAG だと証明されるわけではありません。部品のデータシートと導通測定を使って、実際の信号を特定できます。<sup>[[5]](#references)</sup>

## SDW

SWD は Arm の2ピンのパケットベースのデバッグインターフェースです。<sup>[[4]](#references)</sup>

このインターフェースは、データ用の双方向 **SWDIO** と、クロック用の **SWCLK** を使用します。多くのデバイスは、共有ピン上で SWD と JTAG の切り替えを可能にする **Serial Wire/JTAG Debug Port (SWJ-DP)** を実装しています。<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 ワーキンググループ — JTAG と boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator ドキュメント](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG ピンの列挙](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — マルチデバイスシステム向け低ピン数デバッグインターフェース](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — デバッグおよびプログラミングケーブル用フットプリント](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
