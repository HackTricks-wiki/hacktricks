# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

デバイスに物理的にアクセスできる場合は、基板や信号に露出しているインターフェースから調べます。[UART serial consoles](uart.md)、[JTAG/SWD debug access](jtag.md)、[CoreSight instruction tracing](arm-coresight-instruction-tracing.md)、[I²C](i2c.md)、[SPI flash](spi.md) バスなどです。[Side-channel analysis](side_channel_analysis.md) と [fault injection](fault_injection_attacks.md) は、それぞれ異なる測定やグリッチ注入の手法を扱います。[Radio signal analysis](radio.md) は、無線経由のエントリーポイントを扱います。対象に応じた RFID/NFC、sub-GHz、赤外線、BLE、LoRaWAN、iButton の手順については、[Radio Hacking and Proximity Interfaces](../radio-hacking/README.md) を参照してください。ツールを接続する前に、対象の電圧レベルと該当する章に記載された制限事項を確認してください。

## JTAG

JTAG (IEEE 1149.1) は、デバイスの I/O ピン周辺に配置されたセルを介してバウンダリスキャンテストを行います。多くのプロセッサは、同じ Test Access Port (TAP) を通じてベンダー固有のデバッグ機能も公開します。バウンダリスキャンと CPU デバッグは、JTAG の関連する用途であり、同義語ではありません。<sup>[[1]](#references)</sup>

JTAG 規格は、以下を含む**バウンダリスキャンを実行するための特定のコマンド**を定義しています。

- **BYPASS** は、1ビットのバイパスレジスタを選択し、スキャンチェーン内の他のデバイスに最小限のオーバーヘッドでアクセスできるようにします。
- **SAMPLE/PRELOAD** は、通常動作中のピン値を取得し、別の命令を実行する前にバウンダリスキャンレジスタへ値を事前ロードできます。
- **EXTEST** は、ピンの状態を設定および読み取ります。

また、次のようなコマンドもサポートする場合があります。

- デバイスの識別に使う **IDCODE**
- デバイスの内部テストに使う **INTEST**

JTAGulator のようなツールを使用すると、これらの命令を目にすることがあります。

### The Test Access Port

**Test Access Port (TAP)** は、コンポーネントの JTAG テストロジックへのアクセスを提供します。必要な信号は4つで、`TRST` はオプションです。<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK は、TAP コントローラーが次の状態へ遷移する頻度を定める**クロック**です（つまり、ステートマシンの次の状態へ進む頻度です）。
- Test mode select (**TMS**) input TMS は**有限状態機械**を制御します。クロックの各立ち上がりで、デバイスの JTAG TAP コントローラーは TMS ピンの電圧を確認します。電圧がしきい値を下回ると信号は low とみなされて 0 と解釈され、しきい値を上回ると high とみなされて 1 と解釈されます。
- Test data input (**TDI**) は、シリアル命令またはテストデータを選択した TAP レジスタにシフト入力します。IEEE 1149.1 は TAP の転送動作を定義し、オプションの命令やデバッグレジスタは各ベンダーが定義します。
- Test data output (**TDO**) TDO は、**チップからデータを出力する**ピンです。
- Test reset (**TRST**) input オプションの TRST は、有限状態機械を**既知の正常な状態に**リセットします。また、TMS を5クロックサイクル連続で 1 に保持しても、TRST ピンと同じようにリセットできるため、TRST はオプションです。

基板上にこれらのピンが表示されていることもあります。表示がない場合は、**特定する**必要があります。

### Identifying JTAG pins

JTAG ポートを検出する専用の高速な方法として、比較的高価ですが **JTAGulator** があります。UART のピン配置も特定できます。<sup>[[2]](#references)</sup>

24個の**チャンネル**を基板上のテストポイントに接続できます。**IDCODE** および **BYPASS** スキャンを使って候補となるピンの組み合わせを列挙し、検出した JTAG 信号に対応するチャンネルを報告します。

JTAG のピン配置を特定する、より安価ですが大幅に遅い方法は、Arduino 互換マイクロコントローラーに [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) を書き込んで使うことです。

**JTAGenum** を使う場合は、まず列挙に使用するプロービング用マイクロコントローラーのピンを定義します。ピン配置を確認し、それらのピンを対象基板上の候補テストポイントに接続してください。<sup>[[3]](#references)</sup>

JTAG ピンを特定する**3つ目の方法**は、既知のフットプリントがないか**基板を調べる**ことです。基板によっては **Tag-Connect** フットプリントを備えています。ただし、Tag-Connect は JTAG、SWD、UART、その他のインターフェースに使えるコネクターシステムであり、それだけではピンが JTAG である証拠にはなりません。コンポーネントのデータシートと導通測定を使って、実際の信号を特定できます。<sup>[[5]](#references)</sup>

## SDW

SWD は、Arm の2ピン式パケットベースのデバッグインターフェースです。<sup>[[4]](#references)</sup>

このインターフェースは、データ用の双方向 **SWDIO** とクロック用の **SWCLK** を使用します。多くのデバイスは、共有ピンで SWD と JTAG の切り替えを可能にする **Serial Wire/JTAG Debug Port (SWJ-DP)** を実装しています。<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 working group — JTAG とバウンダリスキャン](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator のドキュメント](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino による JTAG ピンの列挙](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — マルチデバイスシステム向け低ピン数デバッグインターフェース](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — デバッグおよびプログラミングケーブル用フットプリント](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
