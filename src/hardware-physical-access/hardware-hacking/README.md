# ハードウェアハッキング

{{#include ../../banners/hacktricks-training.md}}

デバイスに物理的にアクセスできる場合は、基板や信号に露出しているインターフェースから調査を始めましょう。[UART serial consoles](uart.md)、[JTAG/SWD debug access](jtag.md)、[I²C](i2c.md)、[SPI flash](spi.md) バスを確認してください。[Side-channel analysis](side_channel_analysis.md) と [fault injection](fault_injection_attacks.md) は、異なる測定やグリッチの手法を扱います。[Radio signal analysis](radio.md) では、無線経由の侵入経路を扱います。ツールを接続する前に、対象の電圧レベルと、関連する章で説明されている制限を確認してください。

## JTAG

JTAG (IEEE 1149.1) は、デバイスの I/O ピンの周囲に配置されたセルを使って、boundary-scan テストを行います。また、多くのプロセッサは、同じ Test Access Port (TAP) を介して、ベンダー固有のデバッグ機能も公開しています。boundary scan と CPU デバッグは、JTAG の関連する用途ですが、同義語ではありません。<sup>[[1]](#references)</sup>

JTAG 標準では、**boundary scan を実行するための特定のコマンド**が定義されています。次のものが含まれます。

- **BYPASS** は、1 ビットのバイパスレジスタを選択します。これにより、scan chain 内の他のデバイスに、最小限のオーバーヘッドでアクセスできます。
- **SAMPLE/PRELOAD** は、通常動作中のピン値を取得し、別の命令を実行する前に boundary-scan レジスタへ値を事前ロードできます。
- **EXTEST** は、ピンの状態を設定および読み取りします。

次のような他のコマンドもサポートすることがあります。

- デバイスの識別に使う **IDCODE**
- デバイス内部のテストに使う **INTEST**

JTAGulator などのツールを使うと、これらの命令を目にすることがあります。

### Test Access Port

**Test Access Port (TAP)** は、コンポーネントの JTAG テストロジックへのアクセスを提供します。必要な信号は4つで、`TRST` はオプションです。<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK は、TAP コントローラーが1回の動作を行う頻度（つまり、ステートマシンの次の状態へ移るタイミング）を定める**クロック**です。
- Test mode select (**TMS**) input TMS は、**有限状態マシン**を制御します。クロックの各サイクルで、デバイスの JTAG TAP コントローラーは TMS ピンの電圧を確認します。電圧が特定のしきい値より低ければ信号は low とみなされて 0 と解釈され、しきい値より高ければ high とみなされて 1 と解釈されます。
- Test data input (**TDI**) は、シリアル命令またはテストデータを選択された TAP レジスタへシフト入力します。IEEE 1149.1 は TAP の転送動作を定義し、ベンダーはオプションの命令やデバッグレジスタを定義します。
- Test data output (**TDO**) は、**チップからデータを出力する**ピンです。
- Test reset (**TRST**) input オプションの TRST は、有限状態マシンを**既知の正常な状態**にリセットします。また、TMS を5回連続のクロックサイクルで 1 に保つことでもリセットできます。TRST ピンと同じ動作をするため、TRST はオプションです。

基板上でこれらのピンの表示を見つけられる場合もあります。表示がなく、自分で**特定する**必要がある場合もあります。

### JTAG ピンの特定

JTAG ポートを検出する専用の高速な方法として、比較的高価な **JTAGulator** があります。UART のピン配置も特定できます。<sup>[[2]](#references)</sup>

JTAGulator には、基板上のテストポイントに接続できる **24 チャンネル**があります。**IDCODE** と **BYPASS** の scan を使ってピンの組み合わせ候補を順に調べ、検出した JTAG 信号に対応するチャンネルを報告します。

JTAG のピン配置を特定する、より安価ですが大幅に時間のかかる方法は、Arduino 互換マイクロコントローラーに [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) をロードして使うことです。

**JTAGenum** では、まず列挙に使うプローブ用マイクロコントローラーのピンを設定します。ピン配置を確認してから、それらのピンを対象基板のテストポイント候補に接続してください。<sup>[[3]](#references)</sup>

JTAG ピンを特定する**3つ目の方法**は、既知のフットプリントがないか**基板を調べる**ことです。基板によっては **Tag-Connect** フットプリントが露出しています。ただし、Tag-Connect は JTAG、SWD、UART、その他のインターフェースに使えるコネクターシステムであり、それだけではピンが JTAG である証拠にはなりません。コンポーネントのデータシートと導通測定を使って、実際の信号を特定できます。<sup>[[5]](#references)</sup>

## SDW

SWD は、Arm の2ピン、パケットベースのデバッグインターフェースです。<sup>[[4]](#references)</sup>

このインターフェースでは、データ用の双方向 **SWDIO** とクロック用の **SWCLK** を使います。多くのデバイスには、共有ピンで SWD と JTAG を切り替えられる **Serial Wire/JTAG Debug Port (SWJ-DP)** が実装されています。<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 ワーキンググループ — JTAG と boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator のドキュメント](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino による JTAG ピンの列挙](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — マルチデバイスシステム向け低ピン数デバッグインターフェース](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — デバッグ・プログラミングケーブル用フットプリント](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
