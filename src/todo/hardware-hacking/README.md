# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG（IEEE 1149.1）は、デバイスのI/Oピン周辺に配置されたセルを通じて、boundary-scanテストをサポートします。多くのプロセッサは、同じTest Access Port（TAP）を通じてベンダー固有のデバッグ機能も公開しています。boundary scanとCPUデバッグはJTAGの関連する用途ですが、同義ではありません。<sup>[[1]](#references)</sup>

JTAG標準では、**boundary scanを実行するための特定のコマンド**が定義されています。以下はその一部です。

- **BYPASS** は1ビットのバイパスレジスタを選択し、scan chain内の他のデバイスに最小限のオーバーヘッドでアクセスできるようにします。
- **SAMPLE/PRELOAD** は通常動作中のピンの値を取得し、別の命令の前にboundary-scanレジスタへ事前ロードできます。
- **EXTEST** はピンの状態を設定および読み取りします。

次のようなその他のコマンドもサポートされる場合があります。

- デバイスを識別する **IDCODE**
- デバイス内部のテストを行う **INTEST**

JTAGulatorのようなツールを使用すると、これらの命令を目にすることがあります。

### Test Access Port

**Test Access Port（TAP）** は、コンポーネントのJTAGテストロジックへのアクセスを提供します。4つの信号が必要で、`TRST` はオプションです。<sup>[[1]](#references)</sup>

- Test clock input（**TCK**） TCKは、TAPコントローラが1回のアクションを実行する頻度、つまりstate machineの次の状態へ移行するタイミングを定義する**クロック**です。
- Test mode select（**TMS**） input TMSは**finite state machine**を制御します。クロックの各ビートで、デバイスのJTAG TAPコントローラはTMSピンの電圧を確認します。電圧が特定のしきい値未満の場合、信号はlowと見なされて0として解釈されます。一方、電圧が特定のしきい値を超える場合、信号はhighと見なされて1として解釈されます。
- Test data input（**TDI**） は、シリアル命令またはテストデータを選択されたTAPレジスタへシフト入力します。IEEE 1149.1はTAPの転送動作を定義し、オプションの命令やデバッグレジスタはベンダーが定義します。
- Test data output（**TDO**） TDOは**チップからデータを出力する**ピンです。
- Test reset（**TRST**） input オプションのTRSTはfinite state machineを**既知の正常な状態**へリセットします。また、TMSを5回連続するクロックサイクルの間1に保持すると、TRSTピンと同様にリセットが実行されます。そのためTRSTはオプションです。

PCB上でこれらのピンにマークが付いていることもあります。それ以外の場合は、**見つける**必要があります。

### JTAG pinsの識別

JTAGポートを検出するための高速で専用設計された、ただし比較的高価な選択肢が**JTAGulator**です。JTAGulatorはUART pinoutも識別できます。<sup>[[2]](#references)</sup>

JTAGulatorには、ボード上のテストポイントへ接続できる**24チャンネル**があります。**IDCODE**および**BYPASS**スキャンを使用して候補となるピンの組み合わせを列挙し、検出されたJTAG信号に対応するチャンネルを報告します。

JTAG pinoutを識別する、より安価ですがはるかに遅い方法は、Arduino互換マイクロコントローラにロードした [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) を使用することです。

**JTAGenum**では、まず列挙に使用するprobe用マイクロコントローラのピンを定義します。そのpinoutを確認し、それらのピンをターゲットボード上の候補テストポイントへ接続します。<sup>[[3]](#references)</sup>

JTAG pinsを識別する**3つ目の方法**は、既知のfootprintがないか**PCBを調べる**ことです。一部のボードには**Tag-Connect** footprintがあります。ただし、Tag-ConnectはJTAG、SWD、UART、その他のインターフェースを伝送できるコネクタシステムであり、それだけでピンがJTAGである証拠にはなりません。コンポーネントのデータシートと導通測定によって、実際の信号を特定できます。<sup>[[5]](#references)</sup>

## SDW

SWDはArmの2ピン式、パケットベースのデバッグインターフェースです。<sup>[[4]](#references)</sup>

このインターフェースでは、データに双方向の**SWDIO**、クロックに**SWCLK**を使用します。多くのデバイスは、共有ピン上でSWDとJTAGを切り替えられる**Serial Wire/JTAG Debug Port（SWJ-DP）**を実装しています。<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1作業グループ — JTAGとboundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulatorドキュメント](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAGピン列挙](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — マルチデバイスシステム向け低ピン数デバッグインターフェース](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — デバッグおよびプログラミングケーブル用footprint](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
