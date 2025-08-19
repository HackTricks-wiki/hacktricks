# JTAG

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) は、Arduino互換のMCUまたは（実験的に）Raspberry Piにロードして、未知のJTAGピンアウトをブルートフォースし、命令レジスタを列挙するためのツールです。

- Arduino: デジタルピンD2–D11を最大10の疑わしいJTAGパッド/テストポイントに接続し、Arduino GNDをターゲットGNDに接続します。レールが安全であることがわからない限り、ターゲットに別途電源を供給してください。3.3 Vロジック（例：Arduino Due）を好むか、1.8–3.3 Vターゲットをプローブする際にはレベルシフタ/直列抵抗を使用してください。
- Raspberry Pi: Piビルドは使用可能なGPIOが少なく（スキャンが遅くなる）、現在のピンマップと制約についてはリポジトリを確認してください。

フラッシュが完了したら、115200ボーでシリアルモニタを開き、ヘルプのために `h` を送信します。典型的なフロー：

- `l` ループバックを見つけて偽陽性を避ける
- `r` 必要に応じて内部プルアップを切り替える
- `s` TCK/TMS/TDI/TDO（時にはTRST/SRST）をスキャンする
- `y` 文書化されていないオペコードを発見するためにIRをブルートフォースする
- `x` ピン状態の境界スキャンスナップショット

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)



有効なTAPが見つかると、発見されたピンを示す `FOUND!` で始まる行が表示されます。

ヒント
- 常にグラウンドを共有し、未知のピンをターゲットVtref以上に駆動しないでください。疑わしい場合は、候補ピンに100–470 Ωの直列抵抗を追加してください。
- デバイスが4線JTAGの代わりにSWD/SWJを使用している場合、JTAGenumはそれを検出できないことがあります。SWDツールまたはSWJ-DPをサポートするアダプタを試してください。

## Safer pin hunting and hardware setup

- まずマルチメーターでVtrefとGNDを特定します。多くのアダプタはI/O電圧を設定するためにVtrefを必要とします。
- レベルシフティング: プッシュプル信号用に設計された双方向レベルシフタを好みます（JTAGラインはオープンドレインではありません）。JTAG用の自動方向I2Cシフタは避けてください。
- 有用なアダプタ: FT2232H/FT232Hボード（例：Tigard）、CMSIS-DAP、J-Link、ST-LINK（ベンダー特有）、ESP-USB-JTAG（ESP32-Sx上）。最低限TCK、TMS、TDI、TDO、GNDおよびVtrefを接続し、オプションでTRSTとSRSTを接続します。

## First contact with OpenOCD (scan and IDCODE)

OpenOCDはJTAG/SWDの事実上のOSSです。サポートされているアダプタを使用すると、チェーンをスキャンしてIDCODEを読み取ることができます：

- J-Linkを使用した一般的な例:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 内蔵 USB‑JTAG（外部プローブは不要）：
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
ノート
- "すべての1/0" IDCODEが表示された場合は、配線、電源、Vtref、およびポートがヒューズ/オプションバイトによってロックされていないことを確認してください。
- 不明なチェーンを立ち上げる際の手動TAPインタラクションについては、OpenOCDの低レベル`irscan`/`drscan`を参照してください。

## CPUの停止とメモリ/フラッシュのダンプ

TAPが認識され、ターゲットスクリプトが選択されると、コアを停止させ、メモリ領域または内部フラッシュをダンプできます。例（ターゲット、ベースアドレス、サイズを調整してください）：

- 初期化後の一般的なターゲット:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（利用可能な場合はSBAを優先）：
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3、OpenOCDヘルパーを介してプログラムまたは読み取る:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- `mdw/mdh/mdb`を使用して、長いダンプの前にメモリをサニティチェックします。
- マルチデバイスチェーンの場合、非ターゲットにBYPASSを設定するか、すべてのTAPを定義するボードファイルを使用します。

## バウンダリスキャンのトリック (EXTEST/SAMPLE)

CPUのデバッグアクセスがロックされていても、バウンダリスキャンが露出している場合があります。UrJTAG/OpenOCDを使用すると、次のことができます：
- SAMPLEを使用して、システムが動作している間にピンの状態をスナップショットします（バスのアクティビティを見つけ、ピンのマッピングを確認します）。
- EXTESTを使用してピンを駆動します（例：ボードの配線が許可されている場合、MCUを介して外部SPIフラッシュラインをビットバンギングしてオフラインで読み取ります）。

FT2232xアダプタを使用した最小限のUrJTAGフロー：
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
デバイスのBSDLが必要で、境界レジスタのビット順序を知る必要があります。いくつかのベンダーは、製造時に境界スキャンセルをロックすることに注意してください。

## 現代のターゲットと注意事項

- ESP32‑S3/C3はネイティブUSB‑JTAGブリッジを含んでおり、OpenOCDは外部プローブなしでUSB経由で直接通信できます。トリアージやダンプに非常に便利です。
- RISC‑Vデバッグ（v0.13+）はOpenOCDによって広くサポートされています。コアを安全に停止できない場合は、メモリアクセスにはSBAを優先してください。
- 多くのMCUはデバッグ認証とライフサイクル状態を実装しています。JTAGが死んでいるように見えるが電源が正しい場合、デバイスは閉じた状態にフューズされているか、認証されたプローブが必要です。

## 防御と強化（実際のデバイスで期待されること）

- 製造時にJTAG/SWDを永久に無効にするかロックします（例：STM32 RDPレベル2、PAD JTAGを無効にするESP eFuses、NXP/Nordic APPROTECT/DPAP）。
- 製造アクセスを維持しながら、認証されたデバッグを要求します（ARMv8.2‑A ADIv6デバッグ認証、OEM管理のチャレンジ‑レスポンス）。
- 簡単なテストパッドを配線しないでください；テストビアを埋め、TAPを隔離するために抵抗を取り除く/配置し、キー付きコネクタやポゴピンフィクスチャを使用します。
- 電源オンデバッグロック：セキュアブートを強制する初期ROMの背後にTAPをゲートします。

## 参考文献

- OpenOCDユーザーガイド – JTAGコマンドと設定。 https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAGデバッグ（USB‑JTAG、OpenOCDの使用）。 https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
