# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) は、Arduino互換MCUまたは（実験的に）Raspberry Piにロードして、未知のJTAGピン配置を総当たりし、命令レジスタを列挙することもできるツールです。

- Arduino: デジタルピンD2〜D11を、最大10個のJTAG候補パッド/テストポイントに接続し、ArduinoのGNDをターゲットのGNDに接続します。電源レールが安全だと分かっている場合を除き、ターゲットには別途電源を供給してください。3.3 Vロジック（例: Arduino Due）を優先するか、1.8〜3.3 Vのターゲットをプローブする際はレベルシフター/直列抵抗を使用してください。
- Raspberry Pi: Pi版では使用可能なGPIOが少ないため、スキャンは遅くなります。現在のピンマップと制約については、リポジトリを確認してください。

書き込み後、115200 baudでシリアルモニターを開き、`h`を送信してヘルプを表示します。一般的な流れ:

- `l` 誤検出を避けるためにループバックを検索
- `r` 必要に応じて内部プルアップを切り替え
- `s` TCK/TMS/TDI/TDO（場合によってはTRST/SRSTも）をスキャン
- `y` IRを総当たりして未文書化のopcodeを発見
- `x` boundary-scanでピン状態をスナップショット

![JTAG - JTAGenum: x boundary-scanによるピン状態のスナップショット](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scanによるピン状態のスナップショット](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scanによるピン状態のスナップショット](<../../images/image (774).png>)



有効なTAPが見つかると、発見されたピンを示す`FOUND!`で始まる行が表示されます。

ヒント
- 必ずグランドを共有し、未知のピンをターゲットのVtrefを超える電圧で駆動しないでください。不明な場合は、候補ピンに100〜470 Ωの直列抵抗を追加してください。
- デバイスが4線式JTAGではなくSWD/SWJを使用している場合、JTAGenumでは検出できない可能性があります。SWD tools、またはSWJ-DPをサポートするアダプターを試してください。

## より安全なピン探索とハードウェア設定

- まずマルチメーターでVtrefとGNDを特定します。多くのアダプターでは、I/O電圧を設定するためにVtrefが必要です。
- レベルシフト: push-pull信号向けに設計された双方向レベルシフターを優先してください（JTAGラインはopen-drainではありません）。JTAGには自動方向I2Cシフターを使用しないでください。
- 便利なアダプター: FT2232H/FT232Hボード（例: Tigard）、CMSIS-DAP、J-Link、ST-LINK（ベンダー固有）、ESP-USB-JTAG（ESP32-Sx上）。最低限、TCK、TMS、TDI、TDO、GND、Vtrefを接続し、必要に応じてTRSTとSRSTも接続します。

## OpenOCDでの初回接続（スキャンとIDCODE）

OpenOCDは、JTAG/SWD向けの事実上のOSSです。サポート対象のアダプターを使用すれば、チェーンをスキャンしてIDCODEを読み取れます。

- J-Linkを使用する一般的な例:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32-S3 built-in USB-JTAG（外部プローブ不要）：
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
注記
- 「all ones/zeros」IDCODE が表示された場合は、配線、電源、Vtref、およびポートが fuse/option bytes によってロックされていないことを確認してください。
- 不明な chain の bring-up 時に手動で TAP を操作するには、OpenOCD の low-level `irscan`/`drscan` を参照してください。<sup>[[1]](#references)</sup>

## CPU を halt して memory/flash を dump する

TAP が認識され、target script が選択されたら、core を halt して memory 領域または internal flash を dump できます。例（target、base addresses、sizes は適宜調整してください）:

- init 後の generic target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（利用可能な場合はSBAを優先）：
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3、OpenOCD helperを介して書き込みまたは読み取り:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- 長時間のダンプの前に、`mdw/mdh/mdb` を使ってメモリを sanity-check する。
- 複数デバイスの chain では、対象外のデバイスで BYPASS を設定するか、すべての TAP を定義した board file を使用する。

## Boundary-scan tricks (EXTEST/SAMPLE)

CPU の debug access がロックされていても、boundary-scan が公開されたままの場合があります。UrJTAG/OpenOCD を使用すると、以下が可能です。
- システムの実行中に SAMPLE でピンの状態をスナップショットし、バスのアクティビティを確認してピンマッピングを検証する。
- EXTEST でピンを駆動する（例：MCU 経由で外部 SPI flash のラインを bit-bang し、board の配線が対応していればオフラインで読み取る）。

FT2232x adapter を使用した最小限の UrJTAG フロー:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
デバイスの BSDL が必要です。boundary register のビット順序を把握するためです。本番環境では一部のベンダーが boundary-scan cell をロックしていることに注意してください。

## 最新の target と注意事項

- ESP32‑S3/C3 には native USB‑JTAG bridge が搭載されています。OpenOCD は外部 probe なしで USB 経由で直接通信できます。triage や dump に非常に便利です。<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) は OpenOCD で広くサポートされています。core を安全に halt できない場合は、memory access に SBA を優先してください。
- 多くの MCU は debug authentication と lifecycle state を実装しています。電源が正常なのに JTAG が dead に見える場合、device が closed state に fuse されているか、authenticated probe が必要な可能性があります。

## 防御と hardening（実際の device で想定されるもの）

- 本番環境では JTAG/SWD を恒久的に無効化または lock する（例：STM32 RDP level 2、PAD JTAG を無効化する ESP eFuse、NXP/Nordic APPROTECT/DPAP）。
- 製造時の access を維持しながら、authenticated debug（ARMv8.2‑A ADIv6 Debug Authentication、OEM 管理の challenge‑response）を必須にする。
- 簡単にアクセスできる test pad を配置しない。test via を埋め込み、resistor を remove/populate して TAP を分離し、keying 付き connector または pogo‑pin fixture を使用する。
- Power-on debug lock：secure boot を適用する初期 ROM によって TAP を gate する。

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
