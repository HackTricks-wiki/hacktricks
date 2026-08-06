# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) は、Arduino互換MCUまたは（実験的に）Raspberry Piにロードして、未知のJTAGピン配置をbrute-forceし、命令レジスタを列挙することもできるツールです。

- Arduino: デジタルピンD2〜D11を、JTAGの候補となる最大10個のパッドまたはテストポイントに接続し、ArduinoのGNDを対象デバイスのGNDに接続します。電源レールが安全だと確信できない限り、対象デバイスには別途電源を供給してください。3.3 Vロジック（例: Arduino Due）を優先するか、1.8〜3.3 Vの対象デバイスをプローブする際はレベルシフターまたは直列抵抗を使用してください。
- Raspberry Pi: Pi版では使用可能なGPIOが少ないため、スキャンが遅くなります。現在のピンマップと制約については、リポジトリを確認してください。

書き込み後、115200 baudでシリアルモニターを開き、`h`を送信するとヘルプが表示されます。一般的な流れは次のとおりです。

- `l` 誤検出を避けるためにloopbackを検出
- `r` 必要に応じて内部pull-upを切り替え
- `s` TCK/TMS/TDI/TDO（場合によってはTRST/SRSTも）をスキャン
- `y` IRをbrute-forceして、文書化されていないopcodeを発見
- `x` boundary-scanでピン状態をスナップショット

![JTAG - JTAGenum: x boundary-scanによるピン状態のスナップショット](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scanによるピン状態のスナップショット](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scanによるピン状態のスナップショット](<../../images/image (774).png>)



有効なTAPが見つかると、発見されたピンを示す`FOUND!`で始まる行が表示されます。

ヒント
- 必ずグラウンドを共有し、対象デバイスのVtrefを超える電圧を未知のピンに印加しないでください。判断に迷う場合は、候補ピンに100〜470 Ωの直列抵抗を追加してください。
- デバイスが4線式JTAGではなくSWD/SWJを使用している場合、JTAGenumでは検出できないことがあります。SWD toolsまたはSWJ-DPをサポートするアダプターを試してください。

## より安全なピン探索とハードウェアセットアップ

- まずマルチメーターでVtrefとGNDを特定します。多くのアダプターでは、I/O電圧を設定するためにVtrefが必要です。
- Level shifting: push-pull信号用に設計された双方向レベルシフターを優先してください（JTAGラインはopen-drainではありません）。JTAGには自動方向検出I2Cシフターを使用しないでください。
- 有用なアダプター: FT2232H/FT232Hボード（例: Tigard）、CMSIS-DAP、J-Link、ST-LINK（vendor-specific）、ESP-USB-JTAG（ESP32-Sx上）。最低限、TCK、TMS、TDI、TDO、GND、Vtrefを接続し、必要に応じてTRSTとSRSTも接続します。

## OpenOCDとの最初の接触（スキャンとIDCODE）

OpenOCDはJTAG/SWD向けのde-facto OSSです。対応アダプターを使用すると、chainをスキャンしてIDCODEを読み取れます:<sup>[[1]](#references)</sup>

- J-Linkを使用するGeneric example:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32-S3 内蔵 USB-JTAG（外部プローブ不要）：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notes
- 「all ones/zeros」のIDCODEが取得される場合は、配線、電源、Vtref、およびポートがfuse/option bytesによってlockされていないことを確認します。
- 不明なchainのbring-up時に手動でTAPを操作する場合は、OpenOCDの低レベルな`irscan`/`drscan`を参照してください。<sup>[[1]](#references)</sup>

## CPUをhaltしてmemory/flashをdumpする

TAPが認識され、target scriptを選択したら、coreをhaltしてmemory領域またはinternal flashをdumpできます。例（target、base address、sizeは調整してください）：<sup>[[1]](#references)</sup>

- init後のGeneric target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（利用可能な場合は SBA を優先）:
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3、OpenOCD helper経由でプログラムまたは読み取り:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- 長時間のダンプの前に、`mdw/mdh/mdb` を使ってメモリを sanity-check する。
- 複数デバイスのチェーンでは、対象外のデバイスに BYPASS を設定するか、すべての TAP を定義した board file を使用する。

## Boundary-scan の tricks（EXTEST/SAMPLE）

CPU の debug access がロックされていても、boundary-scan が公開されたままの場合がある。UrJTAG/OpenOCD を使うと、次のことができる。<sup>[[1]](#references)</sup>
- SAMPLE でシステムの実行中に pin の状態をスナップショットし、バスの activity を検出したり、pin mapping を確認したりする。
- EXTEST で pin を駆動する（たとえば、board の配線が対応していれば、MCU 経由で外部 SPI flash のラインを bit-bang し、オフラインで読み取る）。

FT2232x adapter を使った最小限の UrJTAG flow:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
デバイスの BSDL が必要です。boundary register の bit ordering を把握するためです。一部のベンダーは production で boundary-scan cells を lock しているため、注意してください。

## Modern targets and notes

- ESP32‑S3/C3 には native USB‑JTAG bridge が含まれており、外部 probe なしで OpenOCD から USB 経由で直接通信できます。triage や dump に非常に便利です。<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) は OpenOCD で広くサポートされています。core を安全に halt できない場合は、memory access に SBA を優先してください。
- 多くの MCU は debug authentication と lifecycle states を実装しています。電源が正常なのに JTAG が dead に見える場合、device が closed state に fuse されているか、authenticated probe が必要な可能性があります。

## Defenses and hardening (what to expect on real devices)

- production で JTAG/SWD を permanently disable または lock する（例：STM32 RDP level 2、PAD JTAG を disable する ESP eFuses、NXP/Nordic APPROTECT/DPAP）。
- manufacturing access を維持しながら、authenticated debug（ARMv8.2‑A ADIv6 Debug Authentication、OEM 管理の challenge-response）を要求する。
- 簡単にアクセスできる test pads を route しない。test vias を埋め、resistors を remove/populate して TAP を isolate し、keying 付き connectors または pogo-pin fixtures を使用する。
- Power-on debug lock：secure boot を強制する early ROM の背後で TAP を gate する。

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
