# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** は、Arduino互換 MCU、または実験的に Raspberry Pi 上で動作させることで、未知の JTAG ピン配置を brute-force し、instruction register を列挙できる tool です。<sup>[[3]](#references)</sup>

- Arduino: デジタルピン D2–D11 を、最大10個の JTAG と推測される pad/testpoint に接続し、Arduino GND を対象デバイスの GND に接続します。電源レールが安全だと分かっていない限り、対象デバイスには別途給電してください。3.3 V ロジック（例: Arduino Due）を優先するか、1.8–3.3 V の対象を probe する際は level shifter または series resistor を使用してください。
- Raspberry Pi: Pi 版では使用可能な GPIO が少ないため（その分 scan は遅くなります）、現在の pin map と制約については repo を確認してください。

flash 後、serial monitor を 115200 baud で開き、`h` を送信して help を表示します。一般的な flow は次のとおりです。

- `l` false positive を避けるため loopback を検出
- `r` 必要に応じて internal pull-up を切り替え
- `s` TCK/TMS/TDI/TDO（場合によっては TRST/SRST）を scan
- `y` IR を brute-force して undocumented opcode を発見
- `x` pin state の boundary-scan snapshot

![JTAG - JTAGenum: x pin state の boundary-scan snapshot](<../../images/image (939).png>)

![JTAG - JTAGenum: x pin state の boundary-scan snapshot](<../../images/image (578).png>)

![JTAG - JTAGenum: x pin state の boundary-scan snapshot](<../../images/image (774).png>)



有効な TAP が見つかると、発見された pin を示す `FOUND!` で始まる行が表示されます。

### JTAGenum の安全上のヒント

- 必ず ground を共有し、対象の Vtref を超える電圧を未知の pin に印加しないでください。不明な場合は、候補 pin に 100–470 Ω の series resistor を追加してください。
- デバイスが 4-wire JTAG ではなく SWD/SWJ を使用している場合、JTAGenum では検出できない可能性があります。SWD tools、または SWJ-DP をサポートする adapter を試してください。

## より安全な pin 探索と hardware setup

- まず multimeter で Vtref と GND を特定します。多くの adapter は I/O voltage を設定するために Vtref を必要とします。
- Level shifting: push-pull signal 用に設計された bidirectional level shifter を優先してください（JTAG line は open-drain ではありません）。JTAG には auto-direction I2C shifter を使用しないでください。
- Useful adapter: FT2232H/FT232H board（例: Tigard）、CMSIS-DAP、J-Link、ST-LINK（vendor-specific）、ESP-USB-JTAG（ESP32-Sx 上）。最低限 TCK、TMS、TDI、TDO、GND、Vtref を接続し、必要に応じて TRST と SRST も接続します。

## OpenOCD との最初の接続（scan と IDCODE）

OpenOCD は JTAG/SWD 用の de-facto OSS です。対応する adapter を使えば、chain を scan して IDCODE を読み取れます。<sup>[[1]](#references)</sup>

- J-Link を使った Generic example:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3内蔵USB‑JTAG（外部プローブ不要）：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### メモ

- 「all ones/zeros」のIDCODEが返される場合は、配線、電源、Vtref、およびポートがfuse/option bytesによってロックされていないことを確認してください。
- 不明なchainをbring upする際に手動でTAPを操作するには、OpenOCDのlow-levelな`irscan`/`drscan`を参照してください。<sup>[[1]](#references)</sup>

## CPUを停止してmemory/flashをdumpする

TAPが認識され、target scriptを選択したら、coreを停止してmemory領域またはinternal flashをdumpできます。例（target、base address、sizeは調整してください）：<sup>[[1]](#references)</sup>

- init後のgeneric target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（利用可能な場合は SBA を優先）：
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3、OpenOCD helper を介してプログラムまたは読み取り：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Memory-DumpingのTips

- 長時間のdumpの前に、`mdw/mdh/mdb`を使ってメモリの状態をsanity-checkする。
- 複数デバイスのchainでは、target以外にBYPASSを設定するか、すべてのTAPを定義したボードファイルを使用する。

## Boundary-scan tricks (EXTEST/SAMPLE)

CPUのdebug accessがロックされていても、boundary-scanが露出している場合がある。UrJTAG/OpenOCDを使うと、次のことができる:<sup>[[1]](#references)</sup>
- SAMPLEでシステムの動作中にpinの状態をsnapshotする（bus activityの検出、pin mappingの確認）。
- EXTESTでpinをdriveする（ボードの配線が対応していれば、MCU経由で外部SPI flashのlineをbit-bangして、offlineで読み取るなど）。

FT2232x adapterを使った最小限のUrJTAG flow:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
デバイスの BSDL が必要です。boundary register のビット順序を把握するためです。なお、一部のベンダーは production 環境で boundary-scan cell をロックしています。

## Modern targets and notes

- ESP32-S3/C3 には native USB-JTAG bridge が搭載されています。OpenOCD は external probe なしで USB 経由で直接通信できます。triage や dump に非常に便利です。<sup>[[2]](#references)</sup>
- RISC-V debug (v0.13+) は OpenOCD で広くサポートされています。core を安全に halt できない場合は、memory access に SBA を優先してください。
- 多くの MCU は debug authentication と lifecycle state を実装しています。電源が正常なのに JTAG が反応しない場合、device が closed state に fuse されているか、authenticated probe が必要な可能性があります。

## Defenses and hardening (what to expect on real devices)

- production 環境では JTAG/SWD を permanently disable または lock します（例：STM32 RDP level 2、PAD JTAG を disable する ESP eFuse、NXP/Nordic APPROTECT/DPAP）。
- manufacturing access を維持しながら、authenticated debug（ARMv8.2‑A ADIv6 Debug Authentication、OEM 管理の challenge-response）を要求します。
- 簡単にアクセスできる test pad は配置しないでください。test via を埋め込み、resistor を remove/populate して TAP を isolate し、keying 付き connector または pogo-pin fixture を使用します。
- Power-on debug lock：secure boot を強制する early ROM によって TAP を gate します。

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino-based JTAG pinout scanner](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
