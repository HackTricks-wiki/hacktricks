# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum**は、Arduino互換MCU、または実験的にRaspberry Piに書き込んで、未知のJTAG pinoutをbrute-forceし、instruction registerを列挙できるツールです。<sup>[[3]](#references)</sup>

- Arduino: デジタルピンD2–D11を、JTAGの候補となる最大10個のpad/testpointに接続し、ArduinoのGNDをターゲットのGNDに接続します。電源レールが安全だと確認できていない場合は、ターゲットには別途給電してください。3.3 Vロジック（例: Arduino Due）を優先するか、1.8–3.3 Vのターゲットをプロービングする場合はlevel shifter/series resistorを使用します。
- Raspberry Pi: Pi版で使用できるGPIOは少ないため（スキャンが遅くなります）、最新のpin mapと制約をrepoで確認してください。

書き込み後、115200 baudでserial monitorを開き、`h`を送信するとヘルプが表示されます。一般的な流れ:

- `l` loopbackを検出してfalse positiveを回避する
- `r` 必要に応じて内部pull-upを切り替える
- `s` TCK/TMS/TDI/TDO（場合によってはTRST/SRSTも）をスキャンする
- `y` IRをbrute-forceし、未公開のopcodeを検出する
- `x` boundary-scanでpin状態のスナップショットを取得する

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



有効なTAPが見つかると、検出されたpinを示す`FOUND!`で始まる行が表示されます。

### JTAGenum Safety Tips

- 必ずGNDを共通にし、未知のpinにターゲットのVtrefを超える電圧を絶対に印加しないでください。不明な場合は、候補pinに100–470 Ωのseries resistorを追加します。
- デバイスが4-wire JTAGではなくSWD/SWJを使用している場合、JTAGenumでは検出できないことがあります。SWDツール、またはSWJ‑DP対応adapterを試してください。

## より安全なpin探しとhardware setup

- まずmultimeterでVtrefとGNDを特定します。多くのadapterはI/O電圧の設定にVtrefを必要とします。
- Level shifting: push-pull信号用に設計されたbidirectional level shifterを優先します（JTAG lineはopen-drainではありません）。JTAGではauto-direction I2C shifterを避けてください。
- 便利なadapter: FT2232H/FT232Hボード（例: Tigard）、CMSIS-DAP、J‑Link、ST‑LINK（vendor-specific）、ESP‑USB‑JTAG（ESP32‑Sx上）。最低限、TCK、TMS、TDI、TDO、GND、Vtrefを接続します。必要に応じてTRSTとSRSTも接続します。

## OpenOCDでの最初の操作（scanとIDCODE）

OpenOCDは、JTAG/SWD用の事実上のOSSです。対応adapterを使うと、chainをスキャンしてIDCODEを読み取れます。<sup>[[1]](#references)</sup>

- J‑Linkを使う一般的な例:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 内蔵 USB‑JTAG（外部プローブ不要）:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### 注意事項

- IDCODE が「すべて 1／0」になる場合は、配線、電源、Vtref、およびヒューズ／オプションバイトによってポートがロックされていないかを確認してください。
- 不明な chain の立ち上げ時に手動で TAP を操作するには、OpenOCD の低レベル `irscan`／`drscan` を参照してください。<sup>[[1]](#references)</sup>

## CPU の停止とメモリ／flash のダンプ

TAP が認識され、target script を選択したら、コアを停止してメモリ領域や内蔵 flash をダンプできます。例（target、ベースアドレス、サイズは適宜変更してください）：<sup>[[1]](#references)</sup>

- 初期化後の汎用 target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（利用可能な場合はSBAを優先）:
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3、OpenOCD helperを介したプログラムまたは読み取り:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### メモリダンプのヒント

- 長時間のダンプを行う前に、`mdw/mdh/mdb` を使ってメモリの状態を確認する。
- 複数デバイスのチェーンでは、対象外のデバイスに BYPASS を設定するか、すべての TAP を定義した board file を使用する。

## Boundary-scan のテクニック（EXTEST/SAMPLE）

CPU の debug access がロックされていても、boundary-scan が公開されている場合があります。UrJTAG/OpenOCD を使うと、次のことができます。<sup>[[1]](#references)</sup>
- SAMPLE でシステムの稼働中にピンの状態をスナップショットし、バスの動作を調べたり、ピンのマッピングを確認したりする。
- EXTEST でピンを駆動する（例：基板の配線が許せば、MCU 経由で外部 SPI flash のラインを bit-bang して、オフラインで読み取る）。

FT2232x adapter を使った UrJTAG の最小限の手順：
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
デバイスのBSDLが必要です。boundary registerのビット順を確認するためです。一部のベンダーは製造時にboundary-scan cellsをロックするため、注意してください。

## 最新のターゲットと注意点

- ESP32‑S3/C3にはネイティブのUSB‑JTAGブリッジが搭載されており、外部プローブなしでOpenOCDからUSB経由で直接接続できます。トリアージやダンプに非常に便利です。<sup>[[2]](#references)</sup>
- RISC‑V debug（v0.13以降）はOpenOCDで広くサポートされています。コアを安全に停止できない場合は、メモリアクセスにSBAを優先してください。
- 多くのMCUはdebug authenticationとライフサイクル状態を実装しています。電源に問題がないのにJTAGが反応しない場合、デバイスがヒューズ設定によって閉鎖状態になっているか、認証済みプローブが必要な可能性があります。

## 防御と強化（実機で想定されること）

- 製造時にJTAG/SWDを恒久的に無効化するか、ロックします（例：STM32 RDP level 2、PAD JTAGを無効化するESP eFuses、NXP/Nordic APPROTECT/DPAP）。
- 製造時のアクセスを維持しつつ、認証済みdebugを必須にします（ARMv8.2‑A ADIv6 Debug Authentication、OEM管理のchallenge-response）。
- 簡単にアクセスできるテストパッドを設けないでください。テストビアを埋め、抵抗を取り外す／実装してTAPを分離し、キー付きコネクタまたはpogo-pin fixtureを使用します。
- 電源投入時にdebugをロックします。セキュアブートを強制する初期ROMを介してTAPを制御してください。

## References

- [1] [OpenOCDユーザーガイド – JTAGコマンドと設定](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAGデバッグ（USB‑JTAG、OpenOCDの使用方法）](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – ArduinoベースのJTAGピン配置スキャナー](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
