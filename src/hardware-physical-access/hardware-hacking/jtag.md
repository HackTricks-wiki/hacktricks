# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## より安全なピンの特定とハードウェアのセットアップ

- まずマルチメーターでVtrefとGNDを特定します。多くのアダプターは、I/O電圧の設定にVtrefを必要とします。
- レベルシフター：プッシュプル信号向けに設計された双方向レベルシフターを使用してください（JTAGラインはオープンドレインではありません）。JTAGには、方向自動判定式のI2C用レベルシフターを使用しないでください。
- 便利なアダプター：FT2232H/FT232Hボード（例：Tigard）、CMSIS-DAP、J-Link、ST-LINK（ベンダー固有）、ESP-USB-JTAG（ESP32-Sx上）。最低限、TCK、TMS、TDI、TDO、GND、Vtrefを接続します。必要に応じてTRSTとSRSTも接続します。

未文書化のヘッダーでは、ターゲットの電源を切った状態で、既知のグランドプレーンとの導通を確認してGNDを特定します。電圧モードに切り替えて電源を入れた後は、高電圧のピンをすべてVtrefと判断しないでください。デジタル入力のHighも、マルチメーターでは似た値に見えることがあります。候補となる電源ラインを近くのデカップリングコンデンサーまでたどり、オシロスコープで電源投入時と電源遮断時の波形を比較します。コンデンサーの充放電を示すような緩やかな立ち上がりや立ち下がりは、電源または基準電圧のネットである証拠になりますが、レベルシフト対応プローブを接続する前に、電圧と配線を確認してください。PiFexでは、デフォルトの3.3 V設定の代わりに、`VCCA_IN`を通じて外部の低電圧ターゲットリファレンスを選択できます。<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum**は、Arduino互換MCU、または実験的にRaspberry Piに読み込ませて、未知のJTAGピン配置を総当たりで調べ、命令レジスターを列挙できるツールです。<sup>[[3]](#references)</sup>

- Arduino：デジタルピンD2～D11を、JTAGの候補となるパッド／テストポイントに最大10個まで接続し、ArduinoのGNDをターゲットのGNDに接続します。電源ラインが安全だと分かっている場合を除き、ターゲットには別途電源を供給してください。3.3 Vロジック（例：Arduino Due）を推奨します。1.8～3.3 Vのターゲットを調べる場合は、レベルシフターまたは直列抵抗を使用してください。
- Raspberry Pi：Pi版では使用できるGPIOが少ないため（スキャンに時間がかかります）、最新のピン配置と制約をリポジトリで確認してください。

書き込み後、115200 baudでシリアルモニターを開き、ヘルプを表示するには`h`を送信します。一般的な手順は次のとおりです。

- `l` 誤検出を避けるため、ループバックを検出する
- `r` 必要に応じて内部プルアップを切り替える
- `s` TCK/TMS/TDI/TDO（場合によってはTRST/SRSTも）をスキャンする
- `y` 未文書化のopcodeを見つけるため、IRを総当たりで調べる
- `x` ピン状態のboundary-scanスナップショットを取得する

![JTAG - JTAGenum: x ピン状態のboundary-scanスナップショット](<../../images/image (939).png>)

![JTAG - JTAGenum: x ピン状態のboundary-scanスナップショット](<../../images/image (578).png>)

![JTAG - JTAGenum: x ピン状態のboundary-scanスナップショット](<../../images/image (774).png>)



有効なTAPが見つかると、検出されたピンを示す`FOUND!`で始まる行が表示されます。

### JTAGenumの安全に関する注意

- 必ずグランドを共有し、ターゲットのVtrefを超える電圧を未知のピンに印加しないでください。不確かな場合は、候補ピンに100～470 Ωの直列抵抗を追加してください。
- デバイスが4線式JTAGではなくSWD/SWJを使用している場合、JTAGenumでは検出できないことがあります。SWDツール、またはSWJ-DPに対応したアダプターを試してください。

## go-jtagenumによるGPIOピンの特定

電源が入ったターゲットに対し、グランドが共通であることとI/O電圧の互換性を確認したうえで、`go-jtagenum`を使ってRaspberry PiのGPIOからJTAG信号の候補を列挙できます。`-pins`のJSONでは、ラベルは物理ヘッダーの位置ではなく**GPIO番号**に対応します。<sup>[[5]](#references)</sup> SSDの例では、最初のIDCODEスキャンで、値が変化する異常に長いチェーンも報告されました。TDO候補の値が変化するだけでは、有効なTAPの証拠にはなりません。TDIから1ビットのバイパスレジスターを経由してTDOへ既知のビットパターンをシフトするBYPASSスキャンで、妥当な結果を再確認してください。<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

そのボードでは、BYPASS により `TCK=10`、`TMS=14`、`TDI=9`、`TDO=15` が確認されました。追加のピンは nTRST の候補として**可能性がある**にすぎません。候補からすべてゼロ、または一貫しないパターンが返る場合は、信号を割り当てる前に、接触状態、ターゲットの電源、プルアップ、クロック／リセットの遅延を確認してください。<sup>[[4]](#references)[[5]](#references)</sup> このツールでは `test_bypass` とともに `-known-pins` を指定して、復元したピン割り当てを再テストすることもできます。<sup>[[5]](#references)</sup>

## UrJTAG で未公開 TAP の特性を調べる

ピン配置が判明しても、デバッグに必要な命令レジスタ（IR）の opcode やデータレジスタ（DR）の幅は特定できません。Raspberry Pi GPIO ケーブルに対応した UrJTAG のビルドで、復元したピン配置を設定し、`idcode`、`detect`、続いて `discover` を実行します。SSD の例では、1 つの TAP、4 ビットの IR、および IR 値ごとに異なる DR 幅が返されました。DR 長が `-1` と表示されたり、「TDO stuck at 0」と表示されたりする場合、それは使用可能なレジスタ定義ではありません。幅を割り当てるのではなく、タイミング、配線、選択されている命令を調べてください。<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

これはTAPの偵察であり、自動的なCPU識別ではありません。取得したIDCODEをデバイスのドキュメントおよび対応するOpenOCDターゲットと照合してください。UrJTAGのローカルなメーカー データベースでは、有効なIDがunknownと表示される場合があります。<sup>[[4]](#references)</sup>

## OpenOCDでの最初の接続（スキャンとIDCODE）

OpenOCDはJTAG/SWD向けの事実上のOSSです。対応アダプターを使えば、チェーンをスキャンしてIDCODEを読み取れます。<sup>[[1]](#references)</sup>

- J-Linkを使った一般的な例：
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32-S3内蔵USB-JTAG（外部プローブ不要）：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notes

- 「すべて1/0」のIDCODEが表示された場合は、配線、電源、Vtref、およびポートがfuse/option bytesによってロックされていないかを確認してください。
- 未知のchainを立ち上げる際に手動でTAPを操作する方法については、OpenOCDの低レベルコマンド`irscan`/`drscan`を参照してください。<sup>[[1]](#references)</sup>

## Bring an undocumented target into OpenOCD

TAP IDとIR lengthが判明したら、OpenOCDの`cpu/`、`target/`、`board/`スクリプトを調べて**一致するCPU architecture**を探し、adapterとtargetの設定を別々に作成します。<sup>[[4]](#references)[[6]](#references)</sup> 以下のPi GPIOマッピングとARCv2 targetは、動作確認済みのSSDの例であり、あらゆるJTAG構成に適用できるものではありません。ARC targetの選択とdebug設定はこのデバイスで動作した仮定に基づいています。別のボードでは、対象の測定済みID、IR length、architecture、GPIO番号に置き換えてください。<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

`openocd -f raspberrypi-io.cfg -f target.cfg` を実行し、メモリを読み取る前に TAP の検査が成功することを確認します。この例では、Telnet はポート `4444`、GDB server はポート `3333` で起動しました。IDCODE が認識されただけでは、選択した CPU target を検査またはデバッグできるとは限りません。<sup>[[4]](#references)</sup> adapter で `adapter gpio` による remapping が可能な場合、Raspberry Pi の GPIO は breakout board 上で JTAG と表示されたピンである必要はありません。<sup>[[4]](#references)[[6]](#references)</sup>

## CPU の停止とメモリ/flash のダンプ

TAP が認識され、target script を選択したら、core を停止してメモリ領域または内蔵 flash をダンプできます。例（target、ベースアドレス、サイズを調整してください）：<sup>[[1]](#references)</sup>

- init 後の汎用 target：
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（利用可能な場合はSBAを優先）:
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3、OpenOCD helperを介して書き込みまたは読み取り:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### メモリダンプのヒント

- 長時間のダンプの前に、`mdw/mdh/mdb`を使ってメモリを簡単に確認する。
- 複数デバイスのチェーンでは、対象外のデバイスにBYPASSを設定するか、すべてのTAPを定義したboard fileを使う。

メモリマップが不明な場合、SSDの調査では1 MiBのダンプを調べ、認識可能なコントローラの文字列を探した後、OpenOCD経由でアーキテクチャに対応したGDBを使い、`$pc`、逆アセンブリ、レジスタを調査した。これらの実行中のアドレスを手掛かりに、2回目の領域ダンプを行い、ARCに対応したGhidraビルドで一致する命令と照合した。文字列は妥当性を確認する手掛かりにすぎず、イメージが完全であることや、正しくマッピングされていることの証明にはならない。<sup>[[4]](#references)</sup> より広範な静的解析の手順については、[firmware analysis](../firmware-analysis/)を参照。

## Boundary-scanのテクニック（EXTEST/SAMPLE）

CPUのデバッグアクセスがロックされていても、boundary-scanが公開されている場合がある。UrJTAG/OpenOCDを使うと、次のことができる。<sup>[[1]](#references)</sup>
- SAMPLEでシステムの動作中にピンの状態をスナップショットし、バスのアクティビティを見つけたり、ピンのマッピングを確認したりする。
- EXTESTでピンを駆動する（例：基板の配線が許せば、MCU経由で外部SPIフラッシュのラインをbit-bangして、オフラインで読み取る）。

FT2232xアダプターを使ったUrJTAGの最小限の手順：
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
デバイスのBSDLが必要です。境界レジスタのビット順序を確認してください。一部のベンダーは製造時にboundary-scanセルをロックするため、注意してください。

## 最新のターゲットと注意点

- ESP32‑S3/C3にはネイティブのUSB‑JTAGブリッジが搭載されており、OpenOCDは外部プローブなしでUSB経由で直接通信できます。トリアージやダンプの取得に非常に便利です。<sup>[[2]](#references)</sup>
- RISC‑V debug（v0.13以降）はOpenOCDで広くサポートされています。コアを安全に停止できない場合は、メモリアクセスにSBAを優先してください。
- 多くのMCUはdebug authenticationとライフサイクル状態を実装しています。電源に問題がないのにJTAGが反応しない場合、デバイスがclosed状態にヒューズ設定されているか、認証済みプローブが必要な可能性があります。

## 防御と強化（実デバイスで想定されること）

- 製造時にJTAG/SWDを恒久的に無効化またはロックする（例：STM32 RDP level 2、PAD JTAGを無効化するESP eFuse、NXP/Nordic APPROTECT/DPAP）。
- 製造時のアクセスを維持しながら、認証済みdebugを必須にする（ARMv8.2‑A ADIv6 Debug Authentication、OEM管理のchallenge-response）。
- 見つけやすいtest padへの配線を避ける。test viaを埋め、抵抗を取り外す／実装してTAPを切り離し、キー付きコネクタまたはpogo-pin fixtureを使用する。
- 電源投入時にdebugをロックする：セキュアブートを適用する初期ROMの背後にTAPを配置する。

## References

- [1] [OpenOCDユーザーガイド – JTAGコマンドと設定](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAGデバッグ（USB‑JTAG、OpenOCDの使用方法）](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – ArduinoベースのJTAGピン配置スキャナー](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — Raspberry Piを使ったJTAG Hacking](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — GPIOによるJTAG列挙](https://github.com/gremwell/go-jtagenum)
- [6] [OpenOCDユーザーガイド — Debug Adapterの設定](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
