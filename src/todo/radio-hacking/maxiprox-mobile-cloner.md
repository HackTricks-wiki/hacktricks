# ポータブル HID MaxiProx 125 kHz Mobile Cloner の構築

{{#include ../../banners/hacktricks-training.md}}

## 目的
商用電源で動作する HID MaxiProx 5375 long-range 125 kHz reader を、現場へ持ち運べるバッテリー駆動の badge cloner に改造し、physical-security assessments 中に proximity card を気付かれずに収集できるようにする。

ここで説明する改造は、TrustedSec の「Let’s Clone a Cloner – Part 3: Putting It All Together」research series をもとにしており、機械、電気、RF に関する考慮事項を組み合わせ、完成したデバイスをバックパックに入れて現場ですぐ使用できるようにする。<sup>[[1]](#references)</sup>

> [!warning]
> 商用電源機器や Lithium-ion power-bank の取り扱いは危険な場合がある。回路に**通電する前**にすべての接続を確認し、reader の detuning を避けるため、antenna、coax、ground plane は工場設計時の状態を正確に維持すること。

## 部品表 (BOM)

* HID MaxiProx 5375 reader（または 12 V HID Prox® long-range reader）
* ESP RFID Tool v2.2（ESP32-based Wiegand sniffer/logger）
* 12 V @ ≥3 A を negotiate できる USB-PD (Power-Delivery) trigger module
* 100 W USB-C power-bank（12 V PD profile を出力）
* 26 AWG silicone-insulated hook-up wire – red/white
* Panel-mount SPST toggle switch（beeper kill-switch 用）
* NKK AT4072 switch-guard / accident-proof cap
* はんだごて、solder wick、desolder pump
* ABS対応 hand tools: coping-saw、utility-knife、flat & half-round files
* Drill bits 1/16″ (1.5 mm) および 1/8″ (3 mm)
* 3 M VHB double-sided tape および Zip-ties

## 1. 電源サブシステム

1. Logic PCB 用の 5 V を生成するために使用されている factory buck-converter daughter-board を desolder して取り外す。
2. ESP RFID Tool の隣に USB-PD trigger を取り付け、trigger の USB-C receptacle を enclosure の外側へ引き出す。
3. PD trigger は power-bank から 12 V を negotiate し、それを MaxiProx に直接供給する（reader は本来 10–14 V を想定）。アクセサリへの電力供給用として、ESP board から secondary 5 V rail を取り出す。
4. 100 W battery pack は internal standoff にぴったり接するように配置し、ferrite antenna の上に電源ケーブルが**またがらない**ようにすることで、RF performance を維持する。

## 2. Beeper Kill-Switch – 無音動作

1. MaxiProx logic board 上の 2 つの speaker pad を特定する。
2. *両方*の pad をきれいに wick し、その後 **negative** pad のみを再 solder する。
3. 26 AWG wires（white = negative、red = positive）を beeper pad に solder し、新たに切り開いた slot を通して panel-mount SPST switch へ配線する。
4. switch を open にすると beeper circuit が切断され、reader は完全な無音で動作する – covert badge harvesting に適している。
5. toggle の上に NKK AT4072 spring-loaded safety cap を取り付ける。coping-saw / file で bore を慎重に広げ、switch body に snap で固定できるようにする。guard により、バックパック内部での accidental activation を防止できる。

## 3. Enclosure と機械加工

• flush cutters を使用してから knife と file で、内部の ABS 製「bump-out」を*取り除く*。これにより、大型 USB-C battery を standoff 上に平らに置ける。
• USB-C cable 用に enclosure wall に平行な 2 本の channel を切り、battery を所定位置に固定して movement/vibration をなくす。
• battery の **power** button 用に rectangular aperture を作成する:
1. 位置に paper stencil を tape で貼る。
2. 4 隅すべてに 1/16″ pilot hole を drill する。
3. 1/8″ bit で穴を広げる。
4. coping saw で穴同士をつなぎ、file で edges を仕上げる。
✱  rotary Dremel は*避ける* – 高速 bit が厚い ABS を溶かし、見栄えの悪い edge を残すためである。

## 4. 最終組み立て

1. MaxiProx logic board を再取り付けし、SMA pigtail を reader の PCB ground pad に再 solder する。
2. ESP RFID Tool と USB-PD trigger を 3 M VHB で固定する。
3. すべての wiring を zip-ties で整え、power leads を antenna loop から**十分に離す**。
4. battery が軽く圧縮されるまで enclosure screws を締める。internal friction により、各 card read 後に device が recoil しても pack がずれない。

## 5. Range と Shielding のテスト

* 125 kHz **Pupa** test card を使用した場合、portable cloner は free-air で **約 8 cm** の安定した read を達成し、商用電源での動作と同一だった。<sup>[[1]](#references)</sup>
* reader を薄い金属製 cash box（bank lobby desk を想定）に入れると、range は ≤ 2 cm に低下した。これは、相当量の metal enclosure が effective RF shield として機能することを確認している。<sup>[[1]](#references)</sup>

## 使用手順

1. USB-C battery を充電して接続し、main power switch を flip する。
2. （任意）bench-testing 時に audible feedback を有効にする場合は beeper guard を開く。covert field use の前には lock しておく。
3. target badge holder の横を通過する – MaxiProx が card を energise し、ESP RFID Tool が Wiegand stream を capture する。
4. captured credentials を Wi-Fi または USB-UART 経由で dump し、必要に応じて replay/clone する。

## トラブルシューティング

| 症状 | 考えられる原因 | 対処 |
|---------|--------------|------|
| card を提示すると reader が reboot する | PD trigger が 12 V ではなく 9 V を negotiate した | trigger jumper を確認する / より high-power の USB-C cable を試す |
| read range がない | battery または wiring が antenna の*真上*にある | cables を再配線し、ferrite loop の周囲に 2 cm の clearance を確保する |
| beeper が鳴り続ける | switch が negative ではなく positive lead に配線されている | kill-switch を移動し、**negative** speaker trace を切断する |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
