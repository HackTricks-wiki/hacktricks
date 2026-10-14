# 無線ハッキング

{{#include ../../banners/hacktricks-training.md}}

無線セキュリティテストでは、デバイスが無線信号をどのように送信、受信、解釈するかを調べます。Software-defined radio（SDR）を使うと、信号の位置を特定し、in-phase/quadrature（I/Q）サンプルを記録し、プロトコル専用のハードウェアを用意せずに、復調やデコードをテストできます。<sup>[[1]](#references)</sup>

実践的な手順としては、周波数帯とチャネル幅を特定し、デバイスで既知の操作を複数回行って信号をキャプチャし、結果の信号を比較してから、変調方式とパケット構造を特定します。replayや送信テストは、隔離された環境で、使用許可のある周波数と機器に限って行ってください。このセクションでは、RFID、NFC、sub-GHz radio、赤外線、BLE、および関連ツールを扱います。<sup>[[1]](#references)</sup>

## 関連するインターフェースを探す

- 入退室用バッジや接触式キーの場合は、[RFID/NFC tag types and attacks](pentesting-rfid.md)、[Proxmark3 workflows](proxmark-3.md)、または[iButton and 1-Wire keys](ibutton.md)から始めてください。[Flipper Zero guide](flipper-zero/README.md)には、インターフェース固有の操作へのリンクがあります。
- リモコン信号の場合は、[sub-GHz RF and rolling codes](sub-ghz-rf.md)または[infrared protocols and attacks](infrared.md)を参照してください。
- 近くのデバイスやセンサーの場合は、[BLE advertising, GATT, and mesh testing](pentesting-ble-bluetooth-low-energy.md)または[LPWAN/LoRaWAN security](low-power-wide-area-network.md)を参照してください。
- キャプチャ済み、または不明なRF信号の場合は、[SigDigger signal analysis](../hardware-hacking/radio.md#sigdigger)または[FISSURE framework](fissure-the-rf-framework.md)を参照してください。

## References

- [1] [Great Scott Gadgets - HackRFを使ったSoftware Defined Radio](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
