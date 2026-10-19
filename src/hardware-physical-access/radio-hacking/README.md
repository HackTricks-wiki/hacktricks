# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Radio security testing では、デバイスがワイヤレス信号をどのように送信、受信、解釈するかを調査します。software-defined radio (SDR) を使うと、信号の特定、in-phase/quadrature (I/Q) サンプルの記録、プロトコル固有のハードウェアを用意せずに復調やデコードのテストを行えます。<sup>[[1]](#references)</sup>

実践的なワークフローでは、周波数帯とチャネル幅を特定し、既知のデバイス操作を複数回キャプチャして、得られた信号を比較し、変調方式とパケット構造を判断します。リプレイや送信のテストは、隔離された環境で、許可を得た周波数と機器を使用してのみ行ってください。このセクションでは、RFID、NFC、sub-GHz radio、赤外線、BLE、および関連ツールを扱います。<sup>[[1]](#references)</sup>

## 関連するインターフェースを探す

- アクセスバッジや接触式キーの場合は、[RFID/NFCタグの種類と攻撃](pentesting-rfid.md)、[Proxmark3のワークフロー](proxmark-3.md)、または[iButtonと1-Wireキー](ibutton.md)から始めてください。[Flipper Zeroガイド](flipper-zero/README.md)には、インターフェース固有の操作へのリンクがあります。
- リモコン信号の場合は、[sub-GHz RFとローリングコード](sub-ghz-rf.md)または[赤外線プロトコルと攻撃](infrared.md)を使用してください。
- 近くにあるデバイスやセンサーの場合は、[BLE advertising、GATT、meshのテスト](pentesting-ble-bluetooth-low-energy.md)または[LPWAN/LoRaWAN security](low-power-wide-area-network.md)を使用してください。
- キャプチャ済みまたは未知のRF信号の場合は、[SigDiggerによる信号解析](../hardware-hacking/radio.md#sigdigger)または[FISSURE framework](fissure-the-rf-framework.md)を使用してください。
- 衛星端末のダウンリンクについては、[VSAT forward-link signal injection](vsat-forward-link-injection.md)を参照してください。



## References

- [1] [Great Scott Gadgets - HackRFによるSoftware Defined Radio](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
