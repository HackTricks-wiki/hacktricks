# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Radio security testingでは、デバイスが無線信号をどのように送信、受信、解釈するかを調査します。software-defined radio（SDR）は、信号の位置を特定し、in-phase/quadrature（I/Q）サンプルを記録し、プロトコル固有のハードウェアに依存せずに復調やデコードをテストするのに役立ちます。<sup>[[1]](#references)</sup>

実践的なワークフローでは、周波数帯とチャネル幅を特定し、既知のデバイス操作を複数回キャプチャし、得られた信号を比較してから、変調方式とパケット構造を特定します。replayまたは送信のテストは、隔離された環境で、かつ許可を得ている周波数と機器のみを使用して実施してください。このセクションのページでは、RFID、NFC、サブGHz無線、赤外線、BLE、および関連ツールを扱います。<sup>[[1]](#references)</sup>

## References

- [1] [Great Scott Gadgets - HackRFを使用したSoftware Defined Radio](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
