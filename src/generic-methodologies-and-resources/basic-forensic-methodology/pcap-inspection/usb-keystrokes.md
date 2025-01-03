# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

USB経由でのキーボードの通信を含むpcapがある場合、次のようなものです：

![](<../../../images/image (962).png>)

ツール[**ctf-usb-keyboard-parser**](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)を使用して、通信で書かれた内容を取得できます：
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
この分析方法についての詳細情報やスクリプトは、以下のリンクで読むことができます：

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
