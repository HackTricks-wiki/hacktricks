{{#include ../../../banners/hacktricks-training.md}}

Wenn Sie ein pcap einer USB-Verbindung mit vielen Unterbrechungen haben, handelt es sich wahrscheinlich um eine USB-Tastaturverbindung.

Ein Wireshark-Filter wie dieser könnte nützlich sein: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Es könnte wichtig sein zu wissen, dass die Daten, die mit "02" beginnen, mit Shift gedrückt werden.

Sie können weitere Informationen lesen und einige Skripte finden, wie man dies analysiert in:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
