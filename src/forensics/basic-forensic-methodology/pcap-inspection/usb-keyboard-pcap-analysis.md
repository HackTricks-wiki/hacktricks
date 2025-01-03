{{#include ../../../banners/hacktricks-training.md}}

As jy 'n pcap van 'n USB-verbinding met baie onderbrekings het, is dit waarskynlik 'n USB-keyboardverbinding.

'n Wireshark-filter soos hierdie kan nuttig wees: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Dit kan belangrik wees om te weet dat die data wat met "02" begin, met shift gedruk word.

Jy kan meer inligting lees en 'n paar skrifte vind oor hoe om dit te analiseer in:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
