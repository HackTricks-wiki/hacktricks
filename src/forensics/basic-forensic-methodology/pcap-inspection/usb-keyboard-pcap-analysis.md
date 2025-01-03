{{#include ../../../banners/hacktricks-training.md}}

Ikiwa una pcap ya muunganisho wa USB wenye usumbufu mwingi, huenda ni muunganisho wa USB Keyboard.

Filter ya wireshark kama hii inaweza kuwa na manufaa: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Inaweza kuwa muhimu kujua kwamba data inayoanisha na "02" inamaanisha imebonyezwa kwa kutumia shift.

Unaweza kusoma maelezo zaidi na kupata baadhi ya scripts kuhusu jinsi ya kuchambua hii katika:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
