{{#include ../../../banners/hacktricks-training.md}}

Ako imate pcap datoteku USB veze sa mnogo prekida, verovatno se radi o USB tastaturi.

Wireshark filter poput ovog može biti koristan: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Može biti važno znati da podaci koji počinju sa "02" predstavljaju pritisnuti taster uz pritisnut shift.

Možete pročitati više informacija i pronaći neke skripte o tome kako analizirati ovo na:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
