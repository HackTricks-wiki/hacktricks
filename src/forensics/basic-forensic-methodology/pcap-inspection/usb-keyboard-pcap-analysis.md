{{#include ../../../banners/hacktricks-training.md}}

Si tienes un pcap de una conexión USB con muchas interrupciones, probablemente sea una conexión de teclado USB.

Un filtro de wireshark como este podría ser útil: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Podría ser importante saber que los datos que comienzan con "02" se presionan usando shift.

Puedes leer más información y encontrar algunos scripts sobre cómo analizar esto en:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
