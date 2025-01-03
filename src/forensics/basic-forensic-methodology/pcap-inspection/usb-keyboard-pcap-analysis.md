{{#include ../../../banners/hacktricks-training.md}}

Se você tiver um pcap de uma conexão USB com muitas interrupções, provavelmente é uma conexão de teclado USB.

Um filtro do wireshark como este pode ser útil: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Pode ser importante saber que os dados que começam com "02" são pressionados usando shift.

Você pode ler mais informações e encontrar alguns scripts sobre como analisar isso em:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
