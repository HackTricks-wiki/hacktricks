{{#include ../../../banners/hacktricks-training.md}}

Se hai un pcap di una connessione USB con molte interruzioni, probabilmente si tratta di una connessione USB Keyboard.

Un filtro wireshark come questo potrebbe essere utile: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

È importante sapere che i dati che iniziano con "02" sono stati premuti utilizzando il tasto shift.

Puoi leggere ulteriori informazioni e trovare alcuni script su come analizzare questo in:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
