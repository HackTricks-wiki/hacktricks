{{#include ../../../banners/hacktricks-training.md}}

Jeśli masz pcap z połączeniem USB z wieloma przerwami, prawdopodobnie jest to połączenie klawiatury USB.

Filtr wireshark taki jak ten może być przydatny: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Może być ważne, aby wiedzieć, że dane, które zaczynają się od "02", są wciśnięte przy użyciu klawisza shift.

Możesz przeczytać więcej informacji i znaleźć kilka skryptów dotyczących analizy tego w:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
