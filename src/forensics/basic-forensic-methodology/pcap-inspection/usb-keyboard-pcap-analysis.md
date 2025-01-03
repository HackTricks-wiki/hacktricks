{{#include ../../../banners/hacktricks-training.md}}

Eğer birçok kesinti ile birlikte bir USB bağlantısının pcap'ine sahipseniz, muhtemelen bu bir USB Klavye bağlantısıdır.

Bunun gibi bir wireshark filtresi faydalı olabilir: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

"02" ile başlayan verilerin shift tuşu kullanılarak basıldığını bilmek önemli olabilir.

Bununla ilgili daha fazla bilgi okuyabilir ve analiz etme hakkında bazı scriptler bulabilirsiniz:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
