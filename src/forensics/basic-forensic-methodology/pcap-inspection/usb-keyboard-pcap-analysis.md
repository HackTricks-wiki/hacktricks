{{#include ../../../banners/hacktricks-training.md}}

Якщо у вас є pcap USB-з'єднання з великою кількістю перерв, ймовірно, це з'єднання USB-клавіатури.

Фільтр wireshark, як цей, може бути корисним: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Важливо знати, що дані, які починаються з "02", натискаються з використанням shift.

Ви можете прочитати більше інформації та знайти деякі скрипти про те, як це аналізувати, за адресами:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
