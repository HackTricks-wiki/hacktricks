{{#include ../../../banners/hacktricks-training.md}}

Si vous avez un pcap d'une connexion USB avec beaucoup d'interruptions, il s'agit probablement d'une connexion de clavier USB.

Un filtre wireshark comme celui-ci pourrait être utile : `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Il pourrait être important de savoir que les données qui commencent par "02" sont pressées en utilisant shift.

Vous pouvez lire plus d'informations et trouver quelques scripts sur la façon d'analyser cela dans :

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
