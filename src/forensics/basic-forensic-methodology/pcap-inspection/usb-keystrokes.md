{{#include ../../../banners/hacktricks-training.md}}

Ikiwa una pcap inayojumuisha mawasiliano kupitia USB ya kibodi kama ifuatavyo:

![](<../../../images/image (613).png>)

Unaweza kutumia chombo [**ctf-usb-keyboard-parser**](https://github.com/carlospolop-forks/ctf-usb-keyboard-parser) kupata kile kilichoandikwa katika mawasiliano:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Unaweza kusoma maelezo zaidi na kupata baadhi ya scripts kuhusu jinsi ya kuchambua hii katika:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
