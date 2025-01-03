# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Ako imate pcap koji sadrži komunikaciju putem USB-a tastature kao što je sledeća:

![](<../../../images/image (962).png>)

Možete koristiti alat [**ctf-usb-keyboard-parser**](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser) da dobijete ono što je napisano u komunikaciji:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Možete pročitati više informacija i pronaći neke skripte o tome kako analizirati ovo na:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
