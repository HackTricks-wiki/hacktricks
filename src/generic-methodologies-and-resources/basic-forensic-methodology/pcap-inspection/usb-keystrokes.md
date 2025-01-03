# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Si vous avez un pcap contenant la communication via USB d'un clavier comme celui-ci :

![](<../../../images/image (962).png>)

Vous pouvez utiliser l'outil [**ctf-usb-keyboard-parser**](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser) pour obtenir ce qui a été écrit dans la communication :
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Vous pouvez lire plus d'informations et trouver des scripts sur la façon d'analyser cela dans :

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
