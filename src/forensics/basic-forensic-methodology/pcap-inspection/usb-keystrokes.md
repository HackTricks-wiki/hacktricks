{{#include ../../../banners/hacktricks-training.md}}

Jeśli masz pcap zawierający komunikację przez USB klawiatury, jak ta poniżej:

![](<../../../images/image (613).png>)

Możesz użyć narzędzia [**ctf-usb-keyboard-parser**](https://github.com/carlospolop-forks/ctf-usb-keyboard-parser), aby uzyskać to, co zostało napisane w komunikacji:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Możesz przeczytać więcej informacji i znaleźć kilka skryptów dotyczących analizy tego w:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
