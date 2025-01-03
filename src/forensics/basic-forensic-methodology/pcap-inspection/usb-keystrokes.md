{{#include ../../../banners/hacktricks-training.md}}

Wenn Sie eine pcap-Datei haben, die die Kommunikation über USB einer Tastatur wie die folgende enthält:

![](<../../../images/image (613).png>)

können Sie das Tool [**ctf-usb-keyboard-parser**](https://github.com/carlospolop-forks/ctf-usb-keyboard-parser) verwenden, um herauszufinden, was in der Kommunikation geschrieben wurde:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Sie können weitere Informationen lesen und einige Skripte finden, wie Sie dies analysieren können in:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
