{{#include ../../../banners/hacktricks-training.md}}

Eğer aşağıdaki gibi bir klavyenin USB üzerinden iletişimini içeren bir pcap dosyanız varsa:

![](<../../../images/image (613).png>)

İletişimde yazılanları almak için [**ctf-usb-keyboard-parser**](https://github.com/carlospolop-forks/ctf-usb-keyboard-parser) aracını kullanabilirsiniz:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Daha fazla bilgi okuyabilir ve bunu analiz etme hakkında bazı betikler bulabilirsiniz:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
