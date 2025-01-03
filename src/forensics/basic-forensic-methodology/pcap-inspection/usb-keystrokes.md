{{#include ../../../banners/hacktricks-training.md}}

यदि आपके पास एक pcap है जिसमें एक कीबोर्ड के माध्यम से USB के जरिए संचार शामिल है, जैसे कि निम्नलिखित:

![](<../../../images/image (613).png>)

आप संचार में जो लिखा गया था उसे प्राप्त करने के लिए उपकरण [**ctf-usb-keyboard-parser**](https://github.com/carlospolop-forks/ctf-usb-keyboard-parser) का उपयोग कर सकते हैं:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
आप अधिक जानकारी पढ़ सकते हैं और इस पर विश्लेषण करने के लिए कुछ स्क्रिप्ट्स पा सकते हैं:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
