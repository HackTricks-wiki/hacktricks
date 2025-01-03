# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

USB를 통한 키보드 통신이 포함된 pcap 파일이 있는 경우, 다음과 같은:

![](<../../../images/image (962).png>)

[**ctf-usb-keyboard-parser**](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser) 도구를 사용하여 통신에서 작성된 내용을 얻을 수 있습니다:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
다음 링크에서 이 분석 방법에 대한 더 많은 정보와 스크립트를 찾을 수 있습니다:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
