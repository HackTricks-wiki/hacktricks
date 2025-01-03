{{#include ../../../banners/hacktricks-training.md}}

USB 연결의 pcap에 많은 중단이 있는 경우, 아마도 USB 키보드 연결일 것입니다.

다음과 같은 wireshark 필터가 유용할 수 있습니다: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

"02"로 시작하는 데이터는 shift를 사용하여 눌린 것입니다.

이 분석 방법에 대한 더 많은 정보와 스크립트를 찾으려면 다음을 참조하세요:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
