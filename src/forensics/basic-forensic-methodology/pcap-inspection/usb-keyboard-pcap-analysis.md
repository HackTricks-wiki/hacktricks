{{#include ../../../banners/hacktricks-training.md}}

USB接続のpcapに多くの中断がある場合、おそらくそれはUSBキーボード接続です。

このようなwiresharkフィルターが役立つかもしれません: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

「02」で始まるデータはシフトを使用して押されたことを知っておくことが重要です。

これを分析する方法についての情報やスクリプトを見つけることができます:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
