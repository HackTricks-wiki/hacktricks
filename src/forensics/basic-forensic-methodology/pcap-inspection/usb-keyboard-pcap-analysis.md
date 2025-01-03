{{#include ../../../banners/hacktricks-training.md}}

如果你有一个 USB 连接的 pcap，且有很多中断，可能这是一个 USB 键盘连接。

这样的 wireshark 过滤器可能会很有用：`usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

重要的是要知道，以 "02" 开头的数据是通过 shift 键按下的。

你可以在以下链接中阅读更多信息并找到一些关于如何分析的脚本：

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
