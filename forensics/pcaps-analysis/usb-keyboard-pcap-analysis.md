# USB Keyboard pcap analysis

If you have a pcap of a USB connection with a lot of Interruptions probably it is a USB Keyboard connection.

A wireshark filter like this could be useful: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

It could be important to know that the data that starts with "02" is pressed using shift.

You can read more information and find some scripts about how to analyse this in:

* [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
* [https://github.com/tanc7/HacktheBox\_Deadly\_Arthropod\_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

