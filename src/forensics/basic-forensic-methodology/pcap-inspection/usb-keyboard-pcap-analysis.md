{{#include ../../../banners/hacktricks-training.md}}

यदि आपके पास एक USB कनेक्शन का pcap है जिसमें बहुत सारी रुकावटें हैं, तो यह संभवतः एक USB कीबोर्ड कनेक्शन है।

इस तरह का एक wireshark फ़िल्टर उपयोगी हो सकता है: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

यह जानना महत्वपूर्ण हो सकता है कि "02" से शुरू होने वाला डेटा शिफ्ट का उपयोग करके दबाया गया है।

आप इस पर अधिक जानकारी पढ़ सकते हैं और इसे विश्लेषण करने के लिए कुछ स्क्रिप्ट पा सकते हैं:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
