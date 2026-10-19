# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Radio security testing में जाँचा जाता है कि कोई डिवाइस wireless signals कैसे transmit, receive और interpret करता है। Software-defined radio (SDR) से signal का पता लगाने, in-phase/quadrature (I/Q) samples रिकॉर्ड करने और protocol-specific hardware का उपयोग किए बिना demodulation तथा decoding की जाँच करने में मदद मिल सकती है।<sup>[[1]](#references)</sup>

एक व्यावहारिक workflow में frequency band और channel width की पहचान करना, डिवाइस की कई ज्ञात कार्रवाइयों को capture करना, उनसे बने signals की तुलना करना और फिर modulation तथा packet structure निर्धारित करना शामिल है। Replay या transmission का परीक्षण केवल isolated environment में, और उन frequencies तथा equipment पर करें जिनके लिए आपके पास authorization है। इस section के पेज RFID, NFC, sub-GHz radio, infrared, BLE और संबंधित tools को कवर करते हैं।<sup>[[1]](#references)</sup>

## प्रासंगिक interface खोजें

- Access badge या contact key के लिए, [RFID/NFC tag types और attacks](pentesting-rfid.md), [Proxmark3 workflows](proxmark-3.md), या [iButton और 1-Wire keys](ibutton.md) से शुरू करें। [Flipper Zero guide](flipper-zero/README.md) में इसके interface-विशिष्ट actions के links हैं।
- Remote-control signal के लिए, [sub-GHz RF और rolling codes](sub-ghz-rf.md) या [infrared protocols और attacks](infrared.md) का उपयोग करें।
- आसपास के devices और sensors के लिए, [BLE advertising, GATT और mesh testing](pentesting-ble-bluetooth-low-energy.md) या [LPWAN/LoRaWAN security](low-power-wide-area-network.md) का उपयोग करें।
- Captured या अज्ञात RF signals के लिए, [SigDigger signal analysis](../hardware-hacking/radio.md#sigdigger) या [FISSURE framework](fissure-the-rf-framework.md) का उपयोग करें।
- Satellite terminal downlinks के लिए, [VSAT forward-link signal injection](vsat-forward-link-injection.md) देखें। 



## References

- [1] [Great Scott Gadgets - HackRF के साथ Software Defined Radio](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
