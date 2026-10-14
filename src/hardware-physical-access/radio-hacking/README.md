# रेडियो Hacking

{{#include ../../banners/hacktricks-training.md}}

रेडियो सुरक्षा परीक्षण में यह जाँचा जाता है कि कोई डिवाइस वायरलेस सिग्नल कैसे प्रसारित, प्राप्त और समझता है। Software-defined radio (SDR) की मदद से सिग्नल का पता लगाया जा सकता है, in-phase/quadrature (I/Q) samples रिकॉर्ड किए जा सकते हैं और protocol-specific hardware पर निर्भर हुए बिना demodulation तथा decoding का परीक्षण किया जा सकता है।<sup>[[1]](#references)</sup>

एक व्यावहारिक workflow में frequency band और channel width की पहचान करना, डिवाइस की कई ज्ञात कार्रवाइयों को capture करना, उनसे बने signals की तुलना करना और फिर modulation तथा packet structure का पता लगाना शामिल है। Replay या transmission का परीक्षण केवल अलग-थलग environment में और उन्हीं frequencies तथा equipment पर करें, जिनके लिए आपके पास अनुमति है। इस section के पेज RFID, NFC, sub-GHz radio, infrared, BLE और संबंधित tools को कवर करते हैं।<sup>[[1]](#references)</sup>

## संबंधित interface खोजें

- Access badge या contact key के लिए, [RFID/NFC tag types and attacks](pentesting-rfid.md), [Proxmark3 workflows](proxmark-3.md), या [iButton and 1-Wire keys](ibutton.md) से शुरुआत करें। [Flipper Zero guide](flipper-zero/README.md) में इसके interface-विशिष्ट actions के लिंक हैं।
- Remote-control signal के लिए, [sub-GHz RF and rolling codes](sub-ghz-rf.md) या [infrared protocols and attacks](infrared.md) देखें।
- आस-पास के devices और sensors के लिए, [BLE advertising, GATT, and mesh testing](pentesting-ble-bluetooth-low-energy.md) या [LPWAN/LoRaWAN security](low-power-wide-area-network.md) देखें।
- Captured या अज्ञात RF signals के लिए, [SigDigger signal analysis](../hardware-hacking/radio.md#sigdigger) या [FISSURE framework](fissure-the-rf-framework.md) देखें।

## References

- [1] [Great Scott Gadgets - HackRF के साथ Software Defined Radio](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
