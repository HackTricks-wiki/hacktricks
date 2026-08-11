# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

रेडियो सुरक्षा परीक्षण यह जांचता है कि कोई device wireless signals को कैसे transmit, receive और interpret करता है। Software-defined radio (SDR) किसी signal का स्थान पता लगाने, in-phase/quadrature (I/Q) samples record करने और protocol-specific hardware पर निर्भर हुए बिना demodulation तथा decoding का परीक्षण करने में सहायता कर सकता है।<sup>[[1]](#references)</sup>

एक practical workflow में frequency band और channel width की पहचान करना, कई ज्ञात device actions को capture करना, resulting signals की तुलना करना और फिर modulation तथा packet structure निर्धारित करना शामिल है। Replay या transmission का परीक्षण केवल isolated environment में और उन frequencies तथा equipment पर करें, जिनके लिए आपके पास authorization है। इस section के pages में RFID, NFC, sub-GHz radio, infrared, BLE और संबंधित tools शामिल हैं।<sup>[[1]](#references)</sup>

## References

- [1] [Great Scott Gadgets - HackRF के साथ Software Defined Radio](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
