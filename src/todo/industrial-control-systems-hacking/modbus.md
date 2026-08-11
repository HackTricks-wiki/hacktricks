# Modbus Protocol

{{#include ../../banners/hacktricks-training.md}}

## Modbus का परिचय

Modbus एक open application-layer protocol है, जिसे PLCs, sensors, actuators और अन्य industrial devices में व्यापक रूप से लागू किया गया है। इसका request/response model function codes के माध्यम से coils और registers को expose करता है। इसलिए security testing का ध्यान केवल TCP port 502 खोजने पर नहीं, बल्कि unauthorized reads/writes, traffic observation, replay और unsafe device behavior पर केंद्रित होता है।<sup>[[1]](#references)</sup>

कई deployments में legacy serial equipment अब भी रखा जाता है, क्योंकि upgrades के लिए downtime, recertification या field devices का replacement आवश्यक होता है। Traditional Modbus में confidentiality या peer authentication की कोई सुविधा नहीं होती; Modbus Security एक अलग TLS-based profile है, जो X.509 certificates और TCP port 802 का उपयोग करता है। Specification public और independently implementable होने के कारण vendor behavior और optional-function support अलग-अलग हो सकते हैं; इन्हें मान लेने के बजाय fingerprint किया जाना चाहिए।<sup>[[1]](#references)[[2]](#references)</sup>

## Client-Server Architecture

वर्तमान terminology में, एक **client** transaction शुरू करता है और एक **server** response लौटाता है। पुराने documentation में **master/slave** शब्दों का उपयोग किया जाता है। इस application relationship को SPI या I2C के साथ भ्रमित न करें: वे अलग bus protocols हैं।<sup>[[1]](#references)</sup>

## Serial और Ethernet transports

एक ही Modbus application data को serial variants (RTU या ASCII framing) और Modbus TCP के माध्यम से ले जाया जा सकता है। Modbus TCP में MBAP header जुड़ता है और सामान्यतः TCP port 502 का उपयोग होता है; serial RTU compact binary framing और CRC का उपयोग करता है, जबकि serial ASCII bytes को hexadecimal characters के रूप में दर्शाता है और LRC का उपयोग करता है।<sup>[[1]](#references)[[3]](#references)</sup>

## Data representation

Data model में single-bit coils/discrete inputs और 16-bit input/holding registers शामिल होते हैं। Multi-register values, byte order, scaling और semantic meaning device-specific होते हैं और vendor के register map के आधार पर पुष्टि किए जाने चाहिए।<sup>[[1]](#references)</sup>

## Function codes

Function codes ऐसी operations का चयन करते हैं, जैसे coils (`0x01`) पढ़ना, holding registers (`0x03`) पढ़ना, single coil/register (`0x05`/`0x06`) लिखना और multiple coils/registers (`0x0F`/`0x10`) लिखना। जब deployment में compensating authentication या process-state checks नहीं होते, तो captured write request को replay किया जा सकता है। लंबे serial runs तक authorized physical access होने पर, electrical interface, termination और safe connection method की पहचान करने के बाद assessor wiring पर सीधे frames capture या inject भी कर सकता है। इनमें से कोई भी action physical process को प्रभावित कर सकता है, इसलिए lab या explicit operational authorization का उपयोग करें।<sup>[[1]](#references)[[3]](#references)</sup>

## Addressing

Serial devices में unit address का उपयोग होता है। Modbus TCP में IP addressing के साथ MBAP header में Unit Identifier का उपयोग होता है, जो विशेष रूप से तब relevant होता है जब TCP-to-serial gateway requests को downstream units तक route करता है। Product documentation में दिखाए गए register references one-based (`40001`) हो सकते हैं, जबकि protocol addresses zero-based होते हैं; यह off-by-one errors का सामान्य स्रोत है।<sup>[[1]](#references)[[3]](#references)</sup>

Serial framing में transmission-error checks शामिल होते हैं (RTU के लिए CRC और ASCII के लिए LRC), जबकि TCP अपना सामान्य transport checksum प्रदान करता है। ये accidental corruption का पता लगाते हैं; ये cryptographic integrity या origin authentication प्रदान नहीं करते।<sup>[[3]](#references)</sup>

Authorized assessment के दौरान exposure, permitted function codes, writable address ranges, exception handling, rate limits और यह जांचें कि network segmentation या Modbus-aware firewall clients को सीमित करता है या नहीं। Relevant threats में passive disclosure, unauthorized command injection, replay, data forgery और denial of service शामिल हैं। सभी active tests को process owners के साथ coordinate करें, क्योंकि register में apparently छोटे changes भी physical process को बदल सकते हैं।

## References

- [1] [Modbus Organization — Modbus Application Protocol Specification V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Modbus Security Protocol और implementation guides](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Modbus over Serial Line Specification और Implementation Guide V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
