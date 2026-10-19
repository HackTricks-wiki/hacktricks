# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Radio-sekuriteitstoetsing ondersoek hoe ’n toestel draadlose seine uitstuur, ontvang en interpreteer. ’n Sagtewaregedefinieerde radio (SDR) kan help om ’n sein op te spoor, in-fase-/kwadratuurmonsters (I/Q) op te neem en demodulasie en dekodering te toets sonder om jou tot protokolspesifieke hardeware te verbind.<sup>[[1]](#references)</sup>

’n Praktiese werkvloei is om die frekwensieband en kanaalwydte te identifiseer, verskeie bekende toestelaksies vas te lê, die gevolglike seine te vergelyk en dan die modulasie en pakkiestruktuur te bepaal. Toets die terugspeel of uitsending slegs in ’n geïsoleerde omgewing en op frekwensies en toerusting waarvoor jy toestemming het. Die bladsye in hierdie afdeling dek RFID, NFC, sub-GHz-radio, infrarooi, BLE en verwante nutsmiddels.<sup>[[1]](#references)</sup>

## Vind die toepaslike koppelvlak

- Vir ’n toegangskaartjie of kontakslot, begin met [RFID/NFC-etikettipes en aanvalle](pentesting-rfid.md), [Proxmark3-werkvloeie](proxmark-3.md), of [iButton- en 1-Wire-sleutels](ibutton.md). Die [Flipper Zero-gids](flipper-zero/README.md) skakel na aksies wat spesifiek op die koppelvlak van toepassing is.
- Vir ’n afstandbeheersein, gebruik [sub-GHz RF en rolling codes](sub-ghz-rf.md) of [infrarooi-protokolle en aanvalle](infrared.md).
- Vir nabygeleë toestelle en sensors, gebruik [BLE-advertering, GATT en mesh-toetsing](pentesting-ble-bluetooth-low-energy.md) of [LPWAN/LoRaWAN-sekuriteit](low-power-wide-area-network.md).
- Vir vasgelegde of onbekende RF-seine, gebruik [SigDigger-seinontleding](../hardware-hacking/radio.md#sigdigger) of die [FISSURE-raamwerk](fissure-the-rf-framework.md).
- Vir satellietterminaal-afskakelseine, sien [VSAT-voorwaartse-skakelseininspuiting](vsat-forward-link-injection.md).



## References

- [1] [Great Scott Gadgets - Sagtewaregedefinieerde radio met HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
