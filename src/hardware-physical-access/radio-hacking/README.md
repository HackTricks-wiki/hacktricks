# Radio-hacking

{{#include ../../banners/hacktricks-training.md}}

Radio-sekuriteitstoetsing ondersoek hoe ’n toestel draadlose seine uitstuur, ontvang en interpreteer. ’n Software-defined radio (SDR) kan help om ’n sein op te spoor, in-fase-/kwadratuurmonsters (I/Q) op te neem en demodulasie en dekodering te toets sonder om jou tot hardeware te verbind wat spesifiek vir ’n protokol ontwerp is.<sup>[[1]](#references)</sup>

’n Praktiese werkvloei is om die frekwensieband en kanaalwydte te identifiseer, verskeie bekende toestelaksies op te neem, die gevolglike seine te vergelyk en dan die modulasie en pakkiestruktuur te bepaal. Toets die herspeel of versending slegs in ’n geïsoleerde omgewing en op frekwensies en toerusting waarvoor jy toestemming het. Die bladsye in hierdie afdeling dek RFID, NFC, sub-GHz-radio, infrarooi, BLE en verwante nutsgoed.<sup>[[1]](#references)</sup>

## Vind die toepaslike koppelvlak

- Vir ’n toegangskenteken of kontakteleutel, begin met [RFID/NFC-etikettipes en aanvalle](pentesting-rfid.md), [Proxmark3-werkvloeie](proxmark-3.md), of [iButton- en 1-Wire-sleutels](ibutton.md). Die [Flipper Zero-gids](flipper-zero/README.md) skakel na aksies wat spesifiek vir die koppelvlak is.
- Vir ’n afstandbeheersein, gebruik [sub-GHz RF en rollende kodes](sub-ghz-rf.md) of [infrarooi-protokolle en aanvalle](infrared.md).
- Vir toestelle en sensors naby jou, gebruik [BLE-advertensies, GATT en maasnetwerktoetsing](pentesting-ble-bluetooth-low-energy.md) of [LPWAN/LoRaWAN-sekuriteit](low-power-wide-area-network.md).
- Vir vasgelegde of onbekende RF-seine, gebruik [SigDigger-seinontleding](../hardware-hacking/radio.md#sigdigger) of die [FISSURE-raamwerk](fissure-the-rf-framework.md).

## References

- [1] [Great Scott Gadgets - Sagtewaregedefinieerde radio met HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
