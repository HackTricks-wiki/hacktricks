# Hakowanie radiowe

{{#include ../../banners/hacktricks-training.md}}

Testowanie bezpieczeństwa radiowego polega na analizie sposobu, w jaki urządzenie transmituje, odbiera i interpretuje sygnały bezprzewodowe. Radio definiowane programowo (SDR) może pomóc zlokalizować sygnał, zarejestrować próbki in-phase/quadrature (I/Q) oraz przetestować demodulację i dekodowanie bez konieczności korzystania ze sprzętu przeznaczonego dla konkretnego protokołu.<sup>[[1]](#references)</sup>

Praktyczny proces obejmuje ustalenie pasma częstotliwości i szerokości kanału, przechwycenie kilku znanych działań urządzenia, porównanie uzyskanych sygnałów, a następnie określenie modulacji i struktury pakietów. Testuj odtwarzanie sygnału lub transmisję tylko w odizolowanym środowisku oraz na częstotliwościach i sprzęcie, do których masz upoważnienie. Strony w tej sekcji obejmują RFID, NFC, radio sub-GHz, podczerwień, BLE i powiązane narzędzia.<sup>[[1]](#references)</sup>

## Znajdź odpowiedni interfejs

- W przypadku karty dostępu lub klucza zbliżeniowego zacznij od [typów tagów RFID/NFC i ataków](pentesting-rfid.md), [przebiegów pracy z Proxmark3](proxmark-3.md) lub [kluczy iButton i 1-Wire](ibutton.md). [Przewodnik po Flipper Zero](flipper-zero/README.md) zawiera odnośniki do działań związanych z konkretnymi interfejsami.
- W przypadku sygnału z pilota użyj [RF sub-GHz i kodów zmiennych](sub-ghz-rf.md) lub [protokołów podczerwieni i ataków](infrared.md).
- W przypadku pobliskich urządzeń i czujników skorzystaj z [testowania rozgłoszeń BLE, GATT i sieci mesh](pentesting-ble-bluetooth-low-energy.md) lub [bezpieczeństwa LPWAN/LoRaWAN](low-power-wide-area-network.md).
- W przypadku przechwyconych lub nieznanych sygnałów RF skorzystaj z [analizy sygnałów w SigDigger](../hardware-hacking/radio.md#sigdigger) lub [frameworka FISSURE](fissure-the-rf-framework.md).

## References

- [1] [Great Scott Gadgets - Radio definiowane programowo z HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
