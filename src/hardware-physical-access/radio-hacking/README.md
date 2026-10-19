# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Testowanie bezpieczeństwa systemów radiowych sprawdza, jak urządzenie nadaje, odbiera i interpretuje sygnały bezprzewodowe. Radio definiowane programowo (SDR) może pomóc zlokalizować sygnał, zarejestrować próbki I/Q (składowe zgodne i kwadraturowe) oraz testować demodulację i dekodowanie bez konieczności korzystania ze sprzętu przeznaczonego do konkretnego protokołu.<sup>[[1]](#references)</sup>

Praktyczny przebieg pracy obejmuje określenie pasma częstotliwości i szerokości kanału, przechwycenie sygnałów związanych z kilkoma znanymi działaniami urządzenia, porównanie uzyskanych sygnałów, a następnie ustalenie modulacji i struktury pakietów. Testy odtwarzania lub transmisji wykonuj wyłącznie w odizolowanym środowisku oraz na częstotliwościach i sprzęcie, do których użycia masz upoważnienie. Strony w tej sekcji dotyczą RFID, NFC, radia sub-GHz, podczerwieni, BLE i powiązanych narzędzi.<sup>[[1]](#references)</sup>

## Znajdź odpowiedni interfejs

- W przypadku karty dostępu lub klucza stykowego zacznij od [typów tagów RFID/NFC i ataków](pentesting-rfid.md), [przebiegów pracy z Proxmark3](proxmark-3.md) lub [kluczy iButton i 1-Wire](ibutton.md). [Przewodnik po Flipper Zero](flipper-zero/README.md) zawiera odnośniki do działań dotyczących konkretnych interfejsów.
- W przypadku sygnału z pilota użyj [RF sub-GHz i kodów kroczących](sub-ghz-rf.md) lub [protokołów i ataków na podczerwień](infrared.md).
- W przypadku pobliskich urządzeń i czujników użyj [testowania reklam BLE, GATT i mesh](pentesting-ble-bluetooth-low-energy.md) lub [zabezpieczeń LPWAN/LoRaWAN](low-power-wide-area-network.md).
- W przypadku przechwyconych lub nieznanych sygnałów RF użyj [analizy sygnałów w SigDigger](../hardware-hacking/radio.md#sigdigger) lub [frameworka FISSURE](fissure-the-rf-framework.md).
- Informacje o łączach dosyłowych terminali satelitarnych znajdziesz w sekcji [wstrzykiwanie sygnału VSAT do łącza dosyłowego](vsat-forward-link-injection.md).



## References

- [1] [Great Scott Gadgets - Radio definiowane programowo z HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
