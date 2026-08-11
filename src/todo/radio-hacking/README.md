# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Testowanie bezpieczeństwa radiowego analizuje sposób, w jaki urządzenie transmituje, odbiera i interpretuje sygnały bezprzewodowe. Software-defined radio (SDR) może pomóc zlokalizować sygnał, zarejestrować próbki in-phase/quadrature (I/Q) oraz przetestować demodulację i dekodowanie bez konieczności korzystania ze sprzętu przeznaczonego dla konkretnego protokołu.<sup>[[1]](#references)</sup>

Praktyczny workflow obejmuje identyfikację pasma częstotliwości i szerokości kanału, przechwycenie kilku znanych działań urządzenia, porównanie uzyskanych sygnałów, a następnie określenie modulacji i struktury pakietów. Testuj replay lub transmisję wyłącznie w odizolowanym środowisku oraz na częstotliwościach i sprzęcie, do których masz autoryzację. Strony w tej sekcji obejmują RFID, NFC, radio sub-GHz, podczerwień, BLE i powiązane narzędzia.<sup>[[1]](#references)</sup>

## References

- [1] [Great Scott Gadgets - Radio definiowane programowo z HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
