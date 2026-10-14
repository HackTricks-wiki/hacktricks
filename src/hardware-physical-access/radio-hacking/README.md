# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Testiranje radio-bezbednosti ispituje kako uređaj emituje, prima i tumači bežične signale. Software-defined radio (SDR) može da pomogne u pronalaženju signala, snimanju I/Q uzoraka (in-phase/quadrature) i testiranju demodulacije i dekodiranja bez oslanjanja na hardver namenjen određenom protokolu.<sup>[[1]](#references)</sup>

Praktičan postupak je da utvrdite frekvencijski opseg i širinu kanala, snimite nekoliko poznatih radnji uređaja, uporedite dobijene signale, a zatim odredite modulaciju i strukturu paketa. Testirajte ponavljanje ili emitovanje signala samo u izolovanom okruženju i na frekvencijama i opremi za koje imate ovlašćenje. Stranice u ovom odeljku obrađuju RFID, NFC, sub-GHz radio, infracrvenu vezu, BLE i povezane alate.<sup>[[1]](#references)</sup>

## Pronađite odgovarajući interfejs

- Za pristupnu karticu ili kontaktni ključ, počnite od [RFID/NFC tag types and attacks](pentesting-rfid.md), [Proxmark3 workflows](proxmark-3.md) ili [iButton and 1-Wire keys](ibutton.md). [Flipper Zero guide](flipper-zero/README.md) sadrži linkove ka radnjama specifičnim za njegov interfejs.
- Za signal daljinskog upravljača koristite [sub-GHz RF and rolling codes](sub-ghz-rf.md) ili [infrared protocols and attacks](infrared.md).
- Za obližnje uređaje i senzore koristite [BLE advertising, GATT, and mesh testing](pentesting-ble-bluetooth-low-energy.md) ili [LPWAN/LoRaWAN security](low-power-wide-area-network.md).
- Za snimljene ili nepoznate RF signale koristite [SigDigger signal analysis](../hardware-hacking/radio.md#sigdigger) ili [FISSURE framework](fissure-the-rf-framework.md).

## References

- [1] [Great Scott Gadgets - Softverski definisani radio sa HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
