# Radio hacking

{{#include ../../banners/hacktricks-training.md}}

Testiranje bezbednosti radio-veza ispituje kako uređaj emituje, prima i tumači bežične signale. Softverski definisan radio (SDR) može da pomogne u pronalaženju signala, snimanju uzoraka u fazi/kvadraturi (I/Q) i testiranju demodulacije i dekodiranja bez vezivanja za hardver namenjen određenom protokolu.<sup>[[1]](#references)</sup>

Praktičan postupak podrazumeva utvrđivanje frekvencijskog opsega i širine kanala, snimanje nekoliko poznatih radnji uređaja, poređenje dobijenih signala, a zatim određivanje modulacije i strukture paketa. Testirajte ponavljanje ili emitovanje samo u izolovanom okruženju i na frekvencijama i opremi za koje imate ovlašćenje. Stranice u ovom odeljku obrađuju RFID, NFC, sub-GHz radio, infracrvenu vezu, BLE i srodne alate.<sup>[[1]](#references)</sup>

## Pronađite odgovarajući interfejs

- Za pristupnu karticu ili kontaktni ključ počnite od [tipova i napada na RFID/NFC tagove](pentesting-rfid.md), [radnih postupaka za Proxmark3](proxmark-3.md) ili [iButton i 1-Wire ključeva](ibutton.md). [Vodič za Flipper Zero](flipper-zero/README.md) sadrži veze ka radnjama specifičnim za njegov interfejs.
- Za signal daljinskog upravljača koristite [sub-GHz RF i rolling kodove](sub-ghz-rf.md) ili [infracrvene protokole i napade](infrared.md).
- Za uređaje i senzore u blizini koristite [testiranje BLE oglašavanja, GATT-a i mesh mreža](pentesting-ble-bluetooth-low-energy.md) ili [bezbednost LPWAN/LoRaWAN mreža](low-power-wide-area-network.md).
- Za snimljene ili nepoznate RF signale koristite [analizu signala pomoću SigDigger-a](../hardware-hacking/radio.md#sigdigger) ili [FISSURE framework](fissure-the-rf-framework.md).
- Za downlink signale satelitskih terminala pogledajte [ubacivanje signala u VSAT forward-link](vsat-forward-link-injection.md).



## References

- [1] [Great Scott Gadgets - Softverski definisan radio sa HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
