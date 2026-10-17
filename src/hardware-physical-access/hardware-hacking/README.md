# Hakovanje hardvera

{{#include ../../banners/hacktricks-training.md}}

Za uređaj kojem imate fizički pristup, počnite od interfejsa dostupnog preko ploče ili signala: [UART serijske konzole](uart.md), [JTAG/SWD debug pristup](jtag.md), [CoreSight praćenje instrukcija](arm-coresight-instruction-tracing.md), [I²C](i2c.md) i [SPI flash](spi.md) magistrale. [Analiza bočnih kanala](side_channel_analysis.md) i [ubrizgavanje grešaka](fault_injection_attacks.md) obuhvataju različite zadatke merenja i glitching-a; [analiza radio-signala](radio.md) pokriva ulaznu tačku putem radio-talasa. Za postupke specifične za ciljni uređaj, koji se odnose na RFID/NFC, sub-GHz, infracrveni prenos, BLE, LoRaWAN i iButton, koristite [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Pre povezivanja alata proverite električne nivoe ciljnog uređaja i ograničenja navedena u odgovarajućem poglavlju.

## JTAG

JTAG (IEEE 1149.1) podržava boundary-scan testiranje pomoću ćelija postavljenih oko I/O pinova uređaja. Mnogi procesori preko istog Test Access Port-a (TAP) omogućavaju i debug funkcije specifične za proizvođača; boundary scan i CPU debugging su srodne primene JTAG-a, ali nisu sinonimi.<sup>[[1]](#references)</sup>

JTAG standard definiše **specifične komande za sprovođenje boundary scan testiranja**, uključujući sledeće:

- **BYPASS** bira jedan-bitni bypass registar kako bi se do drugih uređaja u scan lancu moglo doći uz minimalno dodatno opterećenje.
- **SAMPLE/PRELOAD** uzorkuje vrednosti pinova tokom normalnog rada i može unapred učitati boundary-scan registar pre druge instrukcije.
- **EXTEST** postavlja i očitava stanja pinova.

Može da podrži i druge komande, kao što su:

- **IDCODE** za identifikaciju uređaja
- **INTEST** za interno testiranje uređaja

Na ove instrukcije možete naići kada koristite alat kao što je JTAGulator.

### Test Access Port

**Test Access Port (TAP)** omogućava pristup JTAG testnoj logici komponente. Potrebna su četiri signala, dok je `TRST` opcionalan:<sup>[[1]](#references)</sup>

- Ulaz za takt testiranja (**TCK**) TCK je **takt** koji određuje koliko često će TAP kontroler izvršiti jednu radnju (drugim rečima, preći u sledeće stanje mašine stanja).
- Ulaz za izbor testnog režima (**TMS**) TMS upravlja **mašinom konačnih stanja**. Pri svakom taktu, JTAG TAP kontroler uređaja proverava napon na TMS pinu. Ako je napon ispod određenog praga, signal se smatra niskim i tumači kao 0, dok se napon iznad tog praga smatra visokim i tumači kao 1.
- Ulaz za testne podatke (**TDI**) pomera serijsku instrukciju ili testne podatke u izabrani TAP registar. IEEE 1149.1 definiše ponašanje TAP prenosa, dok proizvođači definišu opcione instrukcije i debug registre.
- Izlaz za testne podatke (**TDO**) TDO je pin koji šalje **podatke iz čipa**.
- Ulaz za reset testiranja (**TRST**) Opcionalni TRST resetuje mašinu konačnih stanja **u poznato ispravno stanje**. Alternativno, ako se TMS drži na 1 tokom pet uzastopnih taktnih ciklusa, aktivira se reset, isto kao kada bi se koristio TRST pin, zbog čega je TRST opcionalan.

Ponekad ćete ove pinove moći da pronađete označene na PCB-u. U drugim slučajevima možda ćete morati da ih **pronađete**.

### Identifikacija JTAG pinova

Brza, namenski napravljena, ali relativno skupa opcija za otkrivanje JTAG portova je **JTAGulator**, koji može da identifikuje i raspored UART pinova.<sup>[[2]](#references)</sup>

Ima **24 kanala** koji se mogu povezati sa testnim tačkama na ploči. Ispituje moguće kombinacije pinova pomoću **IDCODE** i **BYPASS** skeniranja i prikazuje kanale koji odgovaraju otkrivenim JTAG signalima.

Jeftiniji, ali znatno sporiji način identifikacije rasporeda JTAG pinova jeste korišćenje [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) programa učitanog na mikrokontroler kompatibilan sa Arduino platformom.

Kod **JTAGenum** programa prvo odredite pinove mikrokontrolera za ispitivanje koji će se koristiti za enumeraciju. Pogledajte njegov raspored pinova, a zatim povežite te pinove sa mogućim testnim tačkama na ciljnoj ploči.<sup>[[3]](#references)</sup>

**Treći način** identifikacije JTAG pinova jeste **pregled PCB-a** u potrazi za poznatim rasporedom kontakata. Neke ploče imaju **Tag-Connect** raspored kontakata, mada je Tag-Connect sistem konektora koji može da prenosi JTAG, SWD, UART ili neki drugi interfejs — sam po sebi nije dokaz da su pinovi JTAG. Zatim se stvarni signali mogu identifikovati pomoću tehničke dokumentacije komponenti i merenja kontinuiteta.<sup>[[5]](#references)</sup>

## SDW

SWD je Arm-ov dvožični debug interfejs zasnovan na paketima.<sup>[[4]](#references)</sup>

Interfejs koristi dvosmerni **SWDIO** za podatke i **SWCLK** za takt. Mnogi uređaji implementiraju **Serial Wire/JTAG Debug Port (SWJ-DP)**, koji omogućava izbor između SWD-a i JTAG-a na zajedničkim pinovima.<sup>[[4]](#references)</sup>

## References

- [1] [Radna grupa IEEE 1149.1 — JTAG i boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Dokumentacija za JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumeracija Arduino JTAG pinova](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Debug interfejsi sa malim brojem pinova za sisteme sa više uređaja](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Rasporedi kontakata za debug i programiranje](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
