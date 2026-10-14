# Hardversko hakovanje

{{#include ../../banners/hacktricks-training.md}}

Za uređaj kojem imate fizički pristup, počnite od interfejsa koji izlažu njegova ploča ili signali: [UART serijske konzole](uart.md), [JTAG/SWD debug pristup](jtag.md), [I²C](i2c.md) i [SPI flash](spi.md) magistrale. [Analiza bočnih kanala](side_channel_analysis.md) i [ubrizgavanje grešaka](fault_injection_attacks.md) služe za različite zadatke merenja i izazivanja smetnji; [analiza radio-signala](radio.md) obuhvata ulaznu tačku putem bežičnog prenosa. Za postupke specifične za cilj koji se odnose na RFID/NFC, sub-GHz, infracrveni signal, BLE, LoRaWAN i iButton, koristite [Radio hakovanje i interfejse blizine](../radio-hacking/README.md). Pre povezivanja alata proverite električne nivoe cilja i ograničenja navedena u relevantnom poglavlju.

## JTAG

JTAG (IEEE 1149.1) podržava testiranje boundary-scan pomoću ćelija postavljenih oko I/O pinova uređaja. Mnogi procesori preko istog Test Access Port-a (TAP) izlažu i funkcije debug-a specifične za proizvođača; boundary scan i CPU debug su povezane upotrebe JTAG-a, ali nisu sinonimi.<sup>[[1]](#references)</sup>

JTAG standard definiše **određene komande za sprovođenje boundary scan testiranja**, uključujući sledeće:

- **BYPASS** bira jednobitni bypass registar kako bi se do drugih uređaja u scan chain-u moglo doći uz minimalno dodatno opterećenje.
- **SAMPLE/PRELOAD** beleži vrednosti pinova tokom normalnog rada i može unapred da učita boundary-scan registar pre druge instrukcije.
- **EXTEST** postavlja i očitava stanja pinova.

Može da podrži i druge komande, kao što su:

- **IDCODE** za identifikaciju uređaja
- **INTEST** za interno testiranje uređaja

Na ove instrukcije možete naići koristeći alat kao što je JTAGulator.

### Test Access Port

**Test Access Port (TAP)** omogućava pristup JTAG test logici komponente. Potrebna su četiri signala, dok je `TRST` opcionalan:<sup>[[1]](#references)</sup>

- Ulaz za testni takt (**TCK**) TCK je **takt** koji određuje koliko često će TAP kontroler izvršiti jednu radnju (drugim rečima, preći u sledeće stanje konačnog automata).
- Ulaz za izbor testnog režima (**TMS**) TMS upravlja **konačnim automatom**. Pri svakom taktu, JTAG TAP kontroler uređaja proverava napon na TMS pinu. Ako je napon ispod određenog praga, signal se smatra niskim i tumači kao 0, dok se, ako je iznad određenog praga, smatra visokim i tumači kao 1.
- Ulaz za testne podatke (**TDI**) pomera serijske instrukcije ili testne podatke u izabrani TAP registar. IEEE 1149.1 definiše ponašanje TAP prenosa, dok proizvođači definišu opcionalne instrukcije i debug registre.
- Izlaz za testne podatke (**TDO**) TDO je pin koji šalje **podatke sa čipa**.
- Ulaz za resetovanje testa (**TRST**) Opcionalni TRST vraća konačni automat **u poznato ispravno stanje**. Druga mogućnost je da se TMS drži na 1 tokom pet uzastopnih taktnih ciklusa; time se pokreće reset, isto kao i pomoću TRST pina, zbog čega je TRST opcionalan.

Ponekad ćete moći da pronađete te pinove označene na PCB-u. U drugim slučajevima moraćete da ih **pronađete**.

### Identifikovanje JTAG pinova

Brza, namenski napravljena, ali relativno skupa opcija za otkrivanje JTAG portova je **JTAGulator**, koji može da identifikuje i raspored UART pinova.<sup>[[2]](#references)</sup>

Ima **24 kanala** koji se mogu povezati sa testnim tačkama na ploči. Ispituje moguće kombinacije pinova pomoću **IDCODE** i **BYPASS** skeniranja i prikazuje kanale koji odgovaraju otkrivenim JTAG signalima.

Jeftiniji, ali znatno sporiji način identifikovanja rasporeda JTAG pinova jeste korišćenje [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) alata učitanog na mikrokontroler kompatibilan sa Arduinom.

Uz **JTAGenum**, prvo definišite pinove mikrokontrolera za ispitivanje koji se koriste za enumeraciju. Pogledajte njegov raspored pinova, pa ih povežite sa mogućim testnim tačkama na ciljnoj ploči.<sup>[[3]](#references)</sup>

**Treći način** za identifikovanje JTAG pinova jeste **pregled PCB-a** radi pronalaženja poznatog otiska. Neke ploče imaju **Tag-Connect** otisak, ali Tag-Connect je sistem konektora koji može da prenosi JTAG, SWD, UART ili neki drugi interfejs — sam po sebi ne dokazuje da su pinovi JTAG. Zatim se stvarni signali mogu utvrditi pomoću specifikacija komponenti i merenja kontinuiteta.<sup>[[5]](#references)</sup>

## SDW

SWD je Arm-ov dvožični debug interfejs zasnovan na paketima.<sup>[[4]](#references)</sup>

Interfejs koristi dvosmerni **SWDIO** za podatke i **SWCLK** za takt. Mnogi uređaji imaju implementiran **Serial Wire/JTAG Debug Port (SWJ-DP)** koji omogućava izbor između SWD-a i JTAG-a na zajedničkim pinovima.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 radna grupa — JTAG i boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Dokumentacija za JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumeracija JTAG pinova pomoću Arduina](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Debug interfejsi sa malim brojem pinova za sisteme sa više uređaja](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Otisci za debug i programerske kablove](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
