# Hakovanje hardvera

{{#include ../../banners/hacktricks-training.md}}

Za uređaj kojem imate fizički pristup, počnite od interfejsa koji izlažu njegova ploča ili signali: [serijske konzole UART](uart.md), [JTAG/SWD pristup za otklanjanje grešaka](jtag.md), magistrale [I²C](i2c.md) i [SPI flash](spi.md). [Analiza bočnih kanala](side_channel_analysis.md) i [ubrizgavanje grešaka](fault_injection_attacks.md) bave se različitim zadacima merenja i izazivanja smetnji; [analiza radio-signala](radio.md) obuhvata ulaznu tačku putem bežične komunikacije. Pre povezivanja alata proverite električne nivoe ciljnog uređaja i ograničenja navedena u odgovarajućem poglavlju.

## JTAG

JTAG (IEEE 1149.1) podržava testiranje skeniranjem granica pomoću ćelija postavljenih oko I/O pinova uređaja. Mnogi procesori preko istog Test Access Port-a (TAP) izlažu i funkcije za otklanjanje grešaka specifične za proizvođača; skeniranje granica i otklanjanje grešaka na CPU-u povezane su primene JTAG-a, ali nisu sinonimi.<sup>[[1]](#references)</sup>

JTAG standard definiše **posebne komande za skeniranje granica**, uključujući sledeće:

- **BYPASS** bira jednobitni registar za zaobilaženje, tako da se do drugih uređaja u lancu za skeniranje može doći uz minimalno dodatno opterećenje.
- **SAMPLE/PRELOAD** beleži vrednosti pinova tokom normalnog rada i može da unapred učita registar za skeniranje granica pre druge instrukcije.
- **EXTEST** postavlja i čita stanja pinova.

Može da podržava i druge komande, kao što su:

- **IDCODE** za identifikaciju uređaja
- **INTEST** za interno testiranje uređaja

Na ove instrukcije možete naići kada koristite alat kao što je JTAGulator.

### Test Access Port

**Test Access Port (TAP)** omogućava pristup JTAG testnoj logici komponente. Potrebna su četiri signala, dok je `TRST` opcioni:<sup>[[1]](#references)</sup>

- Ulazni testni takt (**TCK**) TCK je **takt** koji određuje koliko često TAP kontroler izvršava jednu radnju (drugim rečima, prelazi u sledeće stanje u mašini stanja).
- Ulaz za izbor režima testiranja (**TMS**) TMS upravlja **mašinom konačnih stanja**. Pri svakom taktnom impulsu, JTAG TAP kontroler uređaja proverava napon na TMS pinu. Ako je napon ispod određenog praga, signal se smatra niskim i tumači kao 0; ako je iznad određenog praga, smatra se visokim i tumači kao 1.
- Ulazni testni podaci (**TDI**) pomeraju serijsku instrukciju ili testne podatke u izabrani TAP registar. IEEE 1149.1 definiše ponašanje TAP prenosa, dok proizvođači definišu opcione instrukcije i registre za otklanjanje grešaka.
- Izlazni testni podaci (**TDO**) TDO je pin koji šalje **podatke van čipa**.
- Ulaz za reset testiranja (**TRST**) Opcioni TRST resetuje mašinu konačnih stanja **u poznato ispravno stanje**. Kao alternativa, ako se TMS drži na 1 tokom pet uzastopnih taktnih ciklusa, pokreće se reset, isto kao kada bi se koristio TRST pin, zbog čega je TRST opcioni.

Ponekad ćete moći da pronađete te pinove označene na štampanoj ploči. U drugim slučajevima moraćete da ih **pronađete**.

### Identifikovanje JTAG pinova

Brza, namenski napravljena, ali relativno skupa opcija za otkrivanje JTAG portova je **JTAGulator**, koji može da identifikuje i raspored UART pinova.<sup>[[2]](#references)</sup>

Ima **24 kanala** koji se mogu povezati sa testnim tačkama na ploči. Ispituje moguće kombinacije pinova pomoću skeniranja **IDCODE** i **BYPASS**, a zatim prikazuje kanale koji odgovaraju otkrivenim JTAG signalima.

Jeftiniji, ali znatno sporiji način za identifikaciju rasporeda JTAG pinova jeste korišćenje [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) učitanog na mikrokontroler kompatibilan sa Arduino platformom.

Uz **JTAGenum**, prvo definišite pinove mikrokontrolera za ispitivanje koji će se koristiti za enumeraciju. Pogledajte njegov raspored pinova, a zatim povežite te pinove sa mogućim testnim tačkama na ciljnoj ploči.<sup>[[3]](#references)</sup>

**Treći način** za identifikaciju JTAG pinova jeste **pregled štampane ploče** u potrazi za poznatim rasporedom kontakata. Neke ploče izlažu **Tag-Connect** raspored kontakata, mada je Tag-Connect sistem konektora koji može da prenosi JTAG, SWD, UART ili neki drugi interfejs — sam po sebi ne dokazuje da su pinovi JTAG. Zatim se pomoću tehničkih listova komponenti i merenja kontinuiteta mogu identifikovati stvarni signali.<sup>[[5]](#references)</sup>

## SDW

SWD je Arm-ov dvopinski interfejs za otklanjanje grešaka zasnovan na paketima.<sup>[[4]](#references)</sup>

Interfejs koristi dvosmerni **SWDIO** za podatke i **SWCLK** za takt. Mnogi uređaji implementiraju **Serial Wire/JTAG Debug Port (SWJ-DP)** koji omogućava izbor između SWD-a i JTAG-a na zajedničkim pinovima.<sup>[[4]](#references)</sup>

## References

- [1] [Radna grupa IEEE 1149.1 — JTAG i skeniranje granica](https://sagroups.ieee.org/1149/1/)
- [2] [Dokumentacija za JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumeracija JTAG pinova pomoću Arduina](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfejsi za otklanjanje grešaka sa malim brojem pinova za sisteme sa više uređaja](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Rasporedi kontakata za kablove za otklanjanje grešaka i programiranje](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
