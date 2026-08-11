# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) podržava boundary-scan testiranje kroz ćelije postavljene oko I/O pinova uređaja. Mnogi procesori takođe izlažu debug funkcije specifične za proizvođača kroz isti Test Access Port (TAP); boundary scan i CPU debugging su povezane primene JTAG-a, ali nisu sinonimi.<sup>[[1]](#references)</sup>

JTAG standard definiše **specifične komande za sprovođenje boundary scanova**, uključujući sledeće:

- **BYPASS** bira jednobitni bypass registar kako bi se drugim uređajima u scan chain-u pristupilo uz minimalni overhead.
- **SAMPLE/PRELOAD** preuzima vrednosti pinova tokom normalnog rada i može unapred učitati boundary-scan registar pre druge instrukcije.
- **EXTEST** postavlja i očitava stanja pinova.

Može podržavati i druge komande, kao što su:

- **IDCODE** za identifikaciju uređaja
- **INTEST** za interno testiranje uređaja

Na ove instrukcije možete naići kada koristite alat kao što je JTAGulator.

### Test Access Port

**Test Access Port (TAP)** omogućava pristup JTAG testnoj logici komponente. Potrebna su četiri signala, dok je `TRST` opcionalan:<sup>[[1]](#references)</sup>

- Ulaz testnog takta (**TCK**) TCK je **takt** koji definiše koliko često će TAP kontroler izvršiti jednu radnju (drugim rečima, preći u sledeće stanje u state machine-u).
- Ulaz za izbor testnog režima (**TMS**) TMS kontroliše **finite state machine**. Pri svakom taktu uređajov JTAG TAP kontroler proverava napon na TMS pinu. Ako je napon ispod određenog praga, signal se smatra niskim i tumači kao 0, dok se, ako je napon iznad određenog praga, signal smatra visokim i tumači kao 1.
- Ulaz testnih podataka (**TDI**) serijski pomera instrukciju ili testne podatke u izabrani TAP registar. IEEE 1149.1 definiše ponašanje TAP transfera, dok proizvođači definišu opcione instrukcije i debug registre.
- Izlaz testnih podataka (**TDO**) TDO je pin koji šalje **podatke iz čipa**.
- Ulaz za reset testa (**TRST**) Opcioni TRST resetuje finite state machine **u poznato dobro stanje**. Alternativno, ako se TMS drži na 1 tokom pet uzastopnih ciklusa takta, aktivira se reset na isti način kao preko TRST pina, zbog čega je TRST opcionalan.

Ponekad ćete moći da pronađete te pinove označene na PCB-u. U drugim slučajevima moraćete da ih **pronađete**.

### Identifikacija JTAG pinova

Brza, namenski napravljena, ali relativno skupa opcija za otkrivanje JTAG portova jeste **JTAGulator**, koji takođe može da identifikuje UART pinout-e.<sup>[[2]](#references)</sup>

Ima **24 kanala** koji se mogu povezati sa testnim tačkama na ploči. Nabrajа kombinacije kandidata za pinove koristeći **IDCODE** i **BYPASS** scanove i prijavljuje kanale koji odgovaraju detektovanim JTAG signalima.

Jeftiniji, ali mnogo sporiji način identifikacije JTAG pinout-a jeste korišćenje alata [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) učitanog na mikrokontroleru kompatibilnom sa Arduinom.

Sa **JTAGenum** alatom najpre definišite pinove mikrokontrolera za probing koji se koriste za enumeraciju. Pogledajte njegov pinout, a zatim povežite te pinove sa testnim tačkama kandidatima na ciljnoj ploči.<sup>[[3]](#references)</sup>

**Treći način** za identifikaciju JTAG pinova jeste **pregled PCB-a** u potrazi za poznatim footprintom. Neke ploče imaju **Tag-Connect** footprint, iako je Tag-Connect sistem konektora koji može prenositi JTAG, SWD, UART ili neki drugi interfejs — sam po sebi nije dokaz da su pinovi JTAG. Datasheet-i komponenti i merenja kontinuiteta zatim mogu da identifikuju stvarne signale.<sup>[[5]](#references)</sup>

## SDW

SWD je Arm-ov dvopinski, packet-based debug interfejs.<sup>[[4]](#references)</sup>

Interfejs koristi bidirekcioni **SWDIO** za podatke i **SWCLK** za takt. Mnogi uređaji implementiraju **Serial Wire/JTAG Debug Port (SWJ-DP)**, koji omogućava izbor između SWD-a i JTAG-a na zajedničkim pinovima.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 radna grupa — JTAG i boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator dokumentacija](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumeracija JTAG pinova za Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Debug interfejsi sa malim brojem pinova za sisteme sa više uređaja](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprint-i debug i programskih kablova](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
