# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG omogućava obavljanje boundary scan-a. Boundary scan analizira određena kola, uključujući ugrađene boundary-scan ćelije i registre za svaki pin.

JTAG standard definiše **specific commands for conducting boundary scans**, uključujući sledeće:

- **BYPASS** omogućava testiranje određenog čipa bez dodatnog opterećenja prolaska kroz druge čipove.
- **SAMPLE/PRELOAD** uzima uzorak podataka koji ulaze u uređaj i izlaze iz njega dok je u svom uobičajenom režimu rada.
- **EXTEST** postavlja i očitava stanja pinova.

Može podržavati i druge komande, kao što su:

- **IDCODE** za identifikaciju uređaja
- **INTEST** za interno testiranje uređaja

Na ove instrukcije možete naići kada koristite alat kao što je JTAGulator.

### Test Access Port

Boundary scan uključuje testiranje četvorožičnog **Test Access Port (TAP)**, porta opšte namene koji omogućava **access to the JTAG test support** funkcijama ugrađenim u komponentu. TAP koristi sledećih pet signala:

- Ulaz testnog takta (**TCK**) TCK je **clock** koji određuje koliko često će TAP kontroler izvršiti jednu radnju (drugim rečima, preći u sledeće stanje u state machine-u).
- Ulaz za izbor testnog režima (**TMS**) TMS kontroliše **finite state machine**. Pri svakom taktu, JTAG TAP kontroler uređaja proverava napon na TMS pinu. Ako je napon ispod određenog praga, signal se smatra niskim i tumači kao 0, dok se, ako je napon iznad određenog praga, signal smatra visokim i tumači kao 1.
- Ulaz testnih podataka (**TDI**) TDI je pin koji šalje **data into the chip through the scan cells**. Svaki proizvođač je odgovoran za definisanje komunikacionog protokola preko ovog pina, jer ga JTAG ne definiše.
- Izlaz testnih podataka (**TDO**) TDO je pin koji šalje **data out of the chip**.
- Ulaz za resetovanje testa (**TRST**) Opciono TRST resetuje finite state machine **to a known good state**. Druga mogućnost je da se TMS drži na 1 tokom pet uzastopnih taktova, čime se pokreće reset na isti način kao putem TRST pina, zbog čega je TRST opcioni.

Ponekad ćete moći da pronađete te pinove označene na PCB-u. U drugim slučajevima možda ćete morati da ih **pronađete**.

### Identifying JTAG pins

Najbrži, ali najskuplji način za otkrivanje JTAG portova jeste korišćenje **JTAGulator** uređaja, napravljenog upravo za tu svrhu (iako može **also detect UART pinouts**).

Ima **24 kanala** koje možete povezati sa pinovima ploče. Zatim izvršava **BF attack** svih mogućih kombinacija, šaljući **IDCODE** i **BYPASS** boundary scan komande. Ako primi odgovor, prikazuje kanal koji odgovara svakom JTAG signalu.

Jeftiniji, ali mnogo sporiji način identifikacije JTAG pinout-a jeste korišćenje [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) učitanog na mikrokontroleru kompatibilnom sa Arduinom.

Korišćenjem alata **JTAGenum**, najpre biste **definisali pinove probing** uređaja koji ćete koristiti za enumeraciju. Morali biste da pogledate dijagram pinout-a uređaja, a zatim da povežete te pinove sa testnim tačkama na ciljnom uređaju.

**Treći način** za identifikaciju JTAG pinova jeste **inspecting the PCB** kako biste pronašli neki od pinout-a. U nekim slučajevima PCB-ovi mogu praktično da obezbede **Tag-Connect interface**, što jasno ukazuje da ploča takođe ima JTAG konektor. Kako taj interfejs izgleda možete videti na [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Pored toga, pregled **datasheets of the chipsets on the PCB** može otkriti dijagrame pinout-a koji ukazuju na JTAG interfejse.

## SDW

SWD je ARM-specifičan protokol dizajniran za debugging.

SWD interfejs zahteva **two pins**: bidirekcioni signal **SWDIO**, koji je ekvivalent **TDI and TDO pins and a clock** kod JTAG-a, i **SWCLK**, koji je ekvivalent za **TCK** kod JTAG-a. Mnogi uređaji podržavaju **Serial Wire or JTAG Debug Port (SWJ-DP)**, kombinovani JTAG i SWD interfejs koji omogućava povezivanje SWD ili JTAG probe sa ciljem.

{{#include ../../banners/hacktricks-training.md}}
