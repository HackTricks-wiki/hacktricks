# FISSURE - RF okvir

**Razumevanje i obrnuto inženjerstvo signala nezavisnog od frekvencije zasnovano na SDR-u**

FISSURE je okvir otvorenog koda za RF i obrnuto inženjerstvo dizajniran za sve nivoe veština sa mogućnostima za detekciju i klasifikaciju signala, otkrivanje protokola, izvršavanje napada, IQ manipulaciju, analizu ranjivosti, automatizaciju i AI/ML. Okvir je izgrađen da promoviše brzu integraciju softverskih modula, radija, protokola, podataka o signalima, skripti, tokova podataka, referentnog materijala i alata trećih strana. FISSURE je omogućavač radnog toka koji drži softver na jednom mestu i omogućava timovima da se lako prilagode dok dele istu proverenu osnovnu konfiguraciju za specifične Linux distribucije.

Okvir i alati uključeni u FISSURE su dizajnirani da detektuju prisustvo RF energije, razumeju karakteristike signala, prikupljaju i analiziraju uzorke, razvijaju tehnike prenosa i/ili injekcije, i kreiraju prilagođene terete ili poruke. FISSURE sadrži rastuću biblioteku informacija o protokolima i signalima koja pomaže u identifikaciji, kreiranju paketa i fuzzingu. Postoje mogućnosti online arhiviranja za preuzimanje signalnih datoteka i izradu plejlista za simulaciju saobraćaja i testiranje sistema.

Prijateljski Python kod i korisnički interfejs omogućavaju početnicima da brzo nauče o popularnim alatima i tehnikama koje se odnose na RF i obrnuto inženjerstvo. Obrazovni radnici u oblasti sajber bezbednosti i inženjerstva mogu iskoristiti ugrađeni materijal ili koristiti okvir za demonstraciju svojih stvarnih aplikacija. Programeri i istraživači mogu koristiti FISSURE za svoje svakodnevne zadatke ili da izlože svoja savremena rešenja široj publici. Kako svest i upotreba FISSURE raste u zajednici, tako će rasti i obim njegovih mogućnosti i širina tehnologije koju obuhvata.

**Dodatne informacije**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Početak rada

**Podržano**

Postoje tri grane unutar FISSURE-a kako bi se olakšalo navigaciju datotekama i smanjila redundancija koda. Grana Python2\_maint-3.7 sadrži kod baziran na Python2, PyQt4 i GNU Radio 3.7; grana Python3\_maint-3.8 je izgrađena oko Python3, PyQt5 i GNU Radio 3.8; a grana Python3\_maint-3.10 je izgrađena oko Python3, PyQt5 i GNU Radio 3.10.

|   Operativni sistem   |   FISSURE grana   |
| :-------------------: | :---------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64)  | Python3\_maint-3.8 |

**U toku (beta)**

Ovi operativni sistemi su još u beta statusu. U razvoju su i poznato je da nedostaju nekoliko funkcija. Stavke u instalatoru mogu biti u sukobu sa postojećim programima ili ne mogu biti instalirane dok se status ne ukloni.

|     Operativni sistem     |    FISSURE grana   |
| :-----------------------: | :----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Napomena: Određeni softverski alati ne rade za svaki OS. Pogledajte [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Instalacija**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Ovo će instalirati PyQt softverske zavisnosti potrebne za pokretanje instalacionih GUI-a ako nisu pronađene.

Zatim, odaberite opciju koja najbolje odgovara vašem operativnom sistemu (trebalo bi da bude automatski otkriveno ako vaš OS odgovara nekoj od opcija).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Preporučuje se instalacija FISSURE na čistom operativnom sistemu kako bi se izbegli postojeći konflikti. Odaberite sve preporučene čekboksove (Default button) kako biste izbegli greške prilikom korišćenja raznih alata unutar FISSURE. Tokom instalacije biće više upita, uglavnom za povišene dozvole i korisnička imena. Ako stavka sadrži "Verify" sekciju na kraju, instalater će pokrenuti komandu koja sledi i označiti stavku čekboks zelenom ili crvenom bojom u zavisnosti od toga da li su komandom proizvedene greške. Obeležene stavke bez "Verify" sekcije će ostati crne nakon instalacije.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Korišćenje**

Otvorite terminal i unesite:
```
fissure
```
Referišite se na FISSURE Help meni za više detalja o korišćenju.

## Detalji

**Komponente**

* Dashboard
* Central Hub (HIPRFISR)
* Identifikacija ciljnog signala (TSI)
* Otkriće protokola (PD)
* Tok graf i izvršitelj skripti (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Mogućnosti**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detektor signala**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulacija IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Pretraga signala**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Prepoznavanje obrazaca**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Napadi**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playliste signala**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galerija slika**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Kreiranje paketa**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy integracija**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC kalkulator**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logovanje**_            |

**Hardver**

Sledeća je lista "podržanog" hardvera sa različitim nivoima integracije:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 adapteri
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lekcije

FISSURE dolazi sa nekoliko korisnih vodiča kako bi se upoznali sa različitim tehnologijama i tehnikama. Mnogi uključuju korake za korišćenje raznih alata koji su integrisani u FISSURE.

* [Lekcija1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lekcija2: Lua disekcioni](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lekcija3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lekcija4: ESP ploče](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lekcija5: Praćenje radiosonda](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lekcija6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lekcija7: Tipovi podataka](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lekcija8: Prilagođeni GNU Radio blokovi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lekcija9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lekcija10: Ham radio ispiti](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lekcija11: Wi-Fi alati](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Plan

* [ ] Dodati više tipova hardvera, RF protokola, parametara signala, alata za analizu
* [ ] Podržati više operativnih sistema
* [ ] Razviti materijal za časove oko FISSURE (RF napadi, Wi-Fi, GNU Radio, PyQt, itd.)
* [ ] Kreirati kondicioner signala, ekstraktor karakteristika i klasifikator signala sa selektivnim AI/ML tehnikama
* [ ] Implementirati rekurzivne demodulacione mehanizme za proizvodnju bitstream-a iz nepoznatih signala
* [ ] Prebaciti glavne FISSURE komponente na generički raspored senzorskih čvorova

## Doprinos

Predlozi za poboljšanje FISSURE su snažno ohrabreni. Ostavite komentar na stranici [Diskusije](https://github.com/ainfosec/FISSURE/discussions) ili na Discord serveru ako imate bilo kakve misli u vezi sa sledećim:

* Predlozi za nove funkcije i promene dizajna
* Softverski alati sa koracima instalacije
* Nove lekcije ili dodatni materijal za postojeće lekcije
* RF protokoli od interesa
* Više tipova hardvera i SDR za integraciju
* IQ analize skripti u Python-u
* Ispravke i poboljšanja instalacije

Doprinosi za poboljšanje FISSURE su ključni za ubrzanje njenog razvoja. Svaki doprinos koji napravite je veoma cenjen. Ako želite da doprinosite kroz razvoj koda, molimo vas da fork-ujete repozitorij i kreirate pull request:

1. Fork-ujte projekat
2. Kreirajte svoju granu funkcije (`git checkout -b feature/AmazingFeature`)
3. Potvrdite svoje promene (`git commit -m 'Dodajte neku AmazingFeature'`)
4. Pomerite na granu (`git push origin feature/AmazingFeature`)
5. Otvorite pull request

Kreiranje [Problema](https://github.com/ainfosec/FISSURE/issues) kako bi se skrenula pažnja na greške je takođe dobrodošlo.

## Saradnja

Kontaktirajte Assured Information Security, Inc. (AIS) poslovni razvoj da predložite i formalizujete bilo koje mogućnosti saradnje oko FISSURE – bilo da se radi o posvećivanju vremena za integraciju vašeg softvera, angažovanju talentovanih ljudi iz AIS-a za razvoj rešenja za vaše tehničke izazove, ili integraciji FISSURE u druge platforme/aplikacije.

## Licenca

GPL-3.0

Za detalje o licenci, pogledajte LICENSE datoteku.

## Kontakt

Pridružite se Discord serveru: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Pratite na Twitter-u: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Poslovni razvoj - Assured Information Security, Inc. - bd@ainfosec.com

## Zasluge

Priznajemo i zahvaljujemo se ovim programerima:

[Zasluge](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Zahvalnosti

Posebna zahvalnost dr. Samuelu Mantravadi i Josephu Reithu za njihov doprinos ovom projektu.
