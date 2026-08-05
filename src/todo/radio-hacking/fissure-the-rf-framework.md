# FISSURE - RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE je open-source RF i reverse engineering framework dizajniran za sve nivoe znanja, sa mogućnostima za detekciju i klasifikaciju signala, otkrivanje protokola, izvršavanje napada, manipulaciju IQ podacima, analizu ranjivosti, automatizaciju i AI/ML. Framework je napravljen radi podsticanja brze integracije softverskih modula, radio-uređaja, protokola, podataka o signalima, skripti, flow graph-ova, referentnog materijala i alata trećih strana. FISSURE omogućava efikasan workflow tako što softver održava na jednom mestu i timovima omogućava da se bez napora osposobe za rad, uz deljenje iste proverene osnovne konfiguracije za određene Linux distribucije.<sup>[[1]](#references)[[2]](#references)</sup>

Framework i alati uključeni u FISSURE dizajnirani su za detekciju prisustva RF energije, razumevanje karakteristika signala, prikupljanje i analizu uzoraka, razvoj tehnika za transmitovanje i/ili injection, kao i izradu prilagođenih payload-a ili poruka. FISSURE sadrži rastuću biblioteku informacija o protokolima i signalima radi pomoći pri identifikaciji, izradi paketa i fuzzing-u. Dostupne su mogućnosti online arhiviranja za preuzimanje datoteka sa signalima i izradu playlista za simulaciju saobraćaja i testiranje sistema.

Pristupačna Python codebase i korisnički interfejs omogućavaju početnicima da brzo nauče o popularnim alatima i tehnikama koji uključuju RF i reverse engineering. Edukatori u oblasti cybersecurity-ja i inženjerstva mogu iskoristiti ugrađeni materijal ili koristiti framework za demonstraciju sopstvenih primena iz stvarnog sveta. Developeri i istraživači mogu koristiti FISSURE za svakodnevne zadatke ili predstaviti svoja napredna rešenja široj publici. Kako svest o FISSURE-u i njegova upotreba rastu u zajednici, tako će rasti i obim njegovih mogućnosti i širina tehnologije koju obuhvata.

**Dodatne informacije**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Početak rada

**Podržano**

U okviru FISSURE-a postoje tri grane radi lakše navigacije kroz datoteke i smanjenja redundanse koda. Grana Python2\_maint-3.7 sadrži codebase zasnovan na Python2, PyQt4 i GNU Radio 3.7; grana Python3\_maint-3.8 zasnovana je na Python3, PyQt5 i GNU Radio 3.8; a grana Python3\_maint-3.10 zasnovana je na Python3, PyQt5 i GNU Radio 3.10.

|   Operativni sistem   |   FISSURE grana   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**U razvoju (beta)**

Ovi operativni sistemi su i dalje u beta statusu. Njihov razvoj je u toku, a poznato je da nedostaje nekoliko funkcija. Stavke u installer-u mogu biti u konfliktu sa postojećim programima ili instalacija može biti neuspešna dok se status ne ukloni.

|     Operativni sistem     |    FISSURE grana   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Napomena: Određeni softverski alati ne rade na svakom operativnom sistemu. Pogledajte [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Instalacija**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Ovo će instalirati PyQt softverske zavisnosti potrebne za pokretanje instalacionih GUI-jeva ako nisu pronađene.

Zatim izaberite opciju koja najbolje odgovara vašem operativnom sistemu (trebalo bi da bude automatski detektovana ako se vaš OS podudara sa nekom od opcija).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Preporučuje se da instalirate FISSURE na čist operativni sistem kako biste izbegli postojeće konflikte. Izaberite sva preporučena polja za potvrdu (dugme Default) da biste izbegli greške prilikom rada sa različitim alatima unutar FISSURE-a. Tokom instalacije biće prikazano više upita, uglavnom za povišene dozvole i korisnička imena. Ako stavka na kraju sadrži odeljak "Verify", installer će pokrenuti naredbu koja sledi i označiti polje za potvrdu zelenom ili crvenom bojom, u zavisnosti od toga da li je naredba proizvela greške. Označene stavke bez odeljka "Verify" ostaće crne nakon instalacije.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Upotreba**

Otvorite terminal i unesite:
```
fissure
```
Za više detalja o korišćenju pogledajte FISSURE Help meni.

## Detalji

**Komponente**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Mogućnosti**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardver**

U nastavku je lista „podržanog“ hardvera sa različitim nivoima integracije:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lekcije

FISSURE sadrži nekoliko korisnih vodiča za upoznavanje sa različitim tehnologijama i tehnikama. Mnogi od njih uključuju korake za korišćenje različitih alata integrisanih u FISSURE.

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Plan razvoja

* [ ] Dodati više tipova hardvera, RF protokola, parametara signala i alata za analizu
* [ ] Podržati više operativnih sistema
* [ ] Razviti nastavni materijal o sistemu FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt itd.)
* [ ] Kreirati signal conditioner, feature extractor i signal classifier sa izbornim AI/ML tehnikama
* [ ] Implementirati mehanizme rekurzivne demodulacije za generisanje bitstream-a iz nepoznatih signala
* [ ] Prebaciti glavne FISSURE komponente na generičku šemu implementacije senzorskih čvorova

## Doprinos

Predlozi za unapređenje sistema FISSURE su veoma poželjni. Ostavite komentar na stranici [Discussions](https://github.com/ainfosec/FISSURE/discussions) ili na Discord Server-u ako imate ideje u vezi sa sledećim:

* Predlozi novih funkcija i izmene dizajna
* Softverski alati sa koracima za instalaciju
* Nove lekcije ili dodatni materijal za postojeće lekcije
* RF protokoli od interesa
* Više tipova hardvera i SDR uređaja za integraciju
* IQ analysis scripts u Python-u
* Ispravke i poboljšanja instalacije

Doprinosi unapređenju sistema FISSURE ključni su za ubrzavanje njegovog razvoja. Svaki vaš doprinos je veoma cenjen. Ako želite da doprinesete razvoju koda, fork-ujte repo i kreirajte pull request:

1. Fork-ujte projekat
2. Kreirajte svoju feature granu (`git checkout -b feature/AmazingFeature`)
3. Commit-ujte izmene (`git commit -m 'Add some AmazingFeature'`)
4. Push-ujte granu (`git push origin feature/AmazingFeature`)
5. Otvorite pull request

Kreiranje [Issues](https://github.com/ainfosec/FISSURE/issues) radi skretanja pažnje na greške takođe je dobrodošlo.

## Saradnja

Kontaktirajte odeljenje za Business Development kompanije Assured Information Security, Inc. (AIS) da biste predložili i formalizovali mogućnosti za saradnju na sistemu FISSURE – bilo kroz izdvajanje vremena za integraciju vašeg softvera, angažovanje stručnjaka iz kompanije AIS za razvoj rešenja za vaše tehničke izazove ili integraciju sistema FISSURE u druge platforme/aplikacije.

## Licenca

GPL-3.0

Detalje o licenci potražite u datoteci LICENSE.

## Kontakt

Pridružite se Discord Server-u: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Pratite nas na Twitter-u: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Zasluge

Odajemo priznanje i zahvaljujemo sledećim developerima:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Zahvalnice

Posebno zahvaljujemo dr Samuelu Mantravadi i Josephu Reithu na njihovom doprinosu ovom projektu.

## Reference

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
