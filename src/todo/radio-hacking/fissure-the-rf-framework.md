# FISSURE - RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Razumevanje i reverse engineering signala zasnovan na Frequency Independent SDR-u**

FISSURE je RF framework otvorenog koda i framework za reverse engineering, namenjen svim nivoima znanja, sa mehanizmima za detekciju i klasifikaciju signala, otkrivanje protokola, izvršavanje napada, IQ manipulaciju, analizu ranjivosti, automatizaciju i AI/ML. Framework je napravljen da omogući brzu integraciju softverskih modula, radio-uređaja, protokola, podataka o signalima, skripti, flow graph-ova, referentnog materijala i alata trećih strana. FISSURE omogućava efikasniji workflow tako što softver održava na jednom mestu i timovima omogućava da se bez napora uhodaju, uz deljenje iste proverene osnovne konfiguracije za određene Linux distribucije.<sup>[[1]](#references)[[2]](#references)</sup>

Framework i alati uključeni u FISSURE namenjeni su detekciji RF energije, karakterizaciji signala, prikupljanju i analizi uzoraka, razvoju tehnika prenosa ili injection-a i izradi prilagođenih payload-a ili poruka. FISSURE takođe pruža informacije o protokolima i signalima za identifikaciju, izradu paketa i fuzzing, kao i arhive i playliste za simulaciju i testiranje saobraćaja.<sup>[[1]](#references)[[2]](#references)</sup>

Python codebase i grafički interfejs pomažu početnicima da nauče RF i reverse-engineering alate. Edukatori mogu koristiti ugrađene lekcije, dok developeri i istraživači mogu integrisati sopstvene module i workflow-e. Aktuelna izdanja podržavaju i distribuirane senzorske čvorove, TAK integraciju, geolokacione workflow-e i Apptainer deployment-e specifične za uloge.<sup>[[1]](#references)[[3]](#references)</sup>

**Dodatne informacije**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Početak rada

**Podržano**

Aktuelni FISSURE koristi granu **`Python3`** za aktivni razvoj sa PyQt5 i GNU Radio 3.8 ili 3.10. Zastarela grana **`Python2_maint-3.7`** i dalje je dostupna za starije operativne sisteme i alate trećih strana koji zahtevaju GNU Radio 3.7. Prethodni nazivi grana `Python3_maint-3.8` i `Python3_maint-3.10` su istorijski; izbor GNU Radio maintenance grane sada se obavlja iz grane `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Operativni sistem | FISSURE grana | Podrazumevana GNU Radio grana |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | koristi podržanu Linux verziju | koristi odgovarajuću verziju |

**U razvoju (beta)**

Ovi operativni sistemi su i dalje u beta statusu. Njihov razvoj je u toku i poznato je da im nedostaje nekoliko funkcija. Stavke u installer-u mogu biti u konfliktu sa postojećim programima ili instalacija može da ne uspe dok se status ne ukloni.

| Operativni sistem | FISSURE grana | Podrazumevana GNU Radio grana |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Određeni alati trećih strana ne rade na svakom operativnom sistemu. Pre instalacije proverite aktuelnu dokumentaciju [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts).<sup>[[3]](#references)</sup>

**Instalacija**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
Korak sa submodule preuzima GNU Radio out-of-tree module koje koristi FISSURE i neophodan je prilikom instaliranja tih modula. Installer će takođe instalirati nedostajuće PyQt dependencies potrebne za pokretanje njegovih instalacionih GUI-ja.<sup>[[3]](#references)</sup>

Zatim izaberite opciju koja najbolje odgovara vašem operativnom sistemu (trebalo bi da bude automatski detektovan ako vaš OS odgovara nekoj od opcija).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Preporučuje se da FISSURE instalirate na čist operativni sistem kako biste izbegli postojeće konflikte. Izaberite sva preporučena polja za potvrdu (dugme Default) da biste izbegli greške pri radu sa različitim alatima u okviru FISSURE-a. Tokom instalacije biće prikazano više upita, uglavnom za povišene privilegije i korisnička imena. Ako stavka na kraju sadrži odeljak "Verify", installer će pokrenuti naredbu koja sledi i označiti stavku polja za potvrdu zelenom ili crvenom bojom, u zavisnosti od toga da li je naredba proizvela greške. Označene stavke bez odeljka "Verify" ostaće crne nakon instalacije.

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

Sledeći hardver ima različite nivoe integracije u FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 adapteri
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lekcije

FISSURE sadrži nekoliko korisnih vodiča za upoznavanje sa različitim tehnologijama i tehnikama. Mnogi uključuju korake za korišćenje različitih alata integrisanih u FISSURE.

* [Lekcija1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lekcija2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lekcija3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lekcija4: ESP ploče](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lekcija5: Praćenje radiosonde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lekcija6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lekcija7: Tipovi podataka](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lekcija8: Prilagođeni GNU Radio blokovi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lekcija9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lekcija10: Ispiti iz radio-amaterstva](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lekcija11: Wi-Fi alati](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lekcija12: Kreiranje bootabilnih USB uređaja](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lekcija13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lekcija14: Plafonski ventilatori](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Plan razvoja

* [ ] Dodati više tipova hardvera, RF protokola, parametara signala i alata za analizu
* [ ] Podržati više operativnih sistema
* [ ] Razviti nastavni materijal o FISSURE-u (RF Attacks, Wi-Fi, GNU Radio, PyQt itd.)
* [ ] Kreirati conditioner signala, extractor karakteristika i classifier signala sa izbornim AI/ML tehnikama
* [ ] Implementirati rekurzivne mehanizme demodulacije za generisanje bitstream-a iz nepoznatih signala
* [ ] Prebaciti glavne FISSURE komponente na generičku šemu implementacije senzorskih čvorova

## Doprinos

Predlozi za unapređenje FISSURE-a su veoma poželjni. Ostavite komentar na stranici [Discussions](https://github.com/ainfosec/FISSURE/discussions) ili na Discord Server-u ako imate ideje u vezi sa sledećim:

* Predlozi novih funkcija i izmene dizajna
* Software alati sa koracima za instalaciju
* Nove lekcije ili dodatni materijal za postojeće lekcije
* RF protokoli od interesa
* Više tipova hardvera i SDR uređaja za integraciju
* IQ analysis skripte u Python-u
* Ispravke i poboljšanja instalacije

Doprinosi unapređenju FISSURE-a ključni su za ubrzavanje njegovog razvoja. Svaki vaš doprinos je veoma cenjen. Ako želite da doprinesete razvoju koda, fork-ujte repo i kreirajte pull request:

1. Fork-ujte projekat
2. Kreirajte svoju feature granu (`git checkout -b feature/AmazingFeature`)
3. Commit-ujte izmene (`git commit -m 'Add some AmazingFeature'`)
4. Push-ujte granu (`git push origin feature/AmazingFeature`)
5. Otvorite pull request

Kreiranje [Issues](https://github.com/ainfosec/FISSURE/issues) radi ukazivanja na greške takođe je dobrodošlo.

## Saradnja

Kontaktirajte Business Development odeljenje kompanije Assured Information Security, Inc. (AIS) da predložite i formalizujete mogućnosti saradnje na projektu FISSURE – bilo da se radi o posvećivanju vremena integraciji vašeg softvera, angažovanju talentovanih ljudi iz AIS-a za razvoj rešenja za vaše tehničke izazove ili integraciji FISSURE-a u druge platforme/aplikacije.

## Licenca

GPL-3.0

Za detalje o licenci pogledajte datoteku LICENSE.

## Kontakt

Pridružite se Discord Server-u: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Pratite nas na Twitter-u: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Zasluge

Odajemo priznanje i zahvaljujemo se sledećim developer-ima:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Zahvalnice

Posebno se zahvaljujemo dr Samuelu Mantravadi-ju i Josephu Reith-u na doprinosu ovom projektu.

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
