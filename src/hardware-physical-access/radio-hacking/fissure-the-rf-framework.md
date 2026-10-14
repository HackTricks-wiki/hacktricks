# FISSURE - RF okvir

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE je open-source RF i reverse engineering okvir namenjen svim nivoima veština, sa mogućnostima za detekciju i klasifikaciju signala, otkrivanje protokola, izvođenje napada, IQ manipulaciju, analizu ranjivosti, automatizaciju i AI/ML. Okvir je napravljen da podstakne brzu integraciju softverskih modula, radio-uređaja, protokola, podataka o signalima, skripti, flow grafova, referentnog materijala i alata trećih strana. FISSURE olakšava radne tokove tako što drži softver na jednom mestu i omogućava timovima da se brzo upoznaju sa sistemom, uz deljenje iste proverene osnovne konfiguracije za određene Linux distribucije.<sup>[[1]](#references)[[2]](#references)</sup>

Okvir i alati uključeni u FISSURE namenjeni su detekciji RF energije, karakterizaciji signala, prikupljanju i analizi uzoraka, razvoju tehnika za emitovanje ili ubacivanje, kao i izradi prilagođenih payload-ova ili poruka. FISSURE pruža i informacije o protokolima i signalima za identifikaciju, izradu paketa i fuzzing, kao i arhive i liste za reprodukciju za simulaciju i testiranje saobraćaja.<sup>[[1]](#references)[[2]](#references)</sup>

Python baza koda i grafički interfejs pomažu početnicima da nauče RF i reverse-engineering alate. Edukatori mogu da koriste ugrađene lekcije, dok programeri i istraživači mogu da integrišu sopstvene module i radne tokove. Aktuelna izdanja podržavaju i distribuirane senzorske čvorove, TAK integraciju, geolokacione radne tokove i Apptainer implementacije prilagođene ulogama.<sup>[[1]](#references)[[3]](#references)</sup>

**Dodatne informacije**

* [AIS stranica](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 slajdovi](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 rad](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transkript Hack Chat-a](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Početak

**Podržani sistemi**

Aktuelni FISSURE koristi granu **`Python3`** za aktivni razvoj uz PyQt5 i GNU Radio 3.8 ili 3.10. Zastarela grana **`Python2_maint-3.7`** i dalje je dostupna za starije operativne sisteme i alate trećih strana kojima je potreban GNU Radio 3.7. Raniji nazivi grana `Python3_maint-3.8` i `Python3_maint-3.10` su istorijski; izbor verzije GNU Radio za održavanje sada se obavlja iz grane `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Operativni sistem | FISSURE grana | Podrazumevana GNU Radio grana |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | koristite podržanu Linux verziju | koristite odgovarajuću verziju |

**U toku (beta)**

Ovi operativni sistemi su još u beta fazi. Njihov razvoj je u toku i poznato je da nedostaje nekoliko funkcija. Stavke u instalacionom programu mogu biti u konfliktu sa postojećim programima ili se možda neće instalirati dok se ovaj status ne ukloni.

| Operativni sistem | FISSURE grana | Podrazumevana GNU Radio grana |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Pojedini alati trećih strana ne rade na svim operativnim sistemima. Pre instalacije proverite aktuelnu dokumentaciju [poznatih konflikata i softvera trećih strana](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts).<sup>[[3]](#references)</sup>

**Instalacija**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

Korak sa podmodulima preuzima GNU Radio out-of-tree module koje koristi FISSURE i neophodan je za njihovu instalaciju. Instalacioni program će takođe instalirati nedostajuće PyQt zavisnosti potrebne za pokretanje njegovih instalacionih GUI-ja.<sup>[[3]](#references)</sup>

Zatim izaberite opciju koja najbolje odgovara vašem operativnom sistemu (trebalo bi da bude automatski prepoznat ako vaš OS odgovara nekoj od opcija).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Preporučuje se da FISSURE instalirate na čist operativni sistem kako biste izbegli postojeće konflikte. Izaberite sva preporučena polja za potvrdu (dugme Default) da biste izbegli greške pri korišćenju različitih alata u okviru FISSURE-a. Tokom instalacije pojaviće se više upita, uglavnom za povišene privilegije i korisnička imena. Ako stavka na kraju sadrži odeljak „Verify“, instalacioni program će pokrenuti komandu koja sledi i označiti polje za potvrdu zelenom ili crvenom bojom, u zavisnosti od toga da li komanda proizvede greške. Označene stavke bez odeljka „Verify“ ostaće crne nakon instalacije.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Korišćenje**

Otvorite terminal i unesite:

```
fissure
```

Pogledajte meni Help u FISSURE-u za više detalja o korišćenju.

## Detalji

**Komponente**

* Kontrolna tabla
* Centralni čvor (HIPRFISR)
* Identifikacija ciljnog signala (TSI)
* Otkrivanje protokola (PD)
* Izvršilac Flow Graph-ova i skripti (FGE)

![komponente](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Mogućnosti**

| ![Ikona detektora signala](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detektor signala**_ | ![Ikona manipulacije IQ signalom](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulacija IQ signalom**_      | ![Ikona pretrage signala](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Pretraga signala**_          | ![Ikona prepoznavanja obrazaca](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Prepoznavanje obrazaca**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Ikona napada](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Napadi**_           | ![Ikona fuzzing-a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Ikona plejlista signala](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Plejliste signala**_       | ![Ikona galerije slika](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galerija slika**_  |
| ![Ikona izrade paketa](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Izrada paketa**_   | ![Ikona Scapy integracije](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy integracija**_ | ![Ikona CRC kalkulatora](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC kalkulator**_ | ![Ikona beleženja](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Beleženje**_            |

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

FISSURE sadrži nekoliko korisnih vodiča za upoznavanje s različitim tehnologijama i tehnikama. Mnogi obuhvataju korake za korišćenje raznih alata integrisanih u FISSURE.

* [Lekcija 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lekcija 2: Lua dissector-i](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lekcija 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lekcija 4: ESP ploče](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lekcija 5: Praćenje radiosondi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lekcija 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lekcija 7: Tipovi podataka](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lekcija 8: Prilagođeni GNU Radio blokovi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lekcija 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lekcija 10: Ispiti za radio-amatere](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lekcija 11: Wi-Fi alati](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lekcija 12: Kreiranje USB uređaja za pokretanje](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lekcija 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lekcija 14: Plafonski ventilatori](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Plan razvoja

* [ ] Dodati više tipova hardvera, RF protokola, parametara signala i alata za analizu
* [ ] Podržati više operativnih sistema
* [ ] Razviti nastavni materijal zasnovan na FISSURE-u (RF napadi, Wi-Fi, GNU Radio, PyQt itd.)
* [ ] Napraviti kondicioner signala, ekstraktor obeležja i klasifikator signala s izborom AI/ML tehnika
* [ ] Implementirati mehanizme rekurzivne demodulacije za generisanje bitstream-a iz nepoznatih signala
* [ ] Preći na šemu raspoređivanja generičkih senzorskih čvorova za glavne FISSURE komponente

## Doprinosi

Predlozi za unapređenje FISSURE-a su veoma dobrodošli. Ostavite komentar na stranici [Discussions](https://github.com/ainfosec/FISSURE/discussions) ili na Discord serveru ako imate predloge u vezi sa sledećim:

* Predlozi za nove funkcije i promene dizajna
* Softverski alati s koracima za instalaciju
* Nove lekcije ili dodatni materijali za postojeće lekcije
* RF protokoli od interesa
* Dodatni hardver i SDR tipovi za integraciju
* Python skripte za IQ analizu
* Ispravke i unapređenja instalacije

Doprinosi unapređenju FISSURE-a ključni su za ubrzavanje njegovog razvoja. Veoma cenimo sve doprinose. Ako želite da doprinesete razvoju koda, fork-ujte repo i napravite pull request:

1. Fork-ujte projekat
2. Napravite svoju granu za funkciju (`git checkout -b feature/AmazingFeature`)
3. Napravite commit promena (`git commit -m 'Add some AmazingFeature'`)
4. Pošaljite promene u granu (`git push origin feature/AmazingFeature`)
5. Otvorite pull request

Dobrodošlo je i otvaranje [Issues](https://github.com/ainfosec/FISSURE/issues) prijava radi ukazivanja na greške.

## Saradnja

Obratite se odeljenju za poslovni razvoj kompanije Assured Information Security, Inc. (AIS) da biste predložili i formalizovali mogućnosti saradnje na FISSURE-u — bilo da se radi o posvećivanju vremena integraciji vašeg softvera, angažovanju stručnjaka iz AIS-a za razvoj rešenja za vaše tehničke izazove ili integraciji FISSURE-a u druge platforme/aplikacije.

## Licenca

GPL-3.0

Detalje o licenci potražite u datoteci LICENSE.

## Kontakt

Pridružite se Discord serveru: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Pratite nas na Twitter-u: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Poslovni razvoj - Assured Information Security, Inc. - bd@ainfosec.com

## Zasluge

Zahvaljujemo se sledećim programerima:

[Zasluge](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Zahvalnice

Posebno zahvaljujemo dr Samuelu Mantravadi-ju i Josephu Reith-u na doprinosu ovom projektu.

## References

- [1] [FISSURE - RF okvir (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [Rad o FISSURE-u (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Dokumentacija za FISSURE - Instalacija](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
