# FISSURE - Framework RF

{{#include ../../banners/hacktricks-training.md}}

**Niezależne od częstotliwości rozumienie i inżynieria wsteczna sygnałów oparte na SDR**

FISSURE to framework open source do RF i inżynierii wstecznej, przeznaczony dla osób o każdym poziomie umiejętności. Oferuje funkcje wykrywania i klasyfikacji sygnałów, odkrywania protokołów, wykonywania ataków, manipulacji IQ, analizy podatności, automatyzacji oraz AI/ML. Framework stworzono z myślą o szybkiej integracji modułów programowych, urządzeń radiowych, protokołów, danych sygnałowych, skryptów, grafów przepływu, materiałów referencyjnych i narzędzi firm trzecich. FISSURE ułatwia pracę, przechowując oprogramowanie w jednym miejscu i pozwalając zespołom szybko rozpocząć pracę na tej samej sprawdzonej konfiguracji bazowej dla określonych dystrybucji Linux.<sup>[[1]](#references)[[2]](#references)</sup>

Framework i narzędzia zawarte w FISSURE służą do wykrywania energii RF, charakteryzowania sygnałów, zbierania i analizowania próbek, opracowywania technik transmisji lub wstrzykiwania oraz tworzenia niestandardowych payloadów lub komunikatów. FISSURE udostępnia również informacje o protokołach i sygnałach na potrzeby identyfikacji, tworzenia pakietów i fuzzingu, a także archiwa i playlisty do symulacji i testowania ruchu.<sup>[[1]](#references)[[2]](#references)</sup>

Baza kodu Python i interfejs graficzny pomagają początkującym poznawać narzędzia RF i inżynierii wstecznej. Edukatorzy mogą korzystać z wbudowanych lekcji, a deweloperzy i badacze integrować własne moduły i przepływy pracy. Obecne wydania obsługują również rozproszone węzły sensorów, integrację TAK, przepływy pracy związane z geolokalizacją oraz wdrożenia Apptainer dostosowane do ról.<sup>[[1]](#references)[[3]](#references)</sup>

**Dodatkowe informacje**

* [Strona AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slajdy GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Artykuł GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Nagranie wideo GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transkrypcja Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Obsługiwane**

Obecnie FISSURE wykorzystuje gałąź **`Python3`** do aktywnego rozwoju z PyQt5 i GNU Radio 3.8 lub 3.10. Przestarzała gałąź **`Python2_maint-3.7`** jest nadal dostępna dla starszych systemów operacyjnych i narzędzi firm trzecich wymagających GNU Radio 3.7. Dawne nazwy gałęzi `Python3_maint-3.8` i `Python3_maint-3.10` mają charakter historyczny; wybór wersji GNU Radio jest teraz obsługiwany z poziomu gałęzi `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| System operacyjny | Gałąź FISSURE | Domyślna gałąź GNU Radio |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | użyj obsługiwanej wersji Linux | użyj odpowiadającej jej wersji |

**W trakcie prac (beta)**

Te systemy operacyjne są nadal w wersji beta. Trwają nad nimi prace rozwojowe i wiadomo, że brakuje w nich kilku funkcji. Elementy instalatora mogą powodować konflikty z istniejącymi programami lub nie instalować się, dopóki status beta nie zostanie zniesiony.

| System operacyjny | Gałąź FISSURE | Domyślna gałąź GNU Radio |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Niektóre narzędzia firm trzecich nie działają na każdym systemie operacyjnym. Przed instalacją zapoznaj się z aktualną dokumentacją [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts).<sup>[[3]](#references)</sup>

**Instalacja**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

Krok submodule pobiera moduły GNU Radio out-of-tree używane przez FISSURE i jest wymagany podczas ich instalacji. Instalator zainstaluje również brakujące zależności PyQt potrzebne do uruchomienia graficznych interfejsów instalatora.<sup>[[3]](#references)</sup>

Następnie wybierz opcję najlepiej pasującą do Twojego systemu operacyjnego (powinna zostać wykryta automatycznie, jeśli Twój system pasuje do jednej z opcji).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Zaleca się zainstalowanie FISSURE w czystym systemie operacyjnym, aby uniknąć istniejących konfliktów. Zaznacz wszystkie zalecane pola wyboru (przycisk Default), aby uniknąć błędów podczas korzystania z różnych narzędzi w FISSURE. W trakcie instalacji pojawi się kilka monitów, które będą dotyczyć głównie uprawnień administratora i nazw użytkowników. Jeśli na końcu elementu znajduje się sekcja „Verify”, instalator uruchomi następujące po niej polecenie i zaznaczy pole wyboru elementu na zielono lub czerwono, w zależności od tego, czy polecenie wygeneruje błędy. Zaznaczone elementy bez sekcji „Verify” po zakończeniu instalacji pozostaną czarne.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Użycie**

Otwórz terminal i wpisz:

```
fissure
```

Zapoznaj się z menu Help programu FISSURE, aby uzyskać więcej informacji na temat korzystania z niego.

## Szczegóły

**Komponenty**

* Pulpit
* Centralny Hub (HIPRFISR)
* Identyfikacja sygnałów docelowych (TSI)
* Odkrywanie protokołów (PD)
* Wykonywanie Flow Graph i skryptów (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Możliwości**

| ![Ikona detektora sygnału](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detektor sygnału**_ | ![Ikona manipulacji IQ](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulacja IQ**_      | ![Ikona wyszukiwania sygnałów](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Wyszukiwanie sygnałów**_          | ![Ikona rozpoznawania wzorców](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Rozpoznawanie wzorców**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Ikona ataków](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataki**_           | ![Ikona fuzzingu](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Ikona list odtwarzania sygnałów](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Listy odtwarzania sygnałów**_       | ![Ikona galerii obrazów](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria obrazów**_  |
| ![Ikona tworzenia pakietów](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Tworzenie pakietów**_   | ![Ikona integracji z Scapy](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integracja z Scapy**_ | ![Ikona kalkulatora CRC](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Kalkulator CRC**_ | ![Ikona rejestrowania](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Rejestrowanie**_            |

**Sprzęt**

Poniższy sprzęt ma różny poziom integracji z FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Adaptery 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lekcje

FISSURE zawiera kilka pomocnych poradników, które pozwalają zapoznać się z różnymi technologiami i technikami. Wiele z nich opisuje kroki potrzebne do korzystania z różnych narzędzi zintegrowanych z FISSURE.

* [Lekcja 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lekcja 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lekcja 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lekcja 4: Płytki ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lekcja 5: Śledzenie radiosond](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lekcja 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lekcja 7: Typy danych](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lekcja 8: Niestandardowe bloki GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lekcja 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lekcja 10: Egzaminy radioamatorskie](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lekcja 11: Narzędzia Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lekcja 12: Tworzenie rozruchowych pamięci USB](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lekcja 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lekcja 14: Wentylatory sufitowe](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Plan rozwoju

* [ ] Dodać więcej typów sprzętu, protokołów RF, parametrów sygnałów i narzędzi analitycznych
* [ ] Obsługiwać więcej systemów operacyjnych
* [ ] Opracować materiały dydaktyczne dotyczące FISSURE (ataki RF, Wi-Fi, GNU Radio, PyQt itp.)
* [ ] Stworzyć kondycjoner sygnału, ekstraktor cech i klasyfikator sygnałów z możliwością wyboru technik AI/ML
* [ ] Wdrożyć mechanizmy rekurencyjnej demodulacji, które umożliwiają uzyskanie strumienia bitów z nieznanych sygnałów
* [ ] Przejść na schemat wdrażania oparty na ogólnych węzłach czujników dla głównych komponentów FISSURE

## Współtworzenie

Zachęcamy do zgłaszania sugestii dotyczących ulepszania FISSURE. Dodaj komentarz na stronie [Dyskusje](https://github.com/ainfosec/FISSURE/discussions) lub na serwerze Discord, jeśli masz uwagi dotyczące następujących kwestii:

* Sugestie dotyczące nowych funkcji i zmian projektowych
* Narzędzia programowe wraz z instrukcjami instalacji
* Nowe lekcje lub dodatkowe materiały do istniejących lekcji
* Interesujące protokoły RF
* Więcej typów sprzętu i SDR do integracji
* Skrypty do analizy IQ w Pythonie
* Poprawki i ulepszenia dotyczące instalacji

Wkład w ulepszanie FISSURE ma kluczowe znaczenie dla przyspieszenia jego rozwoju. Będziemy wdzięczni za każdy wkład. Jeśli chcesz pomóc w rozwoju kodu, utwórz fork repozytorium i zgłoś pull request:

1. Utwórz fork projektu
2. Utwórz gałąź dla swojej funkcji (`git checkout -b feature/AmazingFeature`)
3. Zatwierdź zmiany (`git commit -m 'Add some AmazingFeature'`)
4. Wypchnij zmiany do gałęzi (`git push origin feature/AmazingFeature`)
5. Otwórz pull request

Zachęcamy również do zgłaszania [Issues](https://github.com/ainfosec/FISSURE/issues), aby zwrócić uwagę na błędy.

## Współpraca

Skontaktuj się z działem rozwoju biznesowego Assured Information Security, Inc. (AIS), aby zaproponować i sformalizować możliwości współpracy przy FISSURE — niezależnie od tego, czy chodzi o poświęcenie czasu na integrację Twojego oprogramowania, zlecenie utalentowanym pracownikom AIS opracowania rozwiązań dla Twoich wyzwań technicznych, czy integrację FISSURE z innymi platformami lub aplikacjami.

## Licencja

GPL-3.0

Szczegóły licencji znajdują się w pliku LICENSE.

## Kontakt

Dołącz do serwera Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Obserwuj na Twitterze: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Rozwój biznesowy - Assured Information Security, Inc. - bd@ainfosec.com

## Podziękowania

Dziękujemy następującym programistom:

[Podziękowania](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Wyrazy uznania

Szczególne podziękowania dla dr. Samuela Mantravadhiego i Josepha Reitha za ich wkład w ten projekt.

## References

- [1] [FISSURE - Framework RF (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [Artykuł o FISSURE (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Dokumentacja FISSURE - Instalacja](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
