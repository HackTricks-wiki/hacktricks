# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Niezależne od częstotliwości rozumienie sygnałów i inżynieria wsteczna oparte na SDR**

FISSURE to open-source framework RF i inżynierii wstecznej przeznaczony dla osób na każdym poziomie zaawansowania, oferujący integrację z funkcjami wykrywania i klasyfikacji sygnałów, odkrywania protokołów, wykonywania ataków, manipulowania IQ, analizy podatności, automatyzacji oraz AI/ML. Framework został stworzony w celu szybkiej integracji modułów programowych, radiotelefonów, protokołów, danych sygnałowych, skryptów, grafów przepływu, materiałów referencyjnych i narzędzi innych firm. FISSURE usprawnia przepływ pracy, przechowując oprogramowanie w jednym miejscu i umożliwiając zespołom łatwe rozpoczęcie pracy przy jednoczesnym korzystaniu z tej samej sprawdzonej konfiguracji bazowej dla określonych dystrybucji Linux.<sup>[[1]](#references)[[2]](#references)</sup>

Framework i narzędzia zawarte w FISSURE służą do wykrywania energii RF, charakteryzowania sygnałów, gromadzenia i analizowania próbek, opracowywania technik transmisji lub wstrzykiwania oraz tworzenia niestandardowych payloadów lub komunikatów. FISSURE udostępnia również informacje o protokołach i sygnałach do identyfikacji, tworzenia pakietów i fuzzingu, a także archiwa i playlisty do symulacji oraz testowania ruchu.<sup>[[1]](#references)[[2]](#references)</sup>

Baza kodu w Pythonie i interfejs graficzny pomagają początkującym poznać narzędzia RF i inżynierii wstecznej. Edukatorzy mogą korzystać z wbudowanych lekcji, a deweloperzy i badacze mogą integrować własne moduły oraz przepływy pracy. Obecne wydania obsługują również rozproszone węzły sensorów, integrację z TAK, przepływy pracy związane z geolokalizacją oraz wdrożenia Apptainer dostosowane do ról.<sup>[[1]](#references)[[3]](#references)</sup>

**Dodatkowe informacje**

* [Strona AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slajdy GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Artykuł GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Nagranie GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transkrypcja Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Obsługiwane**

Obecnie FISSURE korzysta z gałęzi **`Python3`** w aktywnym rozwoju, z PyQt5 oraz GNU Radio 3.8 lub 3.10. Wycofana gałąź **`Python2_maint-3.7`** pozostaje dostępna dla starszych systemów operacyjnych i narzędzi innych firm wymagających GNU Radio 3.7. Dawne nazwy gałęzi `Python3_maint-3.8` i `Python3_maint-3.10` mają charakter historyczny; wybór wersji utrzymywanej GNU Radio odbywa się obecnie z poziomu gałęzi `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| System operacyjny | Gałąź FISSURE | Domyślna gałąź GNU Radio |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | użyj obsługiwanej wersji Linux | użyj odpowiadającej wersji |

**W trakcie prac (beta)**

Te systemy operacyjne nadal mają status beta. Są w trakcie rozwoju, a kilka funkcji jest obecnie niedostępnych. Elementy instalatora mogą powodować konflikty z istniejącymi programami lub nie zainstalować się do czasu usunięcia statusu beta.

| System operacyjny | Gałąź FISSURE | Domyślna gałąź GNU Radio |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Niektóre narzędzia innych firm nie działają w każdym systemie operacyjnym. Przed instalacją sprawdź aktualną dokumentację [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts).<sup>[[3]](#references)</sup>

**Instalacja**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
Krok submodule pobiera moduły GNU Radio out-of-tree używane przez FISSURE i jest wymagany podczas instalowania tych modułów. Instalator zainstaluje również brakujące zależności PyQt potrzebne do uruchomienia graficznych interfejsów instalatora.<sup>[[3]](#references)</sup>

Następnie wybierz opcję najlepiej odpowiadającą Twojemu systemowi operacyjnemu (powinna zostać wykryta automatycznie, jeśli Twój system pasuje do jednej z opcji).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Zaleca się zainstalowanie FISSURE w czystym systemie operacyjnym, aby uniknąć istniejących konfliktów. Zaznacz wszystkie zalecane pola wyboru (przycisk Default), aby uniknąć błędów podczas korzystania z różnych narzędzi w FISSURE. W trakcie instalacji pojawi się wiele monitów, głównie dotyczących podwyższonych uprawnień i nazw użytkowników. Jeśli element zawiera na końcu sekcję "Verify", instalator uruchomi następujące po niej polecenie i podświetli element pola wyboru na zielono lub czerwono, zależnie od tego, czy polecenie wygeneruje błędy. Zaznaczone elementy bez sekcji "Verify" pozostaną po instalacji czarne.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Użycie**

Otwórz terminal i wpisz:
```
fissure
```
Więcej informacji na temat użytkowania można znaleźć w menu Help FISSURE.

## Szczegóły

**Komponenty**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![komponenty](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Możliwości**

| ![Ikona detektora sygnału](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detektor sygnału**_ | ![Ikona manipulacji IQ](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulacja IQ**_      | ![Ikona wyszukiwania sygnału](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Wyszukiwanie sygnału**_          | ![Ikona rozpoznawania wzorców](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Rozpoznawanie wzorców**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Ikona ataków](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataki**_           | ![Ikona fuzzingu](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Ikona playlist sygnałów](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlisty sygnałów**_       | ![Ikona galerii obrazów](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria obrazów**_  |
| ![Ikona tworzenia pakietów](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Tworzenie pakietów**_   | ![Ikona integracji z Scapy](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integracja z Scapy**_ | ![Ikona kalkulatora CRC](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Kalkulator CRC**_ | ![Ikona logowania](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logowanie**_            |

**Sprzęt**

Poniższy sprzęt oferuje różne poziomy integracji z FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

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

FISSURE zawiera kilka pomocnych przewodników, które ułatwiają zapoznanie się z różnymi technologiami i technikami. Wiele z nich obejmuje instrukcje używania różnych narzędzi zintegrowanych z FISSURE.

* [Lekcja 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lekcja 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lekcja 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lekcja 4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lekcja 5: śledzenie radiosond](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lekcja 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lekcja 7: typy danych](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lekcja 8: niestandardowe bloki GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lekcja 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lekcja 10: egzaminy radioamatorskie](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lekcja 11: narzędzia Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lekcja 12: tworzenie bootowalnych USB](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lekcja 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lekcja 14: wentylatory sufitowe](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Plan rozwoju

* [ ] Dodać więcej typów sprzętu, protokołów RF, parametrów sygnału i narzędzi analitycznych
* [ ] Obsługiwać więcej systemów operacyjnych
* [ ] Opracować materiały dydaktyczne dotyczące FISSURE (ataki RF, Wi-Fi, GNU Radio, PyQt itd.)
* [ ] Utworzyć conditioner sygnału, ekstraktor cech i klasyfikator sygnału z wybieralnymi technikami AI/ML
* [ ] Zaimplementować rekurencyjne mechanizmy demodulacji do generowania strumienia bitów z nieznanych sygnałów
* [ ] Przenieść główne komponenty FISSURE do ogólnego schematu wdrażania węzłów sensorów

## Współtworzenie

Sugestie dotyczące ulepszania FISSURE są bardzo mile widziane. Zostaw komentarz na stronie [Discussions](https://github.com/ainfosec/FISSURE/discussions) lub na Discord Server, jeśli masz uwagi dotyczące któregokolwiek z poniższych tematów:

* Sugestie dotyczące nowych funkcji i zmiany projektu
* Narzędzia programowe wraz z instrukcjami instalacji
* Nowe lekcje lub dodatkowe materiały do istniejących lekcji
* Interesujące protokoły RF
* Więcej typów sprzętu i SDR do integracji
* Skrypty do analizy IQ w Pythonie
* Poprawki i usprawnienia instalacji

Wkład w rozwój FISSURE ma kluczowe znaczenie dla przyspieszenia jego rozwoju. Wszelkie przesłane zmiany są bardzo doceniane. Jeśli chcesz uczestniczyć w rozwoju kodu, wykonaj fork repozytorium i utwórz pull request:

1. Wykonaj fork projektu
2. Utwórz gałąź funkcji (`git checkout -b feature/AmazingFeature`)
3. Zatwierdź zmiany (`git commit -m 'Add some AmazingFeature'`)
4. Wypchnij zmiany do gałęzi (`git push origin feature/AmazingFeature`)
5. Otwórz pull request

Zgłaszanie [Issues](https://github.com/ainfosec/FISSURE/issues) w celu zwrócenia uwagi na błędy również jest mile widziane.

## Współpraca

Skontaktuj się z działem Business Development firmy Assured Information Security, Inc. (AIS), aby zaproponować i sformalizować możliwości współpracy dotyczące FISSURE – niezależnie od tego, czy chodzi o poświęcenie czasu na integrację Twojego oprogramowania, zlecenie utalentowanym pracownikom AIS opracowania rozwiązań dla Twoich wyzwań technicznych, czy integrację FISSURE z innymi platformami/aplikacjami.

## Licencja

GPL-3.0

Szczegóły licencji znajdują się w pliku LICENSE.

## Kontakt

Dołącz do Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Obserwuj na Twitterze: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Autorzy

Wyrażamy uznanie i wdzięczność następującym deweloperom:

[Autorzy](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Podziękowania

Szczególne podziękowania dla dr. Samuela Mantravadi i Josepha Reitha za ich wkład w ten projekt.

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
