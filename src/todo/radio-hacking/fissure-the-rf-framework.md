# FISSURE - Framework RF

{{#include ../../banners/hacktricks-training.md}}

**Niezależne od częstotliwości rozumienie sygnałów i reverse engineering oparte na SDR**

FISSURE to open-source framework RF i reverse engineering przeznaczony dla osób na każdym poziomie zaawansowania, oferujący mechanizmy wykrywania i klasyfikacji sygnałów, odkrywania protokołów, wykonywania ataków, manipulowania IQ, analizy podatności, automatyzacji oraz AI/ML. Framework został stworzony w celu szybkiej integracji modułów programowych, radioodbiorników, protokołów, danych sygnałowych, skryptów, flow graphs, materiałów referencyjnych i narzędzi firm trzecich. FISSURE ułatwia realizację workflow, przechowując oprogramowanie w jednym miejscu i pozwalając zespołom bezproblemowo rozpocząć pracę przy użyciu tej samej sprawdzonej konfiguracji bazowej dla określonych dystrybucji Linuxa.<sup>[[1]](#references)[[2]](#references)</sup>

Framework i narzędzia zawarte w FISSURE służą do wykrywania obecności energii RF, rozumienia charakterystyki sygnału, zbierania i analizowania próbek, opracowywania technik transmisji i/lub injection oraz tworzenia niestandardowych payloadów lub komunikatów. FISSURE zawiera stale rozwijaną bibliotekę informacji o protokołach i sygnałach, która pomaga w identyfikacji, tworzeniu pakietów i fuzzingu. Dostępne są funkcje archiwizacji online umożliwiające pobieranie plików sygnałowych i tworzenie playlist symulujących ruch oraz testujących systemy.

Przyjazna baza kodu w Pythonie i interfejs użytkownika pozwalają początkującym szybko poznać popularne narzędzia i techniki związane z RF i reverse engineering. Edukatorzy zajmujący się cyberbezpieczeństwem i inżynierią mogą korzystać z wbudowanych materiałów lub używać frameworka do demonstrowania własnych zastosowań w świecie rzeczywistym. Developerzy i badacze mogą używać FISSURE w codziennej pracy lub prezentować za jego pomocą swoje najnowocześniejsze rozwiązania szerszemu gronu odbiorców. Wraz ze wzrostem świadomości i wykorzystania FISSURE w społeczności będzie rosła także skala jego możliwości oraz zakres technologii, które obejmuje.

**Dodatkowe informacje**

* [Strona AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slajdy GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Artykuł GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Nagranie GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transkrypcja Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Rozpoczęcie pracy

**Obsługiwane**

W FISSURE dostępne są trzy branche, które ułatwiają nawigację po plikach i ograniczają redundancję kodu. Branch Python2\_maint-3.7 zawiera bazę kodu opartą na Python2, PyQt4 i GNU Radio 3.7; branch Python3\_maint-3.8 jest oparty na Python3, PyQt5 i GNU Radio 3.8; natomiast branch Python3\_maint-3.10 jest oparty na Python3, PyQt5 i GNU Radio 3.10.

|   System operacyjny   |   Branch FISSURE   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**W trakcie prac (beta)**

Te systemy operacyjne nadal mają status beta. Są w fazie rozwoju, a kilka funkcji jest znanych jako niedostępne. Elementy instalatora mogą powodować konflikty z istniejącymi programami lub nie instalować się do czasu usunięcia statusu beta.

|     System operacyjny     |    Branch FISSURE   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Uwaga: Niektóre narzędzia programowe nie działają w każdym systemie operacyjnym. Zobacz [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Instalacja**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Spowoduje to zainstalowanie zależności oprogramowania PyQt wymaganych do uruchomienia graficznych interfejsów instalacji, jeśli nie zostaną znalezione.

Następnie wybierz opcję najlepiej odpowiadającą Twojemu systemowi operacyjnemu (powinna zostać wykryta automatycznie, jeśli Twój system pasuje do jednej z opcji).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Zaleca się zainstalowanie FISSURE w czystym systemie operacyjnym, aby uniknąć istniejących konfliktów. Zaznacz wszystkie zalecane pola wyboru (przycisk Default), aby uniknąć błędów podczas korzystania z różnych narzędzi w FISSURE. W trakcie instalacji pojawi się wiele monitów, dotyczących głównie uprawnień podwyższonych oraz nazw użytkowników. Jeśli element zawiera na końcu sekcję „Verify”, instalator uruchomi następujące po niej polecenie i podświetli element pola wyboru na zielono lub czerwono, w zależności od tego, czy polecenie wygeneruje błędy. Zaznaczone elementy bez sekcji „Verify” pozostaną czarne po zakończeniu instalacji.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Użycie**

Otwórz terminal i wpisz:
```
fissure
```
Więcej informacji na temat użytkowania znajdziesz w menu Help FISSURE.

## Szczegóły

**Komponenty**

* Panel
* Centralny Hub (HIPRFISR)
* Identyfikacja sygnału docelowego (TSI)
* Wykrywanie protokołów (PD)
* Wykonawca grafów przepływu i skryptów (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Możliwości**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detektor sygnału**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulacja IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Wyszukiwanie sygnału**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Rozpoznawanie wzorców**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataki**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlisty sygnałów**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria obrazów**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Tworzenie pakietów**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integracja z Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Kalkulator CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logowanie**_            |

**Sprzęt**

Poniżej znajduje się lista „obsługiwanego” sprzętu, z różnym poziomem integracji:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adaptery 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lekcje

FISSURE zawiera kilka pomocnych przewodników ułatwiających zapoznanie się z różnymi technologiami i technikami. Wiele z nich obejmuje korzystanie z rozmaitych narzędzi zintegrowanych z FISSURE.

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

## Plan rozwoju

* [ ] Dodać więcej typów sprzętu, protokołów RF, parametrów sygnału i narzędzi analitycznych
* [ ] Obsługiwać więcej systemów operacyjnych
* [ ] Opracować materiały dydaktyczne dotyczące FISSURE (ataki RF, Wi-Fi, GNU Radio, PyQt itd.)
* [ ] Utworzyć kondycjoner sygnału, ekstraktor cech i klasyfikator sygnału z możliwością wyboru technik AI/ML
* [ ] Zaimplementować rekurencyjne mechanizmy demodulacji umożliwiające uzyskiwanie strumienia bitów z nieznanych sygnałów
* [ ] Przenieść główne komponenty FISSURE do ogólnego schematu wdrażania węzłów sensorów

## Współtworzenie

Zachęcamy do zgłaszania sugestii dotyczących ulepszania FISSURE. Zostaw komentarz na stronie [Discussions](https://github.com/ainfosec/FISSURE/discussions) lub na serwerze Discord, jeśli masz uwagi dotyczące któregokolwiek z poniższych tematów:

* Sugestie dotyczące nowych funkcji i zmian projektowych
* Narzędzia software'owe wraz z instrukcjami instalacji
* Nowe lekcje lub dodatkowe materiały do istniejących lekcji
* Interesujące protokoły RF
* Więcej typów sprzętu i SDR do integracji
* Skrypty do analizy IQ w Pythonie
* Korekty i ulepszenia instalacji

Wkład w ulepszanie FISSURE ma kluczowe znaczenie dla przyspieszenia jego rozwoju. Każdy wkład jest bardzo ceniony. Jeśli chcesz współtworzyć projekt poprzez rozwój kodu, wykonaj fork repozytorium i utwórz pull request:

1. Wykonaj fork projektu
2. Utwórz gałąź funkcji (`git checkout -b feature/AmazingFeature`)
3. Zacommituj zmiany (`git commit -m 'Add some AmazingFeature'`)
4. Wypchnij zmiany do gałęzi (`git push origin feature/AmazingFeature`)
5. Otwórz pull request

Zachęcamy również do tworzenia [Issues](https://github.com/ainfosec/FISSURE/issues), aby zwracać uwagę na błędy.

## Współpraca

Skontaktuj się z działem rozwoju biznesu Assured Information Security, Inc. (AIS), aby zaproponować i sformalizować możliwości współpracy dotyczące FISSURE — niezależnie od tego, czy miałoby to polegać na poświęceniu czasu na integrację Twojego software'u, zleceniu utalentowanym pracownikom AIS opracowania rozwiązań dla Twoich wyzwań technicznych, czy integracji FISSURE z innymi platformami/aplikacjami.

## Licencja

GPL-3.0

Szczegółowe informacje dotyczące licencji znajdują się w pliku LICENSE.

## Kontakt

Dołącz do serwera Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Obserwuj na Twitterze: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Rozwój biznesu - Assured Information Security, Inc. - bd@ainfosec.com

## Autorzy

Wyrażamy uznanie i wdzięczność następującym developerom:

[Autorzy](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Podziękowania

Szczególne podziękowania dla dr. Samuela Mantravadi i Josepha Reitha za ich wkład w ten projekt.

## Odnośniki

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
