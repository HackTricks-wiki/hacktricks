# FISSURE - The RF Framework

**Niezależne od częstotliwości zrozumienie sygnału SDR i inżynieria odwrotna**

FISSURE to otwartoźródłowa platforma RF i inżynierii odwrotnej zaprojektowana dla wszystkich poziomów umiejętności, z funkcjami wykrywania i klasyfikacji sygnałów, odkrywania protokołów, wykonywania ataków, manipulacji IQ, analizy podatności, automatyzacji oraz AI/ML. Platforma została stworzona, aby promować szybkie integrowanie modułów oprogramowania, radii, protokołów, danych sygnałowych, skryptów, grafów przepływu, materiałów referencyjnych i narzędzi firm trzecich. FISSURE to narzędzie umożliwiające przepływ pracy, które utrzymuje oprogramowanie w jednym miejscu i pozwala zespołom na łatwe przyswajanie wiedzy, dzieląc się tą samą sprawdzoną konfiguracją bazową dla konkretnych dystrybucji Linuksa.

Platforma i narzędzia zawarte w FISSURE są zaprojektowane do wykrywania obecności energii RF, rozumienia charakterystyki sygnału, zbierania i analizowania próbek, opracowywania technik nadawania i/lub wstrzykiwania oraz tworzenia niestandardowych ładunków lub wiadomości. FISSURE zawiera rosnącą bibliotekę informacji o protokołach i sygnałach, aby wspierać identyfikację, tworzenie pakietów i fuzzing. Istnieją możliwości archiwizacji online, aby pobierać pliki sygnałowe i tworzyć listy odtwarzania do symulacji ruchu i testowania systemów.

Przyjazna baza kodu Python i interfejs użytkownika pozwalają początkującym szybko nauczyć się popularnych narzędzi i technik związanych z RF i inżynierią odwrotną. Nauczyciele w dziedzinie cyberbezpieczeństwa i inżynierii mogą skorzystać z wbudowanego materiału lub wykorzystać platformę do demonstrowania własnych aplikacji w rzeczywistych warunkach. Programiści i badacze mogą używać FISSURE do codziennych zadań lub do prezentowania swoich nowatorskich rozwiązań szerszej publiczności. W miarę jak świadomość i wykorzystanie FISSURE rośnie w społeczności, tak samo wzrośnie zakres jego możliwości i różnorodność technologii, które obejmuje.

**Dodatkowe informacje**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Obsługiwane**

W FISSURE znajdują się trzy gałęzie, aby ułatwić nawigację po plikach i zredukować redundancję kodu. Gałąź Python2\_maint-3.7 zawiera bazę kodu opartą na Python2, PyQt4 i GNU Radio 3.7; gałąź Python3\_maint-3.8 jest oparta na Python3, PyQt5 i GNU Radio 3.8; a gałąź Python3\_maint-3.10 jest oparta na Python3, PyQt5 i GNU Radio 3.10.

|   System operacyjny   |   Gałąź FISSURE   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**W trakcie (beta)**

Te systemy operacyjne są nadal w statusie beta. Są w fazie rozwoju i wiadomo, że brakuje kilku funkcji. Elementy w instalatorze mogą kolidować z istniejącymi programami lub nie instalować się, dopóki status nie zostanie usunięty.

|     System operacyjny     |    Gałąź FISSURE   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Uwaga: Niektóre narzędzia programowe nie działają na każdym systemie operacyjnym. Odwołaj się do [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Instalacja**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
To zainstaluje zależności oprogramowania PyQt wymagane do uruchomienia interfejsów instalacyjnych, jeśli nie zostaną znalezione.

Następnie wybierz opcję, która najlepiej odpowiada twojemu systemowi operacyjnemu (powinna być wykryta automatycznie, jeśli twój system operacyjny odpowiada opcji).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Zaleca się zainstalowanie FISSURE na czystym systemie operacyjnym, aby uniknąć istniejących konfliktów. Wybierz wszystkie zalecane pola wyboru (przycisk domyślny), aby uniknąć błędów podczas korzystania z różnych narzędzi w FISSURE. W trakcie instalacji pojawi się wiele monitów, głównie pytających o podwyższone uprawnienia i nazwy użytkowników. Jeśli element zawiera sekcję "Weryfikacja" na końcu, instalator uruchomi polecenie, które następuje, i podświetli element pola wyboru na zielono lub czerwono w zależności od tego, czy polecenie wygeneruje jakiekolwiek błędy. Zaznaczone elementy bez sekcji "Weryfikacja" pozostaną czarne po zakończeniu instalacji.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Użycie**

Otwórz terminal i wpisz:
```
fissure
```
Odwołaj się do menu pomocy FISSURE, aby uzyskać więcej informacji na temat użytkowania.

## Szczegóły

**Komponenty**

* Dashboard
* Central Hub (HIPRFISR)
* Identyfikacja sygnału docelowego (TSI)
* Odkrywanie protokołów (PD)
* Wykres przepływu i wykonawca skryptów (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Możliwości**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Detektor sygnału**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulacja IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Wyszukiwanie sygnału**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Rozpoznawanie wzorców**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Ataki**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlisty sygnałów**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galeria obrazów**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Tworzenie pakietów**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Integracja Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Kalkulator CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Rejestrowanie**_            |

**Sprzęt**

Poniżej znajduje się lista "obsługiwanych" urządzeń o różnym poziomie integracji:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adaptery 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lekcje

FISSURE zawiera kilka pomocnych przewodników, aby zapoznać się z różnymi technologiami i technikami. Wiele z nich zawiera kroki dotyczące korzystania z różnych narzędzi zintegrowanych z FISSURE.

* [Lekcja1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lekcja2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lekcja3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lekcja4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lekcja5: Śledzenie radiosond](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lekcja6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lekcja7: Typy danych](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lekcja8: Niestandardowe bloki GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lekcja9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lekcja10: Egzaminy na radioamatora](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lekcja11: Narzędzia Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Plan działania

* [ ] Dodaj więcej typów sprzętu, protokołów RF, parametrów sygnału, narzędzi analitycznych
* [ ] Wsparcie dla większej liczby systemów operacyjnych
* [ ] Opracuj materiały dydaktyczne dotyczące FISSURE (Ataki RF, Wi-Fi, GNU Radio, PyQt itp.)
* [ ] Stwórz kondycjonera sygnału, ekstraktora cech i klasyfikatora sygnału z wybieralnymi technikami AI/ML
* [ ] Wdrożenie rekurencyjnych mechanizmów demodulacji do produkcji strumienia bitów z nieznanych sygnałów
* [ ] Przejście głównych komponentów FISSURE do ogólnego schematu wdrażania węzłów czujnikowych

## Wkład

Sugestie dotyczące poprawy FISSURE są zdecydowanie zachęcane. Zostaw komentarz na stronie [Dyskusje](https://github.com/ainfosec/FISSURE/discussions) lub na serwerze Discord, jeśli masz jakiekolwiek uwagi dotyczące:

* Sugestii nowych funkcji i zmian w projekcie
* Narzędzi programowych z krokami instalacji
* Nowych lekcji lub dodatkowych materiałów do istniejących lekcji
* Interesujących protokołów RF
* Więcej sprzętu i typów SDR do integracji
* Skryptów analizy IQ w Pythonie
* Poprawek i ulepszeń instalacji

Wkłady w poprawę FISSURE są kluczowe dla przyspieszenia jego rozwoju. Każdy wkład jest bardzo doceniany. Jeśli chcesz przyczynić się do rozwoju kodu, proszę, zrób fork repozytorium i stwórz pull request:

1. Zrób fork projektu
2. Stwórz swoją gałąź funkcji (`git checkout -b feature/AmazingFeature`)
3. Zatwierdź swoje zmiany (`git commit -m 'Dodaj jakąś AmazingFeature'`)
4. Wypchnij do gałęzi (`git push origin feature/AmazingFeature`)
5. Otwórz pull request

Tworzenie [Zgłoszeń](https://github.com/ainfosec/FISSURE/issues) w celu zwrócenia uwagi na błędy jest również mile widziane.

## Współpraca

Skontaktuj się z Assured Information Security, Inc. (AIS) w celu zaproponowania i sformalizowania wszelkich możliwości współpracy w zakresie FISSURE – niezależnie od tego, czy chodzi o poświęcenie czasu na integrację oprogramowania, czy o to, aby utalentowani ludzie z AIS opracowali rozwiązania dla Twoich wyzwań technicznych, czy też o integrację FISSURE z innymi platformami/aplikacjami.

## Licencja

GPL-3.0

Szczegóły licencji znajdują się w pliku LICENSE.

## Kontakt

Dołącz do serwera Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Śledź na Twitterze: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Rozwój biznesu - Assured Information Security, Inc. - bd@ainfosec.com

## Podziękowania

Uznajemy i jesteśmy wdzięczni tym deweloperom:

[Podziękowania](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Uznania

Szczególne podziękowania dla dr. Samuela Mantravadi i Josepha Reitha za ich wkład w ten projekt.
