# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania miejsc, w których ważne wartości są zapisywane w pamięci uruchomionej gry, oraz do ich zmieniania.\
Po pobraniu i uruchomieniu zostanie wyświetlony **tutorial** dotyczący korzystania z tego narzędzia. Jeśli chcesz nauczyć się z niego korzystać, zdecydowanie zaleca się jego ukończenie.<sup>[[3]](#references)</sup>

## Czego szukasz?

![Cheat Engine - Czego szukasz?: Czego szukasz?](<../../images/image (762).png>)

To narzędzie jest bardzo przydatne do znajdowania **miejsca, w którym jakaś wartość** (zwykle liczba) **jest przechowywana w pamięci** programu.\
**Liczby** są **zwykle przechowywane** w formacie **4bytes**, ale można je również znaleźć w formatach **double** lub **float**, a także można szukać czegoś **innego niż liczba**. Z tego powodu trzeba upewnić się, że **wybrano**, czego chcesz **szukać**:

![Cheat Engine - Czego szukasz?: Liczby są zwykle przechowywane w formacie 4bytes, ale można je również znaleźć w formatach double lub float, a także można szukać czegoś...](<../../images/image (324).png>)

Możesz również wskazać **różne typy wyszukiwania**:

![Cheat Engine - Czego szukasz?: Możesz również wskazać różne typy wyszukiwania](<../../images/image (311).png>)

Możesz także zaznaczyć pole, aby **zatrzymać grę podczas skanowania pamięci**:

![Cheat Engine - Czego szukasz?: Możesz także zaznaczyć pole, aby zatrzymać grę podczas skanowania pamięci](<../../images/image (1052).png>)

### Skróty klawiszowe

W _**Edit --> Settings --> Hotkeys**_ możesz ustawić różne **skróty klawiszowe** do różnych celów, takich jak **zatrzymywanie** **gry** (co jest bardzo przydatne, jeśli w pewnym momencie chcesz przeskanować pamięć). Dostępne są również inne opcje:

![Czego szukasz? - Skróty klawiszowe: W Edit -- Settings -- Hotkeys możesz ustawić różne skróty klawiszowe do różnych celów, takich jak zatrzymywanie gry (co jest bardzo przydatne, jeśli w pewnym momencie...](<../../images/image (864).png>)

## Modyfikowanie wartości

Po **znalezieniu** miejsca, w którym znajduje się **szukana** **wartość** (więcej informacji na ten temat znajduje się w kolejnych krokach), możesz ją **zmodyfikować**, klikając ją dwukrotnie, a następnie klikając dwukrotnie jej wartość:

![Skróty klawiszowe - Modyfikowanie wartości: Po znalezieniu miejsca, w którym znajduje się szukana wartość (więcej informacji na ten temat znajduje się w kolejnych krokach), możesz ją zmodyfikować, klikając ją dwukrotnie, a następnie klikając dwukrotnie...](<../../images/image (563).png>)

Na koniec **zaznacz pole**, aby zastosować modyfikację w pamięci:

![Skróty klawiszowe - Modyfikowanie wartości: Na koniec zaznacz pole, aby zastosować modyfikację w pamięci](<../../images/image (385).png>)

**Zmiana** w **pamięci** zostanie natychmiast **zastosowana** (pamiętaj, że dopóki gra ponownie nie użyje tej wartości, wartość **nie zostanie zaktualizowana w grze**).

## Wyszukiwanie wartości

Załóżmy, że istnieje ważna wartość (na przykład życie twojej postaci), którą chcesz zwiększyć, i szukasz tej wartości w pamięci.

### Na podstawie znanej zmiany

Załóżmy, że szukasz wartości 100. **Wykonujesz skanowanie**, wyszukując tę wartość, i znajdujesz wiele wyników:

![Wyszukiwanie wartości - Na podstawie znanej zmiany: Załóżmy, że szukasz wartości 100, wykonujesz skanowanie, wyszukując tę wartość, i znajdujesz wiele wyników](<../../images/image (108).png>)

Następnie robisz coś, co powoduje, że **wartość się zmienia**, **zatrzymujesz** grę i wykonujesz **kolejne skanowanie**:

![Wyszukiwanie wartości - Na podstawie znanej zmiany: Następnie robisz coś, co powoduje zmianę wartości, zatrzymujesz grę i wykonujesz kolejne skanowanie](<../../images/image (684).png>)

Cheat Engine wyszuka **wartości**, które **zmieniły się ze 100 na nową wartość**. Gratulacje, **znalazłeś** **adres** szukanej wartości — możesz ją teraz zmodyfikować.\
_Jeśli nadal masz kilka wartości, ponownie wykonaj działanie modyfikujące tę wartość i przeprowadź kolejne „next scan”, aby odfiltrować adresy._

### Nieznana wartość, znana zmiana

Jeśli **nie znasz wartości**, ale wiesz, **jak ją zmienić** (a nawet znasz wartość zmiany), możesz wyszukać tę liczbę.

Zacznij od wykonania skanowania typu **„Unknown initial value”**:

![Na podstawie znanej zmiany - Nieznana wartość, znana zmiana: Zacznij od wykonania skanowania typu „Unknown initial value”](<../../images/image (890).png>)

Następnie zmień wartość, wskaż, **jak** zmieniła się **wartość** (w moim przypadku zmniejszyła się o 1) i wykonaj **kolejne skanowanie**:

![Na podstawie znanej zmiany - Nieznana wartość, znana zmiana: Następnie zmień wartość, wskaż, jak zmieniła się wartość (w moim przypadku zmniejszyła się o 1) i wykonaj kolejne skanowanie](<../../images/image (371).png>)

Zostaną wyświetlone **wszystkie wartości, które zostały zmodyfikowane w wybrany sposób**:

![Na podstawie znanej zmiany - Nieznana wartość, znana zmiana: Zostaną wyświetlone wszystkie wartości, które zostały zmodyfikowane w wybrany sposób](<../../images/image (569).png>)

Po znalezieniu wartości możesz ją zmodyfikować.

Pamiętaj, że istnieje **wiele możliwych zmian** i możesz wykonywać te **kroki dowolną liczbę razy**, aby filtrować wyniki:

![Na podstawie znanej zmiany - Nieznana wartość, znana zmiana: Pamiętaj, że istnieje wiele możliwych zmian i możesz wykonywać te kroki dowolną liczbę razy, aby filtrować wyniki](<../../images/image (574).png>)

### Losowy adres pamięci — znajdowanie kodu

Do tej pory nauczyliśmy się znajdować adres przechowujący wartość, ale bardzo prawdopodobne jest, że **podczas różnych uruchomień gry ten adres będzie znajdować się w innym miejscu pamięci**. Sprawdźmy więc, jak zawsze znajdować ten adres.

Korzystając z niektórych opisanych sztuczek, znajdź adres, pod którym aktualnie uruchomiona gra przechowuje ważną wartość. Następnie (zatrzymując grę, jeśli chcesz) kliknij **prawym przyciskiem myszy** znaleziony **adres** i wybierz **„Find out what accesses this address”** albo **„Find out what writes to this address”**:

![Nieznana wartość, znana zmiana - Losowy adres pamięci - znajdowanie kodu: Korzystając z niektórych opisanych sztuczek, znajdź adres, pod którym aktualnie uruchomiona gra przechowuje ważną wartość. Następnie...](<../../images/image (1067).png>)

**Pierwsza opcja** pozwala sprawdzić, które **części** **kodu** **używają** tego **adresu** (co jest przydatne również w innych sytuacjach, na przykład do **ustalenia, gdzie można zmodyfikować kod** gry).\
**Druga opcja** jest bardziej **konkretna** i będzie w tym przypadku bardziej pomocna, ponieważ chcemy wiedzieć, **skąd ta wartość jest zapisywana**.

Po wybraniu jednej z tych opcji **debugger** zostanie **podłączony** do programu i pojawi się nowe **puste okno**. Teraz **zagraj** w **grę** i **zmodyfikuj** tę **wartość** (bez ponownego uruchamiania gry). **Okno** powinno zostać **wypełnione** **adresami**, które **modyfikują** tę **wartość**:

![Nieznana wartość, znana zmiana - Losowy adres pamięci - znajdowanie kodu: Po wybraniu jednej z tych opcji debugger zostanie podłączony do programu i pojawi się nowe puste okno. Teraz...](<../../images/image (91).png>)

Teraz, gdy znalazłeś adres modyfikujący wartość, możesz **zmodyfikować kod według własnego uznania** (Cheat Engine pozwala bardzo szybko zmodyfikować go na NOP-y):

![Nieznana wartość, znana zmiana - Losowy adres pamięci - znajdowanie kodu: Teraz, gdy znalazłeś adres modyfikujący wartość, możesz zmodyfikować kod według własnego uznania (Cheat Engine...](<../../images/image (1057).png>)

Możesz więc zmodyfikować go tak, aby kod nie wpływał na twoją liczbę albo zawsze wpływał na nią w pozytywny sposób.

### Losowy adres pamięci — znajdowanie pointera

Wykonując poprzednie kroki, znajdź miejsce, w którym znajduje się interesująca cię wartość. Następnie, używając **„Find out what writes to this address”**, ustal, który adres zapisuje tę wartość, i kliknij go dwukrotnie, aby wyświetlić widok disassembly:

![Losowy adres pamięci - znajdowanie kodu - Losowy adres pamięci - znajdowanie pointera: Wykonując poprzednie kroki, znajdź miejsce, w którym znajduje się interesująca cię wartość. Następnie, używając „Find out...](<../../images/image (1039).png>)

Następnie wykonaj nowe skanowanie, **wyszukując wartość hex między „\[]”** (w tym przypadku wartość rejestru $edx):

![Losowy adres pamięci - znajdowanie kodu - Losowy adres pamięci - znajdowanie pointera: Następnie wykonaj nowe skanowanie, wyszukując wartość hex między „()” (w tym przypadku wartość rejestru $edx)](<../../images/image (994).png>)

(_Jeśli pojawi się kilka wyników, zwykle potrzebny jest adres o najmniejszej wartości_)\
Teraz **znaleźliśmy pointer, który będzie modyfikował interesującą nas wartość**.

Kliknij **„Add Address Manually”**:

![Losowy adres pamięci - znajdowanie kodu - Losowy adres pamięci - znajdowanie pointera: Kliknij „Add Address Manually”](<../../images/image (990).png>)

Teraz zaznacz pole wyboru „Pointer” i dodaj znaleziony adres w polu tekstowym (w tym przypadku znaleziony adres z poprzedniego obrazu to „Tutorial-i386.exe”+2426B0):

![Losowy adres pamięci - znajdowanie kodu - Losowy adres pamięci - znajdowanie pointera: Teraz zaznacz pole wyboru „Pointer” i dodaj znaleziony adres w polu tekstowym (w tym przypadku...](<../../images/image (392).png>)

(Zwróć uwagę, że pierwszy „Address” jest automatycznie wypełniany na podstawie wprowadzonego adresu pointera).

Kliknij OK, a zostanie utworzony nowy pointer:

![Losowy adres pamięci - znajdowanie kodu - Losowy adres pamięci - znajdowanie pointera: Kliknij OK, a zostanie utworzony nowy pointer](<../../images/image (308).png>)

Od tej pory za każdym razem, gdy zmienisz tę wartość, **zmodyfikujesz ważną wartość, nawet jeśli adres pamięci, pod którym się ona znajduje, będzie inny**.

### Code Injection

Code injection to technika polegająca na wstrzyknięciu fragmentu kodu do procesu docelowego, a następnie przekierowaniu wykonywania kodu tak, aby przechodziło przez napisany przez ciebie kod (na przykład przyznający ci punkty zamiast je odbierać).

Załóżmy, że znaleziono adres odejmujący 1 od życia gracza:

![Losowy adres pamięci - znajdowanie pointera - Code Injection: Załóżmy, że znaleziono adres odejmujący 1 od życia gracza](<../../images/image (203).png>)

Kliknij „Show disassembler”, aby wyświetlić **disassemble code**.\
Następnie kliknij **CTRL+a**, aby otworzyć okno Auto assemble, i wybierz _**Template --> Code Injection**_:

![Losowy adres pamięci - znajdowanie pointera - Code Injection: Następnie kliknij CTRL+a, aby otworzyć okno Auto assemble, i wybierz Template -- Code Injection](<../../images/image (902).png>)

Wprowadź **adres instrukcji, którą chcesz zmodyfikować** (zwykle jest on uzupełniany automatycznie):

![Losowy adres pamięci - znajdowanie pointera - Code Injection: Wprowadź adres instrukcji, którą chcesz zmodyfikować (zwykle jest on uzupełniany automatycznie)](<../../images/image (744).png>)

Zostanie wygenerowany template:

![Losowy adres pamięci - znajdowanie pointera - Code Injection: Zostanie wygenerowany template](<../../images/image (944).png>)

Wstaw swój nowy kod assembly w sekcji **„newmem”** i usuń oryginalny kod z sekcji **„originalcode”**, jeśli nie chcesz, aby był wykonywany**.** W tym przykładzie wstrzyknięty kod doda 2 punkty zamiast odejmować 1:

![Losowy adres pamięci - znajdowanie pointera - Code Injection: Wstaw swój nowy kod assembly w sekcji „newmem” i usuń oryginalny kod z sekcji „originalcode”, jeśli nie...](<../../images/image (521).png>)

**Kliknij execute i tak dalej, a twój kod powinien zostać wstrzyknięty do programu, zmieniając działanie funkcji!**

## Zaawansowane funkcje Cheat Engine 7.x (2023-2025)

Cheat Engine nadal się rozwija od wersji 7.0. Dodano kilka funkcji poprawiających wygodę oraz funkcji z obszaru *offensive-reversing*, które są niezwykle przydatne podczas analizowania nowoczesnego software (nie tylko gier!). Poniżej znajduje się **bardzo skondensowany przewodnik praktyczny** po dodatkach, z których najczęściej korzysta się podczas pracy red-team/CTF.<sup>[[1]](#references)</sup>

### Ulepszenia Pointer Scanner 2
* `Pointers must end with specific offsets` oraz nowy suwak **Deviation** (od wersji ≥7.4) znacznie ograniczają liczbę false positives podczas ponownego skanowania po aktualizacji. Użyj ich razem z porównywaniem wielu map (`.PTR` → *Compare results with other saved pointer map*), aby w ciągu kilku minut uzyskać **pojedynczy, odporny base-pointer**.
* Skrót do filtrowania zbiorczego: po pierwszym skanowaniu naciśnij `Ctrl+A → Space`, aby zaznaczyć wszystko, a następnie `Ctrl+I` (odwróć zaznaczenie), aby odznaczyć adresy, które nie przeszły ponownego skanowania.

### Ultimap 3 — śledzenie Intel PT
*Od wersji 7.5 stary Ultimap został ponownie zaimplementowany na bazie **Intel Processor-Trace (IPT)**.* Oznacza to, że możesz teraz rejestrować *każdą gałąź, którą wykonuje cel*, **bez single-stepping** (tylko w user-mode; nie wywoła to większości anti-debug gadgets).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Po kilku sekundach zatrzymaj przechwytywanie i **kliknij prawym przyciskiem myszy → Save execution list to file**. Połącz adresy branchy z sesją `Find out what addresses this instruction accesses`, aby niezwykle szybko zlokalizować hotspoty logiki gry o wysokiej częstotliwości.

### 1-byte `jmp` / szablony auto-patch
Wersja 7.5 wprowadziła stub *one-byte* JMP (0xEB), który instaluje handler SEH i umieszcza INT3 w oryginalnej lokalizacji. Jest on generowany automatycznie po użyciu **Auto Assembler → Template → Code Injection** dla instrukcji, których nie można spatchować 5-bajtowym skokiem względnym. Umożliwia to tworzenie „tight” hooków wewnątrz spakowanych lub ograniczonych rozmiarowo procedur.

### Stealth na poziomie kernela z DBVM (AMD i Intel)
*DBVM* to wbudowany w CE hypervisor Type-2. Nowsze buildy w końcu dodały **AMD-V/SVM support**, dzięki czemu można użyć `Driver → Load DBVM` na hostach Ryzen/EPYC. DBVM umożliwia:
1. Tworzenie hardware breakpoints niewidocznych dla kontroli Ring-3/anti-debug.
2. Odczytywanie/zapisywanie stronicowanych lub chronionych regionów pamięci kernela, nawet gdy driver user-mode jest wyłączony.
3. Wykonywanie obejść ataków timingowych bez VM-EXIT (np. odpytywanie `rdtsc` z hypervisora).

**Wskazówka:** DBVM odmówi załadowania, gdy w Windows 11 włączone są HVCI/Memory-Integrity → wyłącz je lub uruchom dedykowany VM-host.

### Zdalne / cross-platform debugging z użyciem **ceserver**
CE jest teraz dostarczany z całkowicie przepisanym *ceserver* i może łączyć się przez TCP z celami działającymi na **Linuxie, Androidzie, macOS i iOS**. Popularny fork integruje *Frida*, aby połączyć dynamic instrumentation z GUI CE — idealne rozwiązanie, gdy trzeba patchować gry Unity lub Unreal działające na telefonie:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Dla bridge Frida zobacz `bb33bb/frida-ceserver` na GitHubie.<sup>[[2]](#references)</sup>

### Inne warte uwagi dodatki
* **Patch Scanner** (MemView → Tools) – wykrywa nieoczekiwane zmiany kodu w sekcjach wykonywalnych; przydatne podczas analizy malware.
* **Structure Dissector 2** – przeciągnij adres → `Ctrl+D`, a następnie *Guess fields*, aby automatycznie przeanalizować struktury C.
* **.NET & Mono Dissector** – ulepszone wsparcie dla gier Unity; wywołuj metody bezpośrednio z konsoli CE Lua.
* **Big-Endian custom types** – skanowanie/edycja z odwróconą kolejnością bajtów (przydatne w emulatorach konsol i buforach pakietów sieciowych).
* **Autosave & tabs** dla okien AutoAssembler/Lua oraz `reassemble()` do przepisywania instrukcji obejmującego wiele wierszy.

### Uwagi dotyczące instalacji i OPSEC (2024-2025)
* Oficjalny instalator jest opakowany w **ad-offers** InnoSetup (`RAV` itd.). **Zawsze klikaj *Decline*** *albo kompiluj ze źródeł*, aby uniknąć PUP-ów. AV nadal będzie oznaczać `cheatengine.exe` jako *HackTool*, co jest oczekiwane.
* Nowoczesne sterowniki anti-cheat (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) wykrywają klasę okna CE nawet po jej zmianie. Uruchamiaj swoją kopię do reversing w **jednorazowej VM** albo po wyłączeniu rozgrywki sieciowej.
* Jeśli potrzebujesz wyłącznie dostępu user-mode, wybierz **`Settings → Extra → Kernel mode debug = off`**, aby uniknąć ładowania niepodpisanego sterownika CE, który może powodować BSOD w Windows 11 24H2 z włączonym Secure-Boot.

---

## Odnośniki

- [1] [Informacje o wydaniu Cheat Engine 7.5 (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [cross-platform bridge frida-ceserver](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Samouczek Cheat Engine — ukończ go, aby dowiedzieć się, jak rozpocząć pracę z Cheat Engine

{{#include ../../banners/hacktricks-training.md}}
