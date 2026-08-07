# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania miejsc, w których ważne wartości są zapisywane w pamięci uruchomionej gry, oraz do ich zmieniania.\
Po pobraniu i uruchomieniu zostanie wyświetlony **tutorial** pokazujący, jak korzystać z tego narzędzia. Jeśli chcesz nauczyć się z niego korzystać, zdecydowanie zaleca się jego ukończenie.

## Czego szukasz?

![Cheat Engine - What are you searching?: Czego szukasz?](<../../images/image (762).png>)

To narzędzie jest bardzo przydatne do znajdowania **miejsca, w którym dana wartość** (zwykle liczba) **jest przechowywana w pamięci** programu.\
**Liczby** są zazwyczaj przechowywane w formacie **4bytes**, ale można je również znaleźć w formatach **double** lub **float**, albo można szukać czegoś **innego niż liczba**. Z tego powodu należy upewnić się, że wybrano to, czego chce się **szukać**:

![Cheat Engine - What are you searching?: Zwykle liczby są przechowywane w formacie 4bytes, ale można je również znaleźć w formatach double lub float, albo można szukać czegoś...](<../../images/image (324).png>)

Można również wskazać **różne** typy **wyszukiwania**:

![Cheat Engine - What are you searching?: Można również wskazać różne typy wyszukiwania](<../../images/image (311).png>)

Można także zaznaczyć pole, aby **zatrzymać grę podczas skanowania pamięci**:

![Cheat Engine - What are you searching?: Można także zaznaczyć pole, aby zatrzymać grę podczas skanowania pamięci](<../../images/image (1052).png>)

### Hotkeys

W _**Edit --> Settings --> Hotkeys**_ można ustawić różne **hotkeys** do różnych celów, takich jak **zatrzymywanie** **gry** (co jest bardzo przydatne, jeśli w pewnym momencie chcesz przeskanować pamięć). Dostępne są również inne opcje:

![What are you searching? - Hotkeys: W Edit -- Settings -- Hotkeys można ustawić różne hotkeys do różnych celów, takich jak zatrzymywanie gry (co jest bardzo przydatne, jeśli w pewnym momencie...](<../../images/image (864).png>)

## Modyfikowanie wartości

Po **znalezieniu** miejsca, w którym znajduje się **szukana** **wartość** (więcej informacji znajduje się w kolejnych krokach), można ją **zmodyfikować**, klikając ją dwukrotnie, a następnie klikając dwukrotnie jej wartość:

![Hotkeys - Modifying the value: Po znalezieniu miejsca, w którym znajduje się szukana wartość (więcej informacji znajduje się w kolejnych krokach), można ją zmodyfikować, klikając ją dwukrotnie, a następnie klikając dwukrotnie...](<../../images/image (563).png>)

Na koniec **zaznacz pole**, aby wprowadzić modyfikację w pamięci:

![Hotkeys - Modifying the value: Na koniec zaznacz pole, aby wprowadzić modyfikację w pamięci](<../../images/image (385).png>)

**Zmiana** w **pamięci** zostanie natychmiast **zastosowana** (pamiętaj, że dopóki gra ponownie nie użyje tej wartości, wartość **nie zostanie zaktualizowana w grze**).

## Wyszukiwanie wartości

Załóżmy, że istnieje ważna wartość (na przykład życie twojej postaci), którą chcesz zwiększyć, i szukasz jej w pamięci.

### Poprzez znaną zmianę

Załóżmy, że szukasz wartości 100. **Wykonujesz skanowanie**, szukając tej wartości, i znajdujesz wiele wyników:

![Searching the value - Through a known change: Załóżmy, że szukasz wartości 100, wykonujesz skanowanie w poszukiwaniu tej wartości i znajdujesz wiele wyników](<../../images/image (108).png>)

Następnie robisz coś, co powoduje **zmianę wartości**, **zatrzymujesz** grę i **wykonujesz** **kolejne skanowanie**:

![Searching the value - Through a known change: Następnie robisz coś, co powoduje zmianę wartości, zatrzymujesz grę i wykonujesz kolejne skanowanie](<../../images/image (684).png>)

Cheat Engine wyszuka **wartości**, które **zmieniły się ze 100 na nową wartość**. Gratulacje, **znalazłeś** **adres** szukanej wartości i możesz ją teraz zmodyfikować.\
_Jeśli nadal masz kilka wartości, ponownie zmień tę wartość i wykonaj kolejne „next scan”, aby odfiltrować adresy._

### Nieznana wartość, znana zmiana

W sytuacji, gdy **nie znasz wartości**, ale wiesz, **jak ją zmienić** (a nawet znasz wartość zmiany), możesz wyszukać swoją liczbę.

Zacznij od wykonania skanowania typu „**Unknown initial value**”:

![Through a known change - Unknown Value, known change: Zacznij od wykonania skanowania typu „Unknown initial value”](<../../images/image (890).png>)

Następnie zmień wartość, wskaż, **jak** zmieniła się **wartość** (w moim przypadku zmniejszyła się o 1) i wykonaj **kolejne skanowanie**:

![Through a known change - Unknown Value, known change: Następnie zmień wartość, wskaż, jak zmieniła się wartość (w moim przypadku zmniejszyła się o 1) i wykonaj kolejne skanowanie](<../../images/image (371).png>)

Zostaną wyświetlone **wszystkie wartości, które zostały zmodyfikowane w wybrany sposób**:

![Through a known change - Unknown Value, known change: Zostaną wyświetlone wszystkie wartości, które zostały zmodyfikowane w wybrany sposób](<../../images/image (569).png>)

Po znalezieniu wartości możesz ją zmodyfikować.

Pamiętaj, że istnieje **wiele możliwych zmian** i możesz wykonywać te **kroki dowolną liczbę razy**, aby filtrować wyniki:

![Through a known change - Unknown Value, known change: Pamiętaj, że istnieje wiele możliwych zmian i możesz wykonywać te kroki dowolną liczbę razy, aby filtrować wyniki](<../../images/image (574).png>)

### Losowy adres pamięci - znajdowanie kodu

Do tej pory nauczyliśmy się znajdować adres przechowujący wartość, ale bardzo prawdopodobne jest, że podczas **różnych uruchomień gry adres ten będzie znajdował się w różnych miejscach pamięci**. Sprawdźmy więc, jak zawsze znajdować ten adres.

Korzystając z niektórych wspomnianych metod, znajdź adres, pod którym bieżąca gra przechowuje ważną wartość. Następnie (w razie potrzeby zatrzymując grę) kliknij **prawym przyciskiem myszy** znaleziony **adres** i wybierz opcję „**Find out what accesses this address**” lub „**Find out what writes to this address**”:

![Unknown Value, known change - Random Memory Address - Finding the code: Korzystając z niektórych wspomnianych metod, znajdź adres, pod którym bieżąca gra przechowuje ważną wartość. Następnie...](<../../images/image (1067).png>)

**Pierwsza opcja** pomaga ustalić, które **części** **kodu** **używają** tego **adresu** (jest to przydatne również do innych celów, takich jak **ustalenie, gdzie można zmodyfikować kod** gry).\
**Druga opcja** jest bardziej **konkretna** i w tym przypadku będzie bardziej pomocna, ponieważ chcemy ustalić, **z którego miejsca zapisywana jest ta wartość**.

Po wybraniu jednej z tych opcji **debugger** zostanie **dołączony** do programu i pojawi się nowe **puste okno**. Teraz **graj** w **grę** i **zmień** tę **wartość** (bez ponownego uruchamiania gry). **Okno** powinno zostać **wypełnione** **adresami**, które **modyfikują** tę **wartość**:

![Unknown Value, known change - Random Memory Address - Finding the code: Po wybraniu jednej z tych opcji debugger zostanie dołączony do programu i pojawi się nowe puste okno...](<../../images/image (91).png>)

Po znalezieniu adresu, który modyfikuje wartość, możesz **dowolnie zmodyfikować kod** (Cheat Engine pozwala bardzo szybko zmienić go na NOP):

![Unknown Value, known change - Random Memory Address - Finding the code: Po znalezieniu adresu, który modyfikuje wartość, możesz dowolnie zmodyfikować kod (Cheat Engine...](<../../images/image (1057).png>)

Możesz teraz zmienić kod tak, aby nie wpływał na twoją liczbę albo zawsze wpływał na nią w pozytywny sposób.

### Losowy adres pamięci - znajdowanie wskaźnika

Wykonując poprzednie kroki, znajdź miejsce, w którym znajduje się interesująca cię wartość. Następnie, korzystając z opcji „**Find out what writes to this address**”, ustal, który adres zapisuje tę wartość, i kliknij go dwukrotnie, aby wyświetlić widok disassembly:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Wykonując poprzednie kroki, znajdź miejsce, w którym znajduje się interesująca cię wartość. Następnie, korzystając z opcji „Find out...](<../../images/image (1039).png>)

Następnie wykonaj nowe skanowanie, **szukając wartości hex pomiędzy „\[]”** (w tym przypadku wartości $edx):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Następnie wykonaj nowe skanowanie, szukając wartości hex pomiędzy „ ()” (w tym przypadku wartości $edx)](<../../images/image (994).png>)

(_Jeśli pojawi się kilka wyników, zazwyczaj potrzebujesz tego z najmniejszym adresem_)\
Teraz mamy **wskaźnik, który będzie modyfikował interesującą nas wartość**.

Kliknij „**Add Address Manually**”:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Kliknij „Add Address Manually”](<../../images/image (990).png>)

Teraz zaznacz pole wyboru „Pointer” i dodaj znaleziony adres w polu tekstowym (w tym przypadku znaleziony adres z poprzedniego obrazu to „Tutorial-i386.exe”+2426B0):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Teraz zaznacz pole wyboru „Pointer” i dodaj znaleziony adres w polu tekstowym (w tym przypadku...](<../../images/image (392).png>)

(Zwróć uwagę, że pierwszy „Address” jest automatycznie wypełniany na podstawie wprowadzonego adresu wskaźnika)

Kliknij OK, a zostanie utworzony nowy wskaźnik:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Kliknij OK, a zostanie utworzony nowy wskaźnik](<../../images/image (308).png>)

Od tej pory za każdym razem, gdy zmienisz tę wartość, będziesz **modyfikować ważną wartość, nawet jeśli adres pamięci, pod którym się ona znajduje, będzie inny**.

### Code Injection

Code injection to technika, w której wstrzykujesz fragment kodu do procesu docelowego, a następnie przekierowujesz wykonywanie kodu tak, aby przechodziło przez napisany przez ciebie kod (na przykład przyznający ci punkty zamiast je odejmować).

Załóżmy, że znalazłeś adres, który odejmuje 1 od życia gracza:

![Random Memory Address - Finding the pointer - Code Injection: Załóżmy, że znalazłeś adres, który odejmuje 1 od życia gracza](<../../images/image (203).png>)

Kliknij Show disassembler, aby wyświetlić **kod disassembly**.\
Następnie kliknij **CTRL+a**, aby otworzyć okno Auto assemble, i wybierz _**Template --> Code Injection**_

![Random Memory Address - Finding the pointer - Code Injection: Następnie kliknij CTRL+a, aby otworzyć okno Auto assemble, i wybierz Template -- Code Injection](<../../images/image (902).png>)

Wprowadź **adres instrukcji, którą chcesz zmodyfikować** (zwykle jest on uzupełniany automatycznie):

![Random Memory Address - Finding the pointer - Code Injection: Wprowadź adres instrukcji, którą chcesz zmodyfikować (zwykle jest on uzupełniany automatycznie)](<../../images/image (744).png>)

Zostanie wygenerowany szablon:

![Random Memory Address - Finding the pointer - Code Injection: Zostanie wygenerowany szablon](<../../images/image (944).png>)

Wstaw więc nowy kod assembly w sekcji „**newmem**” i usuń oryginalny kod z sekcji „**originalcode**”, jeśli nie chcesz, aby był wykonywany**.** W tym przykładzie wstrzyknięty kod doda 2 punkty zamiast odejmować 1:

![Random Memory Address - Finding the pointer - Code Injection: Wstaw więc nowy kod assembly w sekcji „newmem” i usuń oryginalny kod z sekcji „originalcode”, jeśli...](<../../images/image (521).png>)

**Kliknij execute itd., a twój kod powinien zostać wstrzyknięty do programu, zmieniając działanie funkcji!**

## Zaawansowane funkcje w Cheat Engine 7.x (2023-2025)

Cheat Engine nadal rozwija się od wersji 7.0 i dodano kilka funkcji poprawiających wygodę obsługi oraz funkcji *offensive-reversing*, które są niezwykle przydatne podczas analizowania nowoczesnego software (nie tylko gier!). Poniżej znajduje się **bardzo skondensowany przewodnik praktyczny** po dodatkach, których najczęściej będziesz używać podczas pracy red-team/CTF.<sup>[[1]](#references)</sup>

### Ulepszenia Pointer Scanner 2
* Opcje `Pointers must end with specific offsets` oraz nowy suwak **Deviation** (≥7.4) znacznie ograniczają liczbę false positives podczas ponownego skanowania po aktualizacji. Użyj ich razem z porównywaniem wielu map (`.PTR` → *Compare results with other saved pointer map*), aby w ciągu zaledwie kilku minut uzyskać **pojedynczy, odporny base-pointer**.
* Skrót do filtrowania zbiorczego: po pierwszym skanowaniu naciśnij `Ctrl+A → Space`, aby zaznaczyć wszystko, a następnie `Ctrl+I` (odwróć zaznaczenie), aby odznaczyć adresy, które nie przeszły ponownego skanowania.

### Ultimap 3 – śledzenie Intel PT
*Od wersji 7.5 stary Ultimap został zaimplementowany ponownie na bazie **Intel Processor-Trace (IPT)**.* Oznacza to, że możesz teraz rejestrować *każdą gałąź, którą wykonuje cel*, **bez wykonywania single-stepping** (tylko user-mode; nie uruchomi to większości anti-debug gadgets).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Po kilku sekundach zatrzymaj przechwytywanie i **kliknij prawym przyciskiem myszy → Save execution list to file**. Połącz adresy branchy z sesją `Find out what addresses this instruction accesses`, aby niezwykle szybko zlokalizować hotspoty logiki gry o wysokiej częstotliwości.

### Jednobajtowe `jmp` / szablony automatycznego patchowania
Wersja 7.5 wprowadziła *jednobajtowy* stub JMP (0xEB), który instaluje handler SEH i umieszcza INT3 w pierwotnej lokalizacji. Jest generowany automatycznie po użyciu **Auto Assembler → Template → Code Injection** na instrukcjach, których nie można spatchować 5-bajtowym skokiem względnym. Umożliwia to tworzenie „tight” hooków wewnątrz spakowanych lub ograniczonych rozmiarem procedur.<sup>[[1]](#references)</sup>

### Stealth na poziomie kernela z DBVM (AMD i Intel)
*DBVM* to wbudowany w CE hypervisor Type-2. Nowsze buildy w końcu dodały **AMD-V/SVM support**, dzięki czemu można uruchomić `Driver → Load DBVM` na hostach Ryzen/EPYC. DBVM umożliwia:
1. Tworzenie hardware breakpoints niewidocznych dla kontroli Ring-3/anti-debug.
2. Odczyt/zapis stronicowanych lub chronionych obszarów pamięci kernela, nawet gdy user-mode driver jest wyłączony.
3. Wykonywanie obejść ataków timingowych bez VM-EXIT, np. odpytywanie hypervisora o `rdtsc`.

**Wskazówka:** DBVM odmówi załadowania, gdy w systemie Windows 11 włączone są HVCI/Memory-Integrity → wyłącz je lub uruchom dedykowany VM-host.

### Zdalne / cross-platform debugging z **ceserver**
CE jest teraz dostarczany z całkowicie przepisanym *ceserver* i może łączyć się przez TCP z targetami na **Linux, Android, macOS i iOS**. Popularny fork integruje *Frida*, łącząc dynamic instrumentation z GUI CE — idealne rozwiązanie, gdy trzeba spatchować gry Unity lub Unreal uruchomione na telefonie:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Dla bridge Frida zobacz `bb33bb/frida-ceserver` na GitHubie.<sup>[[1]](#references)[[2]](#references)</sup>

### Inne godne uwagi dodatki
* **Patch Scanner** (MemView → Tools) – wykrywa nieoczekiwane zmiany kodu w sekcjach wykonywalnych; przydatne podczas analizy malware.
* **Structure Dissector 2** – przeciągnij adres → `Ctrl+D`, a następnie wybierz *Guess fields*, aby automatycznie przeanalizować struktury C.
* **.NET & Mono Dissector** – ulepszona obsługa gier Unity; wywołuj metody bezpośrednio z konsoli CE Lua.
* **Big-Endian custom types** – skanowanie/edycja z odwróconą kolejnością bajtów (przydatne w emulatorach konsol i buforach pakietów sieciowych).
* **Autosave & tabs** dla okien AutoAssembler/Lua oraz `reassemble()` do przepisywania instrukcji wielowierszowych.<sup>[[1]](#references)</sup>

### Uwagi dotyczące instalacji i OPSEC (2024-2025)
* Oficjalny instalator jest opakowany w **ad-offers** InnoSetup (`RAV` itd.). **Zawsze klikaj *Decline*** *albo kompiluj ze źródeł*, aby uniknąć PUPs. AVs nadal będą wykrywać `cheatengine.exe` jako *HackTool*, co jest oczekiwane.
* Nowoczesne sterowniki anti-cheat (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) wykrywają klasę okna CE nawet po jej zmianie. Uruchamiaj kopię do reversing w **jednorazowej VM** albo po wyłączeniu rozgrywki sieciowej.
* Jeśli potrzebujesz tylko dostępu user-mode, wybierz **`Settings → Extra → Kernel mode debug = off`**, aby uniknąć ładowania niepodpisanego sterownika CE, który może powodować BSOD w Windows 11 24H2 z włączonym Secure Boot.

---

## Referencje

- [1] [Informacje o wydaniu Cheat Engine 7.5 (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [Wieloplatformowy bridge frida-ceserver](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
