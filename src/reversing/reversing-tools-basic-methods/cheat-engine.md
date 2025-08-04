# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania, gdzie ważne wartości są zapisywane w pamięci działającej gry i ich zmieniania.\
Po pobraniu i uruchomieniu, **zostaniesz** **przedstawiony** z **samouczkiem** jak używać narzędzia. Jeśli chcesz nauczyć się, jak używać tego narzędzia, zdecydowanie zaleca się jego ukończenie.

## Czego szukasz?

![](<../../images/image (762).png>)

To narzędzie jest bardzo przydatne do znalezienia **gdzie jakaś wartość** (zwykle liczba) **jest przechowywana w pamięci** programu.\
**Zwykle liczby** są przechowywane w formie **4 bajtów**, ale możesz je również znaleźć w formatach **double** lub **float**, lub możesz chcieć szukać czegoś **innego niż liczba**. Z tego powodu musisz upewnić się, że **wybierasz** to, co chcesz **wyszukiwać**:

![](<../../images/image (324).png>)

Możesz również wskazać **różne** typy **wyszukiwań**:

![](<../../images/image (311).png>)

Możesz także zaznaczyć pole, aby **zatrzymać grę podczas skanowania pamięci**:

![](<../../images/image (1052).png>)

### Skróty klawiszowe

W _**Edit --> Settings --> Hotkeys**_ możesz ustawić różne **skróty klawiszowe** do różnych celów, takich jak **zatrzymanie** **gry** (co jest dość przydatne, jeśli w pewnym momencie chcesz zeskanować pamięć). Inne opcje są dostępne:

![](<../../images/image (864).png>)

## Modyfikowanie wartości

Gdy **znajdziesz**, gdzie jest **wartość**, której **szukasz** (więcej na ten temat w kolejnych krokach), możesz **zmodyfikować ją**, klikając dwukrotnie, a następnie klikając dwukrotnie jej wartość:

![](<../../images/image (563).png>)

I w końcu **zaznaczając pole**, aby wprowadzić modyfikację w pamięci:

![](<../../images/image (385).png>)

**Zmiana** w **pamięci** zostanie natychmiast **zastosowana** (zauważ, że dopóki gra nie użyje tej wartości ponownie, wartość **nie zostanie zaktualizowana w grze**).

## Wyszukiwanie wartości

Załóżmy, że istnieje ważna wartość (jak życie twojego użytkownika), którą chcesz poprawić, i szukasz tej wartości w pamięci.

### Przez znaną zmianę

Zakładając, że szukasz wartości 100, **przeprowadzasz skanowanie** w poszukiwaniu tej wartości i znajdujesz wiele trafień:

![](<../../images/image (108).png>)

Następnie robisz coś, aby **wartość się zmieniła**, zatrzymujesz grę i **przeprowadzasz** **następne skanowanie**:

![](<../../images/image (684).png>)

Cheat Engine będzie szukać **wartości**, które **zmieniły się z 100 na nową wartość**. Gratulacje, **znalazłeś** **adres** wartości, której szukałeś, teraz możesz ją zmodyfikować.\
_Jeśli nadal masz kilka wartości, zrób coś, aby ponownie zmodyfikować tę wartość i przeprowadź kolejne "następne skanowanie", aby przefiltrować adresy._

### Nieznana wartość, znana zmiana

W scenariuszu, w którym **nie znasz wartości**, ale wiesz **jak ją zmienić** (a nawet wartość zmiany), możesz szukać swojej liczby.

Zacznij od przeprowadzenia skanowania typu "**Nieznana początkowa wartość**":

![](<../../images/image (890).png>)

Następnie, zmień wartość, wskaż **jak** **wartość** **się zmieniła** (w moim przypadku zmniejszyła się o 1) i przeprowadź **następne skanowanie**:

![](<../../images/image (371).png>)

Zostaną przedstawione **wszystkie wartości, które zostały zmodyfikowane w wybrany sposób**:

![](<../../images/image (569).png>)

Gdy znajdziesz swoją wartość, możesz ją zmodyfikować.

Zauważ, że istnieje **wiele możliwych zmian** i możesz powtarzać te **kroki tyle razy, ile chcesz**, aby przefiltrować wyniki:

![](<../../images/image (574).png>)

### Losowy adres pamięci - Znalezienie kodu

Do tej pory nauczyliśmy się, jak znaleźć adres przechowujący wartość, ale jest bardzo prawdopodobne, że w **różnych wykonaniach gry ten adres znajduje się w różnych miejscach pamięci**. Więc dowiedzmy się, jak zawsze znaleźć ten adres.

Używając niektórych z wymienionych sztuczek, znajdź adres, w którym twoja aktualna gra przechowuje ważną wartość. Następnie (zatrzymując grę, jeśli chcesz) kliknij **prawym przyciskiem** na znaleziony **adres** i wybierz "**Dowiedz się, co uzyskuje dostęp do tego adresu**" lub "**Dowiedz się, co zapisuje do tego adresu**":

![](<../../images/image (1067).png>)

**Pierwsza opcja** jest przydatna, aby wiedzieć, które **części** **kodu** **używają** tego **adresu** (co jest przydatne do innych rzeczy, takich jak **wiedza, gdzie możesz zmodyfikować kod** gry).\
**Druga opcja** jest bardziej **specyficzna** i będzie bardziej pomocna w tym przypadku, ponieważ interesuje nas, **skąd ta wartość jest zapisywana**.

Gdy wybierzesz jedną z tych opcji, **debugger** zostanie **przyłączony** do programu, a nowe **puste okno** się pojawi. Teraz, **graj** w **grę** i **zmodyfikuj** tę **wartość** (bez ponownego uruchamiania gry). **Okno** powinno być **wypełnione** **adresami**, które **zmieniają** **wartość**:

![](<../../images/image (91).png>)

Teraz, gdy znalazłeś adres, który zmienia wartość, możesz **zmodyfikować kod według własnego uznania** (Cheat Engine pozwala na szybkie modyfikowanie go na NOP):

![](<../../images/image (1057).png>)

Możesz teraz zmodyfikować go tak, aby kod nie wpływał na twoją liczbę lub zawsze wpływał w pozytywny sposób.

### Losowy adres pamięci - Znalezienie wskaźnika

Podążając za poprzednimi krokami, znajdź, gdzie znajduje się wartość, która cię interesuje. Następnie, używając "**Dowiedz się, co zapisuje do tego adresu**", dowiedz się, który adres zapisuje tę wartość i kliknij dwukrotnie, aby uzyskać widok disassembly:

![](<../../images/image (1039).png>)

Następnie przeprowadź nowe skanowanie **szukając wartości hex między "\[]"** (wartość $edx w tym przypadku):

![](<../../images/image (994).png>)

(_Jeśli pojawi się kilka, zazwyczaj potrzebujesz najmniejszego adresu_)\
Teraz, **znaleźliśmy wskaźnik, który będzie modyfikował wartość, która nas interesuje**.

Kliknij na "**Dodaj adres ręcznie**":

![](<../../images/image (990).png>)

Teraz, zaznacz pole "Wskaźnik" i dodaj znaleziony adres w polu tekstowym (w tym scenariuszu, znaleziony adres na poprzednim obrazie to "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(Zauważ, że pierwszy "Adres" jest automatycznie wypełniany z adresu wskaźnika, który wprowadzasz)

Kliknij OK, a nowy wskaźnik zostanie utworzony:

![](<../../images/image (308).png>)

Teraz, za każdym razem, gdy modyfikujesz tę wartość, **modyfikujesz ważną wartość, nawet jeśli adres pamięci, w którym znajduje się wartość, jest inny.**

### Wstrzykiwanie kodu

Wstrzykiwanie kodu to technika, w której wstrzykujesz fragment kodu do docelowego procesu, a następnie przekierowujesz wykonanie kodu, aby przechodziło przez twój własny napisany kod (na przykład przyznając ci punkty zamiast je odejmować).

Wyobraź sobie, że znalazłeś adres, który odejmuje 1 od życia twojego gracza:

![](<../../images/image (203).png>)

Kliknij na Pokaż disassembler, aby uzyskać **kod disassembly**.\
Następnie kliknij **CTRL+a**, aby wywołać okno Auto assemble i wybierz _**Template --> Code Injection**_

![](<../../images/image (902).png>)

Wypełnij **adres instrukcji, którą chcesz zmodyfikować** (zwykle jest to automatycznie wypełnione):

![](<../../images/image (744).png>)

Zostanie wygenerowany szablon:

![](<../../images/image (944).png>)

Wstaw swój nowy kod asemblera w sekcji "**newmem**" i usuń oryginalny kod z "**originalcode**", jeśli nie chcesz, aby był wykonywany. W tym przykładzie wstrzyknięty kod doda 2 punkty zamiast odejmować 1:

![](<../../images/image (521).png>)

**Kliknij na wykonaj i tak dalej, a twój kod powinien zostać wstrzyknięty do programu, zmieniając zachowanie funkcjonalności!**

## Zaawansowane funkcje w Cheat Engine 7.x (2023-2025)

Cheat Engine nadal ewoluował od wersji 7.0, a kilka funkcji poprawiających jakość życia i *ofensywnego odwracania* zostało dodanych, które są niezwykle przydatne podczas analizy nowoczesnego oprogramowania (i nie tylko gier!). Poniżej znajduje się **bardzo skondensowany przewodnik po polu** do dodatków, które najprawdopodobniej będziesz używać podczas pracy w red-team/CTF.

### Ulepszenia skanera wskaźników 2
* `Wskaźniki muszą kończyć się na określonych offsetach` i nowy suwak **Odchylenie** (≥7.4) znacznie zmniejsza fałszywe pozytywy, gdy ponownie skanujesz po aktualizacji. Użyj go razem z porównaniem multi-map (`.PTR` → *Porównaj wyniki z inną zapisaną mapą wskaźników*), aby uzyskać **pojedynczy odporny wskaźnik bazowy** w zaledwie kilka minut.
* Skrót do filtrowania zbiorczego: po pierwszym skanowaniu naciśnij `Ctrl+A → Spacja`, aby zaznaczyć wszystko, a następnie `Ctrl+I` (odwróć), aby odznaczyć adresy, które nie przeszły ponownego skanowania.

### Ultimap 3 – Śledzenie Intel PT
*Od wersji 7.5 stary Ultimap został ponownie wdrożony na bazie **Intel Processor-Trace (IPT)***. Oznacza to, że teraz możesz rejestrować *wszystkie* gałęzie, które podejmuje cel **bez pojedynczego kroku** (tylko w trybie użytkownika, nie uruchomi większości gadżetów anty-debug).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Po kilku sekundach zatrzymaj przechwytywanie i **kliknij prawym przyciskiem myszy → Zapisz listę wykonania do pliku**. Połącz adresy gałęzi z sesją `Find out what addresses this instruction accesses`, aby bardzo szybko zlokalizować miejsca o wysokiej częstotliwości logiki gry.

### Szablony `jmp` / auto-patch 1-bajtowe
Wersja 7.5 wprowadziła *jedno-bajtowy* stub JMP (0xEB), który instaluje obsługę SEH i umieszcza INT3 w oryginalnej lokalizacji. Jest generowany automatycznie, gdy używasz **Auto Assembler → Template → Code Injection** na instrukcjach, które nie mogą być załatane za pomocą 5-bajtowego skoku względnego. Umożliwia to tworzenie „ciasnych” haków wewnątrz spakowanych lub ograniczonych rozmiarowo rutyn.

### Stealth na poziomie jądra z DBVM (AMD i Intel)
*DBVM* to wbudowany w CE hipernadzorca typu 2. Ostatnie wersje w końcu dodały **wsparcie AMD-V/SVM**, dzięki czemu możesz uruchomić `Driver → Load DBVM` na hostach Ryzen/EPYC. DBVM pozwala ci:
1. Tworzyć punkty przerwania sprzętowe niewidoczne dla kontroli Ring-3/anty-debug.
2. Odczytywać/zapisywać pamięć jądra stronicowalną lub chronioną, nawet gdy sterownik w trybie użytkownika jest wyłączony.
3. Wykonywać obejścia ataków czasowych bez VM-EXIT (np. zapytanie `rdtsc` z hipernadzorcy).

**Wskazówka:** DBVM odmówi załadowania, gdy HVCI/Memory-Integrity jest włączone w Windows 11 → wyłącz to lub uruchom dedykowanego hosta VM.

### Zdalne / międzyplatformowe debugowanie z **ceserver**
CE teraz dostarcza pełne przepisanie *ceserver* i może łączyć się przez TCP z celami **Linux, Android, macOS i iOS**. Popularny fork integruje *Frida*, aby połączyć dynamiczną instrumentację z GUI CE – idealne, gdy musisz załatać gry Unity lub Unreal działające na telefonie:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Dla mostu Frida zobacz `bb33bb/frida-ceserver` na GitHubie.

### Inne godne uwagi dodatki
* **Patch Scanner** (MemView → Tools) – wykrywa nieoczekiwane zmiany kodu w sekcjach wykonywalnych; przydatne do analizy złośliwego oprogramowania.
* **Structure Dissector 2** – przeciągnij-adres → `Ctrl+D`, następnie *Guess fields* aby automatycznie ocenić struktury C.
* **.NET & Mono Dissector** – poprawione wsparcie dla gier Unity; wywołuj metody bezpośrednio z konsoli CE Lua.
* **Big-Endian custom types** – odwrócony skan/edycja kolejności bajtów (przydatne dla emulatorów konsol i buforów pakietów sieciowych).
* **Autosave & tabs** dla okien AutoAssembler/Lua, plus `reassemble()` do przepisania instrukcji wieloliniowych.

### Notatki dotyczące instalacji i OPSEC (2024-2025)
* Oficjalny instalator jest opakowany w InnoSetup **oferty reklamowe** (`RAV` itd.). **Zawsze klikaj *Odrzuć*** *lub kompiluj ze źródła*, aby uniknąć PUP-ów. AV-y nadal będą oznaczać `cheatengine.exe` jako *HackTool*, co jest oczekiwane.
* Nowoczesne sterowniki antycheatowe (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) wykrywają klasę okna CE nawet po zmianie nazwy. Uruchom swoją kopię do odwracania **w jednorazowej VM** lub po wyłączeniu gry sieciowej.
* Jeśli potrzebujesz tylko dostępu w trybie użytkownika, wybierz **`Settings → Extra → Kernel mode debug = off`**, aby uniknąć ładowania niepodpisanego sterownika CE, który może powodować BSOD w Windows 11 24H2 Secure-Boot.

---

## **Referencje**

- [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- **Cheat Engine tutorial, complete it to learn how to start with Cheat Engine**

{{#include ../../banners/hacktricks-training.md}}
