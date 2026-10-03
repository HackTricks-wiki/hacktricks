# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania miejsc, w których ważne wartości są przechowywane w pamięci uruchomionej gry, oraz do ich zmieniania.\
Po pobraniu i uruchomieniu programu zostanie wyświetlony **tutorial** dotyczący korzystania z narzędzia. Jeśli chcesz nauczyć się korzystać z tego narzędzia, zdecydowanie zaleca się jego ukończenie.

## Czego szukasz?

![Cheat Engine - Czego szukasz?: Czego szukasz?](<../../images/image (762).png>)

To narzędzie jest bardzo przydatne do znajdowania, **gdzie konkretna wartość** (zwykle liczba) **jest przechowywana w pamięci** programu.\
**Liczby są zwykle** przechowywane w formacie **4bytes**, ale można je także znaleźć w formatach **double** lub **float**, albo można szukać czegoś **innego niż liczba**. Z tego powodu należy upewnić się, że wybrano to, czego chce się **szukać**:

![Cheat Engine - Czego szukasz?: Liczby są zwykle przechowywane w formacie 4bytes, ale można je także znaleźć w formatach double lub float, albo można szukać czegoś...](<../../images/image (324).png>)

Można także wskazać **różne typy** **wyszukiwania**:

![Cheat Engine - Czego szukasz?: Można także wskazać różne typy wyszukiwania](<../../images/image (311).png>)

Można również zaznaczyć pole, aby **zatrzymać grę podczas skanowania pamięci**:

![Cheat Engine - Czego szukasz?: Można również zaznaczyć pole, aby zatrzymać grę podczas skanowania pamięci](<../../images/image (1052).png>)

### Skróty klawiszowe

W _**Edit --> Settings --> Hotkeys**_ można ustawić różne **skróty klawiszowe** do różnych celów, takich jak **zatrzymywanie** **gry** (co jest bardzo przydatne, jeśli w pewnym momencie chce się przeskanować pamięć). Dostępne są także inne opcje:

![Czego szukasz? - Skróty klawiszowe: W Edit -- Settings -- Hotkeys można ustawić różne skróty klawiszowe do różnych celów, takich jak zatrzymywanie gry (co jest bardzo przydatne, jeśli w pewnym momencie...](<../../images/image (864).png>)

## Modyfikowanie wartości

Po **znalezieniu** miejsca, w którym znajduje się **szukana** **wartość** (więcej informacji na ten temat znajduje się w kolejnych krokach), można ją **zmodyfikować**, klikając ją dwukrotnie, a następnie klikając dwukrotnie jej wartość:

![Skróty klawiszowe - Modyfikowanie wartości: Po znalezieniu miejsca, w którym znajduje się szukana wartość (więcej informacji na ten temat znajduje się w kolejnych krokach), można ją zmodyfikować, klikając ją dwukrotnie, a następnie klikając dwukrotnie...](<../../images/image (563).png>)

Na koniec **zaznacz pole**, aby zastosować modyfikację w pamięci:

![Skróty klawiszowe - Modyfikowanie wartości: Na koniec zaznacz pole, aby zastosować modyfikację w pamięci](<../../images/image (385).png>)

**Zmiana** w **pamięci** zostanie natychmiast **zastosowana** (pamiętaj, że dopóki gra ponownie nie użyje tej wartości, wartość **nie zostanie zaktualizowana w grze**).

## Wyszukiwanie wartości

Załóżmy, że istnieje ważna wartość (na przykład życie użytkownika), którą chcesz zwiększyć, i szukasz jej w pamięci.

### Przy znanej zmianie

Załóżmy, że szukasz wartości 100. Wykonujesz **skanowanie**, wyszukując tę wartość, i znajdujesz wiele wyników:

![Wyszukiwanie wartości - Przy znanej zmianie: Załóżmy, że szukasz wartości 100. Wykonujesz skanowanie, wyszukując tę wartość, i znajdujesz wiele wyników](<../../images/image (108).png>)

Następnie robisz coś, co powoduje **zmianę wartości**, **zatrzymujesz** grę i wykonujesz **kolejne skanowanie**:

![Wyszukiwanie wartości - Przy znanej zmianie: Następnie robisz coś, co powoduje zmianę wartości, zatrzymujesz grę i wykonujesz kolejne skanowanie](<../../images/image (684).png>)

Cheat Engine wyszuka **wartości**, które **zmieniły się ze 100 na nową wartość**. Gratulacje, **znalazłeś** **adres** szukanej wartości i możesz ją teraz zmodyfikować.\
_Jeśli nadal masz kilka wartości, ponownie zmień tę wartość i wykonaj kolejne „next scan”, aby odfiltrować adresy._

### Nieznana wartość, znana zmiana

Jeśli **nie znasz wartości**, ale wiesz, **jak ją zmienić** (a nawet znasz wartość zmiany), możesz wyszukać tę liczbę.

Zacznij od wykonania skanowania typu **„Unknown initial value”**:

![Przy znanej zmianie - Nieznana wartość, znana zmiana: Zacznij od wykonania skanowania typu „Unknown initial value”](<../../images/image (890).png>)

Następnie zmień wartość, wskaż, **jak** zmieniła się **wartość** (w moim przypadku zmniejszyła się o 1) i wykonaj **kolejne skanowanie**:

![Przy znanej zmianie - Nieznana wartość, znana zmiana: Następnie zmień wartość, wskaż, jak zmieniła się wartość (w moim przypadku zmniejszyła się o 1) i wykonaj kolejne skanowanie](<../../images/image (371).png>)

Zostaną wyświetlone **wszystkie wartości, które zostały zmodyfikowane w wybrany sposób**:

![Przy znanej zmianie - Nieznana wartość, znana zmiana: Zostaną wyświetlone wszystkie wartości, które zostały zmodyfikowane w wybrany sposób](<../../images/image (569).png>)

Po znalezieniu wartości możesz ją zmodyfikować.

Pamiętaj, że istnieje **wiele możliwych zmian** i możesz wykonywać te **kroki dowolną liczbę razy**, aby filtrować wyniki:

![Przy znanej zmianie - Nieznana wartość, znana zmiana: Pamiętaj, że istnieje wiele możliwych zmian i możesz wykonywać te kroki dowolną liczbę razy, aby filtrować wyniki](<../../images/image (574).png>)

### Losowy adres pamięci - znajdowanie kodu

Do tej pory nauczyliśmy się, jak znaleźć adres przechowujący wartość, ale jest bardzo prawdopodobne, że podczas **różnych uruchomień gry adres ten będzie znajdował się w różnych miejscach pamięci**. Sprawdźmy więc, jak zawsze znajdować ten adres.

Korzystając z niektórych opisanych sztuczek, znajdź adres, pod którym bieżąca gra przechowuje ważną wartość. Następnie (jeśli chcesz, zatrzymując grę) kliknij **prawym przyciskiem myszy** znaleziony **adres** i wybierz opcję **„Find out what accesses this address”** lub **„Find out what writes to this address”**:

![Nieznana wartość, znana zmiana - Losowy adres pamięci - znajdowanie kodu: Korzystając z niektórych opisanych sztuczek, znajdź adres, pod którym bieżąca gra przechowuje ważną wartość. Następnie...](<../../images/image (1067).png>)

**Pierwsza opcja** pozwala sprawdzić, które **części** **kodu** **używają** tego **adresu** (co jest przydatne także do innych celów, takich jak **ustalenie, gdzie można zmodyfikować kod** gry).\
**Druga opcja** jest bardziej **konkretna** i będzie w tym przypadku bardziej pomocna, ponieważ chcemy wiedzieć, **z którego miejsca ta wartość jest zapisywana**.

Po wybraniu jednej z tych opcji **debugger** zostanie **dołączony** do programu i pojawi się nowe **puste okno**. Teraz **uruchom** **grę** i **zmodyfikuj** tę **wartość** (bez ponownego uruchamiania gry). **Okno** powinno zostać **wypełnione** **adresami**, które **modyfikują** tę **wartość**:

![Nieznana wartość, znana zmiana - Losowy adres pamięci - znajdowanie kodu: Po wybraniu jednej z tych opcji debugger zostanie dołączony do programu i pojawi się nowe puste okno. Następnie...](<../../images/image (91).png>)

Po znalezieniu adresu, który modyfikuje wartość, możesz **dowolnie zmodyfikować kod** (Cheat Engine pozwala bardzo szybko zmodyfikować go na NOP):

![Nieznana wartość, znana zmiana - Losowy adres pamięci - znajdowanie kodu: Po znalezieniu adresu, który modyfikuje wartość, możesz dowolnie zmodyfikować kod (Cheat Engine...](<../../images/image (1057).png>)

Możesz teraz zmodyfikować kod tak, aby nie wpływał na twoją liczbę lub zawsze wpływał na nią w pozytywny sposób.

### Losowy adres pamięci - znajdowanie wskaźnika

Wykonując poprzednie kroki, znajdź miejsce, w którym znajduje się interesująca cię wartość. Następnie, używając **„Find out what writes to this address”**, sprawdź, który adres zapisuje tę wartość, i kliknij go dwukrotnie, aby wyświetlić widok disassembly:

![Losowy adres pamięci - znajdowanie kodu - Losowy adres pamięci - znajdowanie wskaźnika: Wykonując poprzednie kroki, znajdź miejsce, w którym znajduje się interesująca cię wartość. Następnie, używając „Find out...](<../../images/image (1039).png>)

Następnie wykonaj nowe skanowanie, **wyszukując wartość hex pomiędzy „\[]”** (w tym przypadku wartość $edx):

![Losowy adres pamięci - znajdowanie kodu - Losowy adres pamięci - znajdowanie wskaźnika: Następnie wykonaj nowe skanowanie, wyszukując wartość hex pomiędzy „ ()” (w tym przypadku wartość $edx)](<../../images/image (994).png>)

(_Jeśli pojawi się kilka wyników, zwykle potrzebny jest adres o najmniejszej wartości_)\
Teraz znaleźliśmy **wskaźnik, który będzie modyfikował interesującą nas wartość**.

Kliknij **„Add Address Manually”**:

![Losowy adres pamięci - znajdowanie kodu - Losowy adres pamięci - znajdowanie wskaźnika: Kliknij „Add Address Manually”](<../../images/image (990).png>)

Następnie zaznacz pole wyboru „Pointer” i dodaj znaleziony adres w polu tekstowym (w tym przypadku znaleziony adres z poprzedniego obrazu to „Tutorial-i386.exe”+2426B0):

![Losowy adres pamięci - znajdowanie kodu - Losowy adres pamięci - znajdowanie wskaźnika: Następnie zaznacz pole wyboru „Pointer” i dodaj znaleziony adres w polu tekstowym (w tym przypadku...](<../../images/image (392).png>)

(Zwróć uwagę, że pierwszy „Address” jest automatycznie uzupełniany na podstawie wprowadzonego adresu wskaźnika).

Kliknij OK, a zostanie utworzony nowy wskaźnik:

![Losowy adres pamięci - znajdowanie kodu - Losowy adres pamięci - znajdowanie wskaźnika: Kliknij OK, a zostanie utworzony nowy wskaźnik](<../../images/image (308).png>)

Teraz za każdym razem, gdy zmodyfikujesz tę wartość, **będziesz modyfikować ważną wartość, nawet jeśli adres pamięci, pod którym się ona znajduje, będzie inny**.

### Code Injection

Code injection to technika polegająca na wstrzyknięciu fragmentu kodu do procesu docelowego, a następnie przekierowaniu wykonania kodu tak, aby przechodziło przez napisany przez ciebie kod (na przykład przyznawanie punktów zamiast ich odejmowania).

Załóżmy, że znalazłeś adres odejmujący 1 od życia twojego gracza:

![Losowy adres pamięci - znajdowanie wskaźnika - Code Injection: Załóżmy, że znalazłeś adres odejmujący 1 od życia twojego gracza](<../../images/image (203).png>)

Kliknij Show disassembler, aby wyświetlić **kod disassembly**.\
Następnie kliknij **CTRL+a**, aby otworzyć okno Auto assemble, i wybierz _**Template --> Code Injection**_

![Losowy adres pamięci - znajdowanie wskaźnika - Code Injection: Następnie kliknij CTRL+a, aby otworzyć okno Auto assemble, i wybierz Template -- Code Injection](<../../images/image (902).png>)

Wprowadź **adres instrukcji, którą chcesz zmodyfikować** (zwykle jest on uzupełniany automatycznie):

![Losowy adres pamięci - znajdowanie wskaźnika - Code Injection: Wprowadź adres instrukcji, którą chcesz zmodyfikować (zwykle jest on uzupełniany automatycznie)](<../../images/image (744).png>)

Zostanie wygenerowany template:

![Losowy adres pamięci - znajdowanie wskaźnika - Code Injection: Zostanie wygenerowany template](<../../images/image (944).png>)

Wstaw swój nowy kod assembly w sekcji **„newmem”** i usuń oryginalny kod z sekcji **„originalcode”**, jeśli nie chcesz, aby został wykonany**.** W tym przykładzie wstrzyknięty kod doda 2 punkty zamiast odejmować 1:

![Losowy adres pamięci - znajdowanie wskaźnika - Code Injection: Wstaw swój nowy kod assembly w sekcji „newmem” i usuń oryginalny kod z sekcji „originalcode”, jeśli nie chcesz, aby...](<../../images/image (521).png>)

**Kliknij execute itd., a twój kod powinien zostać wstrzyknięty do programu, zmieniając działanie funkcji!**

## Wstrzykiwanie kodu odporne na relokację z sygnaturami AOB

Skrypt, który hookuje `game.exe+123456`, może przestać działać po zastosowaniu ASLR lub aktualizacji oprogramowania. Sygnatura **Array of Bytes (AOB)** znajduje instrukcję na podstawie otaczającego jej kodu maszynowego. Użyj `aobscanmodule`, aby ograniczyć wyszukiwanie do jednego modułu. Sygnatura powinna być wystarczająco długa, aby zwracać tylko jedno dopasowanie. Używaj wildcardów dla bajtów relokacji, adresów i innych bajtów, które mogą się zmieniać. Nie używaj wildcardów dla całej instrukcji, którą chcesz przywrócić.<sup>[[4]](#references)</sup>

W Memory View wybierz instrukcję i użyj **Tools → Auto Assemble → Template → AOB Injection**. Wygenerowany blok `[DISABLE]` jest ważny. Musi przywracać każdy nadpisany bajt i zwalniać zaalokowaną pamięć.<sup>[[4]](#references)</sup>

<details>
<summary>Minimalny szkielet AOB injection dla x64</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

Przed włączeniem skryptu sprawdź następujące kwestie:

1. AOB zwraca **jeden** adres. Jeśli zwraca ich więcej, dodaj stabilne instrukcje po obu stronach.
2. Skok zastępuje kompletne instrukcje. Nigdy nie dziel instrukcji.
3. Przydzielony cave jest osiągalny za pomocą wygenerowanego skoku. Na x64 odległa alokacja może wymagać 14-bajtowego skoku.
4. Wstrzyknięty kod zachowuje rejestry, flagi i wyrównanie stosu wymagane przez oryginalną funkcję.
5. Blok wyłączający przywraca dokładnie oryginalne bajty. Przed zapisaniem tabeli przetestuj kilkukrotnie włączanie i wyłączanie.

## Reliable pointer workflow

Pointer znaleziony podczas jednego uruchomienia jest tylko kandydatem. Twórz pointer maps podczas kilku świeżych uruchomień i wykonuj rescan względem wszystkich z nich. Między przechwyceniami uruchamiaj ponownie target, aby zmieniły się ASLR i alokacje sterty. Preferuj ścieżki, których baza jest modułem lub innym stabilnym symbolem. Odrzucaj ścieżki, które działają tylko dla jednego zapisu gry, poziomu lub instancji obiektu.

Filtr **pointer must end with specific offsets** oraz jego opcja odchylenia mogą zachować użyteczne ścieżki, gdy pobliskie pole zmienia położenie między buildami. W wydaniu 7.5 dodano również tę kontrolę odchylenia. Jest to filtr, a nie dowód stabilności pointer chain.<sup>[[1]](#references)</sup>

Gdy struktura zmienia położenie zbyt często, aby pointer scanning był skuteczny, zahookuj instrukcję, która uzyskuje do niej dostęp. Przechwyć aktywny pointer do obiektu z rejestru i zapisz go w zaalokowanym symbolu. Jest to często bardziej niezawodne w przypadku list encji i managed objects.

## Tracing code instead of scanning values

Użyj **Find out what writes to this address**, gdy wartość jest bezpośrednio modyfikowana. Użyj **Find out what accesses this address**, gdy potrzebujesz obiektu nadrzędnego lub gdy zapis odbywa się za pośrednictwem skopiowanych danych. W target wywołaj tylko jedną akcję. Następnie porównaj liczbę trafień i stan rejestrów.

**Ultimap 2** wykorzystuje Intel Processor Trace na obsługiwanych procesorach Intel. Rejestruje wykonany control flow z mniejszym zakłóceniem niż wykonywanie każdej instrukcji krok po kroku. Odfiltruj kod wykonany podczas interesującej akcji i usuń kod, który został również wykonany podczas przechwytywania bezczynności. Intel PT nie jest funkcją stealth. Target nadal może wykryć tracing, zmiany czasowe lub samego Cheat Engine.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 dodał również interfejs Intel PT udostępniany przez Windows. Starszy tryb Ultimap oparty na DBVM oraz tryb Intel PT mają różne wymagania sprzętowe i systemowe. Nie zakładaj, że CPU obsługujący DBVM obsługuje również Intel PT.<sup>[[1]](#references)</sup>

## Debugger and breakpoint selection

Wybierz najmniej inwazyjny debugger, który działa:

- **Windows debugger** jest prosty, ale tworzy normalne debug events. Mechanizmy anti-debugging mogą go wykryć.
- **VEH debugger** obsługuje breakpointy za pomocą vectored exception handler. Omija niektóre podstawowe kontrole debuggera, ale nie jest niewidoczny.
- **Hardware breakpoints** nie modyfikują bajtów instrukcji, ale x86/x64 udostępnia tylko niewielką liczbę slotów w debug registers.
- **Software breakpoints** zastępują bajt przez `INT3`. Łatwo je wykryć i mogą kolidować z kontrolami integralności.
- **DBVM debugger** przenosi niektóre operacje poniżej guest OS. Ma znacznie wyższe uprawnienia i może spowodować crash hosta w przypadku błędnej konfiguracji.

Cheat Engine 7.5 może używać jednobajtowego skoku opartego na exception handlerze oraz `INT3`, gdy nie ma wystarczająco dużo miejsca na normalny relative jump. Traktuj go jak software breakpoint. Zweryfikuj przepływ wyjątków i nie zakładaj, że omija kontrole anti-tamper.<sup>[[1]](#references)</sup>

DBVM jest hypervisorem, a nie uniwersalnym przełącznikiem niewidoczności. Używaj go wyłącznie w disposable lab. Nie udostępniaj jego control interface niezaufanemu kodowi. Kernel anti-cheat i produkty endpoint security nadal mogą wykryć driver, stan hypervisora lub zmodyfikowaną pamięć.

## Managed runtimes and recent 7.6/7.7 features

W przypadku targetów Mono, IL2CPP, .NET i Java preferuj runtime metadata zamiast blind scans, jeśli jest dostępne. Otwórz **Mono → Activate mono features** lub odpowiadające mu okno informacji o runtime. Najpierw znajdź klasę, pole lub metodę. Następnie użyj native disassembly, gdy managed method zostanie skompilowana przez JIT.

Linia 7.6 dodała `AOBSCANEX` dla sygnatur wyłącznie w executable memory, interfejs debuggera `gdbserver`, inspekcję Java metadata, szybszą enumerację IL2CPP oraz opcję pointer scan, która ignoruje górny bajt pointera używany przez ARM memory tagging. Linia 7.7 dodała native builds dla Linux, `HOOK`/`UNHOOK`, `aobscanfunction`, lepsze wyszukiwanie generic Mono methods, ulepszoną obsługę struktur PDB oraz podstawową analizę struktur Unreal Engine.<sup>[[3]](#references)</sup>

Dodatki te umożliwiają następujący workflow:

1. Rozwiąż managed method lub static field na podstawie metadata.
2. Prześledź lub zdeasembluj native code wygenerowany dla tej metody.
3. Użyj `AOBSCANEX` lub `aobscanfunction`, aby znaleźć stabilną sygnaturę w executable memory.
4. Wygeneruj odwracalny hook. Zachowaj oryginalne instrukcje i zweryfikuj ścieżkę wyłączania.
5. Ponownie sprawdzaj sygnaturę po każdej aktualizacji targetu. Pomyślne dopasowanie nie gwarantuje, że otaczająca logika nadal ma to samo znaczenie.

## Remote targets with `ceserver`

`ceserver` udostępnia GUI Cheat Engine enumerację procesów, dostęp do pamięci i debugging. Oficjalne buildy obsługują Linux i Android. Uruchom na target odpowiednią architekturę i połącz się przez zakładkę **Network**. Na Androidzie przekierowanie domyślnego portu zapobiega wystawieniu go w sieci:<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
Ten third-party `frida-ceserver` bridge może zapewnić interfejs zgodny z Cheat Engine dla celów iOS. Nie jest to oficjalny `ceserver`, a obsługiwane operacje mogą się różnić.<sup>[[2]](#references)</sup>

Załóż, że protokół zapewnia dostęp na poziomie debuggera. Powiąż go z loopbackiem albo umieść za tunelem SSH/ADB. Nigdy nie wystawiaj TCP 52736 na niezaufaną sieć. Zatrzymaj server po zakończeniu sesji.

## Bezpieczeństwo operacyjne

Podłączaj się wyłącznie do software'u, którego jesteś właścicielem lub do testowania którego masz upoważnienie. Nie uruchamiaj Cheat Engine obok gry online ani production endpointu. Zapisy do pamięci, wstrzyknięty kod, drivery i DBVM mogą spowodować crash lub uszkodzenie celu.<sup>[[3]](#references)</sup>

Pobieraj buildy z oficjalnej witryny albo kompiluj opublikowany source code. Produkty zabezpieczające często klasyfikują memory edytory, debuggery i ich drivery jako hack tools. Nie wyłączaj globalnie ochrony hosta. Używaj dedykowanej VM lub hosta laboratoryjnego i zweryfikuj artifact przed uruchomieniem.<sup>[[3]](#references)</sup>



## References

- [1] [Informacje o wydaniu Cheat Engine 7.5](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver bridge dla zdalnych celów](https://github.com/gmh5225/frida-ceserver)
- [3] [Oficjalne informacje o wydaniach Cheat Engine](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
