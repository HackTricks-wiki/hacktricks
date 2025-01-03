# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) to przydatny program do znajdowania, gdzie ważne wartości są zapisywane w pamięci działającej gry i ich zmieniania.\
Po pobraniu i uruchomieniu programu, **zostaniesz** **przedstawiony** z **samouczkiem** jak używać narzędzia. Jeśli chcesz nauczyć się, jak korzystać z narzędzia, zdecydowanie zaleca się jego ukończenie.

## Czego szukasz?

![](<../../images/image (762).png>)

To narzędzie jest bardzo przydatne do znalezienia **gdzie jakaś wartość** (zwykle liczba) **jest przechowywana w pamięci** programu.\
**Zwykle liczby** są przechowywane w formacie **4bytes**, ale możesz je również znaleźć w formatach **double** lub **float**, lub możesz chcieć szukać czegoś **innego niż liczba**. Z tego powodu musisz upewnić się, że **wybierasz** to, co chcesz **wyszukać**:

![](<../../images/image (324).png>)

Możesz również wskazać **różne** typy **wyszukiwań**:

![](<../../images/image (311).png>)

Możesz także zaznaczyć pole, aby **zatrzymać grę podczas skanowania pamięci**:

![](<../../images/image (1052).png>)

### Skróty klawiszowe

W _**Edit --> Settings --> Hotkeys**_ możesz ustawić różne **skróty klawiszowe** do różnych celów, takich jak **zatrzymanie** **gry** (co jest dość przydatne, jeśli w pewnym momencie chcesz zeskanować pamięć). Inne opcje są dostępne:

![](<../../images/image (864).png>)

## Modyfikowanie wartości

Gdy **znajdziesz**, gdzie jest **wartość**, której **szukasz** (więcej na ten temat w kolejnych krokach), możesz **zmodyfikować ją**, klikając dwukrotnie, a następnie dwukrotnie klikając jej wartość:

![](<../../images/image (563).png>)

A na koniec **zaznaczając pole**, aby wprowadzić modyfikację w pamięci:

![](<../../images/image (385).png>)

**Zmiana** w **pamięci** zostanie natychmiast **zastosowana** (zauważ, że dopóki gra nie użyje tej wartości ponownie, wartość **nie zostanie zaktualizowana w grze**).

## Szukanie wartości

Załóżmy, że istnieje ważna wartość (jak życie twojego użytkownika), którą chcesz poprawić, i szukasz tej wartości w pamięci.

### Przez znaną zmianę

Zakładając, że szukasz wartości 100, **przeprowadzasz skanowanie** w poszukiwaniu tej wartości i znajdujesz wiele zbieżności:

![](<../../images/image (108).png>)

Następnie robisz coś, aby **wartość się zmieniła**, a następnie **zatrzymujesz** grę i **przeprowadzasz** **następne skanowanie**:

![](<../../images/image (684).png>)

Cheat Engine będzie szukać **wartości**, które **zmieniły się z 100 na nową wartość**. Gratulacje, **znalazłeś** **adres** wartości, której szukałeś, teraz możesz ją zmodyfikować.\
&#xNAN;_Jeśli nadal masz kilka wartości, zrób coś, aby ponownie zmodyfikować tę wartość i przeprowadź kolejne "następne skanowanie", aby przefiltrować adresy._

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

### Losowy adres pamięci - Znajdowanie kodu

Do tej pory nauczyliśmy się, jak znaleźć adres przechowujący wartość, ale jest bardzo prawdopodobne, że w **różnych wykonaniach gry ten adres znajduje się w różnych miejscach pamięci**. Więc dowiedzmy się, jak zawsze znaleźć ten adres.

Używając niektórych z wymienionych sztuczek, znajdź adres, w którym twoja aktualna gra przechowuje ważną wartość. Następnie (zatrzymując grę, jeśli chcesz) kliknij prawym przyciskiem myszy na znaleziony **adres** i wybierz "**Dowiedz się, co uzyskuje dostęp do tego adresu**" lub "**Dowiedz się, co zapisuje do tego adresu**":

![](<../../images/image (1067).png>)

**Pierwsza opcja** jest przydatna, aby wiedzieć, które **części** **kodu** **używają** tego **adresu** (co jest przydatne do innych rzeczy, takich jak **wiedza, gdzie możesz zmodyfikować kod** gry).\
**Druga opcja** jest bardziej **specyficzna** i będzie bardziej pomocna w tym przypadku, ponieważ interesuje nas, **skąd ta wartość jest zapisywana**.

Gdy wybierzesz jedną z tych opcji, **debugger** zostanie **przyłączony** do programu, a nowe **puste okno** się pojawi. Teraz **graj** w **grę** i **zmodyfikuj** tę **wartość** (bez ponownego uruchamiania gry). **Okno** powinno być **wypełnione** **adresami**, które **zmieniają** **wartość**:

![](<../../images/image (91).png>)

Teraz, gdy znalazłeś adres, który zmienia wartość, możesz **zmodyfikować kod według własnego uznania** (Cheat Engine pozwala na szybkie modyfikowanie go na NOP):

![](<../../images/image (1057).png>)

Możesz teraz zmodyfikować go tak, aby kod nie wpływał na twoją liczbę lub zawsze wpływał w pozytywny sposób.

### Losowy adres pamięci - Znajdowanie wskaźnika

Podążając za poprzednimi krokami, znajdź, gdzie znajduje się wartość, która cię interesuje. Następnie, używając "**Dowiedz się, co zapisuje do tego adresu**", dowiedz się, który adres zapisuje tę wartość i kliknij dwukrotnie, aby uzyskać widok disassembly:

![](<../../images/image (1039).png>)

Następnie przeprowadź nowe skanowanie **szukając wartości hex między "\[]"** (wartość $edx w tym przypadku):

![](<../../images/image (994).png>)

(_Jeśli pojawi się kilka, zazwyczaj potrzebujesz najmniejszego adresu_)\
Teraz, **znaleźliśmy wskaźnik, który będzie modyfikował wartość, która nas interesuje**.

Kliknij na "**Dodaj adres ręcznie**":

![](<../../images/image (990).png>)

Teraz zaznacz pole "Wskaźnik" i dodaj znaleziony adres w polu tekstowym (w tym scenariuszu, znaleziony adres na poprzednim obrazie to "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(Zauważ, że pierwszy "Adres" jest automatycznie wypełniany z adresu wskaźnika, który wprowadzasz)

Kliknij OK, a nowy wskaźnik zostanie utworzony:

![](<../../images/image (308).png>)

Teraz, za każdym razem, gdy modyfikujesz tę wartość, **modyfikujesz ważną wartość, nawet jeśli adres pamięci, w którym ta wartość się znajduje, jest inny.**

### Wstrzykiwanie kodu

Wstrzykiwanie kodu to technika, w której wstrzykujesz fragment kodu do docelowego procesu, a następnie przekierowujesz wykonanie kodu, aby przechodziło przez twój własny napisany kod (na przykład przyznając ci punkty zamiast je odejmować).

Wyobraź sobie, że znalazłeś adres, który odejmuje 1 od życia twojego gracza:

![](<../../images/image (203).png>)

Kliknij na Pokaż disassembler, aby uzyskać **kod disassembly**.\
Następnie kliknij **CTRL+a**, aby wywołać okno Auto assemble i wybierz _**Template --> Wstrzykiwanie kodu**_

![](<../../images/image (902).png>)

Wypełnij **adres instrukcji, którą chcesz zmodyfikować** (zwykle jest to automatycznie wypełnione):

![](<../../images/image (744).png>)

Zostanie wygenerowany szablon:

![](<../../images/image (944).png>)

Wstaw swój nowy kod asemblera w sekcji "**newmem**" i usuń oryginalny kod z sekcji "**originalcode**", jeśli nie chcesz, aby był wykonywany\*\*.\*\* W tym przykładzie wstrzyknięty kod doda 2 punkty zamiast odejmować 1:

![](<../../images/image (521).png>)

**Kliknij na wykonaj i tak dalej, a twój kod powinien zostać wstrzyknięty do programu, zmieniając zachowanie funkcjonalności!**

## **Referencje**

- **Samouczek Cheat Engine, ukończ go, aby nauczyć się, jak zacząć z Cheat Engine**

{{#include ../../banners/hacktricks-training.md}}
