# Radio

{{#include ../../banners/hacktricks-training.md}}

Informacje o testach konkretnych protokołów po zidentyfikowaniu sygnału znajdziesz w sekcjach [testowania RFID/NFC, sub-GHz, podczerwieni, BLE i LoRaWAN](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) to bezpłatny analizator sygnałów cyfrowych dla GNU/Linux i macOS, przeznaczony do pozyskiwania informacji z nieznanych sygnałów radiowych. Obsługuje urządzenia SDR przez SoapySDR i udostępnia narzędzia do demodulacji oraz analizy w czasie rzeczywistym sygnałów FSK, PSK, ASK, analogowego wideo, sygnałów impulsowych i analogowych kanałów głosowych.<sup>[[1]](#references)</sup>

### Podstawowa konfiguracja

Po instalacji warto rozważyć skonfigurowanie kilku opcji.\
W ustawieniach (drugi przycisk zakładki) wybierz **urządzenie SDR** lub plik wejściowy, częstotliwość dostrojenia oraz częstotliwość próbkowania. Częstotliwość do 2.56 Msps może być praktyczna, jeśli komputer ją obsługuje.

![Ustawienia SigDigger z opcjami wyboru urządzenia SDR, pliku wejściowego, częstotliwości i częstotliwości próbkowania](<../../images/image (245).png>)

W sekcji zachowania GUI zaleca się włączenie kilku opcji, jeśli komputer je obsługuje:

![SigDigger - Podstawowa konfiguracja: w sekcji zachowania GUI zaleca się włączenie kilku opcji, jeśli komputer je obsługuje](<../../images/image (472).png>)

> [!TIP]
> Jeśli zauważysz, że komputer nie przechwytuje sygnałów, spróbuj wyłączyć OpenGL i obniżyć częstotliwość próbkowania.

### Zastosowania

- Aby **przechwycić fragment sygnału i go przeanalizować**, przytrzymaj przycisk "Push to capture" tak długo, jak potrzebujesz.

![Podstawowa konfiguracja - Zastosowania: aby przechwycić fragment sygnału i go przeanalizować, przytrzymaj przycisk "Push to capture" tak długo, jak potrzebujesz](<../../images/image (960).png>)

- **Tuner** SigDigger pomaga **lepiej przechwytywać sygnały** (ale może też je pogorszyć). Najlepiej zacząć od 0 i **stopniowo zwiększać wartość, aż** wprowadzany **szum** będzie **większy** niż potrzebna **poprawa sygnału**.

![Regulacja tunera SigDigger poprawiająca jakość przechwyconego sygnału radiowego](<../../images/image (1099).png>)

### Synchronizacja z kanałem radiowym

W [**SigDigger**](https://github.com/BatchDrake/SigDigger) zsynchronizuj się z kanałem, którego chcesz słuchać, skonfiguruj opcję "Baseband audio preview", ustaw szerokość pasma tak, aby obejmowała wszystkie przesyłane informacje, a następnie ustaw Tuner na poziom, przy którym szum zaczyna wyraźnie narastać:<sup>[[1]](#references)</sup>

![SigDigger zsynchronizowany z kanałem radiowym, z podglądem dźwięku pasma podstawowego i skonfigurowaną szerokością pasma](<../../images/image (585).png>)

## Przydatne wskazówki

- Gdy urządzenie wysyła serie informacji, **pierwsza część zwykle jest preambułą**, więc **nie musisz się martwić**, jeśli **nie znajdziesz tam informacji** lub **wystąpią tam błędy**.
- W ramkach informacji zazwyczaj powinny być widoczne **różne, dobrze wyrównane względem siebie ramki**:

![Synchronizacja z kanałem radiowym - Przydatne wskazówki: ramki informacji powinny być różne i dobrze wyrównane względem siebie](<../../images/image (1076).png>)

![Synchronizacja z kanałem radiowym - Przydatne wskazówki: ramki informacji powinny być różne i dobrze wyrównane względem siebie](<../../images/image (597).png>)

- **Po odzyskaniu przejść między poziomami może być konieczne ich zdekodowanie.** W kodowaniu Manchester jedno kierunkowe przejście oznacza `0`, a przejście w przeciwnym kierunku — `1`; dokładna polaryzacja zależy od użytej konwencji.
- Preambuła może zawierać serię próbek o tym samym poziomie, nawet jeśli payload używa kodowania Manchester, dlatego przed dekodowaniem ustal granicę ramki.

### Ustalanie rodzaju modulacji za pomocą IQ

Informacje w sygnałach można przechowywać na 3 sposoby: przez modulowanie **amplitudy**, **częstotliwości** lub **fazy**.\
Analizując sygnał, można na różne sposoby ustalić, która z tych metod jest używana (więcej sposobów znajdziesz poniżej), ale dobrym rozwiązaniem jest sprawdzenie wykresu IQ.

![Wykres IQ w SigDigger służący do ustalenia, czy sygnał wykorzystuje modulację amplitudy, częstotliwości czy fazy](<../../images/image (788).png>)

- **Wykrywanie AM**: jeśli na wykresie IQ pojawią się na przykład **2 okręgi** (prawdopodobnie jeden w punkcie 0, a drugi przy innej amplitudzie), może to oznaczać sygnał AM. Na wykresie IQ odległość między punktem 0 a okręgiem odpowiada amplitudzie sygnału, więc łatwo zauważyć użycie różnych amplitud.
- **Wykrywanie PM**: jak na poprzednim obrazie, małe, niezwiązane ze sobą okręgi prawdopodobnie oznaczają modulację fazy. Na wykresie IQ kąt między punktem a punktem 0,0 odpowiada fazie sygnału, co oznacza, że używane są 4 różne fazy.
  - Pamiętaj, że jeśli informacja jest zakodowana w zmianie fazy, a nie w samej fazie, różne fazy nie będą wyraźnie od siebie odróżnione.
- **Wykrywanie FM**: wykres IQ nie zawiera pola pokazującego częstotliwość (odległość od środka oznacza amplitudę, a kąt — fazę).\
  Dlatego aby wykryć FM, na wykresie powinien być widoczny **w zasadzie tylko okrąg**.\
  Ponadto przesunięcie częstotliwości zmienia szybkość obrotu wokół okręgu IQ. W SigDigger zmiana szybkości lub kierunku obrotu może więc wskazywać na FM.

## Przykład AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Ustalanie AM

#### Sprawdzanie obwiedni

Podczas analizy danych AM w [**SigDigger**](https://github.com/BatchDrake/SigDigger) obwiednia sygnału może ujawnić różne poziomy amplitudy. Przykładowy sygnał przesyła informacje za pomocą impulsów modulowanych amplitudowo; pojedynczy impuls wygląda tak:<sup>[[1]](#references)</sup>

![Obwiednia sygnału AM w SigDigger z wyraźnymi poziomami amplitudy impulsu](<../../images/image (590).png>)

A tak wygląda fragment symbolu na przebiegu:

![Ustalanie AM - Sprawdzanie obwiedni: tak wygląda fragment symbolu na przebiegu](<../../images/image (734).png>)

#### Sprawdzanie histogramu

Możesz **zaznaczyć cały obszar sygnału** zawierający informacje, wybrać tryb **Amplitude** i **Selection**, a następnie kliknąć **Histogram**. Zobaczysz, że występują tylko 2 wyraźne poziomy.

![Histogram amplitudy w SigDigger pokazujący dwa wyraźne poziomy zaznaczonego sygnału AM](<../../images/image (264).png>)

Jeśli zamiast Amplitude wybierzesz Frequency, w przypadku tego sygnału AM znajdziesz tylko 1 częstotliwość (informacja modulowana częstotliwością nie może być przenoszona przy użyciu tylko jednej częstotliwości).

![Histogram częstotliwości w SigDigger dla sygnału AM pokazujący jedną częstotliwość](<../../images/image (732).png>)

Jeśli znajdziesz wiele częstotliwości, sygnał prawdopodobnie nie jest FM — jego częstotliwość mogła po prostu ulec zmianie w kanale.

#### Wykres IQ

W tym przykładzie widać **duży okrąg**, ale także **wiele punktów w środku**.

![Sprawdzanie histogramu - Wykres IQ: w tym przykładzie widać duży okrąg, ale także wiele punktów w środku](<../../images/image (222).png>)

### Ustalanie szybkości symboli

#### Dla jednego symbolu

Zaznacz najmniejszy przedział, który wyraźnie zawiera jeden symbol, i sprawdź **Selection freq**. W tym przykładzie wynosi ona 1.013 kHz, czyli w przybliżeniu 1 kHz.

![Ustalanie szybkości symboli - Dla jednego symbolu: zaznacz najmniejszy przedział wyraźnie zawierający jeden symbol i sprawdź "Selection freq". W tym przypadku wynosi ona 1.013 kHz (czyli 1 kHz).](<../../images/image (78).png>)

#### Dla grupy symboli

Możesz też określić liczbę symboli, które chcesz zaznaczyć, a SigDigger obliczy częstotliwość jednego symbolu (im więcej zaznaczonych symboli, tym prawdopodobnie lepiej). W tym przypadku zaznaczono 10 symboli, a wartość "Selection freq" wynosi 1.004 kHz:

![Obliczanie szybkości symboli w SigDigger na podstawie zaznaczonej grupy dziesięciu symboli](<../../images/image (1008).png>)

### Odczytywanie bitów

Po ustaleniu, że sygnał wykorzystuje AM, i oszacowaniu **szybkości symboli**, zaznacz obszar sygnału, skonfiguruj próbkowanie amplitudy i poziomy decyzyjne, wybierz **Gardner clock recovery**, a następnie kliknij **Sample**:

![Panel Get Bits w SigDigger skonfigurowany do próbkowania AM, z szybkością symboli i odzyskiwaniem zegara Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** oznacza, że jeśli wcześniej zaznaczono przedziały w celu ustalenia szybkości symboli, zostanie użyta ta szybkość.
- **Manual** oznacza, że zostanie użyta podana szybkość symboli.
- W opcji **Fixed interval selection** określasz liczbę przedziałów do zaznaczenia, a program oblicza na tej podstawie szybkość symboli.
- **Gardner clock recovery** to przydatne ustawienie domyślne, ale nadal wymaga przybliżonej szybkości symboli.

Po kliknięciu Sample pojawi się taki widok:

![Dla grupy symboli - Odczytywanie bitów: po kliknięciu Sample pojawi się taki widok](<../../images/image (644).png>)

Aby SigDigger rozpoznał **zakres poziomów** przenoszących informacje, kliknij **niższy poziom** i przytrzymując przycisk, przeciągnij do najwyższego poziomu:

![Zaznaczanie zakresu poziomów w SigDigger od niższego poziomu amplitudy do wyższego](<../../images/image (439).png>)

Gdyby występowały na przykład **4 różne poziomy amplitudy**, należałoby ustawić **Bits per symbol** na 2 i zaznaczyć zakres od najniższego do najwyższego poziomu.

Na koniec, **zwiększając** wartość **Zoom** i **zmieniając Row size**, możesz wyświetlić bity (możesz zaznaczyć wszystkie i skopiować, aby uzyskać pełny ciąg bitów):

![Dla grupy symboli - Odczytywanie bitów: zwiększając wartość Zoom i zmieniając Row size, można wyświetlić bity i skopiować je wszystkie](<../../images/image (276).png>)

Jeśli sygnał ma więcej niż 1 bit na symbol (na przykład 2), SigDigger **nie wie, który symbol odpowiada** wartości 00, 01, 10 lub 11, więc użyje różnych **odcieni szarości** do reprezentacji każdego z nich (a po skopiowaniu bitów użyje **liczb od 0 do 3**, które trzeba będzie odpowiednio przetworzyć).

W przypadku kodowania liniowego, takiego jak **Manchester**, przekształć każdą poprawną parę przejść (`01` lub `10`) w bit danych zgodnie z konwencją używaną przez protokół.

## Przykład FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Ustalanie FM

#### Sprawdzanie częstotliwości i przebiegu

Przykład sygnału przesyłającego informacje z modulacją FM:

![Ustalanie FM - Sprawdzanie częstotliwości i przebiegu: przykład sygnału przesyłającego informacje z modulacją FM](<../../images/image (725).png>)

Widmo wyraźnie pokazuje **dwie częstotliwości**, choć ich rozróżnienie w przebiegu czasowym może być trudne:

![Przebieg sygnału FM w SigDigger, na którym trudno bezpośrednio rozróżnić dwie częstotliwości](<../../images/image (717).png>)

Dzieje się tak, ponieważ środek przechwyconego sygnału znajduje się między obiema częstotliwościami, więc ich przesunięcia częstotliwości mają w przybliżeniu przeciwne wartości:

![Przechwycony sygnał FM w SigDigger pokazujący dwie częstotliwości o przesunięciach będących w przybliżeniu swoimi przeciwieństwami](<../../images/image (942).png>)

Jeśli dostrojona częstotliwość znajduje się **bliżej jednej częstotliwości niż drugiej**, łatwo zauważysz 2 różne częstotliwości:

![Ustalanie FM - Sprawdzanie częstotliwości i przebiegu: jeśli dostrojona częstotliwość znajduje się bliżej jednej częstotliwości niż drugiej, łatwo zauważysz dwie różne częstotliwości](<../../images/image (422).png>)

![Ustalanie FM - Sprawdzanie częstotliwości i przebiegu: jeśli dostrojona częstotliwość znajduje się bliżej jednej częstotliwości niż drugiej, łatwo zauważysz dwie różne częstotliwości](<../../images/image (488).png>)

#### Sprawdzanie histogramu

Sprawdzając histogram częstotliwości sygnału zawierającego informacje, łatwo zauważysz 2 różne sygnały:

![Sprawdzanie częstotliwości i przebiegu - Sprawdzanie histogramu: histogram częstotliwości sygnału zawierającego informacje wyraźnie pokazuje dwa różne sygnały](<../../images/image (871).png>)

Jeśli w tym przypadku sprawdzisz **histogram amplitudy**, znajdziesz **tylko jedną amplitudę**, a więc sygnał **nie może być AM** (wiele amplitud może wynikać z utraty mocy sygnału w kanale):

![Histogram amplitudy sygnału FM w SigDigger pokazujący jeden poziom amplitudy](<../../images/image (817).png>)

Poniżej znajduje się histogram fazy, który wyraźnie pokazuje, że sygnał nie jest modulowany fazowo:

![Sprawdzanie częstotliwości i przebiegu - Sprawdzanie histogramu: histogram fazy wyraźnie pokazujący, że sygnał nie jest modulowany fazowo](<../../images/image (996).png>)

#### Wykres IQ

Wykres IQ nie zawiera pola pokazującego częstotliwość (odległość od środka oznacza amplitudę, a kąt — fazę).\
Dlatego aby wykryć FM, na wykresie powinien być widoczny **w zasadzie tylko okrąg**.\
Ponadto przesunięcie częstotliwości zmienia szybkość obrotu wokół okręgu IQ. W SigDigger zmiana szybkości lub kierunku obrotu może więc wskazywać na FM:

![Wykres IQ w SigDigger, na którym FM objawia się zmianami szybkości obrotu wokół okręgu](<../../images/image (81).png>)

### Ustalanie szybkości symboli

Po znalezieniu częstotliwości przenoszących symbole możesz użyć **tej samej techniki co w przykładzie AM**, aby ustalić szybkość symboli.

### Odczytywanie bitów

Po **ustaleniu, że sygnał jest modulowany częstotliwościowo**, oraz określeniu **szybkości symboli**, możesz użyć **tej samej techniki co w przykładzie AM**, aby odczytać bity.

## References

- [1] [SigDigger - Bezpłatny analizator sygnałów cyfrowych dla GNU/Linux i macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
