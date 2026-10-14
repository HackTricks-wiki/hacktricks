# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) to darmowy analizator sygnałów cyfrowych dla GNU/Linux i macOS, zaprojektowany do wydobywania informacji z nieznanych sygnałów radiowych. Obsługuje urządzenia SDR za pośrednictwem SoapySDR i udostępnia narzędzia do demodulacji oraz analizy w czasie rzeczywistym dla FSK, PSK, ASK, analogowego wideo, sygnałów impulsowych i analogowych kanałów głosowych.<sup>[[1]](#references)</sup>

### Podstawowa konfiguracja

Po instalacji warto rozważyć skonfigurowanie kilku rzeczy.\
W ustawieniach (przycisk drugiej karty) wybierz **urządzenie SDR** lub plik wejściowy, częstotliwość strojenia i częstotliwość próbkowania. Częstotliwość do 2.56 Msps może być praktyczna, jeśli obsługuje ją komputer.

![Ustawienia SigDigger pokazujące opcje urządzenia SDR, pliku wejściowego, częstotliwości i częstotliwości próbkowania](<../../images/image (245).png>)

W ustawieniach zachowania GUI zaleca się włączenie kilku opcji, jeśli obsługuje je Twój komputer:

![SigDigger - Podstawowa konfiguracja: W ustawieniach zachowania GUI zaleca się włączenie kilku opcji, jeśli obsługuje je Twój komputer](<../../images/image (472).png>)

> [!TIP]
> Jeśli zauważysz, że komputer nie przechwytuje danych, spróbuj wyłączyć OpenGL i obniżyć częstotliwość próbkowania.

### Zastosowania

- Aby **przechwycić fragment sygnału i go przeanalizować**, przytrzymaj przycisk "Push to capture" tak długo, jak potrzebujesz.

![Podstawowa konfiguracja - Zastosowania: Aby przechwycić fragment sygnału i go przeanalizować, przytrzymaj przycisk "Push to capture" tak długo, jak potrzebujesz](<../../images/image (960).png>)

- **Tuner** SigDigger pomaga **lepiej przechwytywać sygnały** (ale może też pogorszyć ich jakość). Najlepiej zacząć od 0 i **zwiększać wartość, aż** wprowadzony **szum** będzie **większy** niż potrzebna **poprawa sygnału**.

![Regulacja tunera SigDigger w celu poprawienia przechwytywanego sygnału radiowego](<../../images/image (1099).png>)

### Synchronizacja z kanałem radiowym

W [**SigDigger** ](https://github.com/BatchDrake/SigDigger)synchronizuj się z kanałem, którego chcesz słuchać, skonfiguruj opcję "Baseband audio preview", ustaw szerokość pasma tak, aby uzyskać wszystkie przesyłane informacje, a następnie ustaw Tuner na poziom, przy którym szum zaczyna wyraźnie narastać:<sup>[[1]](#references)</sup>

![Kanał radiowy zsynchronizowany w SigDigger z włączonym podglądem audio pasma podstawowego i skonfigurowaną szerokością pasma](<../../images/image (585).png>)

## Przydatne wskazówki

- Gdy urządzenie wysyła serie danych, **pierwsza część to zwykle preambuła**, więc **nie musisz się martwić**, jeśli **nie znajdziesz tam informacji** lub **występują tam błędy**.
- W ramkach danych zwykle można **znaleźć różne ramki, dobrze wyrównane względem siebie**:

![Synchronizacja z kanałem radiowym - Przydatne wskazówki: W ramkach danych zwykle można znaleźć różne ramki, dobrze wyrównane względem siebie](<../../images/image (1076).png>)

![Synchronizacja z kanałem radiowym - Przydatne wskazówki: W ramkach danych zwykle można znaleźć różne ramki, dobrze wyrównane względem siebie](<../../images/image (597).png>)

- **Po odzyskaniu przejść między poziomami może być konieczne ich zdekodowanie.** W kodowaniu Manchester jedno kierunkowe przejście oznacza `0`, a przejście w przeciwnym kierunku — `1`; dokładna polaryzacja zależy od użytej konwencji.
- Preambuła może zawierać ciąg próbek o tym samym poziomie, nawet jeśli payload jest kodowany Manchesterem, dlatego przed dekodowaniem określ granicę ramki.

### Ustalanie rodzaju modulacji na podstawie IQ

Informacje w sygnałach można przechowywać na 3 sposoby: modulując **amplitudę**, **częstotliwość** lub **fazę**.\
Analizując sygnał, można na różne sposoby ustalić, która metoda przechowywania informacji jest używana (więcej sposobów poniżej), ale dobrym rozwiązaniem jest sprawdzenie wykresu IQ.

![Wykres IQ SigDigger używany do ustalenia, czy sygnał wykorzystuje modulację amplitudy, częstotliwości czy fazy](<../../images/image (788).png>)

- **Wykrywanie AM**: Jeśli na wykresie IQ widać na przykład **2 okręgi** (prawdopodobnie jeden w punkcie 0, a drugi przy innej amplitudzie), może to oznaczać, że jest to sygnał AM. Na wykresie IQ odległość między punktem 0 a okręgiem odpowiada amplitudzie sygnału, więc łatwo zobaczyć, czy używane są różne amplitudy.
- **Wykrywanie PM**: Podobnie jak na poprzednim obrazie, jeśli widzisz małe, niezwiązane ze sobą okręgi, prawdopodobnie używana jest modulacja fazy. Na wykresie IQ kąt między punktem a punktem 0,0 odpowiada fazie sygnału, co oznacza, że używane są 4 różne fazy.
  - Pamiętaj, że jeśli informacja jest zakodowana w zmianie fazy, a nie w samej fazie, różne fazy nie będą wyraźnie rozróżnialne.
- **Wykrywanie FM**: Wykres IQ nie ma pola pokazującego częstotliwości (odległość od środka oznacza amplitudę, a kąt — fazę).\
  Dlatego przy identyfikacji FM na wykresie powinien być widoczny **zasadniczo tylko okrąg**.\
  Ponadto przesunięcie częstotliwości zmienia szybkość obrotu wokół okręgu IQ. W SigDigger zmiana prędkości lub kierunku obrotu może więc wskazywać na FM.

## Przykład AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Ustalanie AM

#### Sprawdzanie obwiedni

Podczas analizowania danych AM w [**SigDigger**](https://github.com/BatchDrake/SigDigger) obwiednia sygnału może ujawnić wyraźne poziomy amplitudy. Przykładowy sygnał przesyła informacje jako impulsy z modulacją amplitudy; jeden z impulsów wygląda tak:<sup>[[1]](#references)</sup>

![Obwiednia sygnału AM w SigDigger z wyraźnymi poziomami amplitudy impulsu](<../../images/image (590).png>)

Tak wygląda fragment symbolu na przebiegu:

![Ustalanie AM - Sprawdzanie obwiedni: Tak wygląda fragment symbolu na przebiegu](<../../images/image (734).png>)

#### Sprawdzanie histogramu

Możesz **zaznaczyć cały obszar sygnału** zawierający informacje, wybrać tryb **Amplitude** i **Selection**, a następnie kliknąć **Histogram**. Zobaczysz tylko 2 wyraźne poziomy.

![Histogram amplitudy SigDigger pokazujący dwa wyraźne poziomy dla zaznaczonego sygnału AM](<../../images/image (264).png>)

Jeśli w tym sygnale AM wybierzesz Frequency zamiast Amplitude, znajdziesz tylko 1 częstotliwość (informacje modulowane częstotliwością nie mogą być przesyłane przy użyciu tylko jednej częstotliwości).

![Histogram częstotliwości SigDigger dla sygnału AM pokazujący jedną częstotliwość](<../../images/image (732).png>)

Jeśli znajdziesz wiele częstotliwości, sygnał prawdopodobnie nie jest FM — jego częstotliwość mogła się zmieniać z powodu kanału.

#### Wykres IQ

W tym przykładzie widać **duży okrąg**, ale również **wiele punktów w środku**.

![Sprawdzanie histogramu - Wykres IQ: W tym przykładzie widać duży okrąg, ale również wiele punktów w środku](<../../images/image (222).png>)

### Ustalanie szybkości symboli

#### Dla jednego symbolu

Wybierz najmniejszy przedział, który wyraźnie zawiera jeden symbol, i sprawdź **Selection freq**. W tym przykładzie wynosi ona 1.013 kHz, czyli około 1 kHz.

![Ustalanie szybkości symboli - Dla jednego symbolu: Wybierz najmniejszy możliwy przedział zawierający jeden symbol (aby mieć pewność, że to tylko jeden) i sprawdź "Selection freq". W tym przypadku wynosi ona 1.013 kHz (czyli 1 kHz).](<../../images/image (78).png>)

#### Dla grupy symboli

Możesz też podać liczbę symboli, które zamierzasz zaznaczyć, a SigDigger obliczy częstotliwość jednego symbolu (zaznaczenie większej liczby symboli prawdopodobnie da dokładniejszy wynik). W tym przykładzie zaznaczyłem 10 symboli, a wartość "Selection freq" wynosi 1.004 kHz:

![Obliczanie szybkości symboli w SigDigger na podstawie zaznaczonej grupy dziesięciu symboli](<../../images/image (1008).png>)

### Uzyskiwanie bitów

Po rozpoznaniu AM i oszacowaniu **szybkości symboli** zaznacz obszar sygnału, skonfiguruj próbkowanie amplitudy i poziomy decyzyjne, wybierz **Gardner clock recovery**, a następnie kliknij **Sample**:

![Panel Get Bits w SigDigger skonfigurowany do próbkowania AM, z ustawioną szybkością symboli i odzyskiwaniem zegara Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** oznacza, że jeśli wcześniej zaznaczono przedziały w celu ustalenia szybkości symboli, zostanie użyta ta wartość.
- **Manual** oznacza, że zostanie użyta podana szybkość symboli.
- W opcji **Fixed interval selection** podajesz liczbę przedziałów do zaznaczenia, a program oblicza na tej podstawie szybkość symboli.
- **Gardner clock recovery** to przydatne ustawienie domyślne, ale nadal wymaga przybliżonej szybkości symboli.

Po kliknięciu Sample pojawi się ten widok:

![Dla grupy symboli - Uzyskiwanie bitów: Tak wygląda widok po kliknięciu Sample](<../../images/image (644).png>)

Aby SigDigger rozpoznał **zakres poziomów** przenoszących informacje, kliknij **niższy poziom** i przytrzymaj przycisk myszy aż do najwyższego poziomu:

![Wybór zakresu poziomów w SigDigger od niższego poziomu amplitudy do wyższego](<../../images/image (439).png>)

Jeśli na przykład występowałyby **4 różne poziomy amplitudy**, należałoby ustawić **Bits per symbol** na 2 i zaznaczyć zakres od najniższego do najwyższego poziomu.

Na koniec, **zwiększając** **Zoom** i **zmieniając Row size**, możesz zobaczyć bity (możesz zaznaczyć wszystkie i skopiować, aby uzyskać pełny ciąg bitów):

![Dla grupy symboli - Uzyskiwanie bitów: Na koniec, zwiększając Zoom i zmieniając Row size, możesz zobaczyć bity (możesz zaznaczyć wszystkie i skopiować, aby uzyskać pełny ciąg bitów)](<../../images/image (276).png>)

Jeśli sygnał ma więcej niż 1 bit na symbol (na przykład 2), SigDigger **nie wie, który symbol to** 00, 01, 10 lub 11, dlatego każdemu z nich przypisze inną **skalę szarości** (a po skopiowaniu bitów użyje **liczb od 0 do 3**, które trzeba będzie odpowiednio przetworzyć).

W przypadku kodowania liniowego, takiego jak **Manchester**, przekształć każdą prawidłową parę przejść (`01` lub `10`) w bit danych zgodnie z konwencją używaną przez protokół.

## Przykład FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Ustalanie FM

#### Sprawdzanie częstotliwości i przebiegu

Przykładowy sygnał przesyłający informacje z modulacją FM:

![Ustalanie FM - Sprawdzanie częstotliwości i przebiegu: Przykładowy sygnał przesyłający informacje z modulacją FM](<../../images/image (725).png>)

Widmo wyraźnie pokazuje **dwie częstotliwości**, choć mogą być trudne do rozróżnienia na przebiegu w dziedzinie czasu:

![Przebieg FM w SigDigger, na którym trudno bezpośrednio rozróżnić dwie częstotliwości](<../../images/image (717).png>)

Dzieje się tak, ponieważ przechwytywanie jest wyśrodkowane między obiema częstotliwościami, więc ich przesunięcia częstotliwości są w przybliżeniu przeciwne:

![Przechwytywanie FM w SigDigger pokazujące dwie częstotliwości jako w przybliżeniu przeciwne wartości](<../../images/image (942).png>)

Jeśli dostrojona częstotliwość jest **bliższa jednej częstotliwości niż drugiej**, możesz łatwo zobaczyć 2 różne częstotliwości:

![Ustalanie FM - Sprawdzanie częstotliwości i przebiegu: Jeśli dostrojona częstotliwość jest bliższa jednej częstotliwości niż drugiej, możesz łatwo zobaczyć 2 różne częstotliwości](<../../images/image (422).png>)

![Ustalanie FM - Sprawdzanie częstotliwości i przebiegu: Jeśli dostrojona częstotliwość jest bliższa jednej częstotliwości niż drugiej, możesz łatwo zobaczyć 2 różne częstotliwości](<../../images/image (488).png>)

#### Sprawdzanie histogramu

Na histogramie częstotliwości sygnału zawierającego informacje łatwo zobaczyć 2 różne sygnały:

![Sprawdzanie częstotliwości i przebiegu - Sprawdzanie histogramu: Na histogramie częstotliwości sygnału zawierającego informacje łatwo zobaczyć 2 różne sygnały](<../../images/image (871).png>)

Jeśli w tym przypadku sprawdzisz **histogram amplitudy**, znajdziesz **tylko jedną amplitudę**, więc sygnał **nie może być AM** (jeśli znajdziesz wiele amplitud, może to wynikać z utraty mocy sygnału podczas transmisji przez kanał):

![Histogram amplitudy sygnału FM w SigDigger pokazujący jeden poziom amplitudy](<../../images/image (817).png>)

Tak wygląda histogram fazy (wyraźnie pokazuje, że sygnał nie jest modulowany fazowo):

![Sprawdzanie częstotliwości i przebiegu - Sprawdzanie histogramu: Tak wygląda histogram fazy (wyraźnie pokazuje, że sygnał nie jest modulowany fazowo)](<../../images/image (996).png>)

#### Wykres IQ

Wykres IQ nie ma pola pokazującego częstotliwości (odległość od środka oznacza amplitudę, a kąt — fazę).\
Dlatego przy identyfikacji FM na wykresie powinien być widoczny **zasadniczo tylko okrąg**.\
Ponadto przesunięcie częstotliwości zmienia szybkość obrotu wokół okręgu IQ. W SigDigger zmiana prędkości lub kierunku obrotu może więc wskazywać na FM:

![Wykres IQ SigDigger, na którym FM jest widoczna jako zmiany prędkości obrotu wokół okręgu](<../../images/image (81).png>)

### Ustalanie szybkości symboli

Po znalezieniu częstotliwości niosących symbole możesz zastosować **tę samą technikę co w przykładzie AM**, aby ustalić szybkość symboli.

### Uzyskiwanie bitów

Po ustaleniu, że **sygnał jest modulowany częstotliwością**, i określeniu **szybkości symboli**, możesz zastosować **tę samą technikę co w przykładzie AM**, aby uzyskać bity.

## References

- [1] [SigDigger - Darmowy analizator sygnałów cyfrowych dla GNU/Linux i macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
