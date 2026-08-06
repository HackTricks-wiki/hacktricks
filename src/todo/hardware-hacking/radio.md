# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)to darmowy analizator sygnałów cyfrowych dla GNU/Linux i macOS, przeznaczony do wydobywania informacji z nieznanych sygnałów radiowych. Obsługuje różne urządzenia SDR za pośrednictwem SoapySDR i umożliwia regulowaną demodulację sygnałów FSK, PSK i ASK, dekodowanie analogowego wideo, analizowanie sygnałów burstowych oraz słuchanie analogowych kanałów głosowych (wszystko w czasie rzeczywistym).<sup>[[1]](#references)</sup>

### Basic Config

Po instalacji warto rozważyć skonfigurowanie kilku rzeczy.\
W ustawieniach (drugi przycisk zakładki) możesz wybrać **urządzenie SDR** lub **wybrać plik** do odczytu, a także częstotliwość do dostrojenia i częstotliwość próbkowania (zalecane maksymalnie 2.56Msps, jeśli komputer to obsługuje).

![Ustawienia SigDigger pokazujące opcje urządzenia SDR, pliku wejściowego, częstotliwości i częstotliwości próbkowania](<../../images/image (245).png>)

W sekcji GUI behaviour zaleca się włączenie kilku opcji, jeśli komputer je obsługuje:

![SigDigger - Basic Config: W sekcji GUI behaviour zaleca się włączenie kilku opcji, jeśli komputer je obsługuje](<../../images/image (472).png>)

> [!TIP]
> Jeśli zauważysz, że komputer niczego nie przechwytuje, spróbuj wyłączyć OpenGL i zmniejszyć częstotliwość próbkowania.

### Uses

- Aby **przechwycić fragment sygnału i go przeanalizować**, przytrzymuj przycisk "Push to capture" tak długo, jak potrzebujesz.

![Basic Config - Uses: Aby przechwycić fragment sygnału i go przeanalizować, przytrzymuj przycisk "Push to capture" tak długo, jak potrzebujesz](<../../images/image (960).png>)

- **Tuner** w SigDigger pomaga **lepiej przechwytywać sygnały** (ale może je również pogorszyć). Najlepiej zacząć od 0 i **zwiększać wartość, aż** wprowadzany **szum** stanie się **większy niż poprawa sygnału**, której potrzebujesz.

![Element sterujący tunerem SigDigger ustawiony w celu poprawy przechwyconego sygnału radiowego](<../../images/image (1099).png>)

### Synchronize with radio channel

W [**SigDigger** ](https://github.com/BatchDrake/SigDigger)zsynchronizuj się z kanałem, którego chcesz słuchać, skonfiguruj opcję "Baseband audio preview", ustaw szerokość pasma tak, aby uzyskać wszystkie przesyłane informacje, a następnie ustaw Tuner na poziomie tuż przed rozpoczęciem wyraźnego wzrostu szumu:<sup>[[1]](#references)</sup>

![SigDigger zsynchronizowany z kanałem radiowym, z podglądem dźwięku baseband i skonfigurowaną szerokością pasma](<../../images/image (585).png>)

## Interesting tricks

- Gdy urządzenie wysyła bursty informacji, zwykle **pierwsza część będzie preambułą**, więc **nie musisz się martwić**, jeśli **nie znajdziesz tam informacji** lub **wystąpią tam błędy**.
- W ramkach informacji zwykle należy **znaleźć różne ramki odpowiednio wyrównane względem siebie**:

![Synchronize with radio channel - Interesting tricks: W ramkach informacji zwykle należy znaleźć różne ramki odpowiednio wyrównane względem siebie](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: W ramkach informacji zwykle należy znaleźć różne ramki odpowiednio wyrównane względem siebie](<../../images/image (597).png>)

- **Po odzyskaniu bitów może być konieczne ich przetworzenie**. Na przykład w kodowaniu Manchester przejście góra+dół będzie oznaczać 1 lub 0, a dół+góra będzie oznaczać drugą wartość. Zatem pary 1 i 0 (gór i dołów) będą odpowiadać rzeczywistym 1 lub 0.
- Nawet jeśli sygnał używa kodowania Manchester (niemożliwe jest znalezienie więcej niż dwóch kolejnych 0 lub 1), możesz **znaleźć kilka 1 lub 0 obok siebie w preambule**!

### Uncovering modulation type with IQ

Istnieją 3 sposoby przechowywania informacji w sygnałach: modulowanie **amplitudy**, **częstotliwości** lub **fazy**.\
Jeśli analizujesz sygnał, możesz na różne sposoby spróbować ustalić, co jest używane do przechowywania informacji (więcej sposobów poniżej), ale dobrym rozwiązaniem jest sprawdzenie wykresu IQ.

![Wykres IQ SigDigger używany do określenia, czy sygnał wykorzystuje modulację amplitudy, częstotliwości czy fazy](<../../images/image (788).png>)

- **Wykrywanie AM**: Jeśli na wykresie IQ pojawiają się na przykład **2 okręgi** (prawdopodobnie jeden w punkcie 0, a drugi przy innej amplitudzie), może to oznaczać, że jest to sygnał AM. Dzieje się tak, ponieważ na wykresie IQ odległość między punktem 0 a okręgiem oznacza amplitudę sygnału, więc łatwo zobrazować użycie różnych amplitud.
- **Wykrywanie PM**: Podobnie jak na poprzednim obrazie, jeśli znajdziesz małe, niezależne od siebie okręgi, prawdopodobnie oznacza to użycie modulacji fazy. Dzieje się tak, ponieważ na wykresie IQ kąt między punktem a punktem 0,0 oznacza fazę sygnału, co wskazuje na użycie 4 różnych faz.
- Pamiętaj, że jeśli informacja jest ukryta w zmianie fazy, a nie w samej fazie, nie zobaczysz wyraźnie rozdzielonych różnych faz.
- **Wykrywanie FM**: IQ nie ma pola służącego do identyfikacji częstotliwości (odległość od środka oznacza amplitudę, a kąt fazę).\
Dlatego, aby zidentyfikować FM, na tym wykresie powinieneś **widzieć zasadniczo tylko okrąg**.\
Ponadto inna częstotliwość jest "reprezentowana" na wykresie IQ przez **przyspieszenie prędkości wzdłuż okręgu** (gdy w SysDigger wybierzesz sygnał, wykres IQ zostanie wypełniony; jeśli zauważysz przyspieszenie lub zmianę kierunku na utworzonym okręgu, może to oznaczać FM):

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

Sprawdzając informacje AM za pomocą [**SigDigger** ](https://github.com/BatchDrake/SigDigger)i patrząc tylko na **obwiednię**, możesz zobaczyć różne wyraźne poziomy amplitudy. Użyty sygnał wysyła impulsy zawierające informacje w AM; tak wygląda jeden impuls:<sup>[[1]](#references)</sup>

![Obwiednia sygnału AM w SigDigger z wyraźnymi poziomami amplitudy impulsu](<../../images/image (590).png>)

Tak wygląda część symbolu wraz z przebiegiem:

![Uncovering AM - Checking the envelope: Tak wygląda część symbolu wraz z przebiegiem](<../../images/image (734).png>)

#### Checking the Histogram

Możesz **zaznaczyć cały sygnał** zawierający informacje, wybrać tryb **Amplitude** oraz **Selection**, a następnie kliknąć **Histogram.** Możesz zaobserwować, że występują tylko 2 wyraźne poziomy.

![Histogram amplitudy SigDigger pokazujący dwa wyraźne poziomy dla wybranego sygnału AM](<../../images/image (264).png>)

Na przykład, jeśli w tym sygnale AM wybierzesz Frequency zamiast Amplitude, znajdziesz tylko 1 częstotliwość (informacja modulowana częstotliwościowo nie może wykorzystywać tylko 1 częstotliwości).

![Histogram częstotliwości SigDigger dla sygnału AM pokazujący jedną częstotliwość](<../../images/image (732).png>)

Jeśli znajdziesz wiele częstotliwości, prawdopodobnie nie będzie to FM; częstotliwość sygnału mogła zostać zmodyfikowana przez kanał.

#### With IQ

W tym przykładzie widać **duży okrąg**, ale także **wiele punktów w centrum**.

![Checking the Histogram - With IQ: W tym przykładzie widać duży okrąg, ale także wiele punktów w centrum](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

Wybierz najmniejszy znaleziony symbol (aby mieć pewność, że jest to tylko 1) i sprawdź "Selection freq". W tym przypadku będzie to 1.013kHz (czyli 1kHz).

![Get Symbol Rate - With one symbol: Wybierz najmniejszy znaleziony symbol (aby mieć pewność, że jest to tylko 1) i sprawdź "Selection freq". W tym przypadku będzie to 1.013kHz (czyli 1kHz)](<../../images/image (78).png>)

#### With a group of symbols

Możesz również wskazać liczbę symboli, które zamierzasz zaznaczyć, a SigDigger obliczy częstotliwość 1 symbolu (prawdopodobnie im więcej zaznaczonych symboli, tym lepiej). W tym przypadku zaznaczyłem 10 symboli, a "Selection freq" wynosi 1.004 Khz:

![Obliczanie symbol rate w SigDigger z użyciem wybranej grupy dziesięciu symboli](<../../images/image (1008).png>)

### Get Bits

Po ustaleniu, że jest to sygnał **modulowany AM**, oraz poznaniu **symbol rate** (i wiedząc, że w tym przypadku wartość górna oznacza 1, a dolna 0), bardzo łatwo **uzyskać bity** zakodowane w sygnale. Zaznacz więc sygnał zawierający informacje, skonfiguruj próbkowanie i decyzję, a następnie naciśnij sample (sprawdź, czy wybrano **Amplitude**, skonfigurowano wykryty **Symbol rate** oraz wybrano **Gadner clock recovery**):

![Panel Get Bits SigDigger skonfigurowany do próbkowania AM, symbol rate i odzyskiwania zegara Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** oznacza, że jeśli wcześniej wybrano przedziały w celu znalezienia symbol rate, zostanie on użyty.
- **Manual** oznacza, że zostanie użyty wskazany symbol rate.
- W **Fixed interval selection** wskazujesz liczbę przedziałów, które powinny zostać zaznaczone, a program oblicza na tej podstawie symbol rate.
- **Gadner clock recovery** jest zwykle najlepszą opcją, ale nadal trzeba podać przybliżony symbol rate.

Po naciśnięciu sample pojawi się następujący widok:

![With a group of symbols - Get Bits: Po naciśnięciu sample pojawi się następujący widok](<../../images/image (644).png>)

Aby SigDigger zrozumiał, **jaki jest zakres** poziomu niosącego informacje, musisz kliknąć **niższy poziom** i przytrzymać przycisk myszy aż do najwyższego poziomu:

![Wybór zakresu poziomów SigDigger od niższego poziomu amplitudy do wyższego](<../../images/image (439).png>)

Gdyby na przykład występowały **4 różne poziomy amplitudy**, należałoby skonfigurować **Bits per symbol na 2** i zaznaczyć zakres od najmniejszego do największego poziomu.

Na koniec, **zwiększając** **Zoom** i **zmieniając Row size**, możesz zobaczyć bity (możesz zaznaczyć je wszystkie i skopiować, aby uzyskać cały ciąg bitów):

![With a group of symbols - Get Bits: Na koniec, zwiększając Zoom i zmieniając Row size, możesz zobaczyć bity (możesz zaznaczyć je wszystkie i skopiować, aby uzyskać cały ciąg bitów)](<../../images/image (276).png>)

Jeśli sygnał ma więcej niż 1 bit na symbol (na przykład 2), SigDigger **nie ma sposobu, aby wiedzieć, który symbol oznacza** 00, 01, 10 lub 11, więc użyje różnych **odcieni szarości** do przedstawienia każdego z nich (a przy kopiowaniu bitów użyje **liczb od 0 do 3**, które trzeba będzie odpowiednio przetworzyć).

Używaj również **kodowań**, takich jak **Manchester**, gdzie **góra+dół** może oznaczać **1 lub 0**, a dół+góra może oznaczać 1 lub 0. W takich przypadkach trzeba **przetworzyć uzyskane góry (1) i doły (0)**, zastępując pary 01 lub 10 wartościami 0 lub 1.

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

Przykład sygnału wysyłającego informacje modulowane w FM:

![Uncovering FM - Checking the frequencies and waveform: Przykład sygnału wysyłającego informacje modulowane w FM](<../../images/image (725).png>)

Na poprzednim obrazie można dość dobrze zaobserwować, że używane są **2 częstotliwości**, ale jeśli **obserwujesz** **przebieg**, możesz **nie być w stanie poprawnie rozpoznać 2 różnych częstotliwości**:

![Przebieg FM SigDigger, na którym trudno bezpośrednio rozróżnić dwie częstotliwości](<../../images/image (717).png>)

Dzieje się tak, ponieważ przechwyciłem sygnał na obu częstotliwościach, dlatego jedna jest w przybliżeniu ujemną wersją drugiej:

![Przechwycenie FM SigDigger pokazujące dwie częstotliwości jako przybliżone wartości przeciwne](<../../images/image (942).png>)

Jeśli dostrojona częstotliwość jest **bliższa jednej częstotliwości niż drugiej**, możesz łatwo zobaczyć 2 różne częstotliwości:

![Uncovering FM - Checking the frequencies and waveform: Jeśli dostrojona częstotliwość jest bliższa jednej częstotliwości niż drugiej, możesz łatwo zobaczyć 2 różne częstotliwości](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform: Jeśli dostrojona częstotliwość jest bliższa jednej częstotliwości niż drugiej, możesz łatwo zobaczyć 2 różne częstotliwości](<../../images/image (488).png>)

#### Checking the histogram

Sprawdzając histogram częstotliwości sygnału zawierającego informacje, możesz łatwo zobaczyć 2 różne sygnały:

![Checking the frequencies and waveform - Checking the histogram: Sprawdzając histogram częstotliwości sygnału zawierającego informacje, możesz łatwo zobaczyć 2 różne sygnały](<../../images/image (871).png>)

W tym przypadku, jeśli sprawdzisz **histogram amplitudy**, znajdziesz **tylko jedną amplitudę**, więc sygnał **nie może być AM** (jeśli znajdziesz wiele amplitud, może to wynikać z utraty mocy sygnału w kanale):

![Histogram amplitudy SigDigger dla sygnału FM pokazujący pojedynczy poziom amplitudy](<../../images/image (817).png>)

A to jest histogram fazy (który bardzo wyraźnie pokazuje, że sygnał nie jest modulowany fazowo):

![Checking the frequencies and waveform - Checking the histogram: Histogram fazy, który bardzo wyraźnie pokazuje, że sygnał nie jest modulowany fazowo](<../../images/image (996).png>)

#### With IQ

IQ nie ma pola służącego do identyfikacji częstotliwości (odległość od środka oznacza amplitudę, a kąt fazę).\
Dlatego, aby zidentyfikować FM, na tym wykresie powinieneś **widzieć zasadniczo tylko okrąg**.\
Ponadto inna częstotliwość jest "reprezentowana" na wykresie IQ przez **przyspieszenie prędkości wzdłuż okręgu** (gdy w SysDigger wybierzesz sygnał, wykres IQ zostanie wypełniony; jeśli zauważysz przyspieszenie lub zmianę kierunku na utworzonym okręgu, może to oznaczać FM):

![Wykres IQ SigDigger, na którym FM pojawia się jako zmiany przyspieszenia wokół okręgu](<../../images/image (81).png>)

### Get Symbol Rate

Możesz użyć **tej samej techniki co w przykładzie AM**, aby uzyskać symbol rate po znalezieniu częstotliwości przenoszących symbole.

### Get Bits

Możesz użyć **tej samej techniki co w przykładzie AM**, aby uzyskać bity po **ustaleniu, że sygnał jest modulowany częstotliwościowo** i poznaniu **symbol rate**.

## References

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
