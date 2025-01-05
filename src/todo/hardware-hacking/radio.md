# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)to darmowy analizator sygnałów cyfrowych dla GNU/Linux i macOS, zaprojektowany do wydobywania informacji z nieznanych sygnałów radiowych. Obsługuje różnorodne urządzenia SDR przez SoapySDR i pozwala na regulowaną demodulację sygnałów FSK, PSK i ASK, dekodowanie wideo analogowego, analizowanie sygnałów burstowych oraz słuchanie analogowych kanałów głosowych (wszystko w czasie rzeczywistym).

### Podstawowa konfiguracja

Po zainstalowaniu jest kilka rzeczy, które warto skonfigurować.\
W ustawieniach (drugi przycisk zakładki) możesz wybrać **urządzenie SDR** lub **wybrać plik** do odczytu oraz częstotliwość do syntonizacji i częstotliwość próbkowania (zalecane do 2,56 Msps, jeśli twój komputer to obsługuje)\\

![](<../../images/image (245).png>)

W zachowaniu GUI zaleca się włączenie kilku opcji, jeśli twój komputer to obsługuje:

![](<../../images/image (472).png>)

> [!NOTE]
> Jeśli zauważysz, że twój komputer nie rejestruje sygnałów, spróbuj wyłączyć OpenGL i obniżyć częstotliwość próbkowania.

### Zastosowania

- Aby **zarejestrować część sygnału i go przeanalizować**, przytrzymaj przycisk "Push to capture" tak długo, jak potrzebujesz.

![](<../../images/image (960).png>)

- **Tuner** w SigDigger pomaga w **lepszym przechwytywaniu sygnałów** (ale może je również pogorszyć). Idealnie zacznij od 0 i **zwiększaj**, aż znajdziesz, że **szum** wprowadzony jest **większy** niż **poprawa sygnału**, której potrzebujesz.

![](<../../images/image (1099).png>)

### Synchronizacja z kanałem radiowym

Z [**SigDigger** ](https://github.com/BatchDrake/SigDigger)zsynchronizuj się z kanałem, który chcesz słyszeć, skonfiguruj opcję "Podgląd audio w paśmie podstawowym", skonfiguruj szerokość pasma, aby uzyskać wszystkie przesyłane informacje, a następnie ustaw Tuner na poziom przed rozpoczęciem rzeczywistego wzrostu szumu:

![](<../../images/image (585).png>)

## Ciekawe triki

- Gdy urządzenie wysyła serie informacji, zazwyczaj **pierwsza część to będzie preambuła**, więc **nie musisz** się **martwić**, jeśli **nie znajdziesz informacji** w niej **lub jeśli są tam jakieś błędy**.
- W ramach informacji zazwyczaj powinieneś **znaleźć różne ramki dobrze wyrównane między sobą**:

![](<../../images/image (1076).png>)

![](<../../images/image (597).png>)

- **Po odzyskaniu bitów możesz potrzebować je jakoś przetworzyć**. Na przykład, w kodowaniu Manchester, up+down będzie 1 lub 0, a down+up będzie drugim. Tak więc pary 1s i 0s (up i down) będą prawdziwym 1 lub prawdziwym 0.
- Nawet jeśli sygnał używa kodowania Manchester (niemożliwe jest znalezienie więcej niż dwóch 0s lub 1s z rzędu), możesz **znaleźć kilka 1s lub 0s razem w preambule**!

### Odkrywanie typu modulacji z IQ

Istnieją 3 sposoby przechowywania informacji w sygnałach: modulacja **amplitudy**, **częstotliwości** lub **fazy**.\
Jeśli sprawdzasz sygnał, istnieją różne sposoby, aby spróbować ustalić, co jest używane do przechowywania informacji (więcej sposobów poniżej), ale dobrym sposobem jest sprawdzenie wykresu IQ.

![](<../../images/image (788).png>)

- **Wykrywanie AM**: Jeśli na wykresie IQ pojawiają się na przykład **2 okręgi** (prawdopodobnie jeden w 0, a drugi w innej amplitudzie), może to oznaczać, że jest to sygnał AM. Dzieje się tak, ponieważ na wykresie IQ odległość między 0 a okręgiem to amplituda sygnału, więc łatwo jest wizualizować różne amplitudy.
- **Wykrywanie PM**: Jak na poprzednim obrazie, jeśli znajdziesz małe okręgi, które nie są ze sobą powiązane, prawdopodobnie oznacza to, że używana jest modulacja fazy. Dzieje się tak, ponieważ na wykresie IQ kąt między punktem a 0,0 to faza sygnału, co oznacza, że używane są 4 różne fazy.
- Zauważ, że jeśli informacja jest ukryta w tym, że faza jest zmieniana, a nie w samej fazie, nie zobaczysz wyraźnie różniących się faz.
- **Wykrywanie FM**: IQ nie ma pola do identyfikacji częstotliwości (odległość do centrum to amplituda, a kąt to faza).\
Dlatego, aby zidentyfikować FM, powinieneś **widzieć zasadniczo tylko okrąg** na tym wykresie.\
Ponadto, inna częstotliwość jest "reprezentowana" przez wykres IQ przez **przyspieszenie prędkości wzdłuż okręgu** (więc w SysDigger wybierając sygnał, wykres IQ jest zapełniany, jeśli znajdziesz przyspieszenie lub zmianę kierunku w utworzonym okręgu, może to oznaczać, że jest to FM):

## Przykład AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Odkrywanie AM

#### Sprawdzanie obwiedni

Sprawdzając informacje AM za pomocą [**SigDigger** ](https://github.com/BatchDrake/SigDigger) i po prostu patrząc na **obwiednię**, możesz zobaczyć różne wyraźne poziomy amplitudy. Używany sygnał wysyła impulsy z informacjami w AM, tak wygląda jeden impuls:

![](<../../images/image (590).png>)

A tak wygląda część symbolu z falą:

![](<../../images/image (734).png>)

#### Sprawdzanie histogramu

Możesz **wybrać cały sygnał**, w którym znajduje się informacja, wybrać tryb **Amplituda** i **Wybór**, a następnie kliknąć na **Histogram**. Możesz zaobserwować, że znajdują się tylko 2 wyraźne poziomy

![](<../../images/image (264).png>)

Na przykład, jeśli wybierzesz Częstotliwość zamiast Amplitudy w tym sygnale AM, znajdziesz tylko 1 częstotliwość (nie ma możliwości, aby informacja modulowana w częstotliwości używała tylko 1 częstotliwości).

![](<../../images/image (732).png>)

Jeśli znajdziesz wiele częstotliwości, prawdopodobnie nie będzie to FM, prawdopodobnie częstotliwość sygnału została po prostu zmodyfikowana z powodu kanału.

#### Z IQ

W tym przykładzie możesz zobaczyć, jak jest **duże koło**, ale także **wiele punktów w centrum.**

![](<../../images/image (222).png>)

### Uzyskiwanie częstotliwości symbolu

#### Z jednym symbolem

Wybierz najmniejszy symbol, jaki możesz znaleźć (aby mieć pewność, że to tylko 1) i sprawdź "Częstotliwość wyboru". W tym przypadku wynosiłoby to 1,013 kHz (czyli 1 kHz).

![](<../../images/image (78).png>)

#### Z grupą symboli

Możesz również wskazać liczbę symboli, które zamierzasz wybrać, a SigDigger obliczy częstotliwość 1 symbolu (im więcej symboli wybranych, tym lepiej prawdopodobnie). W tym scenariuszu wybrałem 10 symboli, a "Częstotliwość wyboru" wynosi 1,004 kHz:

![](<../../images/image (1008).png>)

### Uzyskiwanie bitów

Po stwierdzeniu, że jest to sygnał **modulowany AM** i **częstotliwość symbolu** (i wiedząc, że w tym przypadku coś w górę oznacza 1, a coś w dół oznacza 0), bardzo łatwo jest **uzyskać bity** zakodowane w sygnale. Więc wybierz sygnał z informacjami i skonfiguruj próbkowanie oraz decyzję i naciśnij próbkę (sprawdź, czy **Amplituda** jest wybrana, odkryta **Częstotliwość symbolu** jest skonfigurowana, a **odzyskiwanie zegara Gadnera** jest wybrane):

![](<../../images/image (965).png>)

- **Synchronizacja z interwałami wyboru** oznacza, że jeśli wcześniej wybrałeś interwały, aby znaleźć częstotliwość symbolu, ta częstotliwość symbolu będzie używana.
- **Ręcznie** oznacza, że wskazana częstotliwość symbolu będzie używana
- W **Wybór o stałym interwale** wskazujesz liczbę interwałów, które powinny być wybrane, a on oblicza częstotliwość symbolu na ich podstawie
- **Odzyskiwanie zegara Gadnera** jest zazwyczaj najlepszą opcją, ale nadal musisz wskazać jakąś przybliżoną częstotliwość symbolu.

Naciskając próbkę, pojawia się to:

![](<../../images/image (644).png>)

Teraz, aby sprawić, by SigDigger zrozumiał **gdzie jest zakres** poziomu niosącego informacje, musisz kliknąć na **niższy poziom** i przytrzymać kliknięte, aż do największego poziomu:

![](<../../images/image (439).png>)

Gdyby na przykład istniały **4 różne poziomy amplitudy**, musiałbyś skonfigurować **Bity na symbol na 2** i wybrać od najmniejszego do największego.

Na koniec **zwiększając** **Zoom** i **zmieniając rozmiar wiersza**, możesz zobaczyć bity (i możesz wszystko zaznaczyć i skopiować, aby uzyskać wszystkie bity):

![](<../../images/image (276).png>)

Jeśli sygnał ma więcej niż 1 bit na symbol (na przykład 2), SigDigger **nie ma sposobu, aby wiedzieć, który symbol to** 00, 01, 10, 11, więc użyje różnych **odcieni szarości**, aby reprezentować każdy (a jeśli skopiujesz bity, użyje **liczb od 0 do 3**, będziesz musiał je przetworzyć).

Ponadto, używaj **kodowań** takich jak **Manchester**, a **up+down** może być **1 lub 0**, a **down+up** może być 1 lub 0. W takich przypadkach musisz **przetworzyć uzyskane up (1) i down (0)**, aby zastąpić pary 01 lub 10 jako 0s lub 1s.

## Przykład FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Odkrywanie FM

#### Sprawdzanie częstotliwości i fali

Przykład sygnału wysyłającego informacje modulowane w FM:

![](<../../images/image (725).png>)

Na poprzednim obrazie możesz dość dobrze zaobserwować, że **używane są 2 częstotliwości**, ale jeśli **obserwujesz** **falę**, możesz **nie być w stanie poprawnie zidentyfikować 2 różnych częstotliwości**:

![](<../../images/image (717).png>)

Dzieje się tak, ponieważ uchwyciłem sygnał w obu częstotliwościach, dlatego jedna jest w przybliżeniu drugą w negatywie:

![](<../../images/image (942).png>)

Jeśli zsynchronizowana częstotliwość jest **bliżej jednej częstotliwości niż drugiej**, możesz łatwo zobaczyć 2 różne częstotliwości:

![](<../../images/image (422).png>)

![](<../../images/image (488).png>)

#### Sprawdzanie histogramu

Sprawdzając histogram częstotliwości sygnału z informacjami, możesz łatwo zobaczyć 2 różne sygnały:

![](<../../images/image (871).png>)

W tym przypadku, jeśli sprawdzisz **histogram amplitudy**, znajdziesz **tylko jedną amplitudę**, więc **nie może to być AM** (jeśli znajdziesz wiele amplitud, może to być spowodowane tym, że sygnał tracił moc wzdłuż kanału):

![](<../../images/image (817).png>)

A to byłby histogram fazy (co jasno pokazuje, że sygnał nie jest modulowany w fazie):

![](<../../images/image (996).png>)

#### Z IQ

IQ nie ma pola do identyfikacji częstotliwości (odległość do centrum to amplituda, a kąt to faza).\
Dlatego, aby zidentyfikować FM, powinieneś **widzieć zasadniczo tylko okrąg** na tym wykresie.\
Ponadto, inna częstotliwość jest "reprezentowana" przez wykres IQ przez **przyspieszenie prędkości wzdłuż okręgu** (więc w SysDigger wybierając sygnał, wykres IQ jest zapełniany, jeśli znajdziesz przyspieszenie lub zmianę kierunku w utworzonym okręgu, może to oznaczać, że jest to FM):

![](<../../images/image (81).png>)

### Uzyskiwanie częstotliwości symbolu

Możesz użyć **tej samej techniki, co w przykładzie AM**, aby uzyskać częstotliwość symbolu, gdy znajdziesz częstotliwości niosące symbole.

### Uzyskiwanie bitów

Możesz użyć **tej samej techniki, co w przykładzie AM**, aby uzyskać bity, gdy **znajdziesz, że sygnał jest modulowany w częstotliwości** i **częstotliwość symbolu**.

{{#include ../../banners/hacktricks-training.md}}
