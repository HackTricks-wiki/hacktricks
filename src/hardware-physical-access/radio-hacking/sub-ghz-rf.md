# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Drzwi garażowe

Piloty do bram garażowych korzystają z pasm sub-GHz, których częstotliwości zależą od regionu i produktu. Spotyka się częstotliwości takie jak 300, 310, 315, 390 i 433,92 MHz, ale nie istnieje uniwersalne pasmo „300–190 MHz” dla bram garażowych. Przed nadawaniem sprawdź etykietę urządzenia, region regulacyjny i zaobserwowany sygnał.<sup>[[1]](#references)</sup>

## Drzwi samochodowe

Wiele pilotów samochodowych korzysta z częstotliwości **315 MHz lub 433,92 MHz**, a wybór zależy od przepisów regionalnych i konstrukcji pojazdu. Sama częstotliwość nie sprawia, że zasięg 433 MHz jest większy niż 315 MHz: znaczenie mają również moc nadawania, sprawność anteny, modulacja, czułość odbiornika, propagacja i lokalne przepisy. W Europie powszechnie stosuje się 433,92 MHz, a w Ameryce Północnej i Japonii — 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

W przedstawionym systemie ze stałym kodem wysłanie każdego kodu raz zamiast pięć razy skraca szacowany czas do sześciu minut:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Usunięcie 2 ms przerwy między sygnałami skraca czas tej demonstracji do około trzech minut.

Zastosowanie sekwencji De Bruijna, która pozwala nakładać na siebie kandydujące ciągi bitów, skraca czas przedstawionego ataku do około ośmiu sekund, jeśli odbiornik akceptuje ciągłą sekwencję bez wymaganego preambuły ani resetowania ramki.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementuje ten atak na zgodne systemy ze stałym kodem.<sup>[[5]](#references)</sup>

Wymóg użycia **preambuły uniemożliwi optymalizację opartą na De Bruijn Sequence**, a **rolling codes uniemożliwią ten atak** (zakładając, że kod jest wystarczająco długi, by nie dało się go złamać metodą brute force).

## Atak Sub-GHz

Aby zaatakować te sygnały za pomocą Flipper Zero, sprawdź:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Ochrona za pomocą Rolling Codes

Automatyczne napędy do bram garażowych zazwyczaj wykorzystują bezprzewodowy pilot do otwierania i zamykania bramy. Pilot **wysyła sygnał radiowy (RF)** do napędu, który uruchamia silnik otwierający lub zamykający bramę.

Ktoś może użyć urządzenia zwanego code grabberem, aby przechwycić sygnał RF i zapisać go do późniejszego wykorzystania. Jest to znane jako **replay attack**. Aby zapobiec tego rodzaju atakom, wiele nowoczesnych napędów do bram garażowych korzysta z bezpieczniejszej metody szyfrowania zwanej systemem **rolling code**.

**Sygnał RF jest zwykle przesyłany z użyciem rolling code**, co oznacza, że kod zmienia się przy każdym użyciu. Utrudnia to **przechwycenie** sygnału i **wykorzystanie** go do uzyskania **nieuprawnionego** dostępu do garażu.

W systemie rolling code pilot i napęd do bramy garażowej korzystają ze **wspólnego algorytmu**, który **generuje nowy kod** przy każdym użyciu pilota. Napęd reaguje tylko na **prawidłowy kod**, co znacznie utrudnia uzyskanie nieuprawnionego dostępu do garażu przez samo przechwycenie kodu.

### **Missing Link Attack**

W skrócie: nasłuchujesz naciśnięcia przycisku i **przechwytujesz sygnał, gdy pilot znajduje się poza zasięgiem urządzenia** (na przykład samochodu lub bramy garażowej). Następnie podchodzisz do urządzenia i **używasz przechwyconego kodu, aby je otworzyć**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Celowe zakłócanie sygnałów RF jest nielegalne w wielu jurysdykcjach i może zakłócać działanie systemów związanych z bezpieczeństwem. Testy jammingowe należy przeprowadzać wyłącznie w ekranowanym, autoryzowanym laboratorium i zgodnie z obowiązującymi przepisami dotyczącymi łączności radiowej.<sup>[[6]](#references)</sup>

Atakujący może **zakłócać sygnał w pobliżu pojazdu lub odbiornika**, aby uniemożliwić odbiornikowi zdekodowanie kodu, osobno przechwycić zablokowaną transmisję, wyłączyć zakłócanie, a następnie odtworzyć przechwycony kod.<sup>[[2]](#references)</sup>

W pewnym momencie ofiara użyje **kluczyków, aby zamknąć samochód**, ale atakujący będzie mieć już **wystarczającą liczbę kodów „zamknij drzwi”**, które, miejmy nadzieję, będzie można ponownie wysłać, aby otworzyć drzwi (może być konieczna **zmiana częstotliwości**, ponieważ niektóre samochody używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

> [!WARNING]
> **Jamming działa**, ale jest zauważalny: jeśli osoba zamykająca samochód po prostu sprawdzi drzwi, aby upewnić się, że są zamknięte, zauważy, że samochód pozostał otwarty. Ponadto, jeśli znałaby takie ataki, mogłaby zauważyć, że drzwi nie wydały dźwięku **zamykania** albo **światła** samochodu nie mignęły po naciśnięciu przycisku „lock”.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Jest to bardziej **skryta technika jammingowa**. Atakujący zakłóca sygnał, więc gdy ofiara próbuje zamknąć drzwi, operacja się nie udaje, ale atakujący **zapisuje ten kod**. Następnie ofiara **ponownie próbuje zamknąć samochód**, naciskając przycisk, a samochód **zapisuje ten drugi kod**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Zaraz potem **atakujący może wysłać pierwszy kod**, a **samochód się zamknie** (ofiara pomyśli, że zamknęła go drugim naciśnięciem). Następnie atakujący będzie mógł **wysłać drugi skradziony kod, aby otworzyć samochód** (zakładając, że kod „zamknij samochód” może być również użyty do jego otwarcia). Może być konieczna zmiana częstotliwości (niektóre samochody używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

Jedna z implementacji RollJam wykorzystuje szerokość pasma odbiornika: jammer nadaje na częstotliwości wystarczająco bliskiej częstotliwości nośnej pilota, aby odczulić szerszy odbiornik pojazdu, podczas gdy węższy odbiornik atakującego pozostaje dostrojony do pilota i nadal może rejestrować jego sygnał. Dokładne przesunięcie częstotliwości i szerokość pasma zależą od sprzętu celu.<sup>[[2]](#references)</sup>

> [!WARNING]
> Inne implementacje opisane w specyfikacjach pokazują, że **rolling code stanowi tylko część** całego wysyłanego kodu. Na przykład wysyłany kod to **24-bitowy klucz**, w którym pierwsze **12 bitów to rolling code**, kolejne **8 to polecenie** (takie jak zamknięcie lub otwarcie), a ostatnie 4 bity to **suma kontrolna**. Pojazdy wykorzystujące takie rozwiązanie są również podatne na atak: atakujący musi jedynie zastąpić fragment rolling code, aby móc **użyć dowolnego rolling code na obu częstotliwościach**.

> [!CAUTION]
> Pamiętaj, że jeśli ofiara wyśle trzeci kod podczas gdy atakujący wysyła pierwszy, pierwszy i drugi kod zostaną unieważnione.

### Alarm Sounding Jamming Attack

Podczas testów systemu aftermarketowego z rolling code, zainstalowanego w samochodzie, **dwukrotne natychmiastowe wysłanie tego samego kodu** uruchomiło **alarm** i immobilizer, zapewniając wyjątkową możliwość przeprowadzenia **denial of service**. Ironią jest to, że **alarm** i immobilizer można było **wyłączyć**, naciskając przycisk na **pilocie**, co dało atakującemu możliwość **ciągłego przeprowadzania ataku DoS**. Można też połączyć ten atak z **poprzednim, aby uzyskać więcej kodów**, ponieważ ofiara będzie chciała jak najszybciej przerwać atak.<sup>[[2]](#references)</sup>

## References

- [1] [Dokumentacja Flipper Zero — regionalne częstotliwości Sub-GHz](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Obchodzenie systemów Rolling Code — Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar — DEF CON 23: Prowadź, jakbyś włamał się do auta (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Jak zhakować samochód — odtworzenie ataku RollJam z użyciem YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Kod źródłowy OpenSesame](https://github.com/samyk/opensesame)
- [6] [Komunikat FCC o egzekwowaniu przepisów — egzekwowanie zakazu używania jammerów](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
