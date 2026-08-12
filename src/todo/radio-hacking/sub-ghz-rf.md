# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Drzwi garażowe

Piloty do drzwi garażowych korzystają z kilku regionalnych i zależnych od produktu przydziałów częstotliwości Sub-GHz. Spotykane są częstotliwości takie jak 300, 310, 315, 390 i 433,92 MHz, ale nie istnieje uniwersalne pasmo drzwi garażowych „300–190 MHz”. Przed rozpoczęciem transmisji należy zidentyfikować oznaczenie celu, region regulacyjny oraz zaobserwowany sygnał.<sup>[[1]](#references)</sup>

## Drzwi samochodowe

Wiele pilotów samochodowych korzysta z częstotliwości **315 MHz lub 433,92 MHz**, przy czym na wybór wpływają przepisy regionalne i konstrukcja pojazdu. Sama częstotliwość nie sprawia, że 433 MHz ma większy zasięg niż 315 MHz: znaczenie mają również moc nadajnika, wydajność anteny, modulacja, czułość odbiornika, propagacja i lokalne przepisy. W Europie powszechnie stosuje się 433,92 MHz, natomiast 315 MHz jest częste w Ameryce Północnej i Japonii.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

W przedstawionym systemie ze stałym kodem wysłanie każdego kodu raz zamiast pięciu razy skraca szacowany czas do sześciu minut:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Usunięcie 2-milisekundowego odstępu między sygnałami skraca czas tego przykładu do około trzech minut.

Zastosowanie sekwencji De Bruijna w celu nakładania się kandydujących ciągów bitów skraca przedstawiony atak do około ośmiu sekund, gdy odbiornik akceptuje ciągłą sekwencję bez wymaganego preambuły lub resetowania ramki.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementuje ten atak przeciwko kompatybilnym systemom ze stałym kodem.<sup>[[5]](#references)</sup>

Wymaganie **preambuły uniemożliwia optymalizację za pomocą sekwencji De Bruijna**, a **rolling codes uniemożliwiają ten atak** (zakładając, że kod jest wystarczająco długi, aby nie można było przeprowadzić brute force).

## Sub-GHz Attack

Aby zaatakować te sygnały za pomocą Flipper Zero, sprawdź:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Ochrona Rolling Codes

Automatyczne mechanizmy otwierania drzwi garażowych zazwyczaj korzystają z bezprzewodowego pilota do otwierania i zamykania drzwi garażowych. Pilot **wysyła sygnał radiowy (RF)** do mechanizmu otwierania drzwi garażowych, który uruchamia silnik otwierający lub zamykający drzwi.

Możliwe jest użycie urządzenia znanego jako code grabber do przechwycenia sygnału RF i zapisania go do późniejszego użycia. Jest to znane jako **replay attack**. Aby zapobiec tego typu atakom, wiele nowoczesnych mechanizmów otwierania drzwi garażowych korzysta z bezpieczniejszej metody szyfrowania znanej jako system **rolling code**.

**Sygnał RF jest zazwyczaj przesyłany przy użyciu rolling code**, co oznacza, że kod zmienia się przy każdym użyciu. Utrudnia to **przechwycenie** sygnału i wykorzystanie go do uzyskania **nieautoryzowanego** dostępu do garażu.

W systemie rolling code pilot i mechanizm otwierania drzwi garażowych mają **wspólny algorytm**, który **generuje nowy kod** za każdym użyciem pilota. Mechanizm otwierania drzwi garażowych reaguje wyłącznie na **prawidłowy kod**, co znacznie utrudnia uzyskanie nieautoryzowanego dostępu do garażu jedynie przez przechwycenie kodu.

### **Missing Link Attack**

Zasadniczo należy nasłuchiwać naciśnięcia przycisku i **przechwycić sygnał, gdy pilot znajduje się poza zasięgiem** urządzenia (na przykład samochodu lub garażu). Następnie należy podejść do urządzenia i **użyć przechwyconego kodu, aby je otworzyć**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Celowe zakłócanie RF jest nielegalne w wielu jurysdykcjach i może zakłócać działanie systemów związanych z bezpieczeństwem. Testy jamming należy przeprowadzać wyłącznie w ekranowanym, autoryzowanym laboratorium i zgodnie z obowiązującymi przepisami dotyczącymi łączności radiowej.<sup>[[6]](#references)</sup>

Atakujący może **zakłócać sygnał w pobliżu pojazdu lub odbiornika**, aby odbiornik nie mógł zdekodować kodu, osobno przechwycić zablokowanej transmisji, przerwać jamming, a następnie odtworzyć przechwycony kod.<sup>[[2]](#references)</sup>

Ofiara w pewnym momencie użyje **kluczy do zamknięcia samochodu**, ale wtedy atakujący będzie miał **zarejestrowaną wystarczającą liczbę kodów „zamknij drzwi”**, które być może będzie można ponownie wysłać, aby otworzyć drzwi (może być konieczna **zmiana częstotliwości**, ponieważ niektóre samochody używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

> [!WARNING]
> **Jamming działa**, ale jest zauważalny, ponieważ jeśli **osoba zamykająca samochód po prostu sprawdzi drzwi**, aby upewnić się, że są zamknięte, zauważy, że samochód pozostał otwarty. Ponadto, jeśli wiedziałaby o takich atakach, mogłaby nawet zauważyć, że drzwi nie wydały dźwięku zamykania lub że **światła samochodu** nie mignęły po naciśnięciu przycisku „lock”.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Jest to bardziej **stealthowa technika jamming**. Atakujący zakłóca sygnał, więc gdy ofiara próbuje zamknąć drzwi, operacja się nie powiedzie, ale atakujący **zarejestruje ten kod**. Następnie ofiara **ponownie spróbuje zamknąć samochód**, naciskając przycisk, a samochód **zarejestruje drugi kod**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Natychmiast po tym **atakujący może wysłać pierwszy kod**, a **samochód się zamknie** (ofiara pomyśli, że zamknęła go drugim naciśnięciem). Następnie atakujący będzie mógł **wysłać drugi skradziony kod, aby otworzyć** samochód (zakładając, że **kod „zamknij samochód” może również służyć do jego otwarcia**). Może być konieczna zmiana częstotliwości (ponieważ niektóre samochody używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

Jedna z implementacji RollJam wykorzystuje szerokość pasma odbiornika: jammer nadaje wystarczająco blisko częstotliwości nośnej pilota, aby odczulić szerszy odbiornik pojazdu, podczas gdy węższy odbiornik atakującego pozostaje dostrojony do pilota i nadal może go rejestrować. Dokładne przesunięcie i szerokość pasma zależą od sprzętu celu.<sup>[[2]](#references)</sup>

> [!WARNING]
> Inne implementacje opisane w specyfikacjach pokazują, że **rolling code stanowi część** całkowitego przesyłanego kodu. Oznacza to, że przesyłany kod jest **24-bitowym kluczem**, w którym pierwsze **12 bitów to rolling code**, kolejne **8 bitów to polecenie** (takie jak lock lub unlock), a ostatnie 4 bity to **checksum**. Pojazdy implementujące ten typ są również naturalnie podatne, ponieważ atakujący musi jedynie zastąpić segment rolling code, aby móc **używać dowolnego rolling code na obu częstotliwościach**.

> [!CAUTION]
> Należy pamiętać, że jeśli ofiara wyśle trzeci kod, gdy atakujący wysyła pierwszy, pierwszy i drugi kod zostaną unieważnione.

### Alarm Sounding Jamming Attack

Podczas testów systemu rolling code zainstalowanego na rynku wtórnym w samochodzie **dwukrotne natychmiastowe wysłanie tego samego kodu** aktywowało **alarm** i immobiliser, stwarzając wyjątkową możliwość przeprowadzenia **denial of service**. Paradoksalnie sposobem na **wyłączenie alarmu** i immobilisera było **naciśnięcie** przycisku na **pilocie**, co dawało atakującemu możliwość **ciągłego przeprowadzania ataku DoS**. Można też połączyć ten atak z **poprzednim, aby uzyskać więcej kodów**, ponieważ ofiara będzie chciała jak najszybciej zakończyć atak.<sup>[[2]](#references)</sup>

## References

- [1] [Dokumentacja Flipper Zero - regionalne częstotliwości Sub-GHz](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Omijanie systemów Rolling Code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Jak zhakować samochód - odtworzenie RollJam za pomocą YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Kod źródłowy OpenSesame](https://github.com/samyk/opensesame)
- [6] [Zalecenie egzekucyjne FCC - egzekwowanie zakazu jammerów](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
