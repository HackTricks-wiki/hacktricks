# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Drzwi garażowe

Otwieracze drzwi garażowych zazwyczaj działają w zakresie częstotliwości 300-190 MHz, przy czym najczęściej używane są częstotliwości 300 MHz, 310 MHz, 315 MHz i 390 MHz. Ten zakres częstotliwości jest powszechnie używany przez otwieracze drzwi garażowych, ponieważ jest mniej zatłoczony niż inne pasma częstotliwości i rzadziej występują w nim zakłócenia powodowane przez inne urządzenia.

## Drzwi samochodowe

Większość pilotów samochodowych działa na częstotliwości **315 MHz lub 433 MHz**. Są to częstotliwości radiowe używane w wielu różnych zastosowaniach. Główna różnica między tymi częstotliwościami polega na tym, że 433 MHz ma większy zasięg niż 315 MHz. Oznacza to, że 433 MHz lepiej sprawdza się w zastosowaniach wymagających większego zasięgu, takich jak zdalny bezkluczykowy dostęp do pojazdu.\
W Europie powszechnie używana jest częstotliwość 433,92 MHz, natomiast w USA i Japonii 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Jeśli zamiast wysyłać każdy kod 5 razy (jest on wysyłany w ten sposób, aby mieć pewność, że odbiornik go odbierze), wyślemy go tylko raz, czas skróci się do 6 minut:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

a jeśli **usuniesz 2 ms oczekiwania** między sygnałami, możesz **skrócić czas do 3 minut.**

Co więcej, dzięki wykorzystaniu De Bruijn Sequence (metody zmniejszającej liczbę bitów potrzebnych do wysłania wszystkich potencjalnych liczb binarnych podczas brute-force) ten **czas skraca się do zaledwie 8 sekund**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Przykład tego ataku zaimplementowano w [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Wymaganie **preambuły uniemożliwi optymalizację De Bruijn Sequence**, a **rolling codes uniemożliwią ten atak** (zakładając, że kod jest wystarczająco długi, aby nie można było przeprowadzić brute-force).

## Sub-GHz Attack

Aby zaatakować te sygnały za pomocą Flipper Zero, sprawdź:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatyczne otwieracze drzwi garażowych zazwyczaj używają bezprzewodowego pilota do otwierania i zamykania drzwi garażowych. Pilot **wysyła sygnał o częstotliwości radiowej (RF)** do otwieracza drzwi garażowych, który uruchamia silnik otwierający lub zamykający drzwi.

Możliwe jest użycie urządzenia znanego jako code grabber do przechwycenia sygnału RF i zapisania go do późniejszego wykorzystania. Jest to znane jako **replay attack**. Aby zapobiec tego typu atakom, wiele współczesnych otwieraczy drzwi garażowych korzysta z bezpieczniejszej metody szyfrowania znanej jako system **rolling code**.

**Sygnał RF jest zazwyczaj przesyłany przy użyciu rolling code**, co oznacza, że kod zmienia się przy każdym użyciu. Utrudnia to **przechwycenie** sygnału i **wykorzystanie** go do uzyskania **nieautoryzowanego** dostępu do garażu.

W systemie rolling code pilot i otwieracz drzwi garażowych mają **wspólny algorytm**, który **generuje nowy kod** za każdym użyciem pilota. Otwieracz drzwi garażowych odpowie tylko na **prawidłowy kod**, co znacznie utrudnia uzyskanie nieautoryzowanego dostępu do garażu wyłącznie przez przechwycenie kodu.

### **Missing Link Attack**

Zasadniczo nasłuchujesz naciśnięcia przycisku i **przechwytujesz sygnał, gdy pilot znajduje się poza zasięgiem** urządzenia (na przykład samochodu lub garażu). Następnie podchodzisz do urządzenia i **używasz przechwyconego kodu, aby je otworzyć**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Atakujący może **zagłuszać sygnał w pobliżu pojazdu lub odbiornika**, aby **odbiornik faktycznie nie mógł „usłyszeć” kodu**, a gdy to nastąpi, może po prostu **przechwycić i odtworzyć** kod po zakończeniu zagłuszania.<sup>[[2]](#references)</sup>

W pewnym momencie ofiara użyje **kluczy, aby zamknąć samochód**, ale atakujący będzie miał już **zarejestrowaną wystarczającą liczbę kodów „zamknij drzwi”**, które będzie można ponownie wysłać w celu otwarcia drzwi (może być konieczna **zmiana częstotliwości**, ponieważ niektóre samochody używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

> [!WARNING]
> **Zagłuszanie działa**, ale jest zauważalne, ponieważ jeśli **osoba zamykająca samochód po prostu sprawdzi drzwi**, aby upewnić się, że są zamknięte, zauważy, że samochód jest odblokowany. Ponadto, jeśli wiedziałaby o takich atakach, mogłaby nawet zwrócić uwagę na to, że drzwi nigdy nie wydały **dźwięku zamykania** lub że **światła samochodu** nie mignęły po naciśnięciu przycisku „lock”.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Jest to bardziej **dyskretna technika Jamming**. Atakujący zagłusza sygnał, więc gdy ofiara próbuje zamknąć drzwi, operacja się nie powiedzie, ale atakujący **zarejestruje ten kod**. Następnie ofiara **ponownie spróbuje zamknąć samochód**, naciskając przycisk, a samochód **zarejestruje drugi kod**.<sup>[[2]](#references)[[4]](#references)</sup>\
Natychmiast po tym **atakujący może wysłać pierwszy kod**, a **samochód się zamknie** (ofiara uzna, że zamknął się po drugim naciśnięciu). Następnie atakujący będzie mógł **wysłać drugi skradziony kod, aby otworzyć** samochód (zakładając, że **kod „zamknij samochód” może również zostać użyty do jego otwarcia**). Może być konieczna zmiana częstotliwości (ponieważ niektóre samochody używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

Atakujący może **zagłuszać odbiornik samochodu, a nie własny odbiornik**, ponieważ jeśli odbiornik samochodu nasłuchuje na przykład szerokiego pasma o szerokości 1 MHz, atakujący nie będzie **zagłuszał** dokładnej częstotliwości używanej przez pilota, lecz **częstotliwość znajdującą się obok niej w tym paśmie**, podczas gdy **odbiornik atakującego będzie nasłuchiwał w węższym zakresie**, w którym będzie mógł odebrać sygnał pilota **bez sygnału zagłuszającego**.

> [!WARNING]
> Inne implementacje opisane w specyfikacjach pokazują, że **rolling code stanowi część** całkowitego wysyłanego kodu. Kod może mieć na przykład **24-bitowy klucz**, gdzie pierwsze **12 bitów to rolling code**, kolejne **8 bitów to polecenie** (takie jak lock lub unlock), a ostatnie 4 bity to **suma kontrolna**. Pojazdy implementujące ten typ rozwiązania są również podatne, ponieważ atakujący musi jedynie zastąpić segment rolling code, aby móc **użyć dowolnego rolling code na obu częstotliwościach**.

> [!CAUTION]
> Pamiętaj, że jeśli ofiara wyśle trzeci kod, gdy atakujący wysyła pierwszy, pierwszy i drugi kod zostaną unieważnione.

### Alarm Sounding Jamming Attack

Podczas testów systemu rolling code zainstalowanego na rynku wtórnym w samochodzie **dwukrotne wysłanie tego samego kodu** natychmiast **aktywowało alarm i immobiliser**, zapewniając wyjątkową możliwość przeprowadzenia **denial of service**. Paradoksalnie sposobem na **wyłączenie alarmu** i immobilisera było **naciśnięcie** przycisku na **pilocie**, co dawało atakującemu możliwość **ciągłego przeprowadzania ataku DoS**. Można też połączyć ten atak z **poprzednim**, aby uzyskać więcej kodów, ponieważ ofiara będzie chciała jak najszybciej zakończyć atak.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
