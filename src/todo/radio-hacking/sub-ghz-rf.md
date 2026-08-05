# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Drzwi garażowe

Otwieracze drzwi garażowych zazwyczaj działają w zakresie częstotliwości 300-190 MHz, przy czym najczęściej używane są częstotliwości 300 MHz, 310 MHz, 315 MHz i 390 MHz. Ten zakres częstotliwości jest powszechnie używany przez otwieracze drzwi garażowych, ponieważ jest mniej zatłoczony niż inne pasma częstotliwości i występuje w nim mniejsze prawdopodobieństwo zakłóceń powodowanych przez inne urządzenia.

## Drzwi samochodowe

Większość pilotów samochodowych działa na częstotliwości **315 MHz lub 433 MHz**. Są to częstotliwości radiowe używane w wielu różnych zastosowaniach. Główna różnica między tymi częstotliwościami polega na tym, że 433 MHz zapewnia większy zasięg niż 315 MHz. Oznacza to, że 433 MHz lepiej sprawdza się w zastosowaniach wymagających większego zasięgu, takich jak zdalny bezkluczykowy dostęp.\
W Europie powszechnie używana jest częstotliwość 433,92 MHz, a w USA i Japonii 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Jeśli zamiast wysyłać każdy kod 5 razy (jest on wysyłany w ten sposób, aby upewnić się, że odbiornik go otrzyma), wyślemy go tylko raz, czas zostanie skrócony do 6 minut:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

a jeśli **usuniesz 2 ms oczekiwania** między sygnałami, możesz **skrócić czas do 3 minut.**

Co więcej, dzięki użyciu sekwencji De Bruijna (sposobu na zmniejszenie liczby bitów potrzebnych do wysłania wszystkich potencjalnych liczb binarnych w celu przeprowadzenia brute-force) ten **czas zostaje skrócony do zaledwie 8 sekund**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Przykład tego ataku zaimplementowano w [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)<sup>[[3]](#references)</sup>

Wymaganie **preambuły uniemożliwi optymalizację za pomocą sekwencji De Bruijna**, a **rolling codes zapobiegną temu atakowi** (zakładając, że kod jest wystarczająco długi, aby nie można było przeprowadzić brute-force).

## Sub-GHz Attack

Aby zaatakować te sygnały za pomocą Flipper Zero, sprawdź:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatyczne otwieracze drzwi garażowych zazwyczaj używają bezprzewodowego pilota do otwierania i zamykania drzwi garażowych. Pilot **wysyła sygnał radiowy (RF)** do otwieracza drzwi garażowych, który uruchamia silnik otwierający lub zamykający drzwi.

Możliwe jest użycie urządzenia znanego jako code grabber do przechwycenia sygnału RF i zapisania go do późniejszego użycia. Jest to znane jako **replay attack**. Aby zapobiec tego typu atakom, wiele nowoczesnych otwieraczy drzwi garażowych używa bezpieczniejszej metody szyfrowania znanej jako system **rolling code**.

**Sygnał RF jest zazwyczaj przesyłany przy użyciu rolling code**, co oznacza, że kod zmienia się przy każdym użyciu. Utrudnia to **przechwycenie** sygnału i wykorzystanie go do uzyskania **nieautoryzowanego** dostępu do garażu.

W systemie rolling code pilot i otwieracz drzwi garażowych mają **wspólny algorytm**, który **generuje nowy kod** za każdym użyciem pilota. Otwieracz drzwi garażowych odpowie wyłącznie na **prawidłowy kod**, co znacznie utrudnia uzyskanie nieautoryzowanego dostępu do garażu poprzez samo przechwycenie kodu.

### **Missing Link Attack**

Zasadniczo nasłuchujesz naciśnięcia przycisku i **przechwytujesz sygnał, gdy pilot znajduje się poza zasięgiem** urządzenia (na przykład samochodu lub garażu). Następnie przemieszczasz się do urządzenia i **używasz przechwyconego kodu, aby je otworzyć**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Atakujący może **zagłuszyć sygnał w pobliżu pojazdu lub odbiornika**, aby **odbiornik faktycznie nie mógł „usłyszeć” kodu**, a gdy już to nastąpi, można po prostu **przechwycić i odtworzyć** kod po zakończeniu zagłuszania.

W pewnym momencie ofiara użyje **kluczy, aby zamknąć samochód**, ale wtedy atakujący będzie miał **zarejestrowaną wystarczającą liczbę kodów „zamknij drzwi”**, które będzie można ponownie wysłać w celu otwarcia drzwi (może być konieczna **zmiana częstotliwości**, ponieważ istnieją samochody używające tych samych kodów do otwierania i zamykania, ale nasłuchujące obu poleceń na różnych częstotliwościach).

> [!WARNING]
> **Jamming działa**, ale jest zauważalny, ponieważ jeśli **osoba zamykająca samochód po prostu sprawdzi drzwi**, aby upewnić się, że są zamknięte, zauważy, że samochód jest odblokowany. Ponadto, jeśli znałaby takie ataki, mogłaby nawet zauważyć, że drzwi nigdy nie wydały dźwięku **zamykania** albo że **światła samochodu** nie mignęły po naciśnięciu przycisku „lock”.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Jest to bardziej **stealth technika Jamming**. Atakujący zagłuszy sygnał, więc gdy ofiara spróbuje zamknąć drzwi, nie zadziała to, ale atakujący **zarejestruje ten kod**. Następnie ofiara **spróbuje ponownie zamknąć samochód**, naciskając przycisk, a samochód **zarejestruje ten drugi kod**.\
Natychmiast po tym **atakujący może wysłać pierwszy kod**, a **samochód zostanie zamknięty** (ofiara uzna, że zamknęła go drugim naciśnięciem). Następnie atakujący będzie mógł **wysłać drugi skradziony kod, aby otworzyć** samochód (zakładając, że **kod „zamknij samochód” może być również użyty do jego otwarcia**). Może być konieczna zmiana częstotliwości (ponieważ istnieją samochody używające tych samych kodów do otwierania i zamykania, ale nasłuchujące obu poleceń na różnych częstotliwościach).<sup>[[3]](#references)[[2]](#references)</sup>

Atakujący może **zagłuszać odbiornik samochodu, a nie własny odbiornik**, ponieważ jeśli odbiornik samochodu nasłuchuje na przykład pasma o szerokości 1 MHz, atakujący nie będzie **zagłuszał** dokładnej częstotliwości używanej przez pilota, lecz **zbliżoną częstotliwość w tym paśmie**, podczas gdy **odbiornik atakującego będzie nasłuchiwał w węższym zakresie**, w którym będzie mógł odebrać sygnał pilota **bez sygnału zagłuszającego**.

> [!WARNING]
> Inne implementacje opisane w specyfikacjach pokazują, że **rolling code stanowi część** całkowitego wysyłanego kodu. Oznacza to, że wysyłany kod jest **24-bitowym kluczem**, w którym pierwsze **12 bitów to rolling code**, kolejne **8 bitów to polecenie** (takie jak lock lub unlock), a ostatnie 4 bity to **suma kontrolna**. Pojazdy implementujące ten typ są również naturalnie podatne, ponieważ atakujący musi jedynie zastąpić segment rolling code, aby móc **użyć dowolnego rolling code na obu częstotliwościach**.

> [!CAUTION]
> Należy pamiętać, że jeśli ofiara wyśle trzeci kod podczas wysyłania przez atakującego pierwszego kodu, pierwszy i drugi kod zostaną unieważnione.

### Alarm Sounding Jamming Attack

Podczas testów aftermarketowego systemu rolling code zainstalowanego w samochodzie **dwukrotne wysłanie tego samego kodu** natychmiast **aktywowało alarm** i immobiliser, zapewniając wyjątkową możliwość przeprowadzenia **denial of service**. Co ciekawe, sposobem na **wyłączenie alarmu** i immobilisera było **naciśnięcie** przycisku **pilota**, co dawało atakującemu możliwość **ciągłego przeprowadzania ataku DoS**. Można też połączyć ten atak z **poprzednim, aby uzyskać więcej kodów**, ponieważ ofiara będzie chciała jak najszybciej zatrzymać atak.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
