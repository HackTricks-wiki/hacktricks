# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Otwieracze do garażu zazwyczaj działają na częstotliwościach w zakresie 300-190 MHz, przy czym najczęściej spotykane częstotliwości to 300 MHz, 310 MHz, 315 MHz i 390 MHz. Ten zakres częstotliwości jest powszechnie używany w otwieraczach do garażu, ponieważ jest mniej zatłoczony niż inne pasma częstotliwości i jest mniej narażony na zakłócenia od innych urządzeń.

## Car Doors

Większość pilotów do samochodów działa na **315 MHz lub 433 MHz**. Obie te częstotliwości to częstotliwości radiowe, które są używane w różnych zastosowaniach. Główna różnica między tymi dwiema częstotliwościami polega na tym, że 433 MHz ma dłuższy zasięg niż 315 MHz. Oznacza to, że 433 MHz jest lepsze do zastosowań wymagających dłuższego zasięgu, takich jak zdalne otwieranie bezkluczykowe.\
W Europie powszechnie używa się 433,92 MHz, a w USA i Japonii 315 MHz.

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Jeśli zamiast wysyłać każdy kod 5 razy (wysyłany w ten sposób, aby upewnić się, że odbiornik go odbierze), wyślesz go tylko raz, czas zostaje skrócony do 6 minut:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

a jeśli **usunięcie 2 ms oczekiwania** między sygnałami pozwoli **zmniejszyć czas do 3 minut.**

Co więcej, używając sekwencji De Bruijn (sposób na zmniejszenie liczby bitów potrzebnych do wysłania wszystkich potencjalnych liczb binarnych do bruteforce), ten **czas zostaje skrócony do 8 sekund**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Przykład tego ataku został zaimplementowany w [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Wymaganie **preambuły unika optymalizacji sekwencji De Bruijn** i **kodowanie zmienne zapobiega temu atakowi** (zakładając, że kod jest wystarczająco długi, aby nie można go było złamać).

## Sub-GHz Attack

Aby zaatakować te sygnały za pomocą Flipper Zero, sprawdź:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatyczne otwieracze do garażu zazwyczaj używają bezprzewodowego pilota do otwierania i zamykania drzwi garażowych. Pilot **wysyła sygnał radiowy (RF)** do otwieracza do garażu, który aktywuje silnik do otwarcia lub zamknięcia drzwi.

Możliwe jest, że ktoś użyje urządzenia znanego jako code grabber, aby przechwycić sygnał RF i nagrać go do późniejszego użycia. Jest to znane jako **atak powtórzeniowy**. Aby zapobiec tego typu atakowi, wiele nowoczesnych otwieraczy do garażu używa bardziej bezpiecznej metody szyfrowania znanej jako system **rolling code**.

**Sygnał RF jest zazwyczaj przesyłany za pomocą rolling code**, co oznacza, że kod zmienia się przy każdym użyciu. To sprawia, że **trudno** jest komuś **przechwycić** sygnał i **użyć** go do uzyskania **nieautoryzowanego** dostępu do garażu.

W systemie rolling code pilot i otwieracz do garażu mają **wspólny algorytm**, który **generuje nowy kod** za każdym razem, gdy pilot jest używany. Otwieracz do garażu zareaguje tylko na **poprawny kod**, co znacznie utrudnia uzyskanie nieautoryzowanego dostępu do garażu tylko poprzez przechwycenie kodu.

### **Missing Link Attack**

W zasadzie nasłuchujesz przycisku i **przechwytujesz sygnał, gdy pilot jest poza zasięgiem** urządzenia (powiedzmy samochodu lub garażu). Następnie przechodzisz do urządzenia i **używasz przechwyconego kodu, aby je otworzyć**.

### Full Link Jamming Attack

Napastnik może **zakłócać sygnał w pobliżu pojazdu lub odbiornika**, aby **odbiornik nie mógł faktycznie „usłyszeć” kodu**, a gdy to się dzieje, możesz po prostu **przechwycić i powtórzyć** kod, gdy przestaniesz zakłócać.

Ofiara w pewnym momencie użyje **kluczy do zablokowania samochodu**, ale atakujący **nagrał wystarczająco dużo kodów „zamknij drzwi”**, które mam nadzieję można będzie ponownie wysłać, aby otworzyć drzwi (może być potrzebna **zmiana częstotliwości**, ponieważ są samochody, które używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

> [!WARNING]
> **Zakłócanie działa**, ale jest zauważalne, ponieważ jeśli **osoba zamykająca samochód po prostu sprawdza drzwi**, aby upewnić się, że są zablokowane, zauważy, że samochód jest odblokowany. Dodatkowo, jeśli byłaby świadoma takich ataków, mogłaby nawet usłyszeć, że drzwi nigdy nie wydały dźwięku **zamka** lub światła samochodu **nigdy nie migały**, gdy nacisnęła przycisk „zablokuj”.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

To bardziej **technika zakłócania w ukryciu**. Napastnik zakłóci sygnał, więc gdy ofiara spróbuje zablokować drzwi, to nie zadziała, ale napastnik **nagra ten kod**. Następnie ofiara **spróbuje ponownie zablokować samochód**, naciskając przycisk, a samochód **nagra ten drugi kod**.\
Natychmiast po tym **napastnik może wysłać pierwszy kod**, a **samochód się zablokuje** (ofiara pomyśli, że drugi nacisk go zamknął). Następnie napastnik będzie mógł **wysłać drugi skradziony kod, aby otworzyć** samochód (zakładając, że **kod „zamknij samochód” może być również użyty do otwarcia**). Może być potrzebna zmiana częstotliwości (ponieważ są samochody, które używają tych samych kodów do otwierania i zamykania, ale nasłuchują obu poleceń na różnych częstotliwościach).

Napastnik może **zakłócać odbiornik samochodu, a nie swój odbiornik**, ponieważ jeśli odbiornik samochodu nasłuchuje na przykład w szerokim paśmie 1 MHz, napastnik nie **zakłóci** dokładnej częstotliwości używanej przez pilot, ale **bliską w tym spektrum**, podczas gdy **odbiornik napastnika będzie nasłuchiwał w mniejszym zakresie**, gdzie może usłyszeć sygnał pilota **bez sygnału zakłócającego**.

> [!WARNING]
> Inne implementacje widziane w specyfikacjach pokazują, że **rolling code jest częścią** całkowitego kodu wysyłanego. Tj. wysyłany kod to **24-bitowy klucz**, gdzie pierwsze **12 to rolling code**, **drugie 8 to polecenie** (takie jak zablokuj lub odblokuj), a ostatnie 4 to **suma kontrolna**. Pojazdy implementujące ten typ są również naturalnie podatne, ponieważ napastnik musi jedynie zastąpić segment rolling code, aby móc **używać dowolnego rolling code na obu częstotliwościach**.

> [!CAUTION]
> Zauważ, że jeśli ofiara wyśle trzeci kod, podczas gdy napastnik wysyła pierwszy, pierwszy i drugi kod zostaną unieważnione.

### Alarm Sounding Jamming Attack

Testując system rolling code zainstalowany w samochodzie, **wysłanie tego samego kodu dwa razy** natychmiast **aktywowało alarm** i immobilizer, co stwarza unikalną **możliwość odmowy usługi**. Ironią jest to, że środkiem **wyłączania alarmu** i immobilizera było **naciśnięcie** **pilota**, co daje napastnikowi możliwość **ciągłego przeprowadzania ataku DoS**. Lub połączenie tego ataku z **poprzednim, aby uzyskać więcej kodów**, ponieważ ofiara chciałaby jak najszybciej zakończyć atak.

## References

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
