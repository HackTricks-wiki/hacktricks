# iButton

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

iButton to ogólna nazwa elektronicznego klucza identyfikacyjnego zapakowanego w **metalowy pojemnik w kształcie monety**. Nazywany jest również **Dallas Touch** Memory lub pamięcią kontaktową. Chociaż często błędnie określa się go jako klucz „magnetyczny”, nie ma w nim **nic magnetycznego**. W rzeczywistości wewnątrz ukryty jest pełnoprawny **mikrochip** działający na protokole cyfrowym.

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Czym jest iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Zazwyczaj iButton odnosi się do fizycznej formy klucza i czytnika - okrągłej monety z dwoma stykami. Dla otaczającej go ramki istnieje wiele wariantów, od najczęstszych plastikowych uchwytów z otworem po pierścienie, wisiorki itp.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Gdy klucz dotrze do czytnika, **styki stykają się** i klucz jest zasilany, aby **przesłać** swoje ID. Czasami klucz **nie jest odczytywany** od razu, ponieważ **PSD styku interkomu jest większy** niż powinien być. W takim przypadku zewnętrzne kontury klucza i czytnika nie mogły się dotknąć. Jeśli tak się stanie, będziesz musiał przycisnąć klucz do jednej ze ścianek czytnika.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protokół 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Klucze Dallas wymieniają dane za pomocą protokołu 1-wire. Z tylko jednym stykiem do transferu danych (!!) w obu kierunkach, od mastera do slave'a i odwrotnie. Protokół 1-wire działa zgodnie z modelem Master-Slave. W tej topologii Master zawsze inicjuje komunikację, a Slave podąża za jego instrukcjami.

Gdy klucz (Slave) kontaktuje się z interkomem (Master), chip wewnątrz klucza włącza się, zasilany przez interkom, a klucz jest inicjowany. Następnie interkom żąda ID klucza. Następnie przyjrzymy się temu procesowi bardziej szczegółowo.

Flipper może działać zarówno w trybie Master, jak i Slave. W trybie odczytu klucza Flipper działa jako czytnik, to znaczy działa jako Master. A w trybie emulacji klucza, flipper udaje klucz, jest w trybie Slave.

### Klucze Dallas, Cyfral i Metakom

Aby uzyskać informacje na temat działania tych kluczy, sprawdź stronę [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataki

iButtony mogą być atakowane za pomocą Flipper Zero:

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Odniesienia

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
