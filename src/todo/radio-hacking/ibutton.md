# iButton

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

iButton to ogólna nazwa elektronicznego klucza identyfikacyjnego umieszczonego w **metalowym pojemniku w kształcie monety**. Jest również nazywany pamięcią **Dallas Touch** lub pamięcią stykową. Chociaż często błędnie określa się go jako klucz „magnetyczny”, **nie ma w nim nic magnetycznego**. W rzeczywistości wewnątrz znajduje się w pełni funkcjonalny **mikrochip** działający zgodnie z cyfrowym protokołem.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Czym jest iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Zwykle iButton oznacza fizyczną postać klucza i czytnika — okrągłą monetę z dwoma stykami. Obudowa, w której się on znajduje, może mieć wiele wariantów: od najpopularniejszego plastikowego uchwytu z otworem po pierścienie, zawieszki itp.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Gdy klucz zetknie się z czytnikiem, **styki dotykają się**, a klucz zostaje zasilony, aby **przesłać** swój identyfikator. Czasami klucz **nie jest odczytywany** natychmiast, ponieważ **PSD styków interkomu jest większy**, niż powinien być. W rezultacie zewnętrzne krawędzie klucza i czytnika nie mogą się zetknąć. W takim przypadku trzeba docisnąć klucz do jednej ze ścianek czytnika.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protokół 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Klucze Dallas wymieniają dane za pomocą protokołu 1-wire. Do transferu danych w obu kierunkach — od mastera do slave’a i odwrotnie — używany jest tylko jeden styk (!!). Protokół 1-wire działa zgodnie z modelem Master-Slave. W tej topologii Master zawsze inicjuje komunikację, a Slave wykonuje jego instrukcje.

Gdy klucz (Slave) zetknie się z interkomem (Master), znajdujący się w kluczu chip włącza się, zasilany przez interkom, a klucz zostaje zainicjalizowany. Następnie interkom żąda identyfikatora klucza. Przyjrzyjmy się teraz temu procesowi bardziej szczegółowo.

Flipper może działać zarówno w trybie Master, jak i Slave. W trybie odczytu klucza Flipper działa jako czytnik, czyli jako Master. W trybie emulacji klucza Flipper udaje klucz i działa w trybie Slave.<sup>[[1]](#references)</sup>

### Klucze Dallas, Cyfral i Metakom

Informacje o działaniu tych kluczy można znaleźć na stronie [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Ataki

iButtons można atakować za pomocą Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Referencje

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
