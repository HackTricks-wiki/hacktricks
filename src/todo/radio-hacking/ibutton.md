# iButton

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

iButton to ogólna nazwa elektronicznego klucza identyfikacyjnego umieszczonego w **metalowej obudowie w kształcie monety**. Nazywa się go również pamięcią **Dallas Touch** lub pamięcią kontaktową. Chociaż często błędnie określa się go jako klucz „magnetyczny”, **nie ma w nim nic magnetycznego**. W rzeczywistości wewnątrz znajduje się pełnoprawny **microchip** działający w oparciu o cyfrowy protokół.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Czym jest iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Zwykle iButton oznacza fizyczną formę klucza i czytnika — okrągłą monetę z dwoma stykami. Istnieje wiele wariantów oprawy, w której jest umieszczony: od najpopularniejszego plastikowego uchwytu z otworem po pierścienie, zawieszki itd.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Gdy klucz dotrze do czytnika, **styki stykają się ze sobą**, a klucz zostaje zasilony, aby **przesłać** swój identyfikator. Czasami klucz **nie jest odczytywany** od razu, ponieważ **powierzchnia stykowa PSD domofonu jest większa**, niż powinna. Zewnętrzne krawędzie klucza i czytnika nie mogą się wtedy zetknąć. W takim przypadku należy docisnąć klucz do jednej ze ścianek czytnika.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protokół 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Klucze Dallas wymieniają dane za pomocą protokołu 1-wire. Do transferu danych w obu kierunkach — od mastera do slave'a i odwrotnie — używany jest tylko jeden styk (!!). Protokół 1-wire działa zgodnie z modelem Master-Slave. W tej topologii Master zawsze inicjuje komunikację, a Slave wykonuje jego instrukcje.

Gdy klucz (Slave) zetknie się z domofonem (Master), znajdujący się wewnątrz klucza chip włącza się, czerpiąc zasilanie z domofonu, a następnie klucz zostaje zainicjalizowany. Domofon żąda później identyfikatora klucza. Następnie przyjrzymy się temu procesowi bardziej szczegółowo.

Flipper może działać zarówno w trybie Master, jak i Slave. W trybie odczytu klucza Flipper działa jako czytnik, czyli jako Master. W trybie emulacji klucza Flipper udaje klucz i działa w trybie Slave.

### Klucze Dallas, Cyfral i Metakom

Informacje o działaniu tych kluczy znajdziesz na stronie [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Ataki

Na iButtons można przeprowadzać ataki za pomocą Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Referencje

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
