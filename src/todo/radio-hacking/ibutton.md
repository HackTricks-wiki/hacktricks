# iButton

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

iButton to ogólna nazwa elektronicznego klucza identyfikacyjnego umieszczonego w **metalowej obudowie w kształcie monety**. Nazywa się go również pamięcią typu **Dallas Touch** lub pamięcią stykową. Mimo że często błędnie określa się go jako klucz „magnetyczny”, **nie ma w nim nic magnetycznego**. W rzeczywistości wewnątrz znajduje się w pełni funkcjonalny **mikrochip** działający w oparciu o cyfrowy protokół.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Czym jest iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Nazwa iButton opisuje trwałą obudowę w kształcie monety oraz układ styków. Uchwyty obejmują plastikowe breloki, pierścienie i zawieszki.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Gdy oba styki zetkną się z czytnikiem, urządzenie otrzymuje zasilanie i wymienia dane. Jeśli zagłębiona geometria styków uniemożliwia zetknięcie się zewnętrznych styków masy, przechylenie klucza w kierunku ścianki czytnika może przywrócić kontakt.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protokół 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Klucze Dallas/Maxim używają protokołu 1-Wire: jeden styk danych obsługuje dwukierunkową komunikację i może również dostarczać zasilanie pasożytnicze, podczas gdy metalowa obudowa pełni funkcję styku powrotnego. Kontroler inicjuje transakcje, a urządzenie odpowiada.<sup>[[2]](#references)</sup>

Gdy klucz (Slave) zetknie się z domofonem (Master), znajdujący się w kluczu chip włącza się, zasilany przez domofon, a klucz zostaje zainicjalizowany. Następnie domofon wysyła do klucza żądanie identyfikatora. Dalej przyjrzymy się temu procesowi bardziej szczegółowo.

Flipper może działać jako kontroler podczas odczytu klucza oraz jako emulowane urządzenie podczas prezentowania zapisanego identyfikatora czytnikowi.<sup>[[1]](#references)</sup>

### Klucze Dallas, Cyfral i Metakom

Informacje o działaniu tych kluczy znajdziesz na stronie [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Ataki

iButton można atakować za pomocą Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Poskramianie iButton za pomocą Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — komunikacja 1-Wire za pomocą software'u](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
