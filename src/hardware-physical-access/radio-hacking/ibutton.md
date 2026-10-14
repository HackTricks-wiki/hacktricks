# iButton

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

iButton to ogólna nazwa elektronicznego klucza identyfikacyjnego umieszczonego w **metalowej obudowie w kształcie monety**. Nazywa się go również pamięcią Dallas Touch lub pamięcią kontaktową. Choć często błędnie określa się go jako klucz „magnetyczny”, **nie ma w nim nic magnetycznego**. W rzeczywistości wewnątrz znajduje się pełnoprawny **mikrochip** działający w oparciu o protokół cyfrowy.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### Czym jest iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Nazwa iButton opisuje trwałą obudowę w kształcie monety i układ styków. Dostępne są uchwyty w formie plastikowych breloków, pierścionków i zawieszek.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Gdy oba styki zetkną się z czytnikiem, urządzenie otrzymuje zasilanie i wymienia dane. Jeśli zagłębiona geometria styków uniemożliwia zetknięcie zewnętrznych styków masy, przechylenie klucza przy ściance czytnika może przywrócić kontakt.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protokół 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Klucze Dallas/Maxim korzystają z protokołu 1-Wire: jeden styk danych obsługuje komunikację dwukierunkową i może również dostarczać zasilanie pasożytnicze, a metalowa obudowa pełni funkcję styku powrotnego. Kontroler inicjuje transakcje, a urządzenie odpowiada.<sup>[[2]](#references)</sup>

Gdy klucz (urządzenie podrzędne) zetknie się z domofonem (urządzeniem nadrzędnym), znajdujący się w nim chip włącza się, zasilany przez domofon, i klucz zostaje zainicjowany. Następnie domofon żąda identyfikatora klucza. Poniżej przyjrzymy się temu procesowi bardziej szczegółowo.

Flipper może działać jako kontroler podczas odczytywania klucza oraz jako emulowane urządzenie, gdy przekazuje zapisany identyfikator do czytnika.<sup>[[1]](#references)</sup>

### Klucze Dallas, Cyfral i Metakom

Informacje o działaniu tych kluczy znajdziesz na stronie [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Ataki

Klucze iButton można atakować za pomocą Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Oswajanie iButton za pomocą Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — komunikacja 1-Wire za pomocą oprogramowania](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
