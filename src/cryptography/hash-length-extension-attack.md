{{#include ../banners/hacktricks-training.md}}

# Podsumowanie ataku

Wyobraź sobie serwer, który **podpisuje** pewne **dane** przez **dodanie** **sekretu** do znanych danych w postaci czystego tekstu, a następnie hashuje te dane. Jeśli wiesz:

- **Długość sekretu** (można to również brutalnie wymusić z danego zakresu długości)
- **Dane w postaci czystego tekstu**
- **Algorytm (i jest podatny na ten atak)**
- **Padding jest znany**
- Zwykle używany jest domyślny, więc jeśli pozostałe 3 wymagania są spełnione, to również jest
- Padding różni się w zależności od długości sekretu + danych, dlatego długość sekretu jest potrzebna

Wtedy możliwe jest, aby **atakujący** **dodał** **dane** i **wygenerował** ważny **podpis** dla **poprzednich danych + dodanych danych**.

## Jak?

Zasadniczo podatne algorytmy generują hashe, najpierw **hashując blok danych**, a następnie, **z** wcześniej utworzonego **hasha** (stanu), **dodają następny blok danych** i **hashują go**.

Wyobraź sobie, że sekret to "secret", a dane to "data", MD5 "secretdata" to 6036708eba0d11f6ef52ad44e8b74d5b.\
Jeśli atakujący chce dodać ciąg "append", może:

- Wygenerować MD5 z 64 "A"
- Zmienić stan wcześniej zainicjowanego hasha na 6036708eba0d11f6ef52ad44e8b74d5b
- Dodać ciąg "append"
- Zakończyć hash, a wynikowy hash będzie **ważny dla "secret" + "data" + "padding" + "append"**

## **Narzędzie**

{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}

## Odniesienia

Możesz znaleźć ten atak dobrze wyjaśniony w [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../banners/hacktricks-training.md}}
