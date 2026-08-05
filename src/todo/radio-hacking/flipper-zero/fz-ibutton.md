# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Więcej informacji o tym, czym jest iButton, znajdziesz tutaj:


{{#ref}}
../ibutton.md
{{#endref}}

## Konstrukcja

**Niebieska** część poniższego obrazu pokazuje, jak należy **przyłożyć prawdziwy iButton**, aby Flipper mógł go **odczytać.** **Zielona** część pokazuje, jak należy **przyłożyć czytnik** do Flipper Zero, aby **prawidłowo emulować iButton**.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Działania

### Odczyt

W trybie odczytu Flipper oczekuje na przyłożenie klucza iButton i potrafi obsługiwać trzy typy kluczy: **Dallas, Cyfral i Metakom**. Flipper **sam określi typ klucza**. Nazwa protokołu klucza zostanie wyświetlona na ekranie nad numerem ID.<sup>[[1]](#references)</sup>

### Dodawanie ręczne

Możliwe jest **ręczne dodanie** iButton typu: **Dallas, Cyfral i Metakom**

### **Emulacja**

Możliwe jest **emulowanie** zapisanych iButtonów (odczytanych lub dodanych ręcznie).

> [!TIP]
> Jeśli nie możesz uzyskać oczekiwanego kontaktu Flipper Zero z czytnikiem, możesz **użyć zewnętrznego GPIO:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Referencje

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
