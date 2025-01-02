# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Aby uzyskać więcej informacji na temat tego, czym jest iButton, sprawdź:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

**Niebieska** część poniższego obrazu to sposób, w jaki należy **umieścić prawdziwy iButton**, aby Flipper mógł **go odczytać.** **Zielona** część to sposób, w jaki należy **dotknąć czytnika** Flipperem zero, aby **prawidłowo emulować iButton**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

W trybie odczytu Flipper czeka na dotknięcie klucza iButton i jest w stanie przetworzyć dowolny z trzech typów kluczy: **Dallas, Cyfral i Metakom**. Flipper **samoistnie określi typ klucza**. Nazwa protokołu klucza zostanie wyświetlona na ekranie powyżej numeru ID.

### Add manually

Możliwe jest **ręczne dodanie** iButtona typu: **Dallas, Cyfral i Metakom**

### **Emulate**

Możliwe jest **emulowanie** zapisanych iButtonów (odczytanych lub dodanych ręcznie).

> [!NOTE]
> Jeśli nie możesz sprawić, aby oczekiwane styki Flippera Zero dotknęły czytnika, możesz **użyć zewnętrznego GPIO:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
