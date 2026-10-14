# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Informacje na temat technologii iButton znajdziesz tutaj:

{{#ref}}
../ibutton.md
{{#endref}}

## Konstrukcja

Na poniższym obrazie **niebieski** obszar pokazuje, jak przyłożyć fizyczny iButton do styków Flipper Zero, aby go odczytać. **Zielony** obszar pokazuje, które styki powinny dotykać czytnika podczas emulacji.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Działania

### Odczyt

W trybie odczytu Flipper Zero czeka, aż klucz dotknie jego styków, wykrywa protokół i wyświetla go nad identyfikatorem klucza. Wbudowana aplikacja obsługuje klucze kontroli dostępu w standardach Dallas, Cyfral i Metakom.<sup>[[2]](#references)</sup>

### Dodaj ręcznie

Możesz ręcznie wprowadzić dane klucza dla protokołów Dallas, Cyfral i Metakom.<sup>[[2]](#references)</sup>

### Emuluj

Możesz emulować zapisany klucz, niezależnie od tego, czy został odczytany z fizycznego klucza, czy wprowadzony ręcznie.<sup>[[2]](#references)</sup>

> [!TIP]
> Jeśli wbudowane styki nie sięgają czytnika, połącz styki danych i masy przez piny GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Oszwajanie kluczy iButton za pomocą Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Dokumentacja Flipper Zero - Odczytywanie kluczy iButton](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

