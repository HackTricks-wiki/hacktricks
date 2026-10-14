# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Довідкову інформацію про технологію iButton дивіться тут:

{{#ref}}
../ibutton.md
{{#endref}}

## Конструкція

На зображенні нижче **синя** область показує, як прикласти фізичний iButton до контактів Flipper Zero для зчитування. **Зелена** область показує, які контакти мають торкатися зчитувача під час емуляції.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Дії

### Читання

У режимі читання Flipper Zero очікує, доки ключ торкнеться його контактів, визначає протокол і відображає його над ID ключа. Вбудований застосунок підтримує ключі контролю доступу Dallas, Cyfral і Metakom.<sup>[[2]](#references)</sup>

### Додати вручну

Дані ключа для протоколів Dallas, Cyfral і Metakom можна ввести вручну.<sup>[[2]](#references)</sup>

### Емуляція

Можна емулювати збережений ключ, зчитаний із фізичного ключа або введений вручну.<sup>[[2]](#references)</sup>

> [!TIP]
> Якщо вбудовані контакти не дістають до зчитувача, з’єднайте контакти даних і заземлення через контакти GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Приборкання ключів iButton за допомогою Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Документація Flipper Zero - Зчитування ключів iButton](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

