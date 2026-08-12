# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Довідкову інформацію про технологію iButton див. тут:

{{#ref}}
../ibutton.md
{{#endref}}

## Конструкція

На зображенні нижче **синя** область показує, як розмістити фізичний iButton навпроти контактів Flipper Zero для зчитування. **Зелена** область показує, які контакти мають торкатися зчитувача під час емуляції.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Дії

### Зчитування

У режимі зчитування Flipper Zero очікує, поки ключ торкнеться його контактів, визначає протокол і відображає протокол над ідентифікатором ключа. Вбудований застосунок підтримує ключі контролю доступу Dallas, Cyfral і Metakom.<sup>[[2]](#references)</sup>

### Додавання вручну

Можна вручну ввести дані ключа для протоколів Dallas, Cyfral і Metakom.<sup>[[2]](#references)</sup>

### Емуляція

Можна емулювати збережений ключ незалежно від того, чи його було зчитано з фізичного ключа, чи введено вручну.<sup>[[2]](#references)</sup>

> [!TIP]
> Якщо вбудовані контакти не можуть дістатися до зчитувача, з'єднайте контакти даних і заземлення через контакти GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero documentation - Reading iButton keys](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
