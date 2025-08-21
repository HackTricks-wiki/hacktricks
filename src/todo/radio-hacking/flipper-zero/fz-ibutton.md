# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Для отримання додаткової інформації про те, що таке iButton, перегляньте:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

**Синя** частина наступного зображення - це те, як вам потрібно **поставити справжній iButton**, щоб Flipper міг **прочитати його.** **Зелена** частина - це те, як вам потрібно **доторкнутися до зчитувача** з Flipper zero, щоб **правильно емуляувати iButton**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

У режимі читання Flipper чекає, поки iButton не доторкнеться, і може обробляти будь-який з трьох типів ключів: **Dallas, Cyfral, і Metakom**. Flipper **визначить тип ключа самостійно**. Назва протоколу ключа буде відображена на екрані над номером ID.

### Add manually

Можна **додати вручну** iButton типу: **Dallas, Cyfral, і Metakom**

### **Emulate**

Можна **емуляувати** збережені iButtons (прочитані або додані вручну).

> [!TIP]
> Якщо ви не можете зробити так, щоб очікувані контакти Flipper Zero доторкнулися до зчитувача, ви можете **використати зовнішній GPIO:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
