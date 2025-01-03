# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Для отримання додаткової інформації про те, що таке iButton, дивіться:

{{#ref}}
../ibutton.md
{{#endref}}

## Дизайн

**Синя** частина наступного зображення - це те, як вам потрібно **поставити справжній iButton**, щоб Flipper міг **зчитати його.** **Зелена** частина - це те, як вам потрібно **доторкнутися до зчитувача** з Flipper zero, щоб **правильно емулювати iButton**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Дії

### Зчитування

У режимі зчитування Flipper чекає, поки ключ iButton доторкнеться, і може обробляти будь-який з трьох типів ключів: **Dallas, Cyfral та Metakom**. Flipper **визначить тип ключа самостійно**. Назва протоколу ключа буде відображена на екрані над номером ID.

### Додати вручну

Можна **додати вручну** iButton типу: **Dallas, Cyfral та Metakom**

### **Емулювати**

Можна **емулювати** збережені iButtons (зчитані або додані вручну).

> [!NOTE]
> Якщо ви не можете зробити очікувані контакти Flipper Zero зчитувача, ви можете **використати зовнішній GPIO:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Посилання

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
