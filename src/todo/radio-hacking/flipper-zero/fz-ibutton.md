# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Вступ

Докладніше про те, що таке iButton, дивіться:


{{#ref}}
../ibutton.md
{{#endref}}

## Конструкція

**Синя** частина наведеного нижче зображення показує, як потрібно **розмістити справжній iButton**, щоб Flipper міг його **зчитати.** **Зелена** частина показує, як потрібно **доторкнутися Flipper zero до зчитувача**, щоб **коректно емулювати iButton**.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Дії

### Зчитування

У режимі Read Flipper очікує, коли ключ iButton торкнеться його, і може обробляти ключі трьох типів: **Dallas, Cyfral та Metakom**. Flipper **сам визначить тип ключа**. Назву протоколу ключа буде відображено на екрані над номером ID.<sup>[[1]](#references)</sup>

### Додавання вручну

Можна **вручну додати** iButton типу: **Dallas, Cyfral та Metakom**

### **Емуляція**

Можна **емулювати** збережені iButton (зчитані або додані вручну).

> [!TIP]
> Якщо вам не вдається забезпечити потрібний контакт Flipper Zero зі зчитувачем, ви можете **використати зовнішній GPIO:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Посилання

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
