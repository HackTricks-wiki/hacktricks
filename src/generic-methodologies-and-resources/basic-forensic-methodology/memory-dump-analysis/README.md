# Аналіз дампа пам'яті

## Початок

Почніть **шукати** **malware** у pcap. Використовуйте **інструменти**, згадані в [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility — це open-source фреймворк для аналізу дампів пам'яті**. Цей Python-інструмент аналізує дампи із зовнішніх джерел або VMware VM, ідентифікуючи такі дані, як процеси та паролі, на основі профілю ОС дампа. Його можна розширювати за допомогою плагінів, що робить його надзвичайно універсальним для forensic-розслідувань.<sup>[[1]](#references)[[2]](#references)</sup>

[**Шпаргалка доступна тут**](volatility-cheatsheet.md)

## Звіт про збій у мінідампі

Якщо дамп невеликий (усього кілька KB, можливо, кілька MB), це може бути звіт про збій у мінідампі, а не повний дамп пам'яті.<sup>[[3]](#references)</sup>

![Volatility — звіт про збій у мінідампі: невеликий файл дампа, ідентифікований як звіт про збій Mini DuMP](<../../../images/image (532).png>)

Якщо у вас встановлено Visual Studio, ви можете відкрити цей файл, щоб переглянути основну інформацію, таку як назва процесу, архітектура, відомості про виняток і завантажені модулі:<sup>[[4]](#references)</sup>

![Volatility — звіт про збій у мінідампі: якщо у вас встановлено Visual Studio, ви можете відкрити цей файл і отримати основну інформацію, таку як назва процесу, архітектура, відомості про виняток тощо](<../../../images/image (263).png>)

Ви також можете перевірити виняток і переглянути дизасемблювання модуля.<sup>[[4]](#references)</sup>

![Панель дій Visual Studio для мінідампа з параметрами нативного налагодження та налаштування шляхів до символів](<../../../images/image (142).png>)

![Дизасемблювання інструкцій винятку мінідампа у Visual Studio](<../../../images/image (610).png>)

У будь-якому разі Visual Studio не є найкращим інструментом для виконання глибокого аналізу дампа.

Вам слід **відкрити** його за допомогою **IDA** або **Radare**, щоб виконати його **глибокий** аналіз.

## References

- [1] [Фреймворк Volatility](https://github.com/volatilityfoundation/volatility)
- [2] [Використання Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Файли мінідампа](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Використання файлів дампа у відладчику Visual Studio](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
