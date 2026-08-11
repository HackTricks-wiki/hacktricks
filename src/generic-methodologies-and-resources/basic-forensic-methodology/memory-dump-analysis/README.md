# Аналіз дампа пам'яті

{{#include ../../../banners/hacktricks-training.md}}

## Початок

Почніть **пошук** **malware** у pcap. Використовуйте **інструменти**, згадані в [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility — це open-source фреймворк для аналізу дампів пам'яті**. Цей Python-інструмент аналізує дампи із зовнішніх джерел або VMware VM, ідентифікуючи такі дані, як процеси та паролі, на основі профілю ОС дампа. Він розширюється за допомогою плагінів, що робить його надзвичайно універсальним для forensic-розслідувань.<sup>[[1]](#references)[[2]](#references)</sup>

[**Знайдіть тут cheatsheet**](volatility-cheatsheet.md)

## Звіт про збій у mini dump

Якщо дамп невеликий (лише кілька KB, можливо, кілька MB), це може бути звіт про збій у mini dump, а не повний дамп пам'яті.<sup>[[3]](#references)</sup>

![Volatility - Звіт про збій у mini dump: Невеликий файл дампа, ідентифікований як звіт про збій Mini DuMP](<../../../images/image (532).png>)

Якщо у вас встановлено Visual Studio, ви можете відкрити цей файл для перегляду базової інформації, такої як назва процесу, архітектура, відомості про виняток і завантажені модулі:<sup>[[4]](#references)</sup>

![Volatility - Звіт про збій у mini dump: Якщо у вас встановлено Visual Studio, ви можете відкрити цей файл і переглянути базову інформацію, таку як назва процесу, архітектура, відомості про виняток та інше](<../../../images/image (263).png>)

Ви також можете перевірити виняток і переглянути дизасемблювання модуля.<sup>[[4]](#references)</sup>

![Панель дій Visual Studio для minidump із параметрами налагодження у нативному режимі та налаштування шляхів до символів](<../../../images/image (142).png>)

![Дизасемблювання інструкцій із винятку minidump у Visual Studio](<../../../images/image (610).png>)

У будь-якому разі Visual Studio — не найкращий інструмент для глибокого аналізу дампа.

Вам слід **відкрити** його за допомогою **IDA** або **Radare**, щоб виконати його **глибокий** аналіз.

## References

- [1] [Фреймворк Volatility](https://github.com/volatilityfoundation/volatility)
- [2] [Використання Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Файли Minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Використання файлів дампа у debugger Visual Studio](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
