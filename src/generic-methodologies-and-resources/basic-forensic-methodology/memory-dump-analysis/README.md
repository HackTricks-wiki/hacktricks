# Аналіз дампа пам'яті

{{#include ../../../banners/hacktricks-training.md}}

## Початок

Почніть **пошук** **malware** усередині pcap. Використовуйте **інструменти**, згадані в [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility — це основний open-source фреймворк для аналізу дампів пам'яті**. Цей Python-інструмент аналізує дампи із зовнішніх джерел або VMware VM, ідентифікуючи такі дані, як процеси та паролі, на основі профілю ОС дампа. Його можна розширювати за допомогою plugins, що робить його надзвичайно універсальним для forensic investigations.

[**Cheatsheet тут**](volatility-cheatsheet.md)

## Звіт про збій mini dump

Якщо дамп невеликий (усього кілька KB, можливо, кілька MB), то, ймовірно, це звіт про збій mini dump, а не дамп пам'яті.

![Volatility - Звіт про збій mini dump: Якщо дамп невеликий (усього кілька KB, можливо, кілька MB), то, ймовірно, це звіт про збій mini dump, а не дамп пам'яті](<../../../images/image (532).png>)

Якщо у вас встановлено Visual Studio, ви можете відкрити цей файл і отримати базову інформацію, як-от назву процесу, архітектуру, інформацію про exception та modules, що виконуються:

![Volatility - Звіт про збій mini dump: Якщо у вас встановлено Visual Studio, ви можете відкрити цей файл і отримати базову інформацію, як-от назву процесу, архітектуру, інформацію про exception та...](<../../../images/image (263).png>)

Також можна завантажити exception і переглянути decompiled instructions

![Volatility - Звіт про збій mini dump: Також можна завантажити exception і переглянути decompiled instructions](<../../../images/image (142).png>)

![Volatility - Звіт про збій mini dump: Також можна завантажити exception і переглянути decompiled instructions](<../../../images/image (610).png>)

У будь-якому разі Visual Studio не є найкращим інструментом для проведення глибокого аналізу дампа.

Для **глибокого** аналізу слід **відкрити** його за допомогою **IDA** або **Radare**.

{{#include ../../../banners/hacktricks-training.md}}
