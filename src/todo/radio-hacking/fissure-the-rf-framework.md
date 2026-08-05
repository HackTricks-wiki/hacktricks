# FISSURE - RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE — це open-source RF і reverse engineering framework, розроблений для користувачів будь-якого рівня підготовки, із підтримкою виявлення та класифікації сигналів, дослідження протоколів, виконання атак, маніпуляцій IQ, аналізу вразливостей, автоматизації та AI/ML. Framework створено для швидкої інтеграції програмних модулів, радіопристроїв, протоколів, даних сигналів, скриптів, flow graph, довідкових матеріалів і сторонніх інструментів. FISSURE спрощує робочі процеси: зберігає програмне забезпечення в одному місці та дає змогу командам швидко розпочати роботу, спільно використовуючи перевірену базову конфігурацію для певних дистрибутивів Linux.<sup>[[1]](#references)[[2]](#references)</sup>

Framework і інструменти, що входять до FISSURE, призначені для виявлення наявності RF-енергії, розуміння характеристик сигналу, збору й аналізу зразків, розробки методів передавання та/або ін'єкції, а також створення власних payload або повідомлень. FISSURE містить бібліотеку інформації про протоколи та сигнали, яка постійно розширюється й допомагає з ідентифікацією, створенням пакетів і fuzzing. Доступні можливості онлайн-архіву для завантаження файлів сигналів і створення playlist, що дають змогу імітувати трафік і тестувати системи.

Зручна codebase на Python і користувацький інтерфейс дають початківцям змогу швидко ознайомитися з популярними інструментами та техніками, пов'язаними з RF і reverse engineering. Викладачі з кібербезпеки та інженерії можуть використовувати вбудовані матеріали або framework для демонстрації власних практичних застосувань. Розробники й дослідники можуть використовувати FISSURE у щоденній роботі або представляти за його допомогою свої передові рішення ширшій аудиторії. У міру зростання обізнаності про FISSURE та його використання спільнотою розширюватимуться його можливості й спектр технологій, які він охоплює.

**Додаткова інформація**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Початок роботи

**Підтримувані системи**

У FISSURE є три гілки, що спрощують навігацію файлами та зменшують дублювання коду. Гілка Python2\_maint-3.7 містить codebase на основі Python2, PyQt4 і GNU Radio 3.7; Python3\_maint-3.8 — на основі Python3, PyQt5 і GNU Radio 3.8; а Python3\_maint-3.10 — на основі Python3, PyQt5 і GNU Radio 3.10.

|   Operating System   |   FISSURE Branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**У процесі розробки (beta)**

Ці операційні системи все ще мають статус beta. Вони перебувають у процесі розробки, і відомо, що в них відсутні деякі функції. Компоненти інсталятора можуть конфліктувати з наявними програмами або не встановлюватися, доки цей статус не буде знято.

|     Operating System     |    FISSURE Branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Примітка: деякі програмні інструменти не працюють у всіх ОС. Див. [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Встановлення**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Це встановить програмні залежності PyQt, необхідні для запуску графічних інтерфейсів встановлення, якщо їх не буде знайдено.

Далі виберіть опцію, яка найкраще відповідає вашій операційній системі (її має бути виявлено автоматично, якщо ваша ОС відповідає одній з опцій).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Рекомендується встановлювати FISSURE на чисту операційну систему, щоб уникнути наявних конфліктів. Виберіть усі рекомендовані прапорці (кнопка Default), щоб уникнути помилок під час роботи з різними інструментами у FISSURE. У процесі встановлення з’являтимуться численні запити, переважно щодо підвищених дозволів і імен користувачів. Якщо елемент містить наприкінці розділ "Verify", інсталятор виконає наведену після нього команду та підсвітить цей елемент прапорця зеленим або червоним залежно від того, чи виникли помилки під час виконання команди. Позначені елементи без розділу "Verify" після встановлення залишаться чорними.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Використання**

Відкрийте термінал і введіть:
```
fissure
```
Зверніться до меню Help у FISSURE, щоб дізнатися більше про використання.

## Деталі

**Компоненти**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![компоненти](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Можливості**

| ![піктограма детектора сигналів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![піктограма маніпуляції IQ](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![піктограма пошуку сигналів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![піктограма розпізнавання шаблонів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![піктограма атак](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![піктограма fuzzing](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![піктограма плейлистів сигналів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![піктограма галереї зображень](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![піктограма створення пакетів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![піктограма інтеграції Scapy](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![піктограма калькулятора CRC](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![піктограма журналювання](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Обладнання**

Нижче наведено список «підтримуваного» обладнання з різним рівнем інтеграції:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Адаптери 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Уроки

FISSURE містить кілька корисних посібників для ознайомлення з різними технологіями та техніками. Багато з них містять інструкції з використання різноманітних інструментів, інтегрованих у FISSURE.

* [Урок 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Урок 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Урок 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Урок 4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Урок 5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Урок 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Урок 7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Урок 8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Урок 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Урок 10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Урок 11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## План розвитку

* [ ] Додати більше типів обладнання, RF-протоколів, параметрів сигналів та інструментів аналізу
* [ ] Додати підтримку більшої кількості операційних систем
* [ ] Розробити навчальні матеріали про FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt тощо)
* [ ] Створити кондиціонер сигналу, екстрактор ознак і класифікатор сигналів із можливістю вибору методів AI/ML
* [ ] Реалізувати рекурсивні механізми демодуляції для отримання бітового потоку з невідомих сигналів
* [ ] Перевести основні компоненти FISSURE на універсальну схему розгортання сенсорних вузлів

## Участь у розробці

Ми наполегливо вітаємо пропозиції щодо вдосконалення FISSURE. Залиште коментар на сторінці [Discussions](https://github.com/ainfosec/FISSURE/discussions) або на Discord Server, якщо маєте думки щодо наведеного нижче:

* Пропозиції нових функцій і зміни дизайну
* Програмні інструменти з інструкціями зі встановлення
* Нові уроки або додаткові матеріали для наявних уроків
* Цікаві RF-протоколи
* Додаткові типи обладнання та SDR для інтеграції
* Скрипти аналізу IQ на Python
* Виправлення та вдосконалення процесу встановлення

Внески для вдосконалення FISSURE мають вирішальне значення для прискорення його розробки. Ми високо цінуємо будь-який ваш внесок. Якщо ви бажаєте долучитися до розробки коду, створіть fork репозиторію та pull request:

1. Створіть fork проєкту
2. Створіть свою feature branch (`git checkout -b feature/AmazingFeature`)
3. Зробіть commit змін (`git commit -m 'Add some AmazingFeature'`)
4. Виконайте push у branch (`git push origin feature/AmazingFeature`)
5. Відкрийте pull request

Також вітається створення [Issues](https://github.com/ainfosec/FISSURE/issues), щоб привернути увагу до помилок.

## Співпраця

Зв’яжіться з відділом Business Development компанії Assured Information Security, Inc. (AIS), щоб запропонувати та офіційно оформити можливості співпраці щодо FISSURE — незалежно від того, чи йдеться про виділення часу на інтеграцію вашого програмного забезпечення, розробку фахівцями AIS рішень для ваших технічних завдань або інтеграцію FISSURE в інші платформи чи застосунки.

## Ліцензія

GPL-3.0

Докладнішу інформацію про ліцензію дивіться у файлі LICENSE.

## Контакти

Приєднуйтеся до Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Слідкуйте у Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Автори

Ми визнаємо внесок і висловлюємо вдячність таким розробникам:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Подяки

Особлива подяка Dr. Samuel Mantravadi та Joseph Reith за їхній внесок у цей проєкт.

## Посилання

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
