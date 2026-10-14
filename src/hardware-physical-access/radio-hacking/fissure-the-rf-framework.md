# FISSURE - RF-фреймворк

{{#include ../../banners/hacktricks-training.md}}

**Розуміння та зворотна розробка сигналів на базі SDR, незалежні від частоти**

FISSURE — це open-source фреймворк для RF і зворотної розробки, розроблений для користувачів із будь-яким рівнем навичок. Він надає засоби для виявлення та класифікації сигналів, дослідження протоколів, виконання атак, маніпуляцій з IQ, аналізу вразливостей, автоматизації та роботи з AI/ML. Фреймворк створено для швидкої інтеграції програмних модулів, радіопристроїв, протоколів, даних сигналів, скриптів, блок-схем, довідкових матеріалів і сторонніх інструментів. FISSURE допомагає організувати робочий процес: зберігає програмне забезпечення в одному місці та дає змогу командам швидко почати роботу, використовуючи спільну перевірену базову конфігурацію для певних дистрибутивів Linux.<sup>[[1]](#references)[[2]](#references)</sup>

Фреймворк і інструменти FISSURE призначені для виявлення RF-енергії, аналізу сигналів, збору й аналізу зразків, розробки методів передавання або ін’єкції, а також створення власних корисних навантажень і повідомлень. FISSURE також надає інформацію про протоколи й сигнали для їх ідентифікації, створення пакетів і fuzzing, а також архіви й списки відтворення для симуляції та тестування трафіку.<sup>[[1]](#references)[[2]](#references)</sup>

Кодова база на Python і графічний інтерфейс допомагають початківцям опановувати RF-інструменти та інструменти зворотної розробки. Викладачі можуть використовувати вбудовані уроки, а розробники й дослідники — інтегрувати власні модулі та робочі процеси. Поточні випуски також підтримують розподілені сенсорні вузли, інтеграцію з TAK, робочі процеси геолокації та розгортання Apptainer із розподілом за ролями.<sup>[[1]](#references)[[3]](#references)</sup>

**Додаткова інформація**

* [Сторінка AIS](https://www.ainfosec.com/technologies/fissure/)
* [Слайди GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Стаття GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Відео GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Транскрипт Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Початок роботи

**Підтримується**

У поточній версії FISSURE для активної розробки використовується гілка **`Python3`** із PyQt5 і GNU Radio 3.8 або 3.10. Застаріла гілка **`Python2_maint-3.7`** залишається доступною для старіших операційних систем і сторонніх інструментів, яким потрібна GNU Radio 3.7. Колишні назви гілок `Python3_maint-3.8` і `Python3_maint-3.10` є історичними; вибір версії GNU Radio для обслуговування тепер здійснюється з гілки `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Операційна система | Гілка FISSURE | Гілка GNU Radio за замовчуванням |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | використовуйте підтримувану версію Linux | використовуйте відповідну версію |

**У розробці (бета)**

Ці операційні системи поки що мають статус бета. Вони перебувають у розробці, і відомо, що в них відсутні деякі функції. Компоненти інсталятора можуть конфліктувати з наявними програмами або не встановлюватися, доки цей статус не буде знято.

| Операційна система | Гілка FISSURE | Гілка GNU Radio за замовчуванням |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Деякі сторонні інструменти працюють не в усіх ОС. Перед встановленням ознайомтеся з актуальною документацією [Відомі конфлікти та стороннє програмне забезпечення](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts).<sup>[[3]](#references)</sup>

**Встановлення**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

Крок із підмодулем завантажує модулі GNU Radio out-of-tree, які використовує FISSURE, і є обов’язковим для встановлення цих модулів. Інсталятор також встановить відсутні залежності PyQt, потрібні для запуску графічних інтерфейсів інсталяції.<sup>[[3]](#references)</sup>

Далі виберіть варіант, який найкраще відповідає вашій операційній системі (якщо ваша ОС відповідає одному з варіантів, він має визначитися автоматично).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Рекомендується встановлювати FISSURE на чисту операційну систему, щоб уникнути наявних конфліктів. Позначте всі рекомендовані прапорці (кнопка Default), щоб уникнути помилок під час роботи з різними інструментами FISSURE. Під час інсталяції з’явиться кілька запитів, переважно щодо підвищених прав і імен користувачів. Якщо наприкінці пункту є розділ "Verify", інсталятор виконає наведену команду та підсвітить відповідний прапорець зеленим або червоним залежно від того, чи спричинила команда помилки. Позначені пункти без розділу "Verify" після інсталяції залишаться чорними.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Використання**

Відкрийте термінал і введіть:

```
fissure
```

Зверніться до меню Help у FISSURE, щоб дізнатися більше про використання.

## Деталі

**Компоненти**

* Панель керування
* Центральний вузол (HIPRFISR)
* Ідентифікація цільового сигналу (TSI)
* Виявлення протоколів (PD)
* Виконавець графів потоків і скриптів (FGE)

![компоненти](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Можливості**

| ![Піктограма детектора сигналу](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Детектор сигналу**_ | ![Піктограма маніпуляції IQ](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Маніпуляція IQ**_      | ![Піктограма пошуку сигналу](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Пошук сигналу**_          | ![Піктограма розпізнавання шаблонів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Розпізнавання шаблонів**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Піктограма атак](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Атаки**_           | ![Піктограма Fuzzing](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Піктограма списків відтворення сигналів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Списки відтворення сигналів**_       | ![Піктограма галереї зображень](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Галерея зображень**_  |
| ![Піктограма створення пакетів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Створення пакетів**_   | ![Піктограма інтеграції Scapy](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Інтеграція Scapy**_ | ![Піктограма калькулятора CRC](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Калькулятор CRC**_ | ![Піктограма журналювання](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Журналювання**_            |

**Обладнання**

Рівень інтеграції наведеного нижче обладнання з FISSURE відрізняється:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Адаптери 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Уроки

FISSURE містить кілька корисних посібників, які допоможуть ознайомитися з різними технологіями та методами. У багатьох з них наведено інструкції з використання різноманітних інструментів, інтегрованих у FISSURE.

* [Урок 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Урок 2: Lua-дисектори](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Урок 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Урок 4: Плати ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Урок 5: Відстеження радіозондів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Урок 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Урок 7: Типи даних](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Урок 8: Користувацькі блоки GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Урок 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Урок 10: Іспити з аматорського радіозв’язку](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Урок 11: Інструменти Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Урок 12: Створення завантажувальних USB-носіїв](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Урок 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Урок 14: Стельові вентилятори](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Дорожня карта

* [ ] Додати більше типів обладнання, RF-протоколів, параметрів сигналу й інструментів аналізу
* [ ] Забезпечити підтримку більшої кількості операційних систем
* [ ] Розробити навчальні матеріали на основі FISSURE (RF-атаки, Wi-Fi, GNU Radio, PyQt тощо)
* [ ] Створити кондиціонер сигналу, екстрактор ознак і класифікатор сигналів із можливістю вибору методів AI/ML
* [ ] Реалізувати механізми рекурсивної демодуляції для отримання бітового потоку з невідомих сигналів
* [ ] Перевести основні компоненти FISSURE на універсальну схему розгортання сенсорних вузлів

## Участь у розробці

Ми заохочуємо пропозиції щодо вдосконалення FISSURE. Залиште коментар на сторінці [Обговорення](https://github.com/ainfosec/FISSURE/discussions) або на Discord-сервері, якщо маєте ідеї щодо наведеного нижче:

* Пропозиції нових функцій і зміни дизайну
* Програмні інструменти з інструкціями зі встановлення
* Нові уроки або додаткові матеріали до наявних уроків
* RF-протоколи, що становлять інтерес
* Додаткове обладнання та типи SDR для інтеграції
* Скрипти аналізу IQ на Python
* Виправлення та покращення процесу встановлення

Ваш внесок у вдосконалення FISSURE має вирішальне значення для прискорення його розробки. Ми будемо вдячні за будь-який внесок. Якщо ви хочете долучитися до розробки коду, зробіть форк репозиторію та створіть pull request:

1. Зробіть форк проєкту
2. Створіть гілку функції (`git checkout -b feature/AmazingFeature`)
3. Зафіксуйте зміни (`git commit -m 'Add some AmazingFeature'`)
4. Надішліть зміни до гілки (`git push origin feature/AmazingFeature`)
5. Створіть pull request

Також вітається створення [Issues](https://github.com/ainfosec/FISSURE/issues), щоб повідомити про помилки.

## Співпраця

Зверніться до відділу розвитку бізнесу Assured Information Security, Inc. (AIS), щоб запропонувати та офіційно оформити можливості співпраці над FISSURE — чи то виділити час на інтеграцію вашого програмного забезпечення, доручити талановитим фахівцям AIS розробити рішення для ваших технічних завдань, чи інтегрувати FISSURE в інші платформи або застосунки.

## Ліцензія

GPL-3.0

Докладніше про ліцензію див. у файлі LICENSE.

## Контакти

Приєднуйтеся до Discord-сервера: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Стежте за нами у Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Відділ розвитку бізнесу - Assured Information Security, Inc. - bd@ainfosec.com

## Подяки

Ми висловлюємо вдячність таким розробникам:

[Подяки](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Особлива подяка

Особлива подяка доктору Samuel Mantravadi та Joseph Reith за їхній внесок у цей проєкт.

## References

- [1] [FISSURE - RF-фреймворк (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [Стаття про FISSURE (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Документація FISSURE - Встановлення](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
