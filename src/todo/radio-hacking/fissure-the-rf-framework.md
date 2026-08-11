# FISSURE - RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Розуміння сигналів і reverse engineering на основі Frequency Independent SDR**

FISSURE — це open-source RF і reverse engineering framework, розроблений для фахівців будь-якого рівня та оснащений механізмами виявлення й класифікації сигналів, дослідження протоколів, виконання атак, маніпуляції IQ, аналізу вразливостей, автоматизації та AI/ML. Framework створено для швидкої інтеграції програмних модулів, радіопристроїв, протоколів, даних сигналів, скриптів, flow graphs, довідкових матеріалів і сторонніх інструментів. FISSURE — це інструмент для організації робочих процесів, який зберігає програмне забезпечення в одному місці та дає змогу командам без зусиль починати роботу, використовуючи одну перевірену базову конфігурацію для конкретних дистрибутивів Linux.<sup>[[1]](#references)[[2]](#references)</sup>

Framework та інструменти, що входять до FISSURE, призначені для виявлення RF-енергії, визначення характеристик сигналів, збору й аналізу семплів, розробки методів передавання або ін'єкції, а також створення власних payloads чи повідомлень. FISSURE також надає інформацію про протоколи й сигнали для ідентифікації, створення пакетів і fuzzing, а також архіви та playlists для симуляції й тестування трафіку.<sup>[[1]](#references)[[2]](#references)</sup>

Python codebase і графічний інтерфейс допомагають початківцям вивчати RF та reverse-engineering інструменти. Викладачі можуть використовувати вбудовані уроки, а розробники й дослідники — інтегрувати власні модулі та робочі процеси. Поточні релізи також підтримують розподілені сенсорні вузли, інтеграцію з TAK, робочі процеси геолокації та рольові розгортання Apptainer.<sup>[[1]](#references)[[3]](#references)</sup>

**Додаткова інформація**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Початок роботи

**Підтримувані**

Поточна версія FISSURE використовує гілку **`Python3`** для активної розробки з PyQt5 і GNU Radio 3.8 або 3.10. Застаріла гілка **`Python2_maint-3.7`** залишається доступною для старих операційних систем і сторонніх інструментів, яким потрібен GNU Radio 3.7. Колишні назви гілок `Python3_maint-3.8` і `Python3_maint-3.10` є історичними; вибір версії GNU Radio тепер виконується з гілки `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | використовуйте підтримувану версію Linux | використовуйте відповідну версію |

**У процесі розробки (beta)**

Ці операційні системи все ще мають beta-статус. Вони перебувають у процесі розробки, і відомо, що в них відсутні деякі функції. Компоненти інсталятора можуть конфліктувати з наявними програмами або не встановлюватися, доки цей статус не буде скасовано.

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Деякі сторонні інструменти працюють не в кожній ОС. Перед встановленням ознайомтеся з актуальною документацією [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts).<sup>[[3]](#references)</sup>

**Встановлення**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
Підмодуль завантажує out-of-tree модулі GNU Radio, які використовує FISSURE, і є необхідним під час встановлення цих модулів. Інсталятор також встановить відсутні залежності PyQt, потрібні для запуску його графічних інтерфейсів встановлення.<sup>[[3]](#references)</sup>

Далі виберіть опцію, яка найкраще відповідає вашій операційній системі (її має бути визначено автоматично, якщо ваша ОС відповідає одній з опцій).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Рекомендується встановлювати FISSURE на чистій операційній системі, щоб уникнути наявних конфліктів. Виберіть усі рекомендовані прапорці (кнопка Default), щоб уникнути помилок під час роботи з різними інструментами в FISSURE. У процесі встановлення з’явиться кілька запитів, переважно щодо підвищених дозволів і імен користувачів. Якщо елемент містить наприкінці розділ "Verify", інсталятор виконає наведену команду та виділить цей елемент прапорця зеленим або червоним кольором залежно від того, чи виникли помилки під час виконання команди. Позначені елементи без розділу "Verify" після завершення встановлення залишаться чорними.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Використання**

Відкрийте термінал і введіть:
```
fissure
```
Докладнішу інформацію про використання див. у меню Help FISSURE.

## Подробиці

**Компоненти**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Можливості**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Детектор сигналів**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Маніпуляції IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Пошук сигналів**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Розпізнавання шаблонів**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Плейлисти сигналів**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Галерея зображень**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Створення пакетів**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Інтеграція Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Калькулятор CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Журналювання**_            |

**Апаратне забезпечення**

Наведене нижче апаратне забезпечення має різні рівні інтеграції з FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

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

FISSURE містить кілька корисних посібників для ознайомлення з різними технологіями та методами. Багато з них містять інструкції з використання різноманітних інструментів, інтегрованих у FISSURE.

* [Урок 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Урок 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Урок 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Урок 4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Урок 5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Урок 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Урок 7: Типи даних](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Урок 8: Користувацькі блоки GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Урок 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Урок 10: Іспити з аматорського радіозв’язку](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Урок 11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Урок 12: Створення завантажувальних USB-носіїв](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Урок 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Урок 14: Стельові вентилятори](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## План розвитку

* [ ] Додати більше типів апаратного забезпечення, RF-протоколів, параметрів сигналів та інструментів аналізу
* [ ] Додати підтримку більшої кількості операційних систем
* [ ] Розробити навчальні матеріали з FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt тощо)
* [ ] Створити кондиціонер сигналу, екстрактор ознак і класифікатор сигналів із можливістю вибору методів AI/ML
* [ ] Реалізувати рекурсивні механізми демодуляції для отримання бітового потоку з невідомих сигналів
* [ ] Перевести основні компоненти FISSURE на універсальну схему розгортання вузлів сенсорів

## Участь у розробці

Ми наполегливо заохочуємо пропозиції щодо вдосконалення FISSURE. Залиште коментар на сторінці [Discussions](https://github.com/ainfosec/FISSURE/discussions) або на Discord Server, якщо у вас є думки щодо наведеного нижче:

* Пропозиції нових функцій і зміни дизайну
* Програмні інструменти з інструкціями зі встановлення
* Нові уроки або додаткові матеріали для наявних уроків
* Цікаві RF-протоколи
* Додаткові типи апаратного забезпечення та SDR для інтеграції
* Скрипти аналізу IQ на Python
* Виправлення та вдосконалення встановлення

Внески для вдосконалення FISSURE мають вирішальне значення для прискорення його розробки. Ми високо цінуємо будь-який ваш внесок. Якщо ви хочете долучитися до розробки коду, створіть fork репозиторію та pull request:

1. Створіть fork проєкту
2. Створіть гілку функції (`git checkout -b feature/AmazingFeature`)
3. Зробіть commit змін (`git commit -m 'Add some AmazingFeature'`)
4. Виконайте push у гілку (`git push origin feature/AmazingFeature`)
5. Відкрийте pull request

Також вітається створення [Issues](https://github.com/ainfosec/FISSURE/issues) для привернення уваги до помилок.

## Співпраця

Зверніться до відділу Business Development компанії Assured Information Security, Inc. (AIS), щоб запропонувати та офіційно оформити можливості співпраці з FISSURE — чи то шляхом виділення часу на інтеграцію вашого програмного забезпечення, залучення талановитих фахівців AIS для розробки рішень ваших технічних проблем, чи інтеграції FISSURE в інші платформи/застосунки.

## Ліцензія

GPL-3.0

Докладні відомості про ліцензію див. у файлі LICENSE.

## Контакти

Приєднуйтеся до Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Стежте у Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Автори

Ми визнаємо внесок і висловлюємо вдячність цим розробникам:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Подяки

Особлива подяка Dr. Samuel Mantravadi та Joseph Reith за їхній внесок у цей проєкт.

## References

- [1] [FISSURE - RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [Стаття про FISSURE (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Документація FISSURE - Встановлення](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
