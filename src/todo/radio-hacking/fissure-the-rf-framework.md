# FISSURE - The RF Framework

**Незалежне від частоти розуміння сигналів на основі SDR та зворотне проектування**

FISSURE - це відкритий фреймворк для RF та зворотного проектування, розроблений для всіх рівнів навичок з можливостями для виявлення та класифікації сигналів, виявлення протоколів, виконання атак, маніпуляцій з IQ, аналізу вразливостей, автоматизації та AI/ML. Фреймворк був створений для сприяння швидкій інтеграції програмних модулів, радіо, протоколів, даних сигналів, скриптів, графіків потоку, довідкових матеріалів та сторонніх інструментів. FISSURE є інструментом для робочих процесів, який зберігає програмне забезпечення в одному місці та дозволяє командам без зусиль швидко адаптуватися, використовуючи одну й ту ж перевірену базову конфігурацію для конкретних дистрибутивів Linux.

Фреймворк та інструменти, включені до FISSURE, призначені для виявлення наявності RF-енергії, розуміння характеристик сигналу, збору та аналізу зразків, розробки технік передачі та/або ін'єкції, а також створення користувацьких корисних навантажень або повідомлень. FISSURE містить зростаючу бібліотеку інформації про протоколи та сигнали для допомоги в ідентифікації, створенні пакетів та фуззингу. Існують можливості онлайн-архіву для завантаження файлів сигналів та створення плейлистів для симуляції трафіку та тестування систем.

Дружня кодова база Python та інтерфейс користувача дозволяють новачкам швидко дізнаватися про популярні інструменти та техніки, пов'язані з RF та зворотним проектуванням. Викладачі в галузі кібербезпеки та інженерії можуть скористатися вбудованими матеріалами або використовувати фреймворк для демонстрації своїх власних реальних застосувань. Розробники та дослідники можуть використовувати FISSURE для своїх щоденних завдань або для представлення своїх передових рішень ширшій аудиторії. З ростом обізнаності та використання FISSURE в спільноті, зросте і обсяг його можливостей та широта технологій, які він охоплює.

**Додаткова інформація**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Початок роботи

**Підтримується**

Існує три гілки в FISSURE, щоб полегшити навігацію по файлах та зменшити надмірність коду. Гілка Python2\_maint-3.7 містить кодову базу, побудовану на Python2, PyQt4 та GNU Radio 3.7; гілка Python3\_maint-3.8 побудована на Python3, PyQt5 та GNU Radio 3.8; а гілка Python3\_maint-3.10 побудована на Python3, PyQt5 та GNU Radio 3.10.

|   Операційна система   |   Гілка FISSURE   |
| :--------------------: | :---------------: |
|  Ubuntu 18.04 (x64)   | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64)  | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64)  | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64)  | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64)  | Python3\_maint-3.8 |

**В процесі (бета)**

Ці операційні системи все ще знаходяться в бета-статусі. Вони знаходяться в розробці, і відомо, що кілька функцій відсутні. Елементи в установнику можуть конфліктувати з існуючими програмами або не встановлюватися, поки статус не буде знято.

|     Операційна система     |    Гілка FISSURE   |
| :------------------------: | :----------------: |
| DragonOS Focal (x86\_64)  |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)     | Python3\_maint-3.10 |

Примітка: Деякі програмні інструменти не працюють для кожної ОС. Зверніться до [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Встановлення**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Це встановить залежності програмного забезпечення PyQt, необхідні для запуску графічних інтерфейсів установки, якщо вони не знайдені.

Далі виберіть опцію, яка найкраще відповідає вашій операційній системі (повинна бути виявлена автоматично, якщо ваша ОС відповідає опції).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Рекомендується встановлювати FISSURE на чисту операційну систему, щоб уникнути існуючих конфліктів. Виберіть всі рекомендовані прапорці (кнопка за замовчуванням), щоб уникнути помилок під час роботи з різними інструментами в FISSURE. Протягом установки буде кілька запитів, в основному запитуючи підвищені дозволи та імена користувачів. Якщо елемент містить розділ "Перевірити" в кінці, установник виконає команду, що йде далі, і підсвітить елемент прапорця зеленим або червоним кольором в залежності від того, чи виникли помилки під час виконання команди. Вибрані елементи без розділу "Перевірити" залишаться чорними після установки.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Використання**

Відкрийте термінал і введіть:
```
fissure
```
Зверніться до меню допомоги FISSURE для отримання додаткової інформації про використання.

## Деталі

**Компоненти**

* Панель управління
* Центральний вузол (HIPRFISR)
* Ідентифікація цільового сигналу (TSI)
* Виявлення протоколів (PD)
* Граф потоку та виконавця скриптів (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Можливості**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Детектор сигналу**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Маніпуляція IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Пошук сигналу**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Визнання шаблонів**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Атаки**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Фаззинг**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Плейлисти сигналів**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Галерея зображень**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Створення пакетів**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Інтеграція Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Калькулятор CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Логування**_            |

**Апаратура**

Наступний список "підтримуваної" апаратури з різними рівнями інтеграції:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Адаптери 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Уроки

FISSURE постачається з кількома корисними посібниками, щоб ознайомитися з різними технологіями та техніками. Багато з них містять кроки для використання різних інструментів, які інтегровані в FISSURE.

* [Урок1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Урок2: Lua Дисектори](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Урок3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Урок4: ESP Плати](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Урок5: Трекінг Радіозондів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Урок6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Урок7: Типи Даних](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Урок8: Користувацькі блоки GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Урок9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Урок10: Екзамени на радіоаматорів](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Урок11: Wi-Fi Інструменти](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Дорожня карта

* [ ] Додати більше типів апаратури, RF протоколів, параметрів сигналу, інструментів аналізу
* [ ] Підтримка більше операційних систем
* [ ] Розробити навчальні матеріали навколо FISSURE (RF Атаки, Wi-Fi, GNU Radio, PyQt тощо)
* [ ] Створити кондиціонер сигналу, екстрактор ознак та класифікатор сигналів з вибором AI/ML технік
* [ ] Реалізувати рекурсивні механізми демодуляції для отримання бітового потоку з невідомих сигналів
* [ ] Перенести основні компоненти FISSURE на загальну схему розгортання сенсорних вузлів

## Участь

Пропозиції щодо покращення FISSURE дуже вітаються. Залиште коментар на сторінці [Обговорення](https://github.com/ainfosec/FISSURE/discussions) або на сервері Discord, якщо у вас є думки щодо наступного:

* Пропозиції нових функцій та зміни дизайну
* Програмні інструменти з кроками установки
* Нові уроки або додаткові матеріали для існуючих уроків
* RF протоколи, що вас цікавлять
* Більше апаратури та типів SDR для інтеграції
* Скрипти аналізу IQ на Python
* Виправлення та покращення установки

Внески для покращення FISSURE є важливими для прискорення його розвитку. Будь-які внески, які ви зробите, дуже цінуються. Якщо ви хочете внести свій внесок через розробку коду, будь ласка, створіть форк репозиторію та створіть запит на злиття:

1. Форкніть проект
2. Створіть свою гілку функцій (`git checkout -b feature/AmazingFeature`)
3. Зафіксуйте свої зміни (`git commit -m 'Додати деякі AmazingFeature'`)
4. Відправте на гілку (`git push origin feature/AmazingFeature`)
5. Відкрийте запит на злиття

Створення [Проблем](https://github.com/ainfosec/FISSURE/issues) для привернення уваги до помилок також вітається.

## Співпраця

Зв'яжіться з Assured Information Security, Inc. (AIS) для пропозиції та формалізації будь-яких можливостей співпраці FISSURE – чи то через виділення часу на інтеграцію вашого програмного забезпечення, чи через залучення талановитих людей з AIS для розробки рішень для ваших технічних викликів, чи інтеграцію FISSURE в інші платформи/додатки.

## Ліцензія

GPL-3.0

Для деталей ліцензії дивіться файл LICENSE.

## Контакт

Приєднуйтесь до сервера Discord: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Слідкуйте за нами в Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Кріс Пур - Assured Information Security, Inc. - poorec@ainfosec.com

Розвиток бізнесу - Assured Information Security, Inc. - bd@ainfosec.com

## Подяки

Ми визнаємо та вдячні цим розробникам:

[Подяки](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Визнання

Особлива подяка доктору Семюелю Мантраві та Джозефу Рейту за їх внесок у цей проект.
