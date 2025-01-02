# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Отримайте перспективу хакера щодо ваших веб-додатків, мережі та хмари**

**Знайдіть і повідомте про критичні, експлуатовані вразливості з реальним бізнес-імпактом.** Використовуйте наші 20+ спеціальних інструментів для картографування поверхні атаки, знаходження проблем безпеки, які дозволяють вам підвищувати привілеї, і використовуйте автоматизовані експлойти для збору важливих доказів, перетворюючи вашу важку працю на переконливі звіти.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Як це працює

**Smbexec** - це інструмент, що використовується для віддаленого виконання команд на системах Windows, подібно до **Psexec**, але він уникає розміщення будь-яких шкідливих файлів на цільовій системі.

### Ключові моменти про **SMBExec**

- Він працює, створюючи тимчасову службу (наприклад, "BTOBTO") на цільовій машині для виконання команд через cmd.exe (%COMSPEC%), без скидання будь-яких бінарних файлів.
- Незважаючи на свій прихований підхід, він генерує журнали подій для кожної виконаної команди, пропонуючи форму неінтерактивної "оболонки".
- Команда для підключення за допомогою **Smbexec** виглядає так:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Виконання команд без бінарних файлів

- **Smbexec** дозволяє безпосереднє виконання команд через binPaths сервісу, усуваючи необхідність у фізичних бінарних файлах на цілі.
- Цей метод корисний для виконання одноразових команд на цільовій системі Windows. Наприклад, поєднання його з модулем `web_delivery` Metasploit дозволяє виконати зворотний Meterpreter payload, націлений на PowerShell.
- Створивши віддалений сервіс на машині атакуючого з binPath, налаштованим для виконання наданої команди через cmd.exe, можна успішно виконати payload, досягнувши зворотного виклику та виконання payload з прослуховувачем Metasploit, навіть якщо виникають помилки у відповіді сервісу.

### Приклад команд

Створення та запуск сервісу можна виконати за допомогою наступних команд:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Для отримання додаткової інформації перегляньте [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Посилання

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Отримайте погляд хакера на ваші веб-додатки, мережу та хмару**

**Знайдіть і повідомте про критичні, експлуатовані вразливості з реальним бізнес-імпактом.** Використовуйте наші 20+ спеціальних інструментів для картографування поверхні атаки, виявлення проблем безпеки, які дозволяють вам підвищити привілеї, і використовуйте автоматизовані експлойти для збору важливих доказів, перетворюючи вашу важку працю на переконливі звіти.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}
