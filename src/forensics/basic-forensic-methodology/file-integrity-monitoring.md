{{#include ../../banners/hacktricks-training.md}}

# Базовий рівень

Базовий рівень складається з створення знімка певних частин системи для **порівняння з майбутнім станом для виявлення змін**.

Наприклад, ви можете обчислити та зберегти хеш кожного файлу файлової системи, щоб дізнатися, які файли були змінені.\
Це також можна зробити з обліковими записами користувачів, запущеними процесами, запущеними службами та будь-якою іншою річчю, яка не повинна змінюватися багато або взагалі.

## Моніторинг цілісності файлів

Моніторинг цілісності файлів (FIM) є критично важливою технікою безпеки, яка захищає ІТ-середовища та дані, відстежуючи зміни у файлах. Це включає два ключові етапи:

1. **Порівняння базового рівня:** Встановіть базовий рівень, використовуючи атрибути файлів або криптографічні контрольні суми (як MD5 або SHA-2) для майбутніх порівнянь для виявлення модифікацій.
2. **Сповіщення про зміни в реальному часі:** Отримуйте миттєві сповіщення, коли файли відкриваються або змінюються, зазвичай через розширення ядра ОС.

## Інструменти

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Посилання

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
