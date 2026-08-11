# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper може запакувати виконуваний файл або скрипт у файл Windows Installer (`.msi`). Завантажте та запустіть безкоштовну версію, потім виберіть виконуваний файл для пакування. Щоб виконати послідовність команд, виберіть файл `.bat` як вхідний, а не пакуйте `cmd.exe`.<sup>[[1]](#references)</sup>

![Вибір вихідного виконуваного файлу або пакетного скрипту в MSI Wrapper](<../../images/image (417).png>)

Уважно налаштуйте контекст виконання та інші властивості інсталятора:

![Налаштування ідентифікатора застосунку та контексту безпеки в MSI Wrapper](<../../images/image (312).png>)

![Налаштування властивостей інсталятора в MSI Wrapper](<../../images/image (346).png>)

![Перевірка параметрів збірки MSI Wrapper](<../../images/image (1072).png>)

Ці значення можна змінити під час пакування користувацького бінарного файлу.

Перейдіть через решту сторінок майстра та виберіть **Build**, щоб згенерувати інсталятор.<sup>[[1]](#references)</sup>

> [!WARNING]
> Створення MSI саме по собі не надає підвищених привілеїв. Підвищення привілеїв під час інсталяції залежить від політики Windows Installer, контексту пакета та авторизації користувача. Microsoft попереджає, що ввімкнення `AlwaysInstallElevated` одночасно для користувача й комп’ютера дає змогу неадміністраторам встановлювати пакети із системними привілеями.<sup>[[2]](#references)</sup>

## References

- [1] [Документація MSI Wrapper - Початок роботи](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Встановлення пакета з підвищеними привілеями для користувача без прав адміністратора](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
{{#include ../../banners/hacktricks-training.md}}
