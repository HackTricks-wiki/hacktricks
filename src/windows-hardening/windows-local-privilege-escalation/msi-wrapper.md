# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper може запакувати виконуваний файл або скрипт у файл Windows Installer (`.msi`). Завантажте та запустіть безкоштовну версію, а потім виберіть виконуваний файл для пакування.<sup>[[3]](#references)</sup> Щоб виконати послідовність команд, виберіть файл `.bat` як вхідний, а не пакуйте `cmd.exe`.<sup>[[1]](#references)</sup>

![Вибір вихідного виконуваного файлу або пакетного скрипту в MSI Wrapper](<../../images/image (417).png>)

Уважно налаштуйте контекст виконання та інші властивості інсталятора:

![Налаштування ID програми та контексту безпеки в MSI Wrapper](<../../images/image (312).png>)

![Налаштування властивостей інсталятора в MSI Wrapper](<../../images/image (346).png>)

![Перевірка параметрів збірки MSI Wrapper](<../../images/image (1072).png>)

Ці значення можна змінити під час пакування власного бінарного файлу.

Перейдіть до решти сторінок майстра та виберіть **Build**, щоб створити інсталятор.<sup>[[1]](#references)</sup>

## Перевірка контексту виконання обгорнутої команди

Для тестового пакета обгорніть файл `.bat`, який записує свій токен, а не припускайте, що параметр підвищення привілеїв MSI застосовується до дочірнього процесу.<sup>[[4]](#references)</sup> У майстрі виберіть контекст безпеки **System**, а не **User**, і виберіть інсталяцію для всього комп’ютера з підвищеними привілеями, якщо саме такий шлях потрібен.<sup>[[5]](#references)</sup> Параметр **System** не обходить авторизацію: користувачу без прав адміністратора все одно потрібен шлях інсталяції з підвищеними привілеями, наприклад [неправильна конфігурація `AlwaysInstallElevated` із двома політиками](index.html#alwaysinstallelevated) або привілейований процес інсталяції.<sup>[[2]](#references)</sup> Натомість вибір **User** запускає обгорнуту команду в контексті користувача, який виконує інсталяцію; це може знадобитися для доступу до ресурсів користувача або мережі.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Створіть MSI, використавши цей batch-файл як вхідний, потім запустіть його на тестовому хості та перевірте записані ідентифікаційні дані й привілеї.<sup>[[4]](#references)</sup> MSI Wrapper перетворює ненульовий код завершення batch-файлу на помилку встановлення 1603, тому явний нульовий код завершення дає змогу уникнути хибної помилки після успішного тесту.<sup>[[4]](#references)</sup> Вихідний файл є тестовим артефактом; не робіть висновок про виконання від SYSTEM лише на підставі успішного завершення `msiexec` або тихого встановлення.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` вимикає інтерфейс MSI, але не обов’язково інтерфейс самого обгорнутого виконуваного файла.<sup>[[6]](#references)[[7]](#references)</sup> Для обгорнутого інсталятора задайте підтримувані аргументи тихого режиму в майстрі; динамічна властивість `WRAPPED_ARGUMENTS` у MSI Wrapper доступна лише у версії PRO.<sup>[[1]](#references)[[7]](#references)</sup> Див. [підхід із custom action у WiX](create-msi-with-wix.md), якщо потрібен прямий контроль над послідовністю виконання custom action і impersonation.

> [!WARNING]
> Створення MSI саме по собі не надає підвищених привілеїв. Підвищення привілеїв під час інсталяції залежить від політики Windows Installer, контексту пакета та авторизації користувача. Microsoft попереджає, що ввімкнення `AlwaysInstallElevated` для користувача й комп’ютера дає змогу не-адміністраторам інсталювати пакети із системними привілеями.<sup>[[2]](#references)</sup>



## References

- [1] [Документація MSI Wrapper - Початок роботи](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Інсталяція пакета з підвищеними привілеями для користувача без прав адміністратора](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Завантаження](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Створення MSI з batch-файла](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Сторінки майстра](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Параметри командного рядка](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Аргументи командного рядка](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
