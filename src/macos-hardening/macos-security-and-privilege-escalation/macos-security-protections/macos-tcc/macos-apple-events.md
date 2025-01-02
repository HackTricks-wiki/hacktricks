# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

**Apple Events** - це функція в macOS від Apple, яка дозволяє додаткам спілкуватися один з одним. Вони є частиною **Apple Event Manager**, який є компонентом операційної системи macOS, відповідальним за обробку міжпроцесного спілкування. Ця система дозволяє одному додатку надсилати повідомлення іншому додатку з проханням виконати певну операцію, наприклад, відкрити файл, отримати дані або виконати команду.

Основний демон - це `/System/Library/CoreServices/appleeventsd`, який реєструє сервіс `com.apple.coreservices.appleevents`.

Кожен додаток, який може отримувати події, перевіряє цей демон, надаючи свій Apple Event Mach Port. І коли додаток хоче надіслати подію, він запитує цей порт у демона.

Пісочничні додатки потребують привілеїв, таких як `allow appleevent-send` та `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`, щоб мати можливість надсилати події. Зверніть увагу, що права, такі як `com.apple.security.temporary-exception.apple-events`, можуть обмежити доступ до надсилання подій, що вимагатиме прав, таких як `com.apple.private.appleevents`.

> [!TIP]
> Можливо використовувати змінну середовища **`AEDebugSends`** для ведення журналу інформації про надіслане повідомлення:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
