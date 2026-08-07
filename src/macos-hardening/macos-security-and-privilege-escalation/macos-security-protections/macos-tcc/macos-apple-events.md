# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

**Apple Events** — це функція в macOS від Apple, яка дозволяє застосункам взаємодіяти один з одним. Вони є частиною **Apple Event Manager** — компонента операційної системи macOS, відповідального за обробку міжпроцесної взаємодії. Ця система дозволяє одному застосунку надсилати повідомлення іншому застосунку із запитом виконати певну операцію, наприклад відкрити файл, отримати дані або виконати команду.

Основним демоном є `/System/Library/CoreServices/appleeventsd`, який реєструє сервіс `com.apple.coreservices.appleevents`.

Кожен застосунок, який може отримувати події, реєструється в цього демона, надаючи свій Apple Event Mach Port. Коли застосунок хоче надіслати йому подію, він запитує цей порт у демона.

Для надсилання подій sandboxed-застосункам потрібні такі привілеї, як `allow appleevent-send` і `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`. Зверніть увагу, що entitlements на кшталт `com.apple.security.temporary-exception.apple-events` можуть обмежувати, хто має доступ до надсилання подій; для цього можуть знадобитися entitlements на кшталт `com.apple.private.appleevents`.

> [!TIP]
> Для журналювання інформації про надіслане повідомлення можна використовувати змінну середовища **`AEDebugSends`**:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
