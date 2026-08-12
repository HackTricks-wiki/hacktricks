# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

**Apple events** — це структуровані міжпроцесні повідомлення, які застосунки використовують для запиту операцій або даних в інших застосунків. **Apple Event Manager** надає API для створення, надсилання, отримання та обробки цих повідомлень.<sup>[[1]](#references)</sup>

У macOS основним брокером є `/System/Library/CoreServices/appleeventsd`, який реєструє Mach service `com.apple.coreservices.appleevents`. Застосунки, що отримують події, реєструють Apple-event Mach port у цьому сервісі; відправники отримують через нього порт призначення.<sup>[[3]](#references)</sup>

Правила sandbox і entitlements обмежують цю комунікацію. Профіль sandbox зазвичай визначає необхідні операції як `allow appleevent-send` і Mach lookup для `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
Публічний entitlement `com.apple.security.temporary-exception.apple-events` може обмежити sandboxed application визначеними ідентифікаторами bundle призначення. Під час аналізу компонентів, підписаних Apple, також перевіряйте private entitlement `com.apple.private.appleevents`; private Apple entitlements зазвичай недоступні для сторонніх application.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Встановіть змінну середовища **`AEDebugSends`**, щоб журналювати інформацію про Apple events, надіслані процесом:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Документація Apple для розробників - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Документація Apple для розробників - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
