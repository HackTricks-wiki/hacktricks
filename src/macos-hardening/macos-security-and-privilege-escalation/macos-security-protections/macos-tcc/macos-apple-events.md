# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

**Apple events** — це структуровані міжпроцесні повідомлення, які програми використовують, щоб запитувати виконання операцій або отримання даних в інших програм. **Apple Event Manager** надає API для створення, надсилання, отримання та обробки цих повідомлень.<sup>[[1]](#references)</sup>

У macOS основним брокером є `/System/Library/CoreServices/appleeventsd`, який реєструє Mach-сервіс `com.apple.coreservices.appleevents`. Програми, що отримують події, реєструють порт Apple-event Mach у цьому сервісі; відправники отримують через нього порт призначення.<sup>[[3]](#references)</sup>

Правила sandbox і entitlements обмежують цей зв’язок. У профілі sandbox потрібні операції зазвичай задаються як `allow appleevent-send` і пошук Mach-сервісу `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

Публічний entitlement `com.apple.security.temporary-exception.apple-events` може обмежити застосунок у sandbox списком ідентифікаторів bundle призначення. Під час аналізу компонентів, підписаних Apple, також перевіряйте приватний entitlement `com.apple.private.appleevents`; приватні entitlements Apple зазвичай недоступні стороннім застосункам.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Установіть змінну середовища **`AEDebugSends`**, щоб журналювати інформацію про Apple events, які надсилає процес:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Щоб визначити відправника й одержувача дозволу Automation, див. [дозволи TCC Apple Events](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Документація Apple для розробників — Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Документація Apple для розробників — тимчасові винятки App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Внутрішня будова Mac OS X та iOS — змінні середовища налагодження Apple-event](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
