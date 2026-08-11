# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

**Apple events** — це структуровані міжпроцесні повідомлення, які застосунки використовують для запиту операцій або даних в інших застосунків. **Apple Event Manager** надає API для створення, надсилання, отримання та обробки цих повідомлень.<sup>[[1]](#references)</sup>

У macOS основним брокером є `/System/Library/CoreServices/appleeventsd`, який реєструє Mach-сервіс `com.apple.coreservices.appleevents`. Застосунки, що отримують події, реєструють Apple-event Mach-порт у цьому сервісі; відправники отримують через нього порт призначення.<sup>[[3]](#references)</sup>

Правила sandbox і entitlements обмежують цю комунікацію. Профіль sandbox має надавати дозвіл на надсилання Apple events і пошук Mach-сервісу брокера. Entitlement `com.apple.security.temporary-exception.apple-events` може додатково обмежити sandboxed застосунок визначеними ідентифікаторами bundle призначення.<sup>[[2]](#references)</sup>

> [!TIP]
> Установіть змінну середовища **`AEDebugSends`**, щоб журналювати інформацію про Apple events, надіслані процесом:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Документація Apple для розробників - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Документація Apple для розробників - Тимчасові винятки entitlement для App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Внутрішня будова Mac OS X та iOS - Змінні середовища для налагодження Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
