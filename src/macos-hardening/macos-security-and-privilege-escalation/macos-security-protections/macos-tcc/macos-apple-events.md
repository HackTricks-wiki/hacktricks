# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**Apple Events**, Apple'ın macOS işletim sisteminde uygulamaların birbirleriyle iletişim kurmasını sağlayan bir özelliktir. Bunlar, süreçler arası iletişimi yönetmekten sorumlu macOS işletim sistemi bileşeni olan **Apple Event Manager**'ın bir parçasıdır. Bu sistem, bir uygulamanın başka bir uygulamaya dosya açma, veri alma veya komut çalıştırma gibi belirli bir işlemi gerçekleştirmesini istemek üzere mesaj göndermesini sağlar.

Ana daemon `/System/Library/CoreServices/appleeventsd` olup `com.apple.coreservices.appleevents` servisini kaydeder.

Event alabilen her uygulama, Apple Event Mach Port'unu bu daemon'a bildirerek kayıt işlemi gerçekleştirir. Bir uygulama başka bir uygulamaya event göndermek istediğinde, bu portu daemon'dan ister.

Sandboxed uygulamaların event gönderebilmesi için `allow appleevent-send` ve `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` gibi ayrıcalıklara ihtiyacı vardır. `com.apple.security.temporary-exception.apple-events` gibi entitlement'lar, event gönderme erişimine sahip olanları kısıtlayabilir; bu durumda `com.apple.private.appleevents` gibi entitlement'lar gerekir.

> [!TIP]
> Gönderilen mesaj hakkındaki bilgileri loglamak için **`AEDebugSends`** env variable'ını kullanmak mümkündür:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
