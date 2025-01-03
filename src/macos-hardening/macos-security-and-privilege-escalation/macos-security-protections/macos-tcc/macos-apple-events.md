# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**Apple Events**, uygulamaların birbirleriyle iletişim kurmasına olanak tanıyan bir macOS özelliğidir. Bunlar, interprocess iletişimini yöneten macOS işletim sisteminin bir bileşeni olan **Apple Event Manager**'ın bir parçasıdır. Bu sistem, bir uygulamanın başka bir uygulamaya belirli bir işlemi gerçekleştirmesi için bir mesaj göndermesini sağlar; örneğin, bir dosyayı açmak, veri almak veya bir komut yürütmek gibi.

mina daemon'ı `/System/Library/CoreServices/appleeventsd` olup, `com.apple.coreservices.appleevents` hizmetini kaydeder.

Olay alabilen her uygulama, Apple Event Mach Port'unu sağlayarak bu daemon ile kontrol edilir. Bir uygulama bir olayı göndermek istediğinde, daemon'dan bu portu talep eder.

Sandboxed uygulamalar, olay gönderebilmek için `allow appleevent-send` ve `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` gibi ayrıcalıklara ihtiyaç duyar. `com.apple.security.temporary-exception.apple-events` gibi yetkilendirmelerin, olay gönderebilecek kişileri kısıtlayabileceğini unutmayın; bu da `com.apple.private.appleevents` gibi yetkilendirmelere ihtiyaç duyacaktır.

> [!TIP]
> Gönderilen mesaj hakkında bilgi kaydetmek için **`AEDebugSends`** ortam değişkenini kullanmak mümkündür:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
