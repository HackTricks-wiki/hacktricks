# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**Apple events**, uygulamaların diğer uygulamalardan işlem veya veri istemek için kullandığı yapılandırılmış süreçler arası iletilerdir. **Apple Event Manager**, bu iletileri oluşturmak, göndermek, almak ve yanıtlamak için API'ler sağlar.<sup>[[1]](#references)</sup>

macOS'ta temel broker, `com.apple.coreservices.appleevents` Mach service'ini kaydeden `/System/Library/CoreServices/appleeventsd` işlemidir. Event alan uygulamalar bu service ile bir Apple-event Mach port'u kaydeder; göndericiler hedef port'u bu service üzerinden alır.<sup>[[3]](#references)</sup>

Sandbox kuralları ve entitlement'lar bu iletişimi sınırlar. Bir sandbox profili, gerekli işlemleri genellikle `allow appleevent-send` ve `com.apple.coreservices.appleevents` için bir Mach lookup olarak ifade eder:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
Genel kullanıma açık `com.apple.security.temporary-exception.apple-events` entitlement'ı, sandbox uygulanmış bir uygulamayı adlandırılmış hedef bundle identifier'larıyla sınırlayabilir. Apple tarafından imzalanmış bileşenleri analiz ederken, özel `com.apple.private.appleevents` entitlement'ını da kontrol edin; özel Apple entitlement'ları normalde üçüncü taraf uygulamaların kullanımına açık değildir.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Bir process tarafından gönderilen Apple events hakkındaki bilgileri loglamak için **`AEDebugSends`** environment variable'ını ayarlayın:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Yöneticisi](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Geçici İstisna Entitlement'ları](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple event debug environment variable'ları](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
