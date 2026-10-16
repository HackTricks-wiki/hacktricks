# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**Apple events**, uygulamaların diğer uygulamalardan işlem veya veri istemek için kullandığı yapılandırılmış süreçler arası mesajlardır. **Apple Event Manager**, bu mesajları oluşturmak, göndermek, almak ve yanıtlamak için API'ler sağlar.<sup>[[1]](#references)</sup>

macOS'te temel aracı `/System/Library/CoreServices/appleeventsd`'dir. Bu servis, `com.apple.coreservices.appleevents` Mach servisini kaydeder. Event alan uygulamalar bu servise bir Apple-event Mach portu kaydeder; gönderenler hedef portu bu servis üzerinden edinir.<sup>[[3]](#references)</sup>

Sandbox kuralları ve yetkilendirmeler bu iletişimi sınırlar. Bir sandbox profili, gerekli işlemleri genellikle `allow appleevent-send` ve `com.apple.coreservices.appleevents` için Mach lookup olarak ifade eder:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

Herkese açık `com.apple.security.temporary-exception.apple-events` entitlement’ı, sandbox’lı bir uygulamayı adı belirtilen hedef bundle identifier’larıyla kısıtlayabilir. Apple tarafından imzalanmış bileşenleri analiz ederken, özel `com.apple.private.appleevents` entitlement’ını da kontrol edin; özel Apple entitlement’ları normalde üçüncü taraf uygulamalara sunulmaz.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Bir süreç tarafından gönderilen Apple event’leriyle ilgili bilgileri günlüğe kaydetmek için **`AEDebugSends`** ortam değişkenini ayarlayın:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Bir Automation grantini gönderen ve alıcıyla eşleştirmek için bkz. [TCC Apple Events grants](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Apple Geliştirici Belgeleri - Apple Event Yöneticisi](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Geliştirici Belgeleri - App Sandbox Geçici İstisna Yetkilendirmeleri](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X ve iOS İç Yapısı - Apple-event hata ayıklama ortam değişkenleri](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
