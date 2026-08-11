# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**Apple events**, uygulamaların diğer uygulamalardan işlem veya veri istemek için kullandığı yapılandırılmış interprocess mesajlardır. **Apple Event Manager**, bu mesajları oluşturmak, göndermek, almak ve yanıtlamak için API'ler sağlar.<sup>[[1]](#references)</sup>

macOS'ta temel broker, `com.apple.coreservices.appleevents` Mach service'ini kaydeden `/System/Library/CoreServices/appleeventsd`'dir. Event alan uygulamalar, bu service ile bir Apple-event Mach port'u kaydeder; gönderenler hedef port'u bu service üzerinden alır.<sup>[[3]](#references)</sup>

Sandbox kuralları ve entitlements bu iletişimi sınırlar. Bir sandbox profile, Apple events göndermek ve broker'ın Mach service'ini aramak için izin gerektirir. `com.apple.security.temporary-exception.apple-events` entitlement'ı, sandbox'lı bir uygulamayı adlandırılmış hedef bundle identifier'larıyla daha fazla kısıtlayabilir.<sup>[[2]](#references)</sup>

> [!TIP]
> Bir process tarafından gönderilen Apple events hakkında bilgi kaydetmek için **`AEDebugSends`** environment variable'ını ayarlayın:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Apple Developer Documentation - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Apple Developer Documentation - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Apple-event debug environment variables](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
