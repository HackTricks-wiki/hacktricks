# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

Les **Apple events** sont des messages interprocessus structurés que les applications utilisent pour demander des opérations ou des données à d'autres applications. L'**Apple Event Manager** fournit les API nécessaires à la création, à l'envoi, à la réception et au traitement de ces messages.<sup>[[1]](#references)</sup>

Sur macOS, le broker principal est `/System/Library/CoreServices/appleeventsd`, qui enregistre le service Mach `com.apple.coreservices.appleevents`. Les applications qui reçoivent des événements enregistrent un port Mach Apple event auprès de ce service ; les émetteurs obtiennent le port de destination par son intermédiaire.<sup>[[3]](#references)</sup>

Les règles de sandbox et les entitlements limitent cette communication. Un profil de sandbox doit disposer de l'autorisation d'envoyer des Apple events et de rechercher le service Mach du broker. L'entitlement `com.apple.security.temporary-exception.apple-events` peut restreindre davantage une application sandboxée à des identifiants de bundle de destination nommés.<sup>[[2]](#references)</sup>

> [!TIP]
> Définissez la variable d'environnement **`AEDebugSends`** pour journaliser les informations sur les Apple events envoyés par un processus :<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Documentation Apple Developer - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Documentation Apple Developer - Entitlements d'exception temporaire de l'App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Internals de Mac OS X et iOS - Variables d'environnement de débogage des Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
