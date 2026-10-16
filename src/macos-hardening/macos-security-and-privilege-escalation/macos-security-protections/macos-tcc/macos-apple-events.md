# Événements Apple

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

Les **événements Apple** sont des messages interprocessus structurés que les applications utilisent pour demander des opérations ou des données à d’autres applications. L’**Apple Event Manager** fournit les API nécessaires pour créer, envoyer, recevoir et traiter ces messages.<sup>[[1]](#references)</sup>

Sur macOS, le broker principal est `/System/Library/CoreServices/appleeventsd`, qui enregistre le service Mach `com.apple.coreservices.appleevents`. Les applications qui reçoivent des événements enregistrent un port Mach pour les événements Apple auprès de ce service ; les expéditeurs obtiennent le port de destination par son intermédiaire.<sup>[[3]](#references)</sup>

Les règles de sandbox et les entitlements limitent cette communication. Un profil de sandbox exprime généralement les opérations requises avec `allow appleevent-send` et une recherche Mach pour `com.apple.coreservices.appleevents` :<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

L’entitlement public `com.apple.security.temporary-exception.apple-events` peut limiter une application sandboxée à des identifiants de bundle de destination nommés. Lors de l’analyse de composants signés par Apple, vérifiez également la présence de l’entitlement privé `com.apple.private.appleevents` ; les entitlements privés d’Apple ne sont généralement pas accessibles aux applications tierces.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Définissez la variable d’environnement **`AEDebugSends`** pour journaliser les informations sur les événements Apple envoyés par un processus :<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Pour associer une autorisation Automation à son émetteur et à son destinataire, consultez [les autorisations TCC Apple Events](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Documentation Apple pour les développeurs - Gestionnaire Apple Event](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Documentation Apple pour les développeurs - Droits d’exception temporaires de l’App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X et les composants internes d’iOS - Variables d’environnement de débogage Apple-event](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
