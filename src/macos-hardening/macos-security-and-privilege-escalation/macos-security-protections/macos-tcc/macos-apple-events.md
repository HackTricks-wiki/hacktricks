# Apple Events de macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Información básica

Los **Apple events** son mensajes estructurados entre procesos que las aplicaciones utilizan para solicitar operaciones o datos a otras aplicaciones. El **Apple Event Manager** proporciona las API para crear, enviar, recibir y responder a estos mensajes.<sup>[[1]](#references)</sup>

En macOS, el broker principal es `/System/Library/CoreServices/appleeventsd`, que registra el servicio Mach `com.apple.coreservices.appleevents`. Las aplicaciones que reciben eventos registran un puerto Mach de Apple events en este servicio; los emisores obtienen el puerto de destino a través de él.<sup>[[3]](#references)</sup>

Las reglas del sandbox y los entitlements limitan esta comunicación. Un perfil de sandbox necesita permiso para enviar Apple events y buscar el servicio Mach del broker. El entitlement `com.apple.security.temporary-exception.apple-events` puede restringir aún más una aplicación en sandbox a identificadores de bundle de destino específicos.<sup>[[2]](#references)</sup>

> [!TIP]
> Establece la variable de entorno **`AEDebugSends`** para registrar información sobre los Apple events enviados por un proceso:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Documentación de Apple para desarrolladores - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Documentación de Apple para desarrolladores - Entitlements de excepción temporal de App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Variables de entorno de depuración de Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
