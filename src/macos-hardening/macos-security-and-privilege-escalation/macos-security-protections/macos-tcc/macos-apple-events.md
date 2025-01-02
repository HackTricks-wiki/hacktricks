# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Información Básica

**Apple Events** son una característica en macOS de Apple que permite a las aplicaciones comunicarse entre sí. Son parte del **Apple Event Manager**, que es un componente del sistema operativo macOS responsable de manejar la comunicación entre procesos. Este sistema permite que una aplicación envíe un mensaje a otra aplicación para solicitar que realice una operación particular, como abrir un archivo, recuperar datos o ejecutar un comando.

El daemon mina es `/System/Library/CoreServices/appleeventsd` que registra el servicio `com.apple.coreservices.appleevents`.

Cada aplicación que puede recibir eventos verificará con este daemon proporcionando su Apple Event Mach Port. Y cuando una aplicación quiere enviar un evento, la aplicación solicitará este puerto al daemon.

Las aplicaciones en sandbox requieren privilegios como `allow appleevent-send` y `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` para poder enviar eventos. Tenga en cuenta que los derechos como `com.apple.security.temporary-exception.apple-events` podrían restringir quién tiene acceso para enviar eventos, lo que necesitará derechos como `com.apple.private.appleevents`.

> [!TIP]
> Es posible usar la variable de entorno **`AEDebugSends`** para registrar información sobre el mensaje enviado:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
