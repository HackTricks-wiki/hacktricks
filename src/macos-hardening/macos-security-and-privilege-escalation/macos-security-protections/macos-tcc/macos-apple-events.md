# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Información básica

**Apple Events** es una función de macOS de Apple que permite a las aplicaciones comunicarse entre sí. Forman parte del **Apple Event Manager**, que es un componente del sistema operativo macOS responsable de gestionar la comunicación entre procesos. Este sistema permite que una aplicación envíe un mensaje a otra para solicitarle que realice una operación concreta, como abrir un archivo, recuperar datos o ejecutar un comando.

El daemon principal es `/System/Library/CoreServices/appleeventsd`, que registra el servicio `com.apple.coreservices.appleevents`.

Cada aplicación que puede recibir eventos se registra con este daemon proporcionando su Apple Event Mach Port. Cuando una aplicación quiere enviarle un evento, solicita este port al daemon.

Las aplicaciones sandboxed necesitan privilegios como `allow appleevent-send` y `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` para poder enviar eventos. Ten en cuenta que entitlements como `com.apple.security.temporary-exception.apple-events` podrían restringir quién tiene acceso para enviar eventos, lo que requeriría entitlements como `com.apple.private.appleevents`.

> [!TIP]
> Es posible utilizar la variable de entorno **`AEDebugSends`** para registrar información sobre el mensaje enviado:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
