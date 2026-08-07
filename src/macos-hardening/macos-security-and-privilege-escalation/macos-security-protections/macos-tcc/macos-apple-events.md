# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informações básicas

**Apple Events** são um recurso do macOS da Apple que permite que os aplicativos se comuniquem entre si. Eles fazem parte do **Apple Event Manager**, que é um componente do sistema operacional macOS responsável por gerenciar a comunicação entre processos. Esse sistema permite que um aplicativo envie uma mensagem para outro aplicativo solicitando que ele execute uma operação específica, como abrir um arquivo, recuperar dados ou executar um comando.

O daemon principal é `/System/Library/CoreServices/appleeventsd`, que registra o serviço `com.apple.coreservices.appleevents`.

Todo aplicativo que pode receber eventos consulta esse daemon, fornecendo sua Apple Event Mach Port. Quando um aplicativo deseja enviar um evento para ele, solicita essa porta ao daemon.

Aplicativos em sandbox precisam de privilégios como `allow appleevent-send` e `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` para poder enviar eventos. Observe que entitlements como `com.apple.security.temporary-exception.apple-events` podem restringir quem tem acesso para enviar eventos, o que exigirá entitlements como `com.apple.private.appleevents`.

> [!TIP]
> É possível usar a variável de ambiente **`AEDebugSends`** para registrar informações sobre a mensagem enviada:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
