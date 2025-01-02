# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

**Apple Events** são um recurso no macOS da Apple que permite que aplicativos se comuniquem entre si. Eles fazem parte do **Apple Event Manager**, que é um componente do sistema operacional macOS responsável por gerenciar a comunicação entre processos. Este sistema permite que um aplicativo envie uma mensagem para outro aplicativo solicitando que ele execute uma operação específica, como abrir um arquivo, recuperar dados ou executar um comando.

O daemon mina é `/System/Library/CoreServices/appleeventsd`, que registra o serviço `com.apple.coreservices.appleevents`.

Todo aplicativo que pode receber eventos verificará com este daemon fornecendo seu Apple Event Mach Port. E quando um aplicativo deseja enviar um evento para ele, o aplicativo solicitará este porto ao daemon.

Aplicativos em sandbox requerem privilégios como `allow appleevent-send` e `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` para poder enviar eventos. Note que permissões como `com.apple.security.temporary-exception.apple-events` podem restringir quem tem acesso para enviar eventos, o que exigirá permissões como `com.apple.private.appleevents`.

> [!TIP]
> É possível usar a variável de ambiente **`AEDebugSends`** para registrar informações sobre a mensagem enviada:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
