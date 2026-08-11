# Apple Events do macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Informações básicas

**Apple events** são mensagens estruturadas entre processos que os aplicativos usam para solicitar operações ou dados de outros aplicativos. O **Apple Event Manager** fornece as APIs para criar, enviar, receber e responder a essas mensagens.<sup>[[1]](#references)</sup>

No macOS, o principal broker é `/System/Library/CoreServices/appleeventsd`, que registra o serviço Mach `com.apple.coreservices.appleevents`. Os aplicativos que recebem eventos registram uma porta Mach de Apple event nesse serviço; os remetentes obtêm a porta de destino por meio dele.<sup>[[3]](#references)</sup>

As regras de sandbox e os entitlements limitam essa comunicação. Um perfil de sandbox precisa de permissão para enviar Apple events e consultar o serviço Mach do broker. O entitlement `com.apple.security.temporary-exception.apple-events` pode restringir ainda mais um aplicativo em sandbox a identificadores de bundle de destino nomeados.<sup>[[2]](#references)</sup>

> [!TIP]
> Defina a variável de ambiente **`AEDebugSends`** para registrar informações sobre os Apple events enviados por um processo:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Documentação do Apple Developer - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Documentação do Apple Developer - Entitlements de exceção temporária do App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Variáveis de ambiente de depuração de Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
