# Apple Events do macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Informações básicas

**Apple events** são mensagens estruturadas entre processos que os aplicativos usam para solicitar operações ou dados de outros aplicativos. O **Apple Event Manager** fornece as APIs para criar, enviar, receber e responder a essas mensagens.<sup>[[1]](#references)</sup>

No macOS, o broker principal é `/System/Library/CoreServices/appleeventsd`, que registra o serviço Mach `com.apple.coreservices.appleevents`. Os aplicativos que recebem eventos registram uma porta Mach de Apple event nesse serviço; os remetentes obtêm a porta de destino por meio dele.<sup>[[3]](#references)</sup>

As regras de sandbox e os entitlements limitam essa comunicação. Um perfil de sandbox normalmente expressa as operações necessárias como `allow appleevent-send` e uma consulta Mach para `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
O entitlement público `com.apple.security.temporary-exception.apple-events` pode restringir uma aplicação em sandbox a identificadores de bundle de destino nomeados. Ao analisar componentes assinados pela Apple, verifique também o entitlement privado `com.apple.private.appleevents`; os entitlements privados da Apple normalmente não estão disponíveis para aplicações de terceiros.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Defina a variável de ambiente **`AEDebugSends`** para registrar informações sobre os Apple events enviados por um processo:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Documentação para desenvolvedores da Apple - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Documentação para desenvolvedores da Apple - Entitlements de exceção temporária do App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Internals do Mac OS X e iOS - Variáveis de ambiente de debug de Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
