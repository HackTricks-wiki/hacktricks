# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Informações básicas

**Apple events** são mensagens estruturadas entre processos que os aplicativos usam para solicitar operações ou dados de outros aplicativos. O **Apple Event Manager** fornece as APIs para criar, enviar, receber e responder a essas mensagens.<sup>[[1]](#references)</sup>

No macOS, o principal broker é `/System/Library/CoreServices/appleeventsd`, que registra o serviço Mach `com.apple.coreservices.appleevents`. Os aplicativos que recebem eventos registram uma porta Mach de Apple events nesse serviço; os remetentes obtêm a porta de destino por meio dele.<sup>[[3]](#references)</sup>

As regras de sandbox e os entitlements limitam essa comunicação. Um perfil de sandbox geralmente expressa as operações necessárias como `allow appleevent-send` e uma consulta Mach para `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

O entitlement público `com.apple.security.temporary-exception.apple-events` pode restringir um aplicativo em sandbox a identificadores de bundle de destino específicos. Ao analisar componentes assinados pela Apple, verifique também o entitlement privado `com.apple.private.appleevents`; os entitlements privados da Apple normalmente não estão disponíveis para aplicativos de terceiros.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Defina a variável de ambiente **`AEDebugSends`** para registrar informações sobre os Apple events enviados por um processo:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Para mapear uma concessão de Automation ao remetente e destinatário, consulte [concessões de TCC para Apple Events](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Documentação para Desenvolvedores da Apple - Gerenciador de Apple Events](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Documentação para Desenvolvedores da Apple - Direitos de exceção temporária do App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X e Internals do iOS - Variáveis de ambiente de depuração de Apple-event](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
