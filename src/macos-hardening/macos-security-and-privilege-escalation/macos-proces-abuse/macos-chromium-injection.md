# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I browser basati su Chromium come Google Chrome, Microsoft Edge, Brave e altri. Questi browser sono costruiti sul progetto open-source Chromium, il che significa che condividono una base comune e, quindi, hanno funzionalità e opzioni per sviluppatori simili.

#### Flag `--load-extension`

Il flag `--load-extension` viene utilizzato quando si avvia un browser basato su Chromium dalla riga di comando o da uno script. Questo flag consente di **caricare automaticamente una o più estensioni** nel browser all'avvio.

#### Flag `--use-fake-ui-for-media-stream`

Il flag `--use-fake-ui-for-media-stream` è un'altra opzione da riga di comando che può essere utilizzata per avviare i browser basati su Chromium. Questo flag è progettato per **bypassare i normali avvisi per l'utente che chiedono il permesso di accedere ai flussi multimediali dalla fotocamera e dal microfono**. Quando questo flag è utilizzato, il browser concede automaticamente il permesso a qualsiasi sito web o applicazione che richiede l'accesso alla fotocamera o al microfono.

### Strumenti

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Esempio
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Trova ulteriori esempi nei link degli strumenti

## Riferimenti

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
