# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

Navegadores baseados em Chromium, como Google Chrome, Microsoft Edge, Brave e outros. Esses navegadores são construídos sobre o projeto de código aberto Chromium, o que significa que compartilham uma base comum e, portanto, têm funcionalidades e opções de desenvolvedor semelhantes.

#### Flag `--load-extension`

A flag `--load-extension` é usada ao iniciar um navegador baseado em Chromium a partir da linha de comando ou de um script. Essa flag permite **carregar automaticamente uma ou mais extensões** no navegador ao iniciar.

#### Flag `--use-fake-ui-for-media-stream`

A flag `--use-fake-ui-for-media-stream` é outra opção de linha de comando que pode ser usada para iniciar navegadores baseados em Chromium. Essa flag é projetada para **contornar os prompts normais do usuário que pedem permissão para acessar fluxos de mídia da câmera e do microfone**. Quando essa flag é usada, o navegador concede automaticamente permissão a qualquer site ou aplicativo que solicite acesso à câmera ou ao microfone.

### Ferramentas

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Exemplo
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Encontre mais exemplos nos links das ferramentas

## Referências

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
